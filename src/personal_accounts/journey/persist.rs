// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The sealed `journeys.json` file and its in-memory slot (design §5.1, §5.2).

use super::super::commit::{Replace, ReplaceStep, replace_file};
use super::super::{TokenEnvelope, encode_fields, open_bytes, read_bounded, seal_bytes};
use super::limits::Rates;
use super::sweep::sweep;
use super::{
    AccountError, JOURNEY_SCHEMA, JOURNEYS_FILE, JourneyError, JourneyLimits, JourneyRefusal,
    JourneyTable, KEY_ID_MAX, StoreConfig,
};
use crate::personal_accounts::{Authority, AuthoritySlot, PersonalAccountStore};

/// AAD domain of the journeys envelope; mirrors `authority_aad` (§5.1).
const JOURNEYS_DOMAIN: &[u8] = b"mcp-gateway/account-journeys-aad/v1";

/// Compact `TokenEnvelope` framing with the widest accepted key id and an
/// empty ciphertext. Key ids are `[A-Za-z0-9._-]`, so nothing is escaped.
pub(super) const ENVELOPE_FRAME: usize =
    r#"{"schema_version":"","key_id":"","nonce":"","ciphertext":""}"#.len()
        + JOURNEY_SCHEMA.len()
        + KEY_ID_MAX
        + 16;

/// The journeys half of the authority mutex. It poisons on its own (R2-1):
/// `Stale` never touches the authority, and only a reopen clears it.
#[derive(Debug, Default)]
pub(crate) struct JourneysSlot {
    table: TableState,
    rates: Rates,
}

#[derive(Debug, Default)]
enum TableState {
    /// Not read yet; the first transition loads it under the lock.
    #[default]
    Unloaded,
    Loaded(JourneyTable),
    /// A write failed after its rename: disk may be newer than any copy here.
    Stale,
}

fn journeys_aad(key_id: &str, instance_id: &str, epoch: &str) -> Result<Vec<u8>, AccountError> {
    encode_fields(
        JOURNEYS_DOMAIN,
        &[JOURNEY_SCHEMA, key_id, instance_id, epoch],
    )
}

/// Decrypt and parse `journeys.json` under `limits.byte_cap()`. A missing file
/// is an empty table; anything unreadable, unauthentic or oversized refuses.
/// The envelope names its key, so a retained old key still opens it (R2-6).
pub(crate) fn read_journeys(
    config: &StoreConfig,
    store_epoch: &str,
    limits: &JourneyLimits,
) -> Result<JourneyTable, AccountError> {
    let cap = limits.byte_cap();
    let Some(encoded) = read_bounded(&config.authority_dir.join(JOURNEYS_FILE), cap)? else {
        return Ok(JourneyTable::default());
    };
    let envelope: TokenEnvelope =
        serde_json::from_slice(&encoded).map_err(|_| AccountError::NotAuthentic)?;
    // Removing the key that sealed this file refuses every journey operation
    // (fail-closed), not per journey: journeys live at most 15 minutes.
    let key = config
        .keys
        .get(&envelope.key_id)
        .ok_or(AccountError::NotAuthentic)?;
    let aad = journeys_aad(&envelope.key_id, &config.instance_id, store_epoch)?;
    let plaintext = open_bytes(JOURNEY_SCHEMA, key, &aad, &envelope, cap)?;
    serde_json::from_slice(&plaintext).map_err(|_| AccountError::NotAuthentic)
}

/// Seal the table under the current key, bound to this store's epoch.
fn seal_journeys(
    config: &StoreConfig,
    store_epoch: &str,
    table: &JourneyTable,
) -> Result<Vec<u8>, AccountError> {
    let key_id = config.current_key_id.as_str();
    let key = config
        .keys
        .get(key_id)
        .ok_or(AccountError::InvalidConfiguration)?;
    let plaintext = serde_json::to_vec(table).map_err(|_| AccountError::StorageUnavailable)?;
    let aad = journeys_aad(key_id, &config.instance_id, store_epoch)?;
    let envelope = seal_bytes(JOURNEY_SCHEMA, key_id, key, &aad, plaintext)?;
    serde_json::to_vec(&envelope).map_err(|_| AccountError::StorageUnavailable)
}

/// The loaded table, reading it on first use. `Stale` refuses until reopen.
fn loaded<'slot>(
    config: &StoreConfig,
    store_epoch: &str,
    limits: &JourneyLimits,
    slot: &'slot mut TableState,
) -> Result<&'slot JourneyTable, AccountError> {
    if matches!(slot, TableState::Unloaded) {
        *slot = TableState::Loaded(read_journeys(config, store_epoch, limits)?);
    }
    match slot {
        TableState::Loaded(table) => Ok(table),
        TableState::Unloaded | TableState::Stale => Err(AccountError::StorageUnavailable),
    }
}

/// Seal and durably replace `journeys.json`, then publish `table`. A failure
/// before the rename keeps the old copy; one after it poisons only this slot.
fn write_journeys(
    config: &StoreConfig,
    store_epoch: &str,
    table: JourneyTable,
    slot: &mut TableState,
) -> Result<(), AccountError> {
    let bytes = seal_journeys(config, store_epoch, &table)?;
    // The one journeys fault boundary: the directory sync after the rename,
    // where a failure poisons only this slot (slice 5, T-R2-1).
    let step = |step: ReplaceStep| -> Result<(), AccountError> {
        #[cfg(test)]
        if matches!(step, ReplaceStep::ParentSync) {
            use crate::personal_accounts::faults::{Boundary, reached_in};
            reached_in(&config.authority_dir, Boundary::JourneysParentSync)?;
        }
        let _ = step;
        Ok(())
    };
    match replace_file(&config.authority_dir, JOURNEYS_FILE, &bytes, step) {
        Ok(()) => {
            *slot = TableState::Loaded(table);
            Ok(())
        }
        Err(Replace::Staged(error)) => Err(error),
        Err(Replace::Renamed(error)) => {
            *slot = TableState::Stale;
            Err(error)
        }
    }
}

/// What a transition closure sees: the post-sweep table it mutates, the
/// pre-sweep snapshot replay is classified against (R3-2), and the rates.
pub(crate) struct Transition<'tx> {
    pub(crate) table: &'tx mut JourneyTable,
    pub(crate) before: &'tx JourneyTable,
    pub(crate) rates: &'tx mut Rates,
    /// Set once the authority has moved (a published grant): any failed
    /// journeys write then poisons the slot, even one before the rename,
    /// because the in-memory table no longer describes a durable outcome.
    pub(crate) stale_on_write_failure: bool,
}

impl PersonalAccountStore {
    /// THE journey mutation (design §5.2): lock, load, expire stale records,
    /// run `f`, then seal and write `journeys.json` whenever the table changed,
    /// publish, release. The write happens EVEN WHEN `f` REFUSES, so the sweep
    /// and a refusal's own effects (`replay_refusals`, a terminal
    /// `browser_mismatch`) are durable; the refusal is returned after it. An
    /// unchanged table is not rewritten. `f` performs no IO.
    pub(crate) fn journey_transition<T>(
        &self,
        now: u64,
        limits: &JourneyLimits,
        f: impl FnOnce(&mut Transition<'_>) -> Result<T, JourneyRefusal>,
    ) -> Result<T, JourneyError> {
        self.journey_transition_with_authority(now, limits, |tx, _| f(tx))
    }

    /// [`Self::journey_transition`] whose closure may also mutate the
    /// authority under the SAME acquisition (the journey grant commit, §6.2
    /// step 11). The authority write is the one IO such a closure performs.
    pub(super) fn journey_transition_with_authority<T>(
        &self,
        now: u64,
        limits: &JourneyLimits,
        f: impl FnOnce(&mut Transition<'_>, &mut Option<Authority>) -> Result<T, JourneyRefusal>,
    ) -> Result<T, JourneyError> {
        let mut guard = self.lock_authority();
        let AuthoritySlot {
            authority,
            journeys,
        } = &mut *guard.guard;
        let epoch = authority
            .as_ref()
            .ok_or(JourneyError::Storage(AccountError::StorageUnavailable))?
            .store_epoch
            .clone();
        let JourneysSlot { table: slot, rates } = journeys;
        let before = loaded(&self.config, &epoch, limits, slot)
            .map_err(JourneyError::Storage)?
            .clone();
        let mut next = before.clone();
        sweep(&mut next, now);
        let mut tx = Transition {
            table: &mut next,
            before: &before,
            rates,
            stale_on_write_failure: false,
        };
        let outcome = f(&mut tx, authority);
        let stale_on_failure = tx.stale_on_write_failure;
        if next != before {
            write_journeys(&self.config, &epoch, next, slot).map_err(|error| {
                if stale_on_failure {
                    *slot = TableState::Stale;
                }
                JourneyError::Storage(error)
            })?;
        }
        outcome.map_err(JourneyError::Refused)
    }
}

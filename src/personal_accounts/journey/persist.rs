// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The sealed `journeys.json` file and its in-memory slot (design §5.1, §5.2).

use super::super::commit::{Replace, replace_file};
use super::super::{TokenEnvelope, encode_fields, open_bytes, read_bounded, seal_bytes};
use super::{
    AccountError, JOURNEY_SCHEMA, JOURNEYS_FILE, JourneyError, JourneyLimits, JourneyRefusal,
    JourneyTable, KEY_ID_MAX, StoreConfig,
};
use crate::personal_accounts::PersonalAccountStore;

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
pub(crate) enum JourneysSlot {
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
    slot: &'slot mut JourneysSlot,
) -> Result<&'slot JourneyTable, AccountError> {
    if matches!(slot, JourneysSlot::Unloaded) {
        *slot = JourneysSlot::Loaded(read_journeys(config, store_epoch, limits)?);
    }
    match slot {
        JourneysSlot::Loaded(table) => Ok(table),
        JourneysSlot::Unloaded | JourneysSlot::Stale => Err(AccountError::StorageUnavailable),
    }
}

/// Seal and durably replace `journeys.json`, then publish `table`. A failure
/// before the rename keeps the old copy; one after it poisons only this slot.
fn write_journeys(
    config: &StoreConfig,
    store_epoch: &str,
    table: JourneyTable,
    slot: &mut JourneysSlot,
) -> Result<(), AccountError> {
    let bytes = seal_journeys(config, store_epoch, &table)?;
    match replace_file(&config.authority_dir, JOURNEYS_FILE, &bytes, |_| Ok(())) {
        Ok(()) => {
            *slot = JourneysSlot::Loaded(table);
            Ok(())
        }
        Err(Replace::Staged(error)) => Err(error),
        Err(Replace::Renamed(error)) => {
            *slot = JourneysSlot::Stale;
            Err(error)
        }
    }
}

impl PersonalAccountStore {
    /// THE journey mutation (design §5.2): lock, load, run `f` on a copy,
    /// seal and write `journeys.json`, publish, release. `f` gets the
    /// pre-sweep snapshot as its second argument (review R3-2). A refusal
    /// persists nothing; an unchanged table is not rewritten.
    // ponytail: the §5.2 step-2 expiry sweep lands with the transitions (part ii).
    pub(crate) fn journey_transition<T>(
        &self,
        _now: u64,
        limits: &JourneyLimits,
        f: impl FnOnce(&mut JourneyTable, &JourneyTable) -> Result<T, JourneyRefusal>,
    ) -> Result<T, JourneyError> {
        let mut guard = self.lock_authority();
        let epoch = guard
            .as_ref()
            .ok_or(JourneyError::Storage(AccountError::StorageUnavailable))?
            .store_epoch
            .clone();
        let slot = &mut guard.guard.journeys;
        let before = loaded(&self.config, &epoch, limits, slot)
            .map_err(JourneyError::Storage)?
            .clone();
        let mut next = before.clone();
        let value = f(&mut next, &before).map_err(JourneyError::Refused)?;
        if next != before {
            write_journeys(&self.config, &epoch, next, slot).map_err(JourneyError::Storage)?;
        }
        Ok(value)
    }
}

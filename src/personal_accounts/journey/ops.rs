// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The five journey operations built on `journey_transition` (design §4-§7).

use super::super::random_hex;
use super::persist::Transition;
use super::sweep::evict_for_insert;
use super::{
    ACCOUNT_ID_MAX, AUTHORITY_MAX, AccountKey, CALLBACK_WINDOW, DigestKind, EXPECTATION_MAX,
    ISSUER_MAX, JourneyError, JourneyId, JourneyLimits, JourneyReason, JourneyRecord,
    JourneyRefusal, JourneyStatus, JourneyTable, JourneyView, NewJourney, RETURN_PATH_MAX,
    START_WINDOW, SUBJECT_MAX, Secret, StartSecrets, digests_equal, keyed_digest, principal_digest,
    principal_digest_of, random_secret,
};
use crate::personal_accounts::config::AccountDescriptor;
use crate::personal_accounts::service::ConsentExpectation;
use crate::personal_accounts::{AccountError, PersonalAccountStore, StoreConfig};

/// Length of a `descriptor_revision` (hex SHA-256).
const REVISION_LEN: usize = 64;

/// Field caps (R2-5), checked before any store access.
fn within_caps(new: &NewJourney) -> bool {
    let expectation = serde_json::to_vec(&new.expected).map_or(usize::MAX, |bytes| bytes.len());
    new.owner.backend_id.len() <= ACCOUNT_ID_MAX
        && new.owner.principal_authority.len() <= AUTHORITY_MAX
        && new.owner.principal_subject.len() <= SUBJECT_MAX
        && new.owner.oauth_issuer.len() <= ISSUER_MAX
        && new.return_path.len() <= RETURN_PATH_MAX
        && new.descriptor_revision.len() <= REVISION_LEN
        && expectation <= EXPECTATION_MAX
}

fn storage(error: AccountError) -> JourneyError {
    JourneyError::Storage(error)
}

/// A fresh pending record; `digest_key_id` is the key current at creation.
fn pending(config: &StoreConfig, new: NewJourney, now: u64) -> Result<JourneyRecord, AccountError> {
    Ok(JourneyRecord {
        owner_digest: new.owner.digest()?,
        principal_digest: principal_digest(&new.owner)?,
        owner_authority: Some(new.owner.principal_authority),
        owner_subject: Some(new.owner.principal_subject),
        account_id: new.owner.backend_id,
        descriptor_revision: new.descriptor_revision,
        issuer: new.owner.oauth_issuer,
        expected: new.expected,
        return_path: new.return_path,
        status: JourneyStatus::Pending,
        reason: None,
        consumed: false,
        state_digest: None,
        binding_digest: None,
        digest_key_id: config.current_key_id.clone(),
        pkce_verifier: None,
        created_at: now,
        start_by: now.saturating_add(START_WINDOW),
        started_at: None,
        callback_by: None,
        terminal_at: None,
        replay_refusals: 0,
    })
}

/// Active predecessors an explicit create supersedes: same principal and account.
fn predecessors(table: &JourneyTable, record: &JourneyRecord) -> Vec<JourneyId> {
    table
        .journeys
        .iter()
        .filter(|(_, old)| {
            old.is_active()
                && old.principal_digest == record.principal_digest
                && old.account_id == record.account_id
        })
        .map(|(id, _)| id.clone())
        .collect()
}

/// `journeys_total` over active records left after the supersede (503).
/// `Retry-After` is the seconds until the earliest active deadline.
fn admit_active(
    table: &JourneyTable,
    superseded: usize,
    limits: &JourneyLimits,
    now: u64,
) -> Result<(), JourneyRefusal> {
    let active = table.journeys.values().filter(|r| r.is_active()).count();
    if active.saturating_sub(superseded) < limits.journeys_total {
        return Ok(());
    }
    let earliest = table
        .journeys
        .values()
        .filter_map(JourneyRecord::deadline)
        .min();
    let retry_after = earliest.map_or(0, |deadline| deadline.saturating_sub(now));
    Err(JourneyRefusal::CapacityExceeded { retry_after })
}

/// Supersede, evict for room, insert, and count the creation.
fn insert(
    tx: &mut Transition<'_>,
    limits: &JourneyLimits,
    id: JourneyId,
    record: JourneyRecord,
    now: u64,
) -> Result<JourneyId, JourneyRefusal> {
    let superseded = predecessors(tx.table, &record);
    tx.rates
        .admit_creation(limits, &record.principal_digest, now)?;
    admit_active(tx.table, superseded.len(), limits, now)?;
    for old in &superseded {
        if let Some(old) = tx.table.journeys.get_mut(old) {
            old.terminate(
                JourneyStatus::Superseded,
                Some(JourneyReason::Superseded),
                now,
            );
        }
    }
    evict_for_insert(tx.table, limits.records_max());
    tx.rates.record_creation(&record.principal_digest, now);
    tx.table.journeys.insert(id.clone(), record);
    Ok(id)
}

/// Freshly minted secrets and their digests under the CURRENT key (R2-6).
struct Minted {
    secrets: StartSecrets,
    key_id: String,
    state_digest: String,
    binding_digest: String,
}

fn mint(config: &StoreConfig) -> Result<Minted, AccountError> {
    let secrets = StartSecrets {
        state: random_secret()?,
        binding: random_secret()?,
        verifier: random_secret()?,
    };
    let key_id = config.current_key_id.clone();
    let digest = |secret, value: &str| {
        keyed_digest(config, &key_id, secret, value).ok_or(AccountError::InvalidConfiguration)
    };
    Ok(Minted {
        state_digest: digest(Secret::State, &secrets.state)?,
        binding_digest: digest(Secret::Binding, &secrets.binding)?,
        key_id: key_id.clone(),
        secrets,
    })
}

/// Owner, status and start rate, then arm the record. A re-start rotates
/// the secrets and re-captures the key but keeps the first `callback_by`.
fn arm(
    tx: &mut Transition<'_>,
    limits: &JourneyLimits,
    id: &str,
    owner_digest: &str,
    minted: Minted,
    now: u64,
) -> Result<StartSecrets, JourneyRefusal> {
    let record = tx
        .table
        .journeys
        .get_mut(id)
        .ok_or(JourneyRefusal::NotFound)?;
    if !digests_equal(DigestKind::Owner, &record.owner_digest, owner_digest) {
        return Err(JourneyRefusal::OwnerMismatch);
    }
    let restart = match record.status {
        JourneyStatus::Pending => false,
        JourneyStatus::Started if !record.consumed => true,
        _ => return Err(JourneyRefusal::NotStartable),
    };
    tx.rates
        .admit_start(limits, &record.principal_digest, now)?;
    if !restart {
        record.status = JourneyStatus::Started;
        record.started_at = Some(now);
        record.callback_by = Some(now.saturating_add(CALLBACK_WINDOW));
    }
    record.digest_key_id = minted.key_id;
    record.state_digest = Some(minted.state_digest);
    record.binding_digest = Some(minted.binding_digest);
    record.pkce_verifier = Some(minted.secrets.verifier.clone());
    Ok(minted.secrets)
}

fn view(record: &JourneyRecord) -> JourneyView {
    JourneyView {
        status: record.status,
        reason: record.reason,
        expires_at: record.deadline(),
        replay_refused: record.replay_refusals > 0,
        replay_refusals: record.replay_refusals,
    }
}

impl PersonalAccountStore {
    /// POST creation: caps, rates, capacity, supersede, eviction (§5.3).
    pub(crate) fn create_journey(
        &self,
        now: u64,
        limits: &JourneyLimits,
        new: NewJourney,
    ) -> Result<JourneyId, JourneyError> {
        if !within_caps(&new) {
            return Err(JourneyError::Refused(JourneyRefusal::InvalidRequest));
        }
        let record = pending(&self.config, new, now).map_err(storage)?;
        let id = random_hex().map_err(storage)?;
        self.journey_transition(now, limits, |tx| insert(tx, limits, id, record, now))
    }

    /// Owner check, then mint state, binding and verifier (§4.2 steps 6-8).
    pub(crate) fn start_journey(
        &self,
        now: u64,
        limits: &JourneyLimits,
        id: &str,
        owner: &AccountKey,
    ) -> Result<StartSecrets, JourneyError> {
        let owner_digest = owner.digest().map_err(storage)?;
        let minted = mint(&self.config).map_err(storage)?;
        self.journey_transition(now, limits, |tx| {
            arm(tx, limits, id, &owner_digest, minted, now)
        })
    }

    /// Terminal transition of an active journey; clears `binding_digest` and
    /// `pkce_verifier` in the same write. A terminal record is never rewritten.
    pub(crate) fn finish_journey(
        &self,
        now: u64,
        limits: &JourneyLimits,
        id: &str,
        status: JourneyStatus,
        reason: Option<JourneyReason>,
    ) -> Result<(), JourneyError> {
        self.journey_transition(now, limits, |tx| {
            let record = tx
                .table
                .journeys
                .get_mut(id)
                .ok_or(JourneyRefusal::NotFound)?;
            if matches!(status, JourneyStatus::Pending | JourneyStatus::Started) {
                return Err(JourneyRefusal::InvalidRequest);
            }
            if !record.is_active() {
                return Err(JourneyRefusal::NotStartable);
            }
            record.terminate(status, reason, now);
            Ok(())
        })
    }

    /// Status API view, after the sweep (which it persists).
    pub(crate) fn journey_status(
        &self,
        now: u64,
        limits: &JourneyLimits,
        id: &str,
    ) -> Result<JourneyView, JourneyError> {
        self.journey_transition(now, limits, |tx| {
            tx.table
                .journeys
                .get(id)
                .map(view)
                .ok_or(JourneyRefusal::NotFound)
        })
    }

    /// POST creation from the configured descriptor: the revision and the
    /// consent expectation are captured here, where the store is (§6.2).
    pub(crate) fn create_connect_journey(
        &self,
        now: u64,
        limits: &JourneyLimits,
        owner: AccountKey,
        descriptor: &AccountDescriptor,
        return_path: String,
    ) -> Result<JourneyId, JourneyError> {
        let descriptor_revision =
            super::super::migration_revision::descriptor_revision(descriptor).map_err(storage)?;
        let expected = ConsentExpectation::captured(&self.lookup(&owner).map_err(storage)?);
        let new = NewJourney {
            owner,
            descriptor_revision,
            expected,
            return_path,
        };
        self.create_journey(now, limits, new)
    }

    /// Status for the journey's own principal only. Another principal gets
    /// the same `NotFound` as an id that never existed (T-C07a).
    pub(crate) fn journey_status_owned(
        &self,
        now: u64,
        limits: &JourneyLimits,
        id: &str,
        principal: (&str, &str),
    ) -> Result<JourneyView, JourneyError> {
        let caller = principal_digest_of(principal.0, principal.1).map_err(storage)?;
        self.journey_transition(now, limits, |tx| {
            tx.table
                .journeys
                .get(id)
                .filter(|record| {
                    digests_equal(DigestKind::Owner, &record.principal_digest, &caller)
                })
                .map(view)
                .ok_or(JourneyRefusal::NotFound)
        })
    }
}

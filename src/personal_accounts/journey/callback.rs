// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Callback admission and consumption (design §6.2 steps 1-4 and 7). The
//! handler admits, runs its own issuer and revision checks with the lock
//! released, then consumes; consumption re-runs every admission check in its
//! own acquisition, so two racing callbacks still consume at most once.

use super::persist::Transition;
use super::{
    Consumed, DigestKind, JourneyError, JourneyId, JourneyLimits, JourneyReason, JourneyRecord,
    JourneyRefusal, JourneyStatus, JourneyTable, Secret, digests_equal, keyed_digest,
};
use crate::personal_accounts::config::AccountDescriptor;
use crate::personal_accounts::service::ConsentExpectation;
use crate::personal_accounts::{PersonalAccountStore, StoreConfig};

/// A minted state or binding is 43 characters; anything past this is refused
/// before it is ever HMAC'd under the authority lock.
const CALLBACK_SECRET_MAX: usize = 64;

/// What an admitted callback needs before it may consume: the owner's
/// principal to rebuild its `AccountKey`, and the values steps 6 and 11 check.
#[derive(Clone)]
pub(crate) struct Admitted {
    pub(crate) journey_id: JourneyId,
    pub(crate) owner_authority: String,
    pub(crate) owner_subject: String,
    pub(crate) account_id: String,
    pub(crate) issuer: String,
    pub(crate) descriptor_revision: String,
    pub(crate) expected: ConsentExpectation,
    pub(crate) return_path: String,
}

impl Admitted {
    /// Step 6's `config_changed` check: `live` is the descriptor this journey
    /// was created against, unchanged by any reload since.
    pub(crate) fn created_against(&self, live: &AccountDescriptor) -> bool {
        super::super::migration_revision::descriptor_revision(live)
            .is_ok_and(|revision| revision == self.descriptor_revision)
    }
}

/// Step 1: the record whose `state_digest` is `HMAC(state)` under the
/// record's own `digest_key_id`. A key no longer configured matches nothing.
fn locate(config: &StoreConfig, table: &JourneyTable, state: &str) -> Option<JourneyId> {
    table.journeys.iter().find_map(|(id, record)| {
        let stored = record.state_digest.as_deref()?;
        let digest = keyed_digest(config, &record.digest_key_id, Secret::State, state)?;
        digests_equal(DigestKind::State, &digest, stored).then(|| id.clone())
    })
}

/// Step 2 (R2-3, R3-2): a replay is decided on the PRE-sweep record.
fn is_replay(before: &JourneyRecord) -> bool {
    before.consumed
        || matches!(
            before.status,
            JourneyStatus::Connected
                | JourneyStatus::Cancelled
                | JourneyStatus::Failed
                | JourneyStatus::Superseded
        )
}

fn binding_matches(config: &StoreConfig, record: &JourneyRecord, binding: Option<&str>) -> bool {
    let (Some(binding), Some(stored)) = (binding, record.binding_digest.as_deref()) else {
        return false;
    };
    keyed_digest(config, &record.digest_key_id, Secret::Binding, binding)
        .is_some_and(|digest| digests_equal(DigestKind::Binding, &digest, stored))
}

/// Steps 1-4. Every refusal after step 1 still persists its effect (the
/// transition writes on refusal).
fn admit<'tx>(
    config: &StoreConfig,
    tx: &'tx mut Transition<'_>,
    state: &str,
    binding: Option<&str>,
    now: u64,
) -> Result<(JourneyId, &'tx mut JourneyRecord), JourneyRefusal> {
    let id = locate(config, tx.table, state).ok_or(JourneyRefusal::UnknownState)?;
    let replay = tx.before.journeys.get(&id).is_some_and(is_replay);
    let record = tx
        .table
        .journeys
        .get_mut(&id)
        .ok_or(JourneyRefusal::UnknownState)?;
    if replay {
        record.replay_refusals = record.replay_refusals.saturating_add(1);
        return Err(JourneyRefusal::Replay);
    }
    if record.status != JourneyStatus::Started {
        // Only an expiry (the sweep's, or a pre-sweep one) reaches here.
        return Err(JourneyRefusal::Expired);
    }
    if !binding_matches(config, record, binding) {
        record.terminate(
            JourneyStatus::Failed,
            Some(JourneyReason::BrowserMismatch),
            now,
        );
        return Err(JourneyRefusal::BrowserMismatch);
    }
    Ok((id, record))
}

/// A record without its owner (written before 5c) cannot rebuild its
/// account key, so admission refuses it like a state it does not know.
fn admitted(id: JourneyId, record: &JourneyRecord) -> Result<Admitted, JourneyRefusal> {
    let (Some(owner_authority), Some(owner_subject)) =
        (record.owner_authority.clone(), record.owner_subject.clone())
    else {
        return Err(JourneyRefusal::UnknownState);
    };
    Ok(Admitted {
        journey_id: id,
        owner_authority,
        owner_subject,
        account_id: record.account_id.clone(),
        issuer: record.issuer.clone(),
        descriptor_revision: record.descriptor_revision.clone(),
        expected: record.expected.clone(),
        return_path: record.return_path.clone(),
    })
}

/// Step 7: `consumed` and the verifier leave the record in the same write.
fn consume(
    config: &StoreConfig,
    tx: &mut Transition<'_>,
    state: &str,
    binding: Option<&str>,
    now: u64,
) -> Result<Consumed, JourneyRefusal> {
    let (journey_id, record) = admit(config, tx, state, binding, now)?;
    let verifier = record
        .pkce_verifier
        .take()
        .ok_or(JourneyRefusal::UnknownState)?;
    record.consumed = true;
    Ok(Consumed {
        journey_id,
        verifier,
    })
}

/// Refused before any store access (the oversize-state review row).
fn within_cap(state: &str, binding: Option<&str>) -> Result<(), JourneyError> {
    let over = |value: &str| value.len() > CALLBACK_SECRET_MAX;
    if over(state) || binding.is_some_and(over) {
        return Err(JourneyError::Refused(JourneyRefusal::InvalidRequest));
    }
    Ok(())
}

impl PersonalAccountStore {
    /// Step 1 alone: the journey `state` names, so the caller can pick that
    /// journey's binding cookie before admission judges it.
    pub(crate) fn callback_journey(
        &self,
        now: u64,
        limits: &JourneyLimits,
        state: &str,
    ) -> Result<JourneyId, JourneyError> {
        within_cap(state, None)?;
        self.journey_transition(now, limits, |tx| {
            locate(&self.config, tx.table, state).ok_or(JourneyRefusal::UnknownState)
        })
    }

    /// Callback steps 1-4 without consuming: locate, replay, expiry, binding.
    pub(crate) fn admit_callback(
        &self,
        now: u64,
        limits: &JourneyLimits,
        state: &str,
        binding: Option<&str>,
    ) -> Result<Admitted, JourneyError> {
        within_cap(state, binding)?;
        self.journey_transition(now, limits, |tx| {
            let (id, record) = admit(&self.config, tx, state, binding, now)?;
            admitted(id, record)
        })
    }

    /// Steps 1-4 again, then step 7, in one acquisition.
    pub(crate) fn consume_callback(
        &self,
        now: u64,
        limits: &JourneyLimits,
        state: &str,
        binding: Option<&str>,
    ) -> Result<Consumed, JourneyError> {
        within_cap(state, binding)?;
        self.journey_transition(now, limits, |tx| {
            consume(&self.config, tx, state, binding, now)
        })
    }
}

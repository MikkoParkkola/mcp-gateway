// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The journey grant commit (design §6.2 step 11): validate the journey,
//! compare-and-commit the grant, and finish the journey, all under ONE
//! authority-lock acquisition, so a journey swept or superseded during the
//! exchange window is never resurrected and a fenced grant writes nothing.

#[cfg(unix)]
use super::JourneyReason;
use super::persist::Transition;
use super::{
    AccountKey, DigestKind, JourneyError, JourneyLimits, JourneyRecord, JourneyStatus,
    digests_equal,
};
#[cfg(unix)]
use crate::personal_accounts::consent::{GuardedCommit, commit_if_unchanged_locked};
use crate::personal_accounts::service::ConsentExpectation;
use crate::personal_accounts::{
    AccountError, Authority, GrantRecord, PersonalAccountStore, StoreConfig,
};

/// Outcome of a journey grant commit. Only `Committed` and
/// `CommittedStatusUnavailable` published a grant.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum JourneyCommit {
    /// Grant published, journey `Connected`.
    Committed,
    /// Grant published and durable; the `journeys.json` write that followed
    /// failed, so only the journey slot is stale (review R2-1).
    CommittedStatusUnavailable,
    /// The generation fence refused; journey `Failed/superseded_grant`.
    Fenced,
    /// No committable journey (swept, superseded, not consumed, another
    /// owner): nothing written, and the journey is not touched.
    JourneyGone,
}

/// The grant a callback is committing, with the owner digest it rebuilt.
struct Grant<'a> {
    account: &'a AccountKey,
    digest: String,
    expected: &'a ConsentExpectation,
    record: &'a GrantRecord,
}

/// Started and consumed, same account and owner, same captured expectation.
fn committable(journey: &JourneyRecord, grant: &Grant<'_>) -> bool {
    journey.status == JourneyStatus::Started
        && journey.consumed
        && journey.account_id == grant.account.backend_id
        && journey.expected == *grant.expected
        && digests_equal(DigestKind::Owner, &journey.owner_digest, &grant.digest)
}

#[cfg(unix)]
/// Runs under the transition's acquisition. A failed grant commit ends the
/// journey `Failed/storage_unavailable` in the same journeys write.
fn settle(
    config: &StoreConfig,
    tx: &mut Transition<'_>,
    authority: &mut Option<Authority>,
    grant: &Grant<'_>,
    journey_id: &str,
    now: u64,
) -> Result<JourneyCommit, AccountError> {
    let Some(journey) = tx
        .table
        .journeys
        .get_mut(journey_id)
        .filter(|journey| committable(journey, grant))
    else {
        return Ok(JourneyCommit::JourneyGone);
    };
    let (account, expected, record) = (grant.account, grant.expected, grant.record);
    match commit_if_unchanged_locked(
        config,
        authority,
        &grant.digest,
        account,
        expected,
        record,
        None,
    ) {
        Ok(GuardedCommit::Committed) => {
            tx.stale_on_write_failure = true;
            journey.terminate(JourneyStatus::Connected, None, now);
            Ok(JourneyCommit::Committed)
        }
        Ok(GuardedCommit::Fenced) => {
            let reason = Some(JourneyReason::SupersededGrant);
            journey.terminate(JourneyStatus::Failed, reason, now);
            Ok(JourneyCommit::Fenced)
        }
        Err(error) => {
            let reason = Some(JourneyReason::StorageUnavailable);
            journey.terminate(JourneyStatus::Failed, reason, now);
            Err(error)
        }
    }
}

/// Off unix the transition refuses before any closure runs; this only keeps
/// the call site compiling.
#[cfg(not(unix))]
fn settle(
    _config: &StoreConfig,
    _tx: &mut Transition<'_>,
    _authority: &mut Option<Authority>,
    _grant: &Grant<'_>,
    _journey_id: &str,
    _now: u64,
) -> Result<JourneyCommit, AccountError> {
    Err(AccountError::InvalidConfiguration)
}

impl PersonalAccountStore {
    /// Commit `record` for `account` if the journey is still committable and
    /// `expected` is still the authoritative state, then finish the journey.
    /// `account` is the owner's key the caller rebuilt; its digest must equal
    /// the journey's `owner_digest`.
    pub(crate) fn commit_journey_grant_if(
        &self,
        now: u64,
        limits: &JourneyLimits,
        account: &AccountKey,
        expected: &ConsentExpectation,
        record: &GrantRecord,
        journey_id: &str,
    ) -> Result<JourneyCommit, JourneyError> {
        let digest = account.digest().map_err(JourneyError::Storage)?;
        let grant = Grant {
            account,
            digest,
            expected,
            record,
        };
        let mut published = false;
        let result = self.journey_transition_with_authority(now, limits, |tx, authority| {
            let outcome = settle(&self.config, tx, authority, &grant, journey_id, now);
            published = outcome == Ok(JourneyCommit::Committed);
            Ok(outcome)
        });
        match result {
            Ok(outcome) => outcome.map_err(JourneyError::Storage),
            Err(JourneyError::Storage(_)) if published => {
                Ok(JourneyCommit::CommittedStatusUnavailable)
            }
            Err(error) => Err(error),
        }
    }
}

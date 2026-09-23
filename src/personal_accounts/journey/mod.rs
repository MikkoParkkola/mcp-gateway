// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-6745 consent journeys: the sealed `authority_dir/journeys.json` table
//! (design §3, §5). Every mutation runs inside one `journey_transition`
//! under the authority lock; no network call ever runs under it.
//!
//! SLICE 2 CONTRACT STUBS: the signatures are the contract `tests.rs` pins;
//! the bodies deliberately return wrong answers until the implementation.
#![cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "MIK-6745 slice 2: the journey table has no production caller until slice 5"
    )
)]
#![cfg_attr(
    test,
    allow(
        dead_code,
        reason = "MIK-6745 slice 2 stubs: reasons and refusals the tests do not yet construct"
    )
)]
#![allow(
    clippy::unused_self,
    clippy::unnecessary_wraps,
    clippy::needless_pass_by_value,
    reason = "MIK-6745 slice 2 contract stubs; the implementation deletes this allow"
)]

use serde::{Deserialize, Serialize};

use super::super::{AccountError, AccountKey, PersonalAccountStore, StoreConfig};
use crate::personal_accounts::service::ConsentExpectation;

#[cfg(test)]
#[path = "tests.rs"]
mod tests;

/// Schema of the sealed journeys envelope (design §5.1).
pub(crate) const JOURNEY_SCHEMA: &str = "personal_accounts.journeys.v1";
/// File name beside `authority.json`.
pub(crate) const JOURNEYS_FILE: &str = "journeys.json";
/// `start_by = created_at + START_WINDOW` (review M4).
pub(crate) const START_WINDOW: u64 = 300;
/// `callback_by = first started_at + CALLBACK_WINDOW` (review M4).
pub(crate) const CALLBACK_WINDOW: u64 = 600;
/// Terminal records are collected this long after `terminal_at` (§3).
pub(crate) const TERMINAL_RETENTION: u64 = 86_400;
/// Sliding window of `journeys_per_user` (review M1).
pub(crate) const PER_USER_WINDOW: u64 = 600;
/// Field caps (design §10, reviews R2-5, R3-1).
pub(crate) const ACCOUNT_ID_MAX: usize = 64;
pub(crate) const RETURN_PATH_MAX: usize = 256;
pub(crate) const ISSUER_MAX: usize = 256;
pub(crate) const KEY_ID_MAX: usize = 64;
/// Serialized size of a maximal record rounded up to 256 bytes (R3-1).
/// STUB: one byte, so the maximal-record assertion fails.
pub(crate) const RECORD_MAX: usize = 1;

/// 32 lowercase hex characters from `storage::random_hex`.
pub(crate) type JourneyId = String;

/// Journey lifecycle (design §3). `Superseded` is reported as `expired`.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum JourneyStatus {
    Pending,
    Started,
    Connected,
    Cancelled,
    Failed,
    Expired,
    Superseded,
}

/// Closed terminal reason (design §6.2, §7). Never carries provider text.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum JourneyReason {
    UserDenied,
    ConsentNotCompleted,
    ProviderUnavailable,
    ProviderError,
    Expired,
    Superseded,
    BrowserMismatch,
    IssuerMismatch,
    ConfigChanged,
    ScopeMissing,
    UnexpectedTokenForm,
    NoRefreshToken,
    AuditUnavailable,
    SupersededGrant,
    JourneyGone,
}

/// One sealed journey (design §5.1). Plaintext only inside `journeys.json`.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct JourneyRecord {
    pub(crate) owner_digest: String,
    pub(crate) account_id: String,
    pub(crate) descriptor_revision: String,
    pub(crate) issuer: String,
    pub(crate) expected: ConsentExpectation,
    pub(crate) return_path: String,
    pub(crate) status: JourneyStatus,
    pub(crate) reason: Option<JourneyReason>,
    pub(crate) consumed: bool,
    pub(crate) state_digest: Option<String>,
    pub(crate) binding_digest: Option<String>,
    pub(crate) principal_digest: String,
    pub(crate) digest_key_id: String,
    pub(crate) pkce_verifier: Option<String>,
    pub(crate) created_at: u64,
    pub(crate) start_by: u64,
    pub(crate) started_at: Option<u64>,
    pub(crate) callback_by: Option<u64>,
    pub(crate) terminal_at: Option<u64>,
    pub(crate) replay_refusals: u32,
}

impl std::fmt::Debug for JourneyRecord {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("JourneyRecord")
            .field("status", &self.status)
            .field("reason", &self.reason)
            .finish_non_exhaustive()
    }
}

/// The whole sealed table, keyed by journey id.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct JourneyTable {
    pub(crate) journeys: std::collections::BTreeMap<JourneyId, JourneyRecord>,
}

/// The four `accounts.limits` journey fields (design §5.3).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct JourneyLimits {
    pub(crate) journeys_total: usize,
    pub(crate) journeys_per_user: u32,
    pub(crate) starts_per_minute_per_user: u32,
    pub(crate) journeys_created_per_minute: u32,
}

impl JourneyLimits {
    /// `records_max = 4 x journeys_total` (design §5.1). STUB: wrong factor.
    pub(crate) fn records_max(&self) -> usize {
        self.journeys_total
    }

    /// `records_max x RECORD_MAX x 2` plus envelope framing. STUB: zero.
    pub(crate) fn byte_cap(&self) -> usize {
        0
    }
}

/// What a POST creation supplies. `owner` is the full account key; the
/// record's `account_id` is `owner.backend_id`, `issuer` is `owner.oauth_issuer`.
#[derive(Clone, Debug)]
pub(crate) struct NewJourney {
    pub(crate) owner: AccountKey,
    pub(crate) descriptor_revision: String,
    pub(crate) expected: ConsentExpectation,
    pub(crate) return_path: String,
}

/// Browser-facing secrets minted by `start`. Never persisted raw.
#[derive(Clone)]
pub(crate) struct StartSecrets {
    pub(crate) state: String,
    pub(crate) binding: String,
    pub(crate) verifier: String,
}

/// A consumed callback: the verifier leaves the record in the same write.
#[derive(Clone)]
pub(crate) struct Consumed {
    pub(crate) journey_id: JourneyId,
    pub(crate) verifier: String,
}

/// Store-level status view (design §3, §7). `status` is the raw record
/// status; the HTTP layer reports `Superseded` as `expired`/`superseded`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct JourneyView {
    pub(crate) status: JourneyStatus,
    pub(crate) reason: Option<JourneyReason>,
    pub(crate) expires_at: Option<u64>,
    pub(crate) replay_refused: bool,
    pub(crate) replay_refusals: u32,
}

/// A journey-level refusal. `retry_after` is in seconds (design §5.3).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum JourneyRefusal {
    InvalidRequest,
    NotFound,
    OwnerMismatch,
    NotStartable,
    UnknownState,
    Replay,
    Expired,
    BrowserMismatch,
    RateLimited { retry_after: u64 },
    CapacityExceeded { retry_after: u64 },
}

/// Everything a journey operation can answer besides success.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum JourneyError {
    Refused(JourneyRefusal),
    Storage(AccountError),
}

/// The three digest comparisons that must be constant time (review L5).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DigestKind {
    State,
    Binding,
    Owner,
}

/// Every digest comparison goes through here (T-CT). STUB: plain `==`, uncounted.
pub(crate) fn digests_equal(_kind: DigestKind, left: &str, right: &str) -> bool {
    left == right
}

/// `cfg(test)` witness: how many comparisons of `kind` ran on this thread.
#[cfg(test)]
pub(crate) fn digest_comparisons(_kind: DigestKind) -> u64 {
    0
}

/// Decrypt and parse `journeys.json` under `limits.byte_cap()`. A missing file
/// is an empty table; anything unreadable, unauthentic or oversized refuses.
/// STUB: always refuses.
pub(crate) fn read_journeys(
    _config: &StoreConfig,
    _store_epoch: &str,
    _limits: &JourneyLimits,
) -> Result<JourneyTable, AccountError> {
    Err(AccountError::StorageUnavailable)
}

impl PersonalAccountStore {
    /// THE journey mutation (design §5.2): lock, expire stale active records,
    /// run `f`, seal and write `journeys.json`, publish, release. `f` gets the
    /// pre-sweep snapshot as its second argument (review R3-2).
    /// STUB: never runs `f`.
    pub(crate) fn journey_transition<T>(
        &self,
        _now: u64,
        _limits: &JourneyLimits,
        _f: impl FnOnce(&mut JourneyTable, &JourneyTable) -> Result<T, JourneyRefusal>,
    ) -> Result<T, JourneyError> {
        Err(JourneyError::Storage(AccountError::StorageUnavailable))
    }

    /// POST creation: caps, rates, capacity, supersede, eviction (§5.3).
    /// STUB: an empty id.
    pub(crate) fn create_journey(
        &self,
        _now: u64,
        _limits: &JourneyLimits,
        _new: NewJourney,
    ) -> Result<JourneyId, JourneyError> {
        Ok(String::new())
    }

    /// Owner check, then mint state, binding and verifier (§4.2 steps 6-8).
    /// STUB: refuses.
    pub(crate) fn start_journey(
        &self,
        _now: u64,
        _limits: &JourneyLimits,
        _id: &str,
        _owner: &AccountKey,
    ) -> Result<StartSecrets, JourneyError> {
        Err(JourneyError::Refused(JourneyRefusal::NotFound))
    }

    /// Callback steps 1-4 and 7: locate, replay, expiry, binding, consume.
    /// STUB: refuses as unknown state.
    pub(crate) fn consume_callback(
        &self,
        _now: u64,
        _limits: &JourneyLimits,
        _state: &str,
        _binding: Option<&str>,
    ) -> Result<Consumed, JourneyError> {
        Err(JourneyError::Refused(JourneyRefusal::UnknownState))
    }

    /// Terminal transition; clears `binding_digest` and `pkce_verifier` in
    /// the same write. STUB: does nothing.
    pub(crate) fn finish_journey(
        &self,
        _now: u64,
        _limits: &JourneyLimits,
        _id: &str,
        _status: JourneyStatus,
        _reason: Option<JourneyReason>,
    ) -> Result<(), JourneyError> {
        Ok(())
    }

    /// Status API view. STUB: not found.
    pub(crate) fn journey_status(
        &self,
        _now: u64,
        _limits: &JourneyLimits,
        _id: &str,
    ) -> Result<JourneyView, JourneyError> {
        Err(JourneyError::Refused(JourneyRefusal::NotFound))
    }
}

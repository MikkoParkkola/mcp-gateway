// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-6745 consent journeys: the sealed `authority_dir/journeys.json` table
//! (design §3, §5). Every mutation runs inside one `journey_transition`
//! under the authority lock; no network call ever runs under it.
//!
//! Split for the file-size ratchet: `persist` owns the sealed file, the slot and
//! the transition; `ops` owns the five operations built on it; `limits` the
//! in-memory rate windows; `sweep` expiry, terminal transitions and eviction.
#![cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "MIK-6745 slice 2: the journey table has no production caller until slice 5"
    )
)]

use hkdf::Hkdf;
use hmac::{Hmac, KeyInit as _, Mac as _};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use super::super::{AccountError, AccountKey, StoreConfig};
use crate::personal_accounts::config::RECORDS_PER_ACTIVE;
use crate::personal_accounts::service::ConsentExpectation;

#[path = "limits.rs"]
mod limits;
#[path = "lookup.rs"]
mod lookup;
#[path = "ops.rs"]
mod ops;
#[path = "persist.rs"]
mod persist;
#[path = "sweep.rs"]
mod sweep;

pub(crate) use persist::JourneysSlot;
#[cfg(test)]
use persist::read_journeys;

#[cfg(test)]
#[path = "tests.rs"]
mod tests;
#[cfg(test)]
#[path = "tests_gaps.rs"]
mod tests_gaps;

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
/// Serialized `ConsentExpectation` cap. The maximal plain JSON form is 241
/// bytes, so the design's 192 could not hold it (operator decision: 256).
pub(crate) const EXPECTATION_MAX: usize = 256;
/// Serialized size of a maximal record (1713 bytes) rounded up to 256 (R3-1).
pub(crate) const RECORD_MAX: usize = 1792;
/// Global creations window of `journeys_created_per_minute`.
pub(crate) const GLOBAL_WINDOW: u64 = 60;
/// Sliding window of `starts_per_minute_per_user`.
pub(crate) const START_RATE_WINDOW: u64 = 60;

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
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
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
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
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
    /// `records_max = RECORDS_PER_ACTIVE x journeys_total` (design §5.1).
    /// Config validation refuses a total whose product overflows; saturating
    /// here only keeps an unvalidated value from panicking.
    pub(crate) fn records_max(&self) -> usize {
        self.journeys_total.saturating_mul(RECORDS_PER_ACTIVE)
    }

    /// Sealed-file bound: `records_max x RECORD_MAX x 2` plus the envelope
    /// framing at the widest key id. The 100% headroom covers base64 (4/3)
    /// and each entry's map key, so a table at `records_max` always fits.
    pub(crate) fn byte_cap(&self) -> usize {
        self.records_max()
            .saturating_mul(RECORD_MAX)
            .saturating_mul(2)
            .saturating_add(persist::ENVELOPE_FRAME)
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

/// Every digest comparison goes through here (review L5, T-CT): constant
/// time over the bytes, so match timing reveals no digest prefix.
pub(crate) fn digests_equal(kind: DigestKind, left: &str, right: &str) -> bool {
    witness(kind, left, right);
    subtle::ConstantTimeEq::ct_eq(left.as_bytes(), right.as_bytes()).into()
}

#[cfg(test)]
thread_local! {
    static COMPARISONS: std::cell::Cell<[u64; 3]> = const { std::cell::Cell::new([0; 3]) };
}

/// Process-wide operand record: the store runs on `spawn_blocking` threads,
/// which a route test's thread-local counts never see. Keyed by operand, so
/// parallel tests with distinct principals cannot satisfy each other.
#[cfg(test)]
static OPERANDS: std::sync::Mutex<std::collections::BTreeSet<(usize, String)>> =
    std::sync::Mutex::new(std::collections::BTreeSet::new());

#[cfg(test)]
fn witness(kind: DigestKind, left: &str, right: &str) {
    COMPARISONS.with(|cell| {
        let mut counts = cell.get();
        counts[kind as usize] += 1;
        cell.set(counts);
    });
    let mut operands = OPERANDS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    operands.insert((kind as usize, left.to_owned()));
    operands.insert((kind as usize, right.to_owned()));
}

#[cfg(not(test))]
fn witness(_kind: DigestKind, _left: &str, _right: &str) {}

/// `cfg(test)` witness: whether a `kind` comparison ever took `operand`, on
/// any thread (T-CT at the route).
#[cfg(test)]
pub(crate) fn digest_compared(kind: DigestKind, operand: &str) -> bool {
    OPERANDS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .contains(&(kind as usize, operand.to_owned()))
}

/// `cfg(test)` witness: how many comparisons of `kind` ran on this thread.
#[cfg(test)]
pub(crate) fn digest_comparisons(kind: DigestKind) -> u64 {
    COMPARISONS.with(|cell| cell.get()[kind as usize])
}

/// HKDF info of the journey digest key (design §4.2, "Which key").
const DIGEST_INFO: &[u8] = b"mcp-gateway/account-journey-digest/v1";
/// Domain of the per-principal rate key (design §5.3).
const PRINCIPAL_DOMAIN: &[u8] = b"mcp-gateway/journey-principal/v1";

/// The digest labels of design §4.2 steps 7-8.
#[derive(Clone, Copy)]
enum Secret {
    State,
    Binding,
}

impl Secret {
    fn label(self) -> &'static [u8] {
        match self {
            Self::State => b"state",
            Self::Binding => b"binding",
        }
    }
}

/// `HMAC-SHA256(HKDF(keys[key_id]), label || value)`, hex. A key id no longer
/// configured yields `None`: the record fails closed as unknown (R2-6).
fn keyed_digest(config: &StoreConfig, key_id: &str, secret: Secret, value: &str) -> Option<String> {
    let mut key = [0_u8; 32];
    Hkdf::<Sha256>::new(None, config.keys.get(key_id)?)
        .expand(DIGEST_INFO, &mut key)
        .ok()?;
    let mut mac = Hmac::<Sha256>::new_from_slice(&key).ok()?;
    mac.update(secret.label());
    mac.update(value.as_bytes());
    Some(hex::encode(mac.finalize().into_bytes()))
}

/// `SHA-256(len-prefixed authority, subject)` under its own domain (§5.3).
fn principal_digest(owner: &AccountKey) -> Result<String, AccountError> {
    principal_digest_of(&owner.principal_authority, &owner.principal_subject)
}

/// [`principal_digest`] from the two parts, for a caller holding no account.
fn principal_digest_of(authority: &str, subject: &str) -> Result<String, AccountError> {
    let fields = [authority, subject];
    let encoded = super::encode_fields(PRINCIPAL_DOMAIN, &fields)?;
    Ok(hex::encode(Sha256::digest(encoded)))
}

/// 32 random bytes, base64url without padding (43 characters).
fn random_secret() -> Result<String, AccountError> {
    use base64::Engine as _;
    use ring::rand::SecureRandom as _;
    let mut bytes = [0_u8; 32];
    ring::rand::SystemRandom::new()
        .fill(&mut bytes)
        .map_err(|_| AccountError::StorageUnavailable)?;
    Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes))
}

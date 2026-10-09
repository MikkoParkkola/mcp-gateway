// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! The sealed payload a continuation carries, and its purpose.

use serde::{Deserialize, Serialize};

use super::ContinuationError;

/// Why a sealed envelope exists. Distinct domains share one keyring and
/// ledger; they must not redeem each other.
///
/// Default is [`Self::BackendInput`]: every envelope minted before this field
/// existed, and [`Payload::mint`] today, continues a backend elicitation.
/// Unknown wire values fail to deserialize, so an unrecognised domain cannot
/// masquerade as either supported one.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContinuationPurpose {
    /// Continues a backend `input_required` exchange.
    #[default]
    BackendInput,
    /// Confirms a destructive outer tool call before task admission.
    DestructiveConfirm,
    /// Resumes a `gateway_execute` chain stopped at an interim round.
    ///
    /// Its own domain so that neither of the other two can stand in for it: a
    /// confirmation grant must not restart a chain's tail, and a chain resume
    /// must not stand in for the confirmation the gated step still owes.
    ChainResume,
}

/// What the envelope carries. None of it is visible to the client.
///
/// `Debug` is implemented by hand rather than derived, and the omissions are the
/// point: this struct is sealed on the wire and plaintext in memory, so a
/// derived `Debug` undoes the sealing the moment anything formats one. The
/// backend's own state may carry the authorization the backend was issued, and
/// the caller bindings say who is entitled to redeem the exchange.
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Payload {
    /// Which backend holds the exchange.
    pub backend_id: String,
    /// The backend's own opaque state, verbatim — `None` when it issued none.
    ///
    /// Optional because the specification lets a server ask for input without
    /// carrying state of its own. Forcing an empty string in its place would
    /// hand the backend a `requestState` it never issued, and a backend is
    /// entitled to treat the presence of that field as meaning something.
    pub backend_request_state: Option<String>,
    /// Who may redeem this. Without it, one caller replays another's.
    pub principal_fingerprint: String,
    /// Which request it continues. The spec confines these fields to the retry
    /// of the original request and to nothing else.
    pub original_request_digest: String,
    /// Which replica holds the exchange, for a legacy backend keeping an RPC
    /// open. A stateless client's retry may land anywhere.
    pub origin_replica: String,
    /// Unix seconds at mint.
    pub issued_at: u64,
    /// Unix seconds after which it is dead.
    pub expires_at: u64,
    /// Unique id, so redemption can be made single-use.
    pub jti: String,
    /// The [`InFlight`](super::InFlight) key for the exchange this continuation continues.
    ///
    /// Sealed rather than derived, and carried rather than looked up: the table
    /// is keyed by a name the gateway chose at mint, and without that name in
    /// the envelope a redemption can only ask whether *some* exchange is open
    /// for this backend. That is a weaker question than the criterion asks —
    /// it answers yes for an honest concurrent exchange belonging to another
    /// caller, so a retry whose own exchange has ended would be admitted on the
    /// strength of a stranger's.
    pub hold_key: String,
    /// Which domain this envelope belongs to.
    ///
    /// Absent on envelopes sealed before the field existed; those deserialize
    /// as [`ContinuationPurpose::BackendInput`]. Confirmation grants set
    /// [`ContinuationPurpose::DestructiveConfirm`] explicitly at mint.
    #[serde(default)]
    pub purpose: ContinuationPurpose,
    /// Index of the chain step that asked. Steps `0..next_step` have run.
    ///
    /// Sealed like everything else here: a caller that could move it could make
    /// the gateway skip a step that never ran. Absent on every envelope that is
    /// not a [`ContinuationPurpose::ChainResume`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_step: Option<usize>,
    /// How many rounds this exchange has already spent.
    ///
    /// Copied forward on every re-seal, never re-initialised. A native chain
    /// resume never enters the legacy bridge, so it inherits none of the
    /// bridge's per-exchange bound; without a count carried in the envelope a
    /// backend that asks one question forever sustains an unbounded
    /// continuation sequence at a single step.
    #[serde(default)]
    pub rounds_used: u32,
}

impl std::fmt::Debug for Payload {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Enough to trace an exchange through a log, and nothing that would let
        // a reader of that log redeem it.
        f.debug_struct("Payload")
            .field("backend_id", &self.backend_id)
            .field("backend_request_state", &"<redacted>")
            .field("principal_fingerprint", &"<redacted>")
            .field("original_request_digest", &"<redacted>")
            .field("origin_replica", &self.origin_replica)
            .field("issued_at", &self.issued_at)
            .field("expires_at", &self.expires_at)
            .field("jti", &self.jti)
            .field("hold_key", &self.hold_key)
            .field("purpose", &self.purpose)
            // An index and a counter: neither identifies a caller nor redeems
            // anything, and both are what a stalled chain is traced by.
            .field("next_step", &self.next_step)
            .field("rounds_used", &self.rounds_used)
            .finish()
    }
}

/// How long a minted continuation stays redeemable.
///
/// Not a parameter. Every call site would pass the same number, and one that
/// passed a larger one would widen the replay window for every other — the
/// spent-ledger that makes redemption single-use is a fixed-capacity table in
/// this process, so a continuation that outlives its entry stops being
/// single-use. Five minutes is a person answering a prompt, not a session.
///
/// Keys do not outlive the process, and neither does the ledger. Persistent
/// keys arrive with the durable ledger (MIK-7312) and not before.
pub(super) const CONTINUATION_LIFETIME_SECS: u64 = 300;

/// How long one key mints before a fresh one replaces it.
///
/// Rotation is lazy: the age is checked inside `mint`, against the `now` the
/// caller already supplies, so nothing runs on a timer and `open` never has to
/// mutate the ring. Not a parameter, for the reason above it is not: the
/// retention window it is measured against has exactly one home, and a second
/// copy of that number is how the two stop agreeing.
pub(super) const CONTINUATION_ROTATION_SECS: u64 = 60;

/// A retired kid must not return while envelopes it sealed can still verify.
///
/// Ids are one byte and each successor is the last plus one, so a kid comes
/// back after 256 rotations. That span must exceed the retention window — if it
/// did not, a rotation would find its successor still live, take the
/// keep-the-current-key fallback every single time, and stop rotating without
/// failing anything an operator could see.
const _: () = assert!(
    256 * CONTINUATION_ROTATION_SECS > CONTINUATION_LIFETIME_SECS,
    "a kid would be reused while a retained key can still verify with it"
);

/// When a continuation minted at `now` dies.
///
/// One function because two things need the answer and they must agree: the
/// envelope's own `expires_at`, and the deadline the reaper enforces on the
/// exchange it continues. A hold that outlives its envelope is a slot nothing
/// can release; one that dies first is an honest retry refused.
pub(super) const fn expiry_for(now: u64) -> u64 {
    now.saturating_add(CONTINUATION_LIFETIME_SECS)
}

/// Now, in the seconds `mint` and `open` measure `now` and `expires_at` in.
///
/// A clock that reads before 1970 is [`ContinuationError::Expired`]
/// (MIK-8202): an open refuses rather than judge a deadline against a clock it
/// cannot read, and a mint is refused rather than stamped `issued_at = 0`.
pub(crate) fn clock_now() -> Result<u64, ContinuationError> {
    crate::clock::unix_secs().map_err(|_| ContinuationError::Expired)
}

/// The real clock, for tests that mint against now.
#[cfg(test)]
pub(crate) fn now_unix_secs() -> u64 {
    crate::clock::unix_secs().expect("a test host clock reads after 1970")
}

impl Payload {
    /// Seal the facts of one interim exchange, valid from `now`.
    ///
    /// The identifier and the expiry are derived here rather than accepted:
    /// a caller that could choose its own `jti` could mint two continuations
    /// the ledger cannot tell apart, and one that could choose `expires_at`
    /// could mint one that outlives the ledger entry retiring it.
    #[must_use]
    pub fn mint(
        backend_id: String,
        backend_request_state: Option<String>,
        principal_fingerprint: String,
        original_request_digest: String,
        origin_replica: String,
        hold_key: String,
        now: u64,
    ) -> Self {
        Self {
            // `mint` keeps the signature it had. Every existing caller mints a
            // backend exchange, and the one caller that does not says so with
            // `with_purpose`, so no call site changes to gain a field it would
            // only ever pass one value for.
            purpose: ContinuationPurpose::BackendInput,
            backend_id,
            backend_request_state,
            principal_fingerprint,
            original_request_digest,
            origin_replica,
            issued_at: now,
            expires_at: expiry_for(now),
            jti: uuid::Uuid::new_v4().to_string(),
            hold_key,
            next_step: None,
            rounds_used: 0,
        }
    }

    /// Re-purpose a freshly minted payload before it is sealed.
    ///
    /// The purpose is sealed inside the authenticated plaintext, so a client
    /// cannot restate it; that, not this signature, is what binds an envelope to
    /// one redemption. Re-tagging an already-opened payload is possible in
    /// process and pointless, because nothing re-seals one. Consuming only so a
    /// mint reads as a single expression.
    #[must_use]
    pub fn with_purpose(mut self, purpose: ContinuationPurpose) -> Self {
        self.purpose = purpose;
        self
    }

    /// Seal one destructive-confirmation grant, valid from `now`.
    ///
    /// Same lifetime, `jti`, and hold contract as [`Self::mint`]. The only
    /// difference is [`ContinuationPurpose::DestructiveConfirm`], which a
    /// backend-input redeem must refuse before touching hold or ledger.
    #[must_use]
    pub fn mint_confirmation(
        backend_id: String,
        backend_request_state: Option<String>,
        principal_fingerprint: String,
        original_request_digest: String,
        origin_replica: String,
        hold_key: String,
        now: u64,
    ) -> Self {
        Self::mint(
            backend_id,
            backend_request_state,
            principal_fingerprint,
            original_request_digest,
            origin_replica,
            hold_key,
            now,
        )
        .with_purpose(ContinuationPurpose::DestructiveConfirm)
    }

    /// Refuse a payload whose domain is not `expected`.
    ///
    /// Kept beside [`Self::redeemable_by`]: authenticity is not purpose, and
    /// folding the two would let a caller skip the domain check by reaching
    /// for the payload directly.
    ///
    /// # Errors
    ///
    /// [`ContinuationError::NotAuthentic`] when the sealed domain is not the
    /// one this redemption path serves.
    pub fn require_purpose(&self, expected: ContinuationPurpose) -> Result<(), ContinuationError> {
        if self.purpose == expected {
            Ok(())
        } else {
            Err(ContinuationError::NotAuthentic)
        }
    }

    /// Whether this continuation belongs to this caller and this request.
    ///
    /// Separate from opening it, and deliberately so. An envelope the gateway
    /// minted is *authentic* no matter who presents it or what they present it
    /// alongside — authenticity says we wrote it, not that this is the moment
    /// it was written for. Folding this into `open` would let a future caller
    /// skip it by reaching for the payload directly; keeping it a method the
    /// caller must invoke makes the omission visible at the call site.
    ///
    /// Compared in constant time, and over fixed-width digests rather than the
    /// values themselves: both are attacker-influenced, and a slice comparison
    /// short-circuits when the lengths differ, so comparing the raw strings
    /// would leak the stored length however careful the comparison after it.
    /// Hashing first makes every comparison the same shape.
    ///
    /// # Errors
    ///
    /// Returns `NotAuthentic` when the continuation was minted for a different
    /// caller or a different request.
    pub fn redeemable_by(
        &self,
        principal_fingerprint: &str,
        original_request_digest: &str,
    ) -> Result<(), ContinuationError> {
        use subtle::ConstantTimeEq as _;

        let digest = |value: &str| ring::digest::digest(&ring::digest::SHA256, value.as_bytes());

        let principal_ok: bool = digest(&self.principal_fingerprint)
            .as_ref()
            .ct_eq(digest(principal_fingerprint).as_ref())
            .into();
        let request_ok: bool = digest(&self.original_request_digest)
            .as_ref()
            .ct_eq(digest(original_request_digest).as_ref())
            .into();
        if principal_ok && request_ok {
            Ok(())
        } else {
            Err(ContinuationError::NotAuthentic)
        }
    }
}

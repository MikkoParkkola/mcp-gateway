// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! The multi-round-trip continuation envelope.
//!
//! A backend returns `InputRequiredResult { inputRequests, requestState }`. The
//! gateway must reach the client, and on retry reach *that* backend with *that*
//! state — while the client is forbidden from inspecting or altering what it
//! echoes back.
//!
//! So the gateway never forwards a backend's `requestState`. It mints its own,
//! with the backend's blob sealed inside:
//!
//! ```text
//! v1 ‖ kid ‖ nonce ‖ AEAD(key[kid], nonce, aad = v1‖kid, payload)
//! ```
//!
//! Encrypted rather than merely signed, for a reason the spec does not state
//! and a gateway must: a backend's state may encode its own authorization, so a
//! signed-but-readable copy hands the client a token it should never hold.
//!
//! The version and key id sit outside the ciphertext and are authenticated as
//! associated data, so a key can be rotated without invalidating every
//! continuation in flight — and so a rotation cannot be passed off as a
//! different version.

/// Wire format version. Outside the ciphertext, authenticated as associated
/// data: a wire format needs a version, and one that can be changed without
/// detection is not a version.
const VERSION: u8 = 1;

/// AES-256-GCM nonce length.
const NONCE_LEN: usize = 12;

/// The largest envelope this gateway will mint or open, measured on the base64
/// text as it arrives on the wire.
///
/// Checked before decoding, which is the only place it does any good: a token
/// is client-controlled and arrives on every retry, so decoding first lets a
/// caller size the gateway's allocation and its AEAD work with nothing but a
/// long string, needing no key and no valid envelope.
///
/// Enforced at both ends deliberately. A bound applied only when opening would
/// let the gateway mint an envelope it will later refuse to redeem, and that
/// failure would surface on the retry — far from the backend whose state caused
/// it. 8 KiB sits well above realistic backend state while keeping the work an
/// unauthenticated caller can demand small.
const MAX_ENVELOPE_LEN: usize = 8 * 1024;

/// Why an envelope was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ContinuationError {
    /// Not a well-formed envelope: wrong shape, bad base64, truncated.
    Malformed,
    /// A version this build does not implement.
    UnknownVersion(u8),
    /// A key id no longer held. Verification keys are retained for at least a
    /// continuation lifetime, so this means older than that, or forged.
    UnknownKey(u8),
    /// Authentication failed: tampered, or minted by someone else.
    NotAuthentic,
    /// Past its deadline.
    Expired,
    /// This key has minted as many envelopes as it is permitted to.
    MintBudgetExhausted,
    /// Larger than [`MAX_ENVELOPE_LEN`], either presented or asked to be minted.
    TooLarge,
    /// Its window is wider than [`CONTINUATION_LIFETIME_SECS`], either
    /// presented or asked to be minted.
    ///
    /// Distinct from [`Self::Expired`], which says a deadline has passed. This
    /// says the deadline was never one this gateway is willing to offer, so an
    /// operator seeing it is looking at a minting bug, not at a slow client.
    LifetimeExceeded,
    /// The host clock reads before 1970, so a deadline cannot be judged
    /// (MIK-8202 AC13). Distinct from [`Self::Expired`]: nothing was spent
    /// and the same continuation may be redeemed once the clock reads.
    ClockUnreadable,
}

impl ContinuationError {
    /// What the client is told, as opposed to what the operator is told.
    ///
    /// The variants distinguish causes so an operator can act on them; a client
    /// gets one sentence for all of them. Reporting *which* key id or wire
    /// version was refused would let a caller map the live keyring and the
    /// build one probe at a time — and the caller can do nothing differently
    /// with the detail, since every one of these means the same thing to them:
    /// this continuation cannot be redeemed, start again.
    #[must_use]
    pub fn client_message(&self) -> &'static str {
        "continuation rejected"
    }
}

impl std::fmt::Display for ContinuationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Malformed => write!(f, "malformed continuation"),
            Self::UnknownVersion(v) => write!(f, "unknown continuation version {v}"),
            Self::UnknownKey(k) => write!(f, "unknown continuation key {k}"),
            Self::NotAuthentic => write!(f, "continuation failed authentication"),
            Self::Expired => write!(f, "continuation expired"),
            Self::MintBudgetExhausted => {
                write!(f, "continuation key has exhausted its mint budget")
            }
            Self::TooLarge => write!(f, "continuation exceeds the permitted size"),
            Self::LifetimeExceeded => {
                write!(f, "continuation outlives the permitted lifetime")
            }
            Self::ClockUnreadable => write!(f, "the clock cannot date this continuation"),
        }
    }
}

impl std::error::Error for ContinuationError {}

mod keyring;
mod ledger;
mod payload;

pub use keyring::Keyring;
pub use ledger::{ConsumedLedger, ContinuationState, InFlight, Routing};
pub(crate) use payload::clock_now;
#[cfg(test)]
pub(crate) use payload::now_unix_secs;
use payload::{CONTINUATION_LIFETIME_SECS, CONTINUATION_ROTATION_SECS, expiry_for};
pub use payload::{ContinuationPurpose, Payload};

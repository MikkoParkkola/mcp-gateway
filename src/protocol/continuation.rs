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

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use ring::aead::{AES_256_GCM, Aad, LessSafeKey, Nonce, UnboundKey};
use ring::rand::{SecureRandom as _, SystemRandom};
use serde::{Deserialize, Serialize};

/// Wire format version. Outside the ciphertext, authenticated as associated
/// data: a wire format needs a version, and one that can be changed without
/// detection is not a version.
const VERSION: u8 = 1;

/// AES-256-GCM nonce length.
const NONCE_LEN: usize = 12;

/// What the envelope carries. None of it is visible to the client.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Payload {
    /// Which backend holds the exchange.
    pub backend_id: String,
    /// The backend's own opaque state, verbatim.
    pub backend_request_state: String,
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
}

impl Payload {
    /// Whether this continuation belongs to this caller and this request.
    ///
    /// Separate from opening it, and deliberately so. An envelope the gateway
    /// minted is *authentic* no matter who presents it or what they present it
    /// alongside — authenticity says we wrote it, not that this is the moment
    /// it was written for. Folding this into `open` would let a future caller
    /// skip it by reaching for the payload directly; keeping it a method the
    /// caller must invoke makes the omission visible at the call site.
    ///
    /// Compared in constant time: both values are attacker-influenced, and a
    /// length-or-prefix timing signal on a principal fingerprint is a way to
    /// learn one.
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

        let principal_ok: bool = self
            .principal_fingerprint
            .as_bytes()
            .ct_eq(principal_fingerprint.as_bytes())
            .into();
        let request_ok: bool = self
            .original_request_digest
            .as_bytes()
            .ct_eq(original_request_digest.as_bytes())
            .into();
        if principal_ok && request_ok {
            Ok(())
        } else {
            Err(ContinuationError::NotAuthentic)
        }
    }
}

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
}

impl std::fmt::Display for ContinuationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Malformed => write!(f, "malformed continuation"),
            Self::UnknownVersion(v) => write!(f, "unknown continuation version {v}"),
            Self::UnknownKey(k) => write!(f, "unknown continuation key {k}"),
            Self::NotAuthentic => write!(f, "continuation failed authentication"),
            Self::Expired => write!(f, "continuation expired"),
        }
    }
}

impl std::error::Error for ContinuationError {}

/// The keys a gateway mints and verifies continuations with.
///
/// One key mints; several may verify. A verification key is retained for at
/// least the maximum continuation lifetime after it stops minting — without
/// that, rotating a key breaks every elicitation in flight, and a redeploy
/// looks exactly like an attack.
pub struct Keyring {
    minting_kid: u8,
    keys: Vec<(u8, LessSafeKey)>,
    rng: SystemRandom,
}

#[expect(
    clippy::missing_fields_in_debug,
    reason = "the omitted field is the key material, and the omission is the point: a Debug that prints keys puts them in every log that ever formats a Keyring"
)]
impl std::fmt::Debug for Keyring {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never the key material, not even in a debug log.
        f.debug_struct("Keyring")
            .field("minting_kid", &self.minting_kid)
            .field("verification_keys", &self.keys.len())
            .finish()
    }
}

impl Keyring {
    /// Build a keyring from raw 32-byte keys, the first of which mints.
    ///
    /// # Errors
    ///
    /// Returns `Malformed` if a key is not 32 bytes or the list is empty.
    pub fn new(keys: &[(u8, [u8; 32])]) -> Result<Self, ContinuationError> {
        let Some((minting_kid, _)) = keys.first() else {
            return Err(ContinuationError::Malformed);
        };
        let mut unbound = Vec::with_capacity(keys.len());
        for (kid, material) in keys {
            let key = UnboundKey::new(&AES_256_GCM, material)
                .map_err(|_| ContinuationError::Malformed)?;
            unbound.push((*kid, LessSafeKey::new(key)));
        }
        Ok(Self {
            minting_kid: *minting_kid,
            keys: unbound,
            rng: SystemRandom::new(),
        })
    }

    /// A keyring with one deterministic key, for tests only.
    #[must_use]
    pub fn for_test() -> Self {
        Self::new(&[(1, [7u8; 32])]).expect("a fixed 32-byte key is valid")
    }

    /// Seal a payload into an envelope for the client to echo back.
    ///
    /// # Errors
    ///
    /// Returns `Malformed` if the payload cannot be serialised or the system
    /// random source fails.
    pub fn mint(&self, payload: &Payload) -> Result<String, ContinuationError> {
        let key = self.key(self.minting_kid)?;
        let mut nonce_bytes = [0u8; NONCE_LEN];
        self.rng
            .fill(&mut nonce_bytes)
            .map_err(|_| ContinuationError::Malformed)?;

        let mut buffer = serde_json::to_vec(payload).map_err(|_| ContinuationError::Malformed)?;
        let header = [VERSION, self.minting_kid];
        key.seal_in_place_append_tag(
            Nonce::assume_unique_for_key(nonce_bytes),
            Aad::from(header),
            &mut buffer,
        )
        .map_err(|_| ContinuationError::Malformed)?;

        let mut wire = Vec::with_capacity(2 + NONCE_LEN + buffer.len());
        wire.extend_from_slice(&header);
        wire.extend_from_slice(&nonce_bytes);
        wire.extend_from_slice(&buffer);
        Ok(B64.encode(wire))
    }

    /// Open an envelope the client presented.
    ///
    /// Treated as attacker-controlled throughout: every failure returns an
    /// error rather than a partially-trusted value, and nothing is read out of
    /// the payload before authentication succeeds.
    ///
    /// # Errors
    ///
    /// Returns the reason it was refused; see [`ContinuationError`].
    pub fn open(&self, token: &str, now: u64) -> Result<Payload, ContinuationError> {
        let wire = B64
            .decode(token)
            .map_err(|_| ContinuationError::Malformed)?;
        if wire.len() <= 2 + NONCE_LEN {
            return Err(ContinuationError::Malformed);
        }
        let version = wire[0];
        if version != VERSION {
            return Err(ContinuationError::UnknownVersion(version));
        }
        let kid = wire[1];
        let key = self.key(kid)?;

        let mut nonce_bytes = [0u8; NONCE_LEN];
        nonce_bytes.copy_from_slice(&wire[2..2 + NONCE_LEN]);
        let mut buffer = wire[2 + NONCE_LEN..].to_vec();

        let plaintext = key
            .open_in_place(
                Nonce::assume_unique_for_key(nonce_bytes),
                Aad::from([version, kid]),
                &mut buffer,
            )
            .map_err(|_| ContinuationError::NotAuthentic)?;

        let payload: Payload =
            serde_json::from_slice(plaintext).map_err(|_| ContinuationError::NotAuthentic)?;

        // Checked after authentication, never before: an unauthenticated
        // deadline is a field an attacker chose.
        if now > payload.expires_at {
            return Err(ContinuationError::Expired);
        }
        Ok(payload)
    }

    fn key(&self, kid: u8) -> Result<&LessSafeKey, ContinuationError> {
        self.keys
            .iter()
            .find(|(id, _)| *id == kid)
            .map(|(_, key)| key)
            .ok_or(ContinuationError::UnknownKey(kid))
    }
}

/// The continuations already spent.
///
/// Encryption makes an envelope unforgeable; it does nothing about how many
/// times an unforgeable envelope is presented. This is the other half, and the
/// specification asks for it in as many words: a state that must be consumed at
/// most once **MUST** have that invariant enforced server-side.
///
/// Three properties, and each has a way of being quietly absent:
///
/// * **Atomic.** Check-and-consume in one operation. As two steps, two retries
///   of a destructive continuation both see it unspent and both proceed.
/// * **Bounded.** A client may abandon a continuation — the spec says a server
///   MUST NOT assume otherwise — so entries arrive at a rate the client chooses
///   and eviction on a deadline alone is not a bound.
/// * **Retained at least as long as the envelope.** Forgetting a spent `jti`
///   while its envelope still opens is a replay window with extra steps.
///
/// Single-process today. A multi-replica deployment needs this shared, which is
/// the same gap `origin_replica` names in the payload; both are the design's
/// stated next step rather than an oversight.
#[derive(Debug)]
pub struct ConsumedLedger {
    capacity: usize,
    /// `jti` -> the deadline of the envelope it came from. A `tokio` lock, so
    /// check-and-consume stays one operation for concurrent callers.
    spent: tokio::sync::Mutex<std::collections::HashMap<String, u64>>,
}

impl ConsumedLedger {
    /// A ledger holding at most `capacity` unexpired entries.
    #[must_use]
    pub fn new(capacity: usize) -> Self {
        Self {
            capacity,
            spent: tokio::sync::Mutex::new(std::collections::HashMap::new()),
        }
    }

    /// Spend a continuation. `true` if this caller won, `false` if it was
    /// already spent.
    ///
    /// One operation under one lock: the check and the write cannot be
    /// separated by a scheduler, which is the whole point.
    pub async fn consume(&self, jti: &str, expires_at: u64) -> bool {
        let mut spent = self.spent.lock().await;
        if spent.contains_key(jti) {
            return false;
        }
        if spent.len() >= self.capacity {
            // At capacity, drop the entry closest to expiry. Dropping *some*
            // entry is unavoidable — the alternative is unbounded growth under
            // a rate the client sets — and the one expiring soonest is the one
            // whose loss is briefest. A dropped entry is a replay window for
            // its remaining life, which is why capacity is a deployment
            // decision and not a constant.
            if let Some(soonest) = spent
                .iter()
                .min_by_key(|(_, deadline)| **deadline)
                .map(|(key, _)| key.clone())
            {
                spent.remove(&soonest);
            }
        }
        spent.insert(jti.to_string(), expires_at);
        true
    }

    /// Drop entries whose continuations have expired.
    ///
    /// An entry is kept until `now` passes its deadline, never before: the
    /// envelope opens until then, so the memory of it being spent must last at
    /// least as long.
    pub async fn evict_expired(&self, now: u64) {
        self.spent
            .lock()
            .await
            .retain(|_, expires_at| now <= *expires_at);
    }

    /// How many entries are held.
    pub async fn len(&self) -> usize {
        self.spent.lock().await.len()
    }

    /// Whether the ledger holds nothing.
    pub async fn is_empty(&self) -> bool {
        self.len().await == 0
    }
}

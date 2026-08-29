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
            .finish()
    }
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
    minted: std::sync::atomic::AtomicU64,
    mint_budget: u64,
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

/// The most envelopes one key may seal.
///
/// AES-GCM here uses a random 96-bit nonce, and random nonces collide by the
/// birthday bound rather than never. NIST SP 800-38D §8.3 caps a key at 2^32
/// invocations to hold the collision probability below 2^-32; a nonce reused
/// under one key is a catastrophic loss of confidentiality, not a degradation.
/// Rotation is what keeps a deployment under this.
///
/// **What this bound actually is, stated precisely because the difference
/// matters**: the counter lives in memory, so it counts envelopes sealed by
/// *this process* since it started — not by this *key* over its life. A
/// restart, a config reload that rebuilds the keyring, or a second replica each
/// begin again at zero. So the ceiling holds per process and the key's true
/// total is the sum across all of them.
///
/// That is a real ceiling and a useful one — it bounds a single runaway process,
/// which is the shape a nonce-collision risk takes when it arrives suddenly —
/// but it is not the per-key guarantee the NIST bound is written about. Making
/// it one requires the count to be durable and shared by key identity, which is
/// the same shared-state gap [`ConsumedLedger`] names. Both are gates on
/// multi-replica production, not on this change: `server.modern_protocol`
/// defaults off and nothing mints yet.
const MINT_BUDGET: u64 = 1 << 32;

impl Keyring {
    /// Build a keyring from raw 32-byte keys, the first of which mints.
    ///
    /// # Errors
    ///
    /// Returns `Malformed` if a key is not 32 bytes, the list is empty, or two
    /// keys share an id. A duplicated id is refused rather than tolerated
    /// because lookup takes the first match: the second key would silently
    /// never verify, and the failure would surface only on envelopes minted
    /// before the deploy that introduced it.
    pub fn new(keys: &[(u8, [u8; 32])]) -> Result<Self, ContinuationError> {
        let Some((minting_kid, _)) = keys.first() else {
            return Err(ContinuationError::Malformed);
        };
        let mut unbound: Vec<(u8, LessSafeKey)> = Vec::with_capacity(keys.len());
        for (kid, material) in keys {
            if unbound.iter().any(|(seen, _)| seen == kid) {
                return Err(ContinuationError::Malformed);
            }
            let key = UnboundKey::new(&AES_256_GCM, material)
                .map_err(|_| ContinuationError::Malformed)?;
            unbound.push((*kid, LessSafeKey::new(key)));
        }
        Ok(Self {
            minting_kid: *minting_kid,
            keys: unbound,
            rng: SystemRandom::new(),
            minted: std::sync::atomic::AtomicU64::new(0),
            mint_budget: MINT_BUDGET,
        })
    }

    /// Lower the mint budget below the default ceiling.
    ///
    /// A deployment that rotates faster than [`MINT_BUDGET`] can say so, and a
    /// test can reach the boundary without sealing four billion envelopes — a
    /// bound nothing can arrive at is a bound nobody has checked. Raising it
    /// above the default is refused: the ceiling is a property of AES-GCM with
    /// random nonces, not a preference.
    #[must_use]
    pub fn with_mint_budget(mut self, budget: u64) -> Self {
        self.mint_budget = budget.min(MINT_BUDGET);
        self
    }

    /// The number of envelopes this key may still seal.
    ///
    /// Exposed so the ceiling can be observed rather than trusted: a bound
    /// nothing can read is a bound nobody can check, and an operator watching
    /// this approach zero is the signal that rotation is overdue.
    #[must_use]
    pub fn mint_budget_remaining(&self) -> u64 {
        self.mint_budget
            .saturating_sub(self.minted.load(std::sync::atomic::Ordering::Relaxed))
    }

    /// Seal a payload into an envelope for the client to echo back.
    ///
    /// # Errors
    ///
    /// Returns `Malformed` if the payload cannot be serialised or the system
    /// random source fails, and `MintBudgetExhausted` once this key has sealed
    /// its budget of envelopes (see [`MINT_BUDGET`]), and `TooLarge` when the
    /// sealed envelope would exceed [`MAX_ENVELOPE_LEN`].
    pub fn mint(&self, payload: &Payload) -> Result<String, ContinuationError> {
        // Counted before the nonce is drawn, so a refusal cannot consume one.
        // Fetch-and-add rather than read-then-write: concurrent minters must not
        // be able to step past the budget between the two halves.
        let used = self
            .minted
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        if used >= self.mint_budget {
            // Saturate rather than wrap: a counter that wraps re-opens the
            // budget it exists to close.
            self.minted
                .store(self.mint_budget, std::sync::atomic::Ordering::Relaxed);
            return Err(ContinuationError::MintBudgetExhausted);
        }
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
        let encoded = B64.encode(wire);
        if encoded.len() > MAX_ENVELOPE_LEN {
            return Err(ContinuationError::TooLarge);
        }
        Ok(encoded)
    }

    /// Open an envelope the client presented.
    ///
    /// Treated as attacker-controlled throughout: every failure returns an
    /// error rather than a partially-trusted value, and nothing is read out of
    /// the payload before authentication succeeds.
    ///
    /// # Errors
    ///
    /// Returns the reason it was refused; see [`ContinuationError`]. A token
    /// longer than [`MAX_ENVELOPE_LEN`] is refused on its length alone.
    pub fn open(&self, token: &str, now: u64) -> Result<Payload, ContinuationError> {
        // Before the decode, so an oversized token costs a length comparison.
        if token.len() > MAX_ENVELOPE_LEN {
            return Err(ContinuationError::TooLarge);
        }
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
    /// already spent or the ledger is full.
    ///
    /// One operation under one lock: the check and the write cannot be
    /// separated by a scheduler, which is the whole point.
    ///
    /// At capacity it **refuses** rather than evicting. Both stay bounded, and
    /// the difference is who pays: forgetting an entry whose envelope still
    /// opens re-opens a replay window on a continuation already spent, which is
    /// the single property this ledger exists to hold. Refusing costs a caller
    /// one retry of an elicitation. An entry is only ever reclaimed once its
    /// own deadline has passed, at which point its envelope no longer opens and
    /// remembering it buys nothing.
    ///
    /// So capacity is a deployment decision about availability, never about
    /// safety — which is the right way round.
    ///
    /// `now` is passed rather than read from a clock, as everywhere else in
    /// this module: reclamation must agree with [`Self::evict_expired`] and
    /// with the deadline [`Keyring::open`] enforced, and three components
    /// reading three clocks is how they come to disagree.
    pub async fn consume(&self, jti: &str, expires_at: u64, now: u64) -> bool {
        let mut spent = self.spent.lock().await;
        if spent.contains_key(jti) {
            return false;
        }
        if spent.len() >= self.capacity {
            // Reclaim only what is genuinely dead — an entry whose own deadline
            // has passed, whose envelope therefore no longer opens. Refusing
            // while holding entries nobody can replay would be a denial of
            // service dressed as caution.
            spent.retain(|_, deadline| now <= *deadline);
            if spent.len() >= self.capacity {
                return false;
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

/// Where a retry must be handled.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Routing {
    /// This replica holds the exchange.
    Here,
    /// Another replica holds it, and the retry belongs there.
    Elsewhere {
        /// The replica that holds the open request.
        replica: String,
    },
    /// Nobody holds it: evicted, expired, or the holder is gone.
    Gone,
}

/// Exchanges this gateway is holding open on behalf of a legacy backend.
///
/// This is the one place the gateway is permitted to hold state, and the reason
/// is not convenience. A **legacy** backend that elicits does so by keeping its
/// RPC open and waiting; there is no continuation it can hand back, because the
/// revision that invented continuations is the one it does not speak. So the
/// gateway absorbs that statefulness and presents the modern client a
/// continuation anyway. That is the bridge earning its keep.
///
/// The open RPC lives on exactly one replica, and a stateless client's retry
/// may land on any of them — which is why `origin_replica` travels inside the
/// sealed envelope. A retry that arrives in the wrong place is **routed**, and
/// one whose holder is gone **fails explicitly**. Starting a second exchange
/// instead would leave the first hanging and ask the user the same question
/// twice; for a destructive tool, the second answer would authorise a call the
/// first one already authorised.
#[derive(Debug)]
pub struct InFlight {
    replica: String,
    capacity: usize,
    /// key -> (replica holding it, deadline).
    held: tokio::sync::Mutex<std::collections::HashMap<String, (String, u64)>>,
}

impl InFlight {
    /// A table for this replica, holding at most `capacity` exchanges.
    #[must_use]
    pub fn new(replica: &str, capacity: usize) -> Self {
        Self {
            replica: replica.to_string(),
            capacity,
            held: tokio::sync::Mutex::new(std::collections::HashMap::new()),
        }
    }

    /// Record that this replica is holding an exchange open, returning its key.
    ///
    /// `None` at capacity — a refusal the caller turns into an error the client
    /// can see. Growing instead would make the table a memory-exhaustion vector
    /// reachable by any client that starts elicitations and walks away, which
    /// the specification explicitly permits it to do.
    pub async fn hold(&self, backend_id: &str, expires_at: u64) -> Option<String> {
        let mut held = self.held.lock().await;
        if held.len() >= self.capacity {
            return None;
        }
        // Named by the gateway, never by the client: two exchanges against one
        // backend must not collide, and no caller may name another's.
        let key = format!("{backend_id}:{}", uuid::Uuid::new_v4());
        held.insert(key.clone(), (self.replica.clone(), expires_at));
        Some(key)
    }

    /// Where a retry for `key` belongs, given the replica that received it.
    ///
    /// Waits for the lock rather than answering under contention. `Gone` means
    /// the exchange no longer exists and a caller acts on it by failing the
    /// retry, so reporting it for a lock a concurrent reaper happens to hold
    /// would turn ordinary contention into a lost elicitation — the outcome
    /// this table exists to prevent. The wait is bounded by the map operations
    /// the other holders are performing, all of which are O(1) or a retain over
    /// a table with a capacity.
    pub async fn route(&self, key: &str, receiving_replica: &str) -> Routing {
        let held = self.held.lock().await;
        match held.get(key) {
            Some((holder, _)) if holder == receiving_replica => Routing::Here,
            Some((holder, _)) => Routing::Elsewhere {
                replica: holder.clone(),
            },
            None => Routing::Gone,
        }
    }

    /// Release an exchange that has finished, reporting whether it held a slot.
    ///
    /// Without this, capacity counts every exchange ever *started* until its
    /// deadline passes, so a busy gateway refuses new elicitations on behalf of
    /// ones that completed long ago. Reaping is the backstop for abandonment,
    /// not the ordinary path — the ordinary path is that an exchange ends.
    pub async fn complete(&self, key: &str) -> bool {
        self.held.lock().await.remove(key).is_some()
    }

    /// Drop exchanges whose deadline has passed.
    ///
    /// Abandonment is the common case, not the exceptional one: a client is
    /// free never to retry, so every held exchange needs a deadline and someone
    /// to enforce it.
    pub async fn reap(&self, now: u64) {
        self.held
            .lock()
            .await
            .retain(|_, (_, deadline)| now <= *deadline);
    }

    /// How many exchanges are held.
    pub async fn len(&self) -> usize {
        self.held.lock().await.len()
    }

    /// Whether nothing is held.
    pub async fn is_empty(&self) -> bool {
        self.len().await == 0
    }
}

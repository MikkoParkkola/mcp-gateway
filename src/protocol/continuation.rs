// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: MIT

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
    /// The [`InFlight`] key for the exchange this continuation continues.
    ///
    /// Sealed rather than derived, and carried rather than looked up: the table
    /// is keyed by a name the gateway chose at mint, and without that name in
    /// the envelope a redemption can only ask whether *some* exchange is open
    /// for this backend. That is a weaker question than the criterion asks —
    /// it answers yes for an honest concurrent exchange belonging to another
    /// caller, so a retry whose own exchange has ended would be admitted on the
    /// strength of a stranger's.
    pub hold_key: String,
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
const CONTINUATION_LIFETIME_SECS: u64 = 300;

/// How long one key mints before a fresh one replaces it.
///
/// Rotation is lazy: the age is checked inside `mint`, against the `now` the
/// caller already supplies, so nothing runs on a timer and `open` never has to
/// mutate the ring. Not a parameter, for the reason above it is not: the
/// retention window it is measured against has exactly one home, and a second
/// copy of that number is how the two stop agreeing.
const CONTINUATION_ROTATION_SECS: u64 = 60;

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
const fn expiry_for(now: u64) -> u64 {
    now.saturating_add(CONTINUATION_LIFETIME_SECS)
}

/// Wall-clock seconds since the Unix epoch — the unit `mint` and `open` measure
/// `now` and `expires_at` in.
///
/// Lives beside them rather than being borrowed from another module: the expiry
/// contract is defined here, so the clock that feeds it belongs to the same
/// unit. A pre-epoch clock yields 0, which expires every continuation rather
/// than minting one that never expires.
pub(crate) fn now_unix_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
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
            backend_id,
            backend_request_state,
            principal_fingerprint,
            original_request_digest,
            origin_replica,
            issued_at: now,
            expires_at: expiry_for(now),
            jti: uuid::Uuid::new_v4().to_string(),
            hold_key,
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
    ring: std::sync::RwLock<Ring>,
    rng: SystemRandom,
    mint_budget: u64,
}

/// One key and what rotation needs to know about it.
struct RingKey {
    kid: u8,
    key: LessSafeKey,
    /// When this key started minting. `None` until its first mint stamps it —
    /// `Keyring::new` has no clock, and a key born at an assumed zero reads as
    /// infinitely old and burns a successor on the first request after startup.
    created_at: Option<u64>,
    /// When this key stopped minting. `None` means it never has, which is true
    /// of the minting key and of every operator-supplied verification key: a
    /// key with no retirement instant is never pruned.
    retired_at: Option<u64>,
    /// Envelopes this key has sealed, against [`Keyring::mint_budget`]. Per key
    /// rather than per keyring because the NIST bound is per key, and because a
    /// counter on the key is what lets an ordinary mint hold a read guard —
    /// were it beside `minting_kid`, every mint would be a writer.
    minted: std::sync::atomic::AtomicU64,
}

/// `minting_kid` and `keys` under one lock, because they are one fact.
///
/// Read apart they can disagree: a mint that resolved the id and then looked it
/// up across a rotation would fail to find a key it had just been told mints.
struct Ring {
    minting_kid: u8,
    keys: Vec<RingKey>,
}

impl std::fmt::Debug for Keyring {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never the key material, not even in a debug log: a `Debug` that
        // prints keys puts them in every log that ever formats a `Keyring`.
        // The counts are what an operator needs and all they get.
        let ring = self.read_ring();
        f.debug_struct("Keyring")
            .field("minting_kid", &ring.minting_kid)
            .field("verification_keys", &ring.keys.len())
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
        let mut unbound: Vec<RingKey> = Vec::with_capacity(keys.len());
        for (kid, material) in keys {
            if unbound.iter().any(|held| held.kid == *kid) {
                return Err(ContinuationError::Malformed);
            }
            let key = UnboundKey::new(&AES_256_GCM, material)
                .map_err(|_| ContinuationError::Malformed)?;
            unbound.push(RingKey {
                kid: *kid,
                key: LessSafeKey::new(key),
                // No clock here, deliberately. The first mint stamps the
                // minting key from the `now` it is handed; the rest are
                // verification keys that never minted under this process and
                // have no retirement instant to prune them by.
                created_at: None,
                retired_at: None,
                minted: std::sync::atomic::AtomicU64::new(0),
            });
        }
        Ok(Self {
            ring: std::sync::RwLock::new(Ring {
                minting_kid: *minting_kid,
                keys: unbound,
            }),
            rng: SystemRandom::new(),
            mint_budget: MINT_BUDGET,
        })
    }

    /// A poisoned lock is not a reason to stop minting.
    ///
    /// The guarded value is a key list, not an invariant a panic can leave
    /// half-written: every mutation of it is a single `Vec` operation under the
    /// write guard. Propagating the poison would turn one panicking thread into
    /// a gateway that refuses every continuation for the rest of the process.
    fn read_ring(&self) -> std::sync::RwLockReadGuard<'_, Ring> {
        self.ring
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn write_ring(&self) -> std::sync::RwLockWriteGuard<'_, Ring> {
        self.ring
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn key(ring: &Ring, kid: u8) -> Result<&RingKey, ContinuationError> {
        ring.keys
            .iter()
            .find(|held| held.kid == kid)
            .ok_or(ContinuationError::UnknownKey(kid))
    }

    /// How many keys this ring can still verify with.
    ///
    /// Exposed for the same reason [`Keyring::mint_budget_remaining`] is: the
    /// retention rule is the criterion, and a rule nothing can read is a rule
    /// nobody can check. Inferring it from a refused envelope would not do —
    /// that answers whether one key is gone, not whether pruning ran.
    #[must_use]
    pub fn retained_kid_count(&self) -> usize {
        self.read_ring().keys.len()
    }

    /// The id currently sealing envelopes.
    #[must_use]
    pub fn minting_kid(&self) -> u8 {
        self.read_ring().minting_kid
    }

    /// Stamp the startup key, then rotate it if it has minted for long enough.
    ///
    /// Both under one write guard and in this order: an unstamped key has no
    /// age, so checking its age first would rotate on the very first mint.
    ///
    /// The age is tested twice — once under the read guard by the caller to
    /// decide whether this is worth a writer, and again here before acting.
    /// Two mints arriving either side of the boundary would otherwise both
    /// rotate, spending two ids for one interval.
    fn rotate_if_due(&self, now: u64) -> Result<(), ContinuationError> {
        let mut ring = self.write_ring();
        let minting_kid = ring.minting_kid;
        let Some(current) = ring.keys.iter().position(|held| held.kid == minting_kid) else {
            return Ok(());
        };
        match ring.keys[current].created_at {
            None => {
                ring.keys[current].created_at = Some(now);
                return Ok(());
            }
            Some(created_at) if now.saturating_sub(created_at) < CONTINUATION_ROTATION_SECS => {
                return Ok(());
            }
            Some(_) => {}
        }

        // Always the successor, never the lowest free id. Reusing a gap would
        // put a kid back on the wire while a retained key still verifies with
        // it, and the two envelopes would be indistinguishable.
        let old_kid = ring.minting_kid;
        let new_kid = old_kid.wrapping_add(1);
        if ring.keys.iter().any(|held| held.kid == new_kid) {
            // Keeping the current key is the honest fallback: the caller asked
            // for an envelope, not for a rotation, and refusing it would turn a
            // ring-sizing mistake into an outage. The bound asserted beside
            // `CONTINUATION_ROTATION_SECS` is what keeps this unreachable.
            tracing::warn!(
                minting_kid = old_kid,
                successor_kid = new_kid,
                "continuation key rotation skipped: successor id still retained"
            );
            return Ok(());
        }

        let mut material = [0u8; 32];
        self.rng
            .fill(&mut material)
            .map_err(|_| ContinuationError::Malformed)?;
        let key =
            UnboundKey::new(&AES_256_GCM, &material).map_err(|_| ContinuationError::Malformed)?;

        ring.keys[current].retired_at = Some(now);
        ring.keys.push(RingKey {
            kid: new_kid,
            key: LessSafeKey::new(key),
            created_at: Some(now),
            retired_at: None,
            minted: std::sync::atomic::AtomicU64::new(0),
        });
        ring.minting_kid = new_kid;

        // Same pass, so retention is bounded by the rotation that caused it
        // rather than by whatever happens to run next. A key with no retirement
        // instant is never dropped, and neither is the one now minting.
        ring.keys.retain(|held| {
            held.kid == new_kid
                || held.retired_at.is_none_or(|retired_at| {
                    now.saturating_sub(retired_at) <= CONTINUATION_LIFETIME_SECS
                })
        });

        tracing::info!(
            retired_kid = old_kid,
            minting_kid = new_kid,
            retained_keys = ring.keys.len(),
            "continuation key rotated"
        );
        Ok(())
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
        let ring = self.read_ring();
        let minted = Self::key(&ring, ring.minting_kid).map_or(0, |held| {
            held.minted.load(std::sync::atomic::Ordering::Relaxed)
        });
        self.mint_budget.saturating_sub(minted)
    }

    /// Seal a payload into an envelope for the client to echo back.
    ///
    /// # Errors
    ///
    /// Returns `Malformed` if the payload cannot be serialised or the system
    /// random source fails, and `MintBudgetExhausted` once this key has sealed
    /// its budget of envelopes (see [`MINT_BUDGET`]), and `TooLarge` when the
    /// sealed envelope would exceed [`MAX_ENVELOPE_LEN`], and
    /// `LifetimeExceeded` when the payload's window is wider than
    /// [`CONTINUATION_LIFETIME_SECS`].
    pub fn mint(&self, payload: &Payload) -> Result<String, ContinuationError> {
        // Ahead of the budget, so a refusal cannot consume one — the same
        // reason the budget is charged before the nonce is drawn.
        //
        // `expiry_for` is the only deadline this gateway offers, and a caller
        // that sets its own could offer any. Checked here rather than only at
        // `open` because a bound applied at one end lets the gateway mint what
        // it will later refuse; the same argument `MAX_ENVELOPE_LEN` makes.
        //
        // `saturating_sub` reads a backwards window (`expires_at` before
        // `issued_at`) as zero rather than wrapping it into a legal width.
        // Sealing one is harmless: it is already past its deadline, and
        // `Expired` is the honest answer for it.
        if payload.expires_at.saturating_sub(payload.issued_at) > CONTINUATION_LIFETIME_SECS {
            return Err(ContinuationError::LifetimeExceeded);
        }
        // The payload's own `issued_at` is the clock. `mint` is handed no other,
        // and reading the wall clock here would let the two disagree — an
        // envelope stamped by one instant and rotated against another.
        //
        // Before the budget, so the very first mint stamps the startup key even
        // if it is then refused: an unstamped key is an ageless one, and it
        // would rotate on whatever request came next.
        //
        // The read guard is dropped before `rotate_if_due` takes the writer.
        // Holding it across the call would deadlock on a non-reentrant lock.
        let due = {
            let ring = self.read_ring();
            Self::key(&ring, ring.minting_kid).is_ok_and(|held| {
                held.created_at.is_none_or(|created_at| {
                    payload.issued_at.saturating_sub(created_at) >= CONTINUATION_ROTATION_SECS
                })
            })
        };
        if due {
            self.rotate_if_due(payload.issued_at)?;
        }

        let ring = self.read_ring();
        let kid = ring.minting_kid;
        let held = Self::key(&ring, kid)?;

        // Counted before the nonce is drawn, so a refusal cannot consume one.
        // Fetch-and-add rather than read-then-write: concurrent minters must not
        // be able to step past the budget between the two halves.
        let used = held
            .minted
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        if used >= self.mint_budget {
            // Saturate rather than wrap: a counter that wraps re-opens the
            // budget it exists to close.
            held.minted
                .store(self.mint_budget, std::sync::atomic::Ordering::Relaxed);
            return Err(ContinuationError::MintBudgetExhausted);
        }
        let mut nonce_bytes = [0u8; NONCE_LEN];
        self.rng
            .fill(&mut nonce_bytes)
            .map_err(|_| ContinuationError::Malformed)?;

        let mut buffer = serde_json::to_vec(payload).map_err(|_| ContinuationError::Malformed)?;
        let header = [VERSION, kid];
        held.key
            .seal_in_place_append_tag(
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

        let mut nonce_bytes = [0u8; NONCE_LEN];
        nonce_bytes.copy_from_slice(&wire[2..2 + NONCE_LEN]);
        let mut buffer = wire[2 + NONCE_LEN..].to_vec();

        // A read guard, never a writer: `open` neither rotates nor prunes. Kid
        // resolution happens above the expiry check, so a pruning `open` would
        // answer for a merely-late handle with the wrong refusal.
        let payload: Payload = {
            let ring = self.read_ring();
            let plaintext = Self::key(&ring, kid)?
                .key
                .open_in_place(
                    Nonce::assume_unique_for_key(nonce_bytes),
                    Aad::from([version, kid]),
                    &mut buffer,
                )
                .map_err(|_| ContinuationError::NotAuthentic)?;
            serde_json::from_slice(plaintext).map_err(|_| ContinuationError::NotAuthentic)?
        };

        // Checked after authentication, never before: an unauthenticated
        // deadline is a field an attacker chose.
        if now > payload.expires_at {
            return Err(ContinuationError::Expired);
        }
        // After the deadline check, never before: a handle that is merely late
        // must answer `Expired`, and an age older than the ceiling implies a
        // passed deadline for every payload `mint` accepts. So this branch is
        // unreachable today — it is what would refuse an envelope sealed by a
        // build whose mint-side check was removed, which is the case the
        // ceiling exists to survive. `saturating_add` keeps an absurd
        // `issued_at` from wrapping the sum into the past and reading as fresh.
        if now > payload.issued_at.saturating_add(CONTINUATION_LIFETIME_SECS) {
            return Err(ContinuationError::LifetimeExceeded);
        }
        Ok(payload)
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
/// Process-local, and correct that way rather than pending a shared store. Key
/// material is generated per process and never shared ([`ContinuationState`]),
/// so an envelope opens on exactly one replica and only that replica can spend
/// it — leaving no second ledger for a partition or a stale read to disagree
/// with. Sharing the keys without sharing this table is what would break it,
/// which is the invariant [`ContinuationState`] carries.
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
/// sealed envelope. A retry that arrives anywhere but the minting replica
/// **fails explicitly**; there is no affinity to send it home with. Starting a
/// second exchange
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

/// Drop exchanges whose deadline has passed.
///
/// A free function rather than a method because [`InFlight::guard`] calls it
/// while already holding the lock.
fn reclaim_abandoned(held: &mut std::collections::HashMap<String, (String, u64)>, now: u64) {
    let before = held.len();
    held.retain(|_, (_, deadline)| now <= *deadline);
    let evicted = before - held.len();
    if evicted > 0 {
        // The only trace this event leaves. A client refused for presenting a
        // stale envelope is counted at its own call site with
        // `reason="deadline_passed"`; a client that simply stops calling makes
        // no call to be counted in, so without this an operator cannot see it
        // at all (NFR.OBS.4). Counted here rather than at the caller because
        // this is where the eviction is decided, and the emission is pinned
        // end-to-end by `tests/continuation_expiry_metric_test.rs`.
        telemetry_metrics::counter!("continuation_expiry_total", "reason" => "hold_evicted")
            .increment(evicted as u64);
    }
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
    pub async fn hold(&self, backend_id: &str, expires_at: u64, now: u64) -> Option<String> {
        // `guard` has already reclaimed against `now`, so the count this
        // refusal reads is of exchanges that are still live. Reclaiming in the
        // capacity branch instead would make the bound the only thing that
        // ever collected an abandoned slot, and every reader below would then
        // be able to observe one.
        let mut held = self.guard(now).await;
        if held.len() >= self.capacity {
            return None;
        }
        // Named by the gateway, never by the client: two exchanges against one
        // backend must not collide, and no caller may name another's.
        let key = format!("{backend_id}:{}", uuid::Uuid::new_v4());
        held.insert(key.clone(), (self.replica.clone(), expires_at));
        Some(key)
    }

    /// Take the lock and reclaim against `now` before anything reads the map.
    ///
    /// Every reader below goes through here, which is what makes "an expired
    /// hold is retained" and "an expired hold routes `Here`" unstateable about
    /// this type. Teaching `route` alone to compare deadlines would leave both
    /// findings stateable about `len`, and about the next reader someone adds.
    ///
    /// **The guarantee is relative to the supplied `now`, and that is the whole
    /// contract.** The table holds no record whose deadline is strictly before the
    /// `now` most recently passed in. It does *not* hold that the table is free
    /// of records expired against the wall clock at the instant a caller reads
    /// the result: `invoke.rs` captures `now` once and reuses it for both the
    /// route and the completion, so an exchange expiring inside that window
    /// survives the reclaim and still routes. That is correct — a dispatch
    /// decided against a single consistent instant is the property the call
    /// path wants, and re-reading the clock per call would make one request
    /// observe two different presents. Said here so that a future call site
    /// cannot inherit the absolute reading.
    async fn guard(
        &self,
        now: u64,
    ) -> tokio::sync::MutexGuard<'_, std::collections::HashMap<String, (String, u64)>> {
        let mut held = self.held.lock().await;
        reclaim_abandoned(&mut held, now);
        held
    }

    /// Whether this replica still holds the exchange for `key`.
    ///
    /// There is no third answer. The holder recorded in the table is always
    /// this replica, because `hold` is the only thing that writes one, so a
    /// retry that reaches the wrong process asks a table that never knew the
    /// key and is told `Gone`. That is the design's own bargain
    /// (`docs/design/2026-08-30-shared-continuation-state.md:116`): the
    /// cross-replica guarantee holds cryptographically, with no shared store
    /// and **no affinity**, and MRTR.6's second arm — fail explicitly — is
    /// what serves the criterion.
    ///
    /// Waits for the lock rather than answering under contention. `Gone` means
    /// the exchange no longer exists and a caller acts on it by failing the
    /// retry, so reporting it for a lock a concurrent reaper happens to hold
    /// would turn ordinary contention into a lost elicitation — the outcome
    /// this table exists to prevent. The wait is bounded by the map operations
    /// the other holders are performing, all of which are O(1) or a retain over
    /// a table with a capacity.
    pub async fn route(&self, key: &str, now: u64) -> Routing {
        let held = self.guard(now).await;
        match held.get(key) {
            Some(_) => Routing::Here,
            None => Routing::Gone,
        }
    }

    /// Release an exchange that has finished, reporting whether it held a slot.
    ///
    /// Without this, capacity counts every exchange ever *started* until its
    /// deadline passes, so a busy gateway refuses new elicitations on behalf of
    /// ones that completed long ago. Reaping is the backstop for abandonment,
    /// not the ordinary path — the ordinary path is that an exchange ends.
    pub async fn complete(&self, key: &str, now: u64) -> bool {
        self.guard(now).await.remove(key).is_some()
    }

    /// How many exchanges are held, as of `now`.
    pub async fn len(&self, now: u64) -> usize {
        self.guard(now).await.len()
    }
}

/// The three pieces of continuation state, with one owner and one lifetime.
///
/// They are separable types and are deliberately not separable fields. A
/// keyring that outlives its ledger is a replay window: envelopes minted before
/// the ledger was replaced still open, and the memory of them being spent is
/// gone. Constructing all three together, and replacing them only together, is
/// what closes it.
///
/// **The invariant this type carries, because a future change could break it
/// while looking like a configuration convenience:**
///
/// > Continuation key material is never shared between processes unless the
/// > consumed-ledger is shared in the same change.
///
/// That is not a caveat, it is the enforcement mechanism for MRTR.5. Key
/// material is generated here, per process, and written nowhere. So an envelope
/// sealed by one replica is `NotAuthentic` on every other one, the set of
/// replicas that can spend it twice is empty, and the one replica that can
/// spend it at all does so atomically under [`ConsumedLedger`]'s own mutex —
/// no shared store, no session affinity, no consensus. A configured shared key
/// without a shared ledger is exactly the deployment the requirement forbids.
///
/// See `docs/design/2026-08-30-shared-continuation-state.md`.
#[derive(Debug)]
pub struct ContinuationState {
    replica: String,
    keyring: Keyring,
    ledger: ConsumedLedger,
    in_flight: InFlight,
}

/// How many spent continuations one process remembers at once.
///
/// An availability figure, never a safety one: at capacity the ledger refuses a
/// redemption rather than forgetting one, so the cost of it being too small is
/// a client retrying an elicitation, not a replay. Sized for a busy gateway's
/// unexpired continuations, which live minutes rather than hours.
const CONSUMED_LEDGER_CAPACITY: usize = 65_536;

/// How many legacy exchanges one process holds open at once.
///
/// Also availability, and also a refusal rather than growth: a client may start
/// an elicitation and never retry, so this table's occupants arrive at a rate
/// the client chooses. Smaller than the ledger because each entry is a live RPC
/// against a backend, not a remembered string.
const IN_FLIGHT_CAPACITY: usize = 4_096;

impl ContinuationState {
    /// Build the state for this process, generating its key material.
    ///
    /// # Panics
    ///
    /// Panics if the platform RNG cannot produce a key. A process that cannot
    /// generate one cannot seal a continuation, so it cannot serve the modern
    /// protocol path — failing at startup says that once, where an operator
    /// sees it, rather than on the first elicitation a user reaches.
    #[must_use]
    pub fn new() -> Self {
        let rng = SystemRandom::new();
        let mut key = [0u8; 32];
        rng.fill(&mut key)
            .expect("platform RNG must produce a continuation key");
        // Named by the process, for the process: `origin_replica` is sealed
        // inside the envelope and read only by the replica that minted it, so
        // any per-process value works and a generated one cannot collide with
        // a restarted predecessor's.
        let replica = uuid::Uuid::new_v4().to_string();
        Self {
            keyring: Keyring::new(&[(1, key)]).expect("a single 32-byte key is a valid keyring"),
            ledger: ConsumedLedger::new(CONSUMED_LEDGER_CAPACITY),
            in_flight: InFlight::new(&replica, IN_FLIGHT_CAPACITY),
            replica,
        }
    }

    /// Open an exchange on this replica and seal a continuation for it
    /// (MRTR.8).
    ///
    /// The hold and the mint are one operation because the criterion is about
    /// their agreement: an envelope naming an exchange nobody holds is
    /// redeemable against nothing, and a held slot no envelope names is a leak
    /// that only the reaper ever closes. Taking the slot first also puts the
    /// capacity refusal before the mint, so a gateway at its limit declines the
    /// question rather than answering it with a handle it cannot honour.
    ///
    /// `None` when the table is full. The caller turns that into the same
    /// refusal it gives an unbindable caller: both are properties of this
    /// gateway's state that a client can do nothing about.
    pub async fn begin_exchange(
        &self,
        backend_id: String,
        backend_request_state: Option<String>,
        principal_fingerprint: String,
        original_request_digest: String,
        now: u64,
    ) -> Option<Payload> {
        let hold_key = self
            .in_flight
            .hold(&backend_id, expiry_for(now), now)
            .await?;
        Some(Payload::mint(
            backend_id,
            backend_request_state,
            principal_fingerprint,
            original_request_digest,
            self.replica.clone(),
            hold_key,
            now,
        ))
    }

    /// The keys this process mints and opens with.
    #[must_use]
    pub fn keyring(&self) -> &Keyring {
        &self.keyring
    }

    /// The continuations this process has already spent.
    #[must_use]
    pub fn ledger(&self) -> &ConsumedLedger {
        &self.ledger
    }

    /// The legacy exchanges this process is holding open.
    #[must_use]
    pub fn in_flight(&self) -> &InFlight {
        &self.in_flight
    }

    /// What this process calls itself in a minted `origin_replica`.
    #[must_use]
    pub fn replica(&self) -> &str {
        &self.replica
    }
}

impl Default for ContinuationState {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod in_flight_lifetime {
    //! MRTR.8b Change A — the `InFlight` table's bounded lifetime.
    //!
    //! Plan: `docs/design/2026-09-06-mrtr-8b-lifetime-test-plan.md`. Row numbers
    //! below are that plan's. Every `now` is supplied by the test and anchored to
    //! one synthetic epoch, never `SystemTime::now()`: a `guard` that read the
    //! clock itself would answer identically to a correct one under a real-clock
    //! fixture, and row .07 could then not fail for its stated reason.

    use super::{IN_FLIGHT_CAPACITY, InFlight, Routing};

    /// The synthetic epoch. Every deadline and every supplied `now` is relative
    /// to this, so a `guard` reading the wall clock is ~1.7 billion seconds past
    /// every deadline in this module and reclaims everything.
    const T: u64 = 1_000;

    /// One replica holding one exchange whose deadline is exactly `T`.
    async fn held_until_t(capacity: usize) -> (InFlight, String) {
        let table = InFlight::new("gw-1", capacity);
        let key = table
            .hold("backend", T, T)
            .await
            .expect("an empty table admits");
        (table, key)
    }

    // --- C1: no reader observes a record whose deadline is behind its `now`. ---

    #[tokio::test]
    async fn row_01_len_does_not_count_an_expired_entry() {
        let (table, _key) = held_until_t(4).await;
        assert_eq!(table.len(T + 1).await, 0);
    }

    #[tokio::test]
    async fn row_02_route_does_not_answer_here_for_an_expired_entry() {
        let (table, key) = held_until_t(4).await;
        assert_eq!(table.route(&key, T + 1).await, Routing::Gone);
    }

    #[tokio::test]
    async fn row_03_complete_does_not_report_completing_an_expired_entry() {
        let (table, key) = held_until_t(4).await;
        assert!(!table.complete(&key, T + 1).await);
    }

    #[tokio::test]
    async fn row_04_a_live_entry_survives_every_reader() {
        // Negative control: the reclaim must not eat live records. A count of 1
        // could be the wrong record, so all three readers name the same key.
        let (table, key) = held_until_t(4).await;
        assert_eq!(table.len(T - 1).await, 1);
        assert_eq!(table.route(&key, T - 1).await, Routing::Here);
        assert!(table.complete(&key, T - 1).await);
    }

    #[tokio::test]
    async fn row_04a_an_entry_is_live_at_its_own_deadline() {
        // The boundary, and the only `now` at which `<` and `<=` differ: .01 and
        // .04 pass under either. `Keyring::open` accepts at equality, so a table
        // reclaiming here would drop a record the envelope still opens.
        let (table, key) = held_until_t(4).await;
        assert_eq!(table.len(T).await, 1);
        assert_eq!(table.route(&key, T).await, Routing::Here);
        assert!(table.complete(&key, T).await);
    }

    #[tokio::test]
    async fn row_07_a_now_that_never_moves_never_expires_an_entry() {
        // The contract's limit, stated: reclamation is driven by the supplied
        // `now`, so repeated reads at the same `now` are idempotent.
        let (table, key) = held_until_t(4).await;
        assert_eq!(table.route(&key, T - 1).await, Routing::Here);
        assert_eq!(table.route(&key, T - 1).await, Routing::Here);
    }

    // --- C2: an abandoned hold leaves without anyone scheduling a reclaimer. ---

    #[tokio::test]
    async fn row_05_the_first_call_through_any_reader_reclaims() {
        // Nothing completes the exchange and no reaper exists. Each reader gets
        // its own fresh fixture, so C2 is not as strong as whichever single
        // method an implementer happened to wire.

        // `len`
        let (table, _key) = held_until_t(4).await;
        assert_eq!(table.len(T + 1).await, 0, "len");

        // `route`
        let (table, key) = held_until_t(4).await;
        assert_eq!(table.route(&key, T + 1).await, Routing::Gone, "route");

        // `complete`
        let (table, key) = held_until_t(4).await;
        assert!(!table.complete(&key, T + 1).await, "complete");

        // `hold` — observed through its own admission at a capacity of one: the
        // slot can only be free if that same call reclaimed the expired entry.
        let (table, _key) = held_until_t(1).await;
        assert!(table.hold("backend", T + 2, T + 1).await.is_some(), "hold");
    }

    #[tokio::test]
    async fn row_06_an_expired_entry_stays_resident_until_the_first_reader() {
        // R2a's bargain, stated as a test: reclamation is lazy, so the record is
        // still in the map after its deadline passes and before anyone asks.
        // Inspected directly rather than through a public reader, because every
        // public reader is the event whose absence is the assertion.
        let (table, _key) = held_until_t(4).await;
        assert_eq!(
            table.held.lock().await.len(),
            1,
            "resident before any reader"
        );
        assert_eq!(table.len(T + 1).await, 0, "gone at the first reader");
    }

    #[tokio::test]
    async fn row_08_hold_at_capacity_admits_when_the_occupants_are_expired() {
        // Transferred from NFR.PERF.3. `hold` keeps only its refusal, so the
        // reclaim must have happened in `guard` before the check reads `len`.
        let table = InFlight::new("gw-1", 4);
        for _ in 0..4 {
            assert!(table.hold("backend", T, T).await.is_some());
        }
        assert!(table.hold("backend", T + 2, T + 1).await.is_some());
    }

    #[tokio::test]
    async fn row_08_capacity_is_the_documented_bound() {
        // The design's cost number, pinned. A test cannot see a walk length.
        assert_eq!(IN_FLIGHT_CAPACITY, 4_096);
    }

    #[tokio::test]
    async fn row_09_hold_at_capacity_still_refuses_when_the_occupants_are_live() {
        // The pair to .08: without it, .08 passes trivially if the capacity
        // refusal is deleted rather than re-ordered.
        let table = InFlight::new("gw-1", 4);
        for _ in 0..4 {
            assert!(table.hold("backend", T, T).await.is_some());
        }
        assert!(table.hold("backend", T, T).await.is_none());
    }
}

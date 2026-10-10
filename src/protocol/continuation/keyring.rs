// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! The AEAD keyring that seals and opens continuation envelopes.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use ring::aead::{AES_256_GCM, Aad, LessSafeKey, Nonce, UnboundKey};
use ring::rand::{SecureRandom as _, SystemRandom};

use super::{
    CONTINUATION_LIFETIME_SECS, CONTINUATION_ROTATION_SECS, ContinuationError, MAX_ENVELOPE_LEN,
    NONCE_LEN, Payload, VERSION,
};

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
pub(super) struct RingKey {
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
pub(super) struct Ring {
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
pub(super) const MINT_BUDGET: u64 = 1 << 32;

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

    /// Whether a key with `kid` is held, minting or retained: the probe's
    /// framing gate (MIK-8323) opens only what could be ours.
    pub(crate) fn holds_kid(&self, kid: u8) -> bool {
        self.read_ring().keys.iter().any(|held| held.kid == kid)
    }

    /// [`Self::open`] at now: a clock that reads before 1970 refuses as
    /// [`ContinuationError::Expired`] (MIK-8202).
    pub(crate) fn open_now(&self, token: &str) -> Result<Payload, ContinuationError> {
        self.open(token, super::clock_now()?)
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

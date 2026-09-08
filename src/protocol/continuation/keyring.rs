// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: MIT
//! Age-driven continuation key rotation and bounded per-key sealing quota.

use super::{
    CONTINUATION_LIFETIME_SECS, CONTINUATION_ROTATION_SECS, ContinuationError, MAX_ENVELOPE_LEN,
    NONCE_LEN, Payload, VERSION,
};
#[cfg(test)]
use super::{ContinuationState, Routing};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use ring::aead::{AES_256_GCM, Aad, LessSafeKey, Nonce, UnboundKey};
use ring::rand::{SecureRandom as _, SystemRandom};

/// The keys a gateway mints and verifies continuations with.
///
/// One key mints; several may verify. A verification key is retained for at
/// least the maximum continuation lifetime after it stops minting — without
/// that, rotating a key breaks every elicitation in flight, and a redeploy
/// looks exactly like an attack.
pub struct Keyring {
    state: parking_lot::RwLock<RingState>,
    rng: SystemRandom,
    mint_budget: u64,
    #[cfg(test)]
    test_hooks: parking_lot::Mutex<KeyringTestHooks>,
}

struct SealingKey {
    cipher: LessSafeKey,
    minted: std::sync::atomic::AtomicU64,
}

impl SealingKey {
    fn new(material: &[u8; 32]) -> Result<Self, ContinuationError> {
        let key =
            UnboundKey::new(&AES_256_GCM, material).map_err(|_| ContinuationError::Malformed)?;
        Ok(Self {
            cipher: LessSafeKey::new(key),
            minted: std::sync::atomic::AtomicU64::new(0),
        })
    }

    fn reserve(&self, mut used: u64, budget: u64) -> Result<(), ContinuationError> {
        use std::sync::atomic::Ordering::Relaxed;
        loop {
            if used >= budget {
                return Err(ContinuationError::MintBudgetExhausted);
            }
            // The budget is at most 2^32. A refusal never increments, so neither
            // overflow nor a later store can restore another minter's capacity.
            match self
                .minted
                .compare_exchange_weak(used, used + 1, Relaxed, Relaxed)
            {
                Ok(_) => return Ok(()),
                Err(observed) => used = observed,
            }
        }
    }
}

#[derive(Clone)]
struct KeyEntry {
    kid: u8,
    key: std::sync::Arc<SealingKey>,
    created_at: Option<u64>,
    retired_at: Option<u64>,
}

#[derive(Clone)]
struct RingState {
    minting_kid: u8,
    keys: Vec<KeyEntry>,
}

impl RingState {
    fn key(&self, kid: u8) -> Result<&KeyEntry, ContinuationError> {
        self.keys
            .iter()
            .find(|entry| entry.kid == kid)
            .ok_or(ContinuationError::UnknownKey(kid))
    }

    fn needs_write(&self, now: u64) -> Result<bool, ContinuationError> {
        Ok(self
            .key(self.minting_kid)?
            .created_at
            .is_none_or(|created| now.saturating_sub(created) >= CONTINUATION_ROTATION_SECS))
    }

    fn valid_stamped_state(&self) -> bool {
        let mut seen = [false; 256];
        let mut has_minting_key = false;
        for entry in &self.keys {
            if std::mem::replace(&mut seen[usize::from(entry.kid)], true) {
                return false;
            }
            if entry.kid == self.minting_kid {
                if entry.created_at.is_none() || entry.retired_at.is_some() {
                    return false;
                }
                has_minting_key = true;
            } else if entry.retired_at.is_none() {
                return false;
            }
        }
        has_minting_key
    }
}

/// Test-only observation/fault boundaries. Production builds contain no hooks.
/// Tests enter public mint; hooks observe its actual transition/reservation or
/// inject successor preparation failures before the single publication point.
#[cfg(test)]
type SuccessorFactory =
    std::sync::Arc<dyn Fn() -> Result<[u8; 32], ContinuationError> + Send + Sync>;

#[cfg(test)]
#[derive(Clone, Default)]
struct KeyringTestHooks {
    successor: Option<SuccessorFactory>,
    before_publish: Option<std::sync::Arc<dyn Fn() + Send + Sync>>,
    due_checked: Option<std::sync::Arc<dyn Fn() + Send + Sync>>,
    quota_observed: Option<std::sync::Arc<dyn Fn(u64) + Send + Sync>>,
    write_requested: Option<std::sync::Arc<dyn Fn() + Send + Sync>>,
}

#[expect(
    clippy::missing_fields_in_debug,
    reason = "the omitted field is the key material, and the omission is the point: a Debug that prints keys puts them in every log that ever formats a Keyring"
)]
impl std::fmt::Debug for Keyring {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never the key material, not even in a debug log.
        let state = self.state.read();
        f.debug_struct("Keyring")
            .field("minting_kid", &state.minting_kid)
            .field("verification_keys", &state.keys.len())
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
/// The counter belongs to one key object in one keyring. Production generates
/// independent process keys and replaces them with fresh material on age-driven
/// rotation. Reusing raw material through the library constructor in another
/// keyring, replica or restarted process creates another counter; callers that
/// do that must account for the material's total use across those instances.
/// Rotation does not create a durable/shared quota or replay ledger.
const MINT_BUDGET: u64 = 1 << 32;

impl Keyring {
    /// Drive the real successor failure path from the actual-builder tests.
    #[cfg(test)]
    pub(crate) fn set_successor_failure_for_test(
        &self,
        calls: Option<std::sync::Arc<std::sync::atomic::AtomicUsize>>,
    ) {
        self.test_hooks.lock().successor = calls.map(|calls| {
            std::sync::Arc::new(move || {
                calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                Err(ContinuationError::Malformed)
            }) as SuccessorFactory
        });
    }

    /// Build a keyring from raw 32-byte keys, the first of which mints.
    ///
    /// # Errors
    ///
    /// Returns `Malformed` if the list is empty or two keys share an id.
    /// A duplicated id is refused rather than tolerated
    /// because lookup takes the first match: the second key would silently
    /// never verify, and the failure would surface only on envelopes minted
    /// before the deploy that introduced it.
    pub fn new(keys: &[(u8, [u8; 32])]) -> Result<Self, ContinuationError> {
        let Some((minting_kid, _)) = keys.first() else {
            return Err(ContinuationError::Malformed);
        };
        let mut entries: Vec<KeyEntry> = Vec::with_capacity(keys.len());
        for (kid, material) in keys {
            if entries.iter().any(|entry| entry.kid == *kid) {
                return Err(ContinuationError::Malformed);
            }
            entries.push(KeyEntry {
                kid: *kid,
                key: std::sync::Arc::new(SealingKey::new(material)?),
                created_at: None,
                retired_at: None,
            });
        }
        Ok(Self {
            state: parking_lot::RwLock::new(RingState {
                minting_kid: *minting_kid,
                keys: entries,
            }),
            rng: SystemRandom::new(),
            mint_budget: MINT_BUDGET,
            #[cfg(test)]
            test_hooks: parking_lot::Mutex::new(KeyringTestHooks::default()),
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
        let state = self.state.read();
        state.key(state.minting_kid).map_or(0, |entry| {
            self.mint_budget
                .saturating_sub(entry.key.minted.load(std::sync::atomic::Ordering::Relaxed))
        })
    }

    /// Seal a payload into an envelope for the client to echo back.
    ///
    /// The trusted `issued_at` stamps the initial key on first use. A mint at
    /// least 60 seconds later prepares one successor, retaining verification
    /// material through the maximum lifetime after retirement. Quota exhaustion
    /// does not rotate a key; opening an envelope never changes this state.
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
        let state = self.state.read();
        if state.needs_write(payload.issued_at)? {
            // Never recursively acquire read or write: parking_lot may have a
            // waiting writer. Racing due minters recheck after taking the writer.
            drop(state);
            #[cfg(test)]
            {
                let hooks = self.test_hooks.lock().clone();
                if let Some(hook) = hooks.due_checked {
                    hook();
                }
                if let Some(hook) = hooks.write_requested {
                    hook();
                }
            }
            let mut state = self.state.write();
            self.prepare_mint_state(&mut state, payload.issued_at)?;
            let state = parking_lot::RwLockWriteGuard::downgrade(state);
            self.seal(&state, payload)
        } else {
            self.seal(&state, payload)
        }
    }

    fn successor_material(&self) -> Result<[u8; 32], ContinuationError> {
        #[cfg(test)]
        {
            let factory = self.test_hooks.lock().successor.clone();
            if let Some(factory) = factory {
                return factory();
            }
        }
        let mut material = [0u8; 32];
        self.rng
            .fill(&mut material)
            .map_err(|_| ContinuationError::Malformed)?;
        Ok(material)
    }

    fn prepare_mint_state(&self, state: &mut RingState, now: u64) -> Result<(), ContinuationError> {
        // This second check is under the write guard. Another due minter may
        // already have published the only successor this epoch permits.
        if !state.needs_write(now)? {
            return Ok(());
        }
        let mut candidate = state.clone();
        let mut rotation = None;
        if state.key(state.minting_kid)?.created_at.is_none() {
            for entry in &mut candidate.keys {
                if entry.kid == candidate.minting_kid {
                    entry.created_at = Some(now);
                } else {
                    entry.retired_at = Some(now);
                }
            }
        } else {
            candidate.keys.retain(|entry| {
                entry
                    .retired_at
                    .is_none_or(|retired| now <= retired.saturating_add(CONTINUATION_LIFETIME_SECS))
            });
            let successor = state.minting_kid.wrapping_add(1);
            if candidate.keys.iter().any(|entry| entry.kid == successor) {
                tracing::warn!(
                    minting_kid = state.minting_kid,
                    successor_kid = successor,
                    retained_keys = state.keys.len(),
                    "Continuation key rotation blocked: successor is retained"
                );
                return Ok(());
            }
            let material = self.successor_material()?;
            let next_key = std::sync::Arc::new(SealingKey::new(&material)?);
            candidate
                .keys
                .iter_mut()
                .find(|entry| entry.kid == state.minting_kid)
                .ok_or(ContinuationError::Malformed)?
                .retired_at = Some(now);
            candidate.keys.push(KeyEntry {
                kid: successor,
                key: next_key,
                created_at: Some(now),
                retired_at: None,
            });
            candidate.minting_kid = successor;
            rotation = Some((state.minting_kid, successor));
        }
        if !candidate.valid_stamped_state() {
            tracing::error!(
                minting_kid = candidate.minting_kid,
                retained_keys = candidate.keys.len(),
                "Continuation key ring invariant failed"
            );
            return Err(ContinuationError::Malformed);
        }
        #[cfg(test)]
        {
            let before_publish = self.test_hooks.lock().before_publish.clone();
            if let Some(before_publish) = before_publish {
                before_publish();
            }
        }
        // All metadata, retention, new material and invariants are prepared.
        // Clones share only immutable cipher objects and their existing atomic
        // quota. One assignment publishes a coherent ring even on panic paths.
        *state = candidate;
        if let Some((old_kid, new_kid)) = rotation {
            tracing::info!(
                old_kid,
                new_kid,
                retained_keys = state.keys.len(),
                "Continuation key rotated"
            );
        }
        Ok(())
    }

    fn seal(&self, state: &RingState, payload: &Payload) -> Result<String, ContinuationError> {
        let key = &state.key(state.minting_kid)?.key;
        let used = key.minted.load(std::sync::atomic::Ordering::Relaxed);
        #[cfg(test)]
        {
            let observed = self.test_hooks.lock().quota_observed.clone();
            if let Some(observed) = observed {
                observed(used);
            }
        }
        // The same observed value enters the CAS loop after any test rendezvous.
        key.reserve(used, self.mint_budget)?;
        let mut nonce_bytes = [0u8; NONCE_LEN];
        self.rng
            .fill(&mut nonce_bytes)
            .map_err(|_| ContinuationError::Malformed)?;

        let mut buffer = serde_json::to_vec(payload).map_err(|_| ContinuationError::Malformed)?;
        let header = [VERSION, state.minting_kid];
        key.cipher
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
        let state = self.state.read();
        let key = &state.key(kid)?.key;

        let mut nonce_bytes = [0u8; NONCE_LEN];
        nonce_bytes.copy_from_slice(&wire[2..2 + NONCE_LEN]);
        let mut buffer = wire[2 + NONCE_LEN..].to_vec();

        let plaintext = key
            .cipher
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

#[cfg(test)]
#[path = "../continuation_rotation_tests.rs"]
mod key_rotation;

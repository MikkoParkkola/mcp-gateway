// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The passthrough token lease: a
//! subscriber's own backend token, held in memory only so that subscriber's
//! event listener can run. Never serialized, cloned, logged or written; wiped
//! with `zeroize` on every wipe trigger and on drop. A lease is refused unless
//! the core-dump guard is applied (E8).

use std::collections::HashMap;
use std::sync::Arc;

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use tokio::sync::{Mutex, RwLock};
use tokio_util::sync::CancellationToken;
use zeroize::Zeroizing;

use crate::clock::{JwtClaimTime, Validity, jwt_window};
use crate::security::dump_guard::{self, DumpGuard};
use crate::transport::upstream_tap::CredentialedSend;

/// Bounds custody of a long-lived token whatever its `exp` says (C3). A code
/// constant on purpose: holding a user's token longer is not an operator knob.
pub(crate) const MAX_LEASE_TTL_SECS: u64 = 12 * 60 * 60;

/// The least life a new lease must have left: two of the listener's revive
/// sweeps (30 s each), so a lease can start a listener before it lapses (L2).
pub(crate) const MIN_LEASE_REMAINING_SECS: u64 = 60;

/// Clock skew allowed when judging `exp` (D6).
const EXP_LEEWAY_SECS: u64 = 0;

/// Which lease: one per backend and observation key (L1).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct LeaseKey {
    pub backend: String,
    pub obs: String,
}

/// Why a lease was refused; each maps to a -32014 detail.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LeaseRefusal {
    /// The core-dump guard is not applied; the value is its refusal detail.
    CoreDumpGuard(&'static str),
    /// Not a JWT with a numeric `exp` (L2, D6).
    NoExpiry,
    /// `exp` has passed, or leaves less than the caller's minimum.
    Expired,
}

impl LeaseRefusal {
    /// The `-32014` reason and its `data.detail`, if any.
    pub(crate) fn reason(self) -> (&'static str, Option<&'static str>) {
        match self {
            Self::CoreDumpGuard(detail) => ("core_dump_guard_unavailable", Some(detail)),
            Self::NoExpiry => ("passthrough_token_no_expiry", None),
            Self::Expired => ("passthrough_token_expired", None),
        }
    }
}

/// Why a lease was wiped (L4); the rows' visible state follows from it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum WipeReason {
    /// Last row gone, expiry, config change or principal revoked: rows wait in
    /// "credential needed".
    Released,
    /// The backend refused the token (C5): "credential rejected".
    Rejected,
}

/// The `exp` claim of a bearer token, decoded without verifying the signature
/// (the backend verifies it). Anything that is not a JWT with a payload object
/// reads as `Absent`.
pub(crate) fn token_exp(token: &str) -> JwtClaimTime {
    let token = token.strip_prefix("Bearer ").unwrap_or(token);
    let mut parts = token.split('.');
    let (Some(_), Some(payload), Some(_), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return JwtClaimTime::Absent;
    };
    let Ok(bytes) = URL_SAFE_NO_PAD.decode(payload.trim_end_matches('=')) else {
        return JwtClaimTime::Absent;
    };
    let Ok(serde_json::Value::Object(claims)) = serde_json::from_slice(&bytes) else {
        return JwtClaimTime::Absent;
    };
    match claims.get("exp") {
        None => JwtClaimTime::Absent,
        Some(exp) => exp
            .as_u64()
            .map_or(JwtClaimTime::Malformed, JwtClaimTime::At),
    }
}

/// One held lease. The token sits behind a lock that every listener send
/// holds for reading (C4); a wipe cancels the generation first, so those sends
/// end and the write lock can be taken to zeroize (D1).
struct Held {
    generation: u128,
    cancel: CancellationToken,
    token: Arc<RwLock<Option<Zeroizing<String>>>>,
    expires_at: u64,
}

/// What admin and UI may see of a lease (L5): never the token or a digest.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LeaseState {
    Active { expires_at: u64 },
    CredentialNeeded,
    CredentialRejected,
}

/// Every held passthrough lease. Not `Clone`, not `Serialize`, and its
/// `Debug` prints nothing of the leases.
pub(crate) struct LeaseStore {
    held: Mutex<HashMap<LeaseKey, Held>>,
    /// Keys whose lease was wiped, with the state their rows show.
    parked: std::sync::Mutex<HashMap<LeaseKey, LeaseState>>,
    /// Each held key's current generation, readable without awaiting: the
    /// listener map asks under its own lock (E7), and a delivery's last check
    /// before its send (A2) has no await between it and the POST.
    /// With its deadline: past it the generation no longer reads as held,
    /// before any sweep runs.
    live: std::sync::Mutex<HashMap<LeaseKey, (u128, u64)>>,
    guard: fn() -> DumpGuard,
}

impl std::fmt::Debug for LeaseStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LeaseStore").finish_non_exhaustive()
    }
}

impl Default for LeaseStore {
    fn default() -> Self {
        Self::with_guard(dump_guard::ensure)
    }
}

impl LeaseStore {
    /// The events hub's store: the real guard, applied once per process.
    #[cfg(not(test))]
    pub(crate) fn for_hub() -> Self {
        Self::default()
    }

    /// A test hub's store: its guard reads applied, so a hub test never
    /// lowers the test process's own limits; LEASE-T10/T11 pin the real one.
    #[cfg(test)]
    pub(crate) fn for_hub() -> Self {
        Self::with_guard(|| DumpGuard::Applied)
    }

    /// A store whose core-dump guard is `guard`; tests inject each outcome.
    pub(crate) fn with_guard(guard: fn() -> DumpGuard) -> Self {
        Self {
            held: Mutex::new(HashMap::new()),
            parked: std::sync::Mutex::new(HashMap::new()),
            live: std::sync::Mutex::new(HashMap::new()),
            guard,
        }
    }

    /// Create or replace the lease for `key` (C1-C3). `authorization` is the
    /// header value the backend expects; the lease lives until the earliest of
    /// its `exp`, `subscription_expires_at` and [`MAX_LEASE_TTL_SECS`], and is
    /// refused if that leaves less than `min_remaining_secs`. A replace
    /// retires the old generation first, drains and wipes the old lease, and
    /// only then installs the new one and returns its generation.
    ///
    /// # Errors
    /// The guard is not applied, the token has no usable `exp`, or it expires
    /// too soon.
    pub(crate) async fn install(
        &self,
        key: LeaseKey,
        authorization: Zeroizing<String>,
        subscription_expires_at: u64,
        min_remaining_secs: u64,
    ) -> Result<u128, LeaseRefusal> {
        if let Some(detail) = (self.guard)().refusal_detail() {
            return Err(LeaseRefusal::CoreDumpGuard(detail));
        }
        let JwtClaimTime::At(exp) = token_exp(&authorization) else {
            return Err(LeaseRefusal::NoExpiry);
        };
        if jwt_window(JwtClaimTime::At(exp), JwtClaimTime::Absent, EXP_LEEWAY_SECS)
            == Validity::Expired
        {
            return Err(LeaseRefusal::Expired);
        }
        let now = crate::clock::unix_secs().map_err(|_| LeaseRefusal::Expired)?;
        let expires_at = exp
            .min(subscription_expires_at)
            .min(now.saturating_add(MAX_LEASE_TTL_SECS));
        if expires_at < now.saturating_add(min_remaining_secs) {
            return Err(LeaseRefusal::Expired);
        }
        let generation = uuid::Uuid::new_v4().as_u128();
        let mut held = self.held.lock().await;
        if let Some(old) = held.remove(&key) {
            // Bump first (§3.5): from here a record observed under the old
            // generation fails delivery's check, so no new handoff begins
            // for it while the old lease's sends drain. The new lease goes
            // in only after the drain, so a call dropped meanwhile leaves
            // none behind.
            self.set_live(&key, None);
            wipe(old).await;
        }
        let cancel = CancellationToken::new();
        let token = Arc::new(RwLock::new(Some(authorization)));
        tokio::spawn(zeroize_at(
            cancel.clone(),
            Arc::clone(&token),
            expires_at.saturating_sub(now),
        ));
        held.insert(
            key.clone(),
            Held {
                generation,
                cancel,
                token,
                expires_at,
            },
        );
        self.set_live(&key, Some((generation, expires_at)));
        self.park(&key, None);
        Ok(generation)
    }

    /// Wipe the lease for `key` (L4); its rows then show `reason`'s state.
    pub(crate) async fn wipe(&self, key: &LeaseKey, reason: WipeReason) {
        let mut held = self.held.lock().await;
        if let Some(old) = held.remove(key) {
            // Retired before the drain, as a replace does (§3.5).
            self.park(key, Some(reason));
            wipe(old).await;
        }
    }

    /// Wipe every lease past its deadline. The token itself was zeroized at
    /// the deadline by its timer; this drops the entry and parks its rows.
    pub(crate) async fn wipe_expired(&self, now: u64) {
        let mut held = self.held.lock().await;
        let expired: Vec<LeaseKey> = held
            .iter()
            .filter(|(_, h)| now >= h.expires_at)
            .map(|(k, _)| k.clone())
            .collect();
        for key in expired {
            if let Some(old) = held.remove(&key) {
                self.park(&key, Some(WipeReason::Released));
                wipe(old).await;
            }
        }
    }

    /// A rejection seen by a send of `generation` (C5): wipes only if that
    /// generation is still current, so a stale response cannot wipe a newer
    /// lease (E5).
    pub(crate) async fn on_rejection(&self, key: &LeaseKey, generation: u128) {
        self.wipe_generation(key, generation, WipeReason::Rejected)
            .await;
    }

    /// The current generation for `key`, if a lease is held.
    #[cfg(test)]
    pub(crate) async fn generation(&self, key: &LeaseKey) -> Option<u128> {
        self.held.lock().await.get(key).map(|h| h.generation)
    }

    /// What the rows of `key` show (L5). A key never leased needs one.
    pub(crate) async fn state(&self, key: &LeaseKey) -> LeaseState {
        if let Some(h) = self.held.lock().await.get(key) {
            return LeaseState::Active {
                expires_at: h.expires_at,
            };
        }
        let parked = self
            .parked
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        parked
            .get(key)
            .copied()
            .unwrap_or(LeaseState::CredentialNeeded)
    }

    /// Run `send` with the lease's `Authorization` header, if `generation` is
    /// still current and unexpired (C4, D2). The send holds the token's read
    /// guard throughout and is cancelled when the generation is wiped; an
    /// expired lease is wiped here and the send never runs.
    ///
    /// # Errors
    /// No current lease of that generation, or it was wiped during the send.
    pub(crate) async fn with_credential(
        &self,
        key: &LeaseKey,
        generation: u128,
        send: CredentialedSend<'_>,
    ) -> crate::Result<reqwest::Response> {
        let (token, cancel, expires_at) = {
            let held = self.held.lock().await;
            match held.get(key) {
                Some(h) if h.generation == generation => {
                    (Arc::clone(&h.token), h.cancel.clone(), h.expires_at)
                }
                _ => return Err(withdrawn()),
            }
        };
        if crate::clock::unix_secs().map_or(true, |now| now >= expires_at) {
            self.wipe_generation(key, generation, WipeReason::Released)
                .await;
            return Err(withdrawn());
        }
        let guard = token.read().await;
        let Some(value) = guard.as_ref() else {
            return Err(withdrawn());
        };
        let headers = vec![("Authorization".to_string(), value.to_string())];
        cancel
            .run_until_cancelled(send(headers))
            .await
            .unwrap_or_else(|| Err(withdrawn()))
    }

    pub(super) async fn wipe_generation(
        &self,
        key: &LeaseKey,
        generation: u128,
        reason: WipeReason,
    ) {
        let mut held = self.held.lock().await;
        if held.get(key).is_some_and(|h| h.generation == generation) {
            self.park(key, Some(reason));
            if let Some(old) = held.remove(key) {
                wipe(old).await;
            }
        }
    }

    /// Whether `key` holds a lease now.
    pub(crate) fn is_held(&self, key: &LeaseKey) -> bool {
        self.held_generation(key).is_some()
    }

    /// The generation `key` holds now, without awaiting. A lease past its
    /// deadline, or judged on a clock that cannot be read, holds none: its
    /// token is already zeroized, so delivery and its listener stop at once,
    /// not at the next expiry sweep.
    pub(crate) fn held_generation(&self, key: &LeaseKey) -> Option<u128> {
        let (generation, expires_at) = self
            .live
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(key)
            .copied()?;
        crate::clock::unix_secs()
            .is_ok_and(|now| now < expires_at)
            .then_some(generation)
    }

    fn set_live(&self, key: &LeaseKey, generation: Option<(u128, u64)>) {
        let mut live = self
            .live
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        match generation {
            Some(generation) => live.insert(key.clone(), generation),
            None => live.remove(key),
        };
    }

    fn park(&self, key: &LeaseKey, reason: Option<WipeReason>) {
        if reason.is_some() {
            self.set_live(key, None);
        }
        let mut parked = self
            .parked
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        match reason {
            None => {
                parked.remove(key);
            }
            Some(WipeReason::Released) => {
                parked.insert(key.clone(), LeaseState::CredentialNeeded);
            }
            Some(WipeReason::Rejected) => {
                parked.insert(key.clone(), LeaseState::CredentialRejected);
            }
        }
    }
}

/// D1's order: cancel the generation, wait for its sends to drop their read
/// guards, then take the write lock and drop the token, which `Zeroizing`
/// wipes.
/// Zeroize `token` after `after_secs` even if no send asks for it: custody
/// ends at the deadline, not at the next use. Cancelling sends first keeps
/// the wipe order (cancel, drain, zeroize); a wipe before the deadline
/// cancels `cancel` and ends this timer.
async fn zeroize_at(
    cancel: CancellationToken,
    token: Arc<RwLock<Option<Zeroizing<String>>>>,
    after_secs: u64,
) {
    tokio::select! {
        () = cancel.cancelled() => {}
        () = tokio::time::sleep(std::time::Duration::from_secs(after_secs)) => {
            cancel.cancel();
            *token.write().await = None;
        }
    }
}

async fn wipe(old: Held) {
    old.cancel.cancel();
    let mut token = old.token.write().await;
    *token = None;
}

/// The error a send gets when its lease is gone: a category only, never the
/// token (C9).
fn withdrawn() -> crate::Error {
    crate::Error::Transport("listener credential withdrawn".to_string())
}

#[cfg(test)]
impl super::EventsHub {
    /// How many keys hold a lease in this hub's store (LEASE-T0).
    pub(crate) async fn held_leases(&self) -> usize {
        self.leases.held.lock().await.len()
    }
}

#[cfg(test)]
#[path = "lease_tests.rs"]
mod tests;

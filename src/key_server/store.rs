// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! Token store — persistence layer for issued temporary tokens.
//!
//! The [`TokenStore`] trait abstracts over storage backends. The only current
//! implementation is [`InMemoryTokenStore`], backed by a `DashMap` with a
//! background reaper that evicts expired tokens every 60 seconds.
//!
//! # Design
//!
//! Tokens are indexed by their **opaque bearer value** (the string clients
//! send in the `Authorization: Bearer` header) for O(1) validation, *and* by
//! their **JTI** for O(1) revocation.

use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;
#[cfg(test)]
use std::time::{SystemTime, UNIX_EPOCH};

use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use tracing::debug;

use super::oidc::VerifiedIdentity;

/// A temporary gateway token issued after OIDC verification.
///
/// Never read back from bytes, and never written out: the bearer it holds is
/// a live credential, and the identity it carries is written to audit
/// records only in its keyed hash form.
///
/// ```compile_fail,E0277
/// fn read(bytes: &str) -> mcp_gateway::key_server::TemporaryToken {
///     serde_json::from_str(bytes).expect("a token")
/// }
/// ```
///
/// nor written out:
///
/// ```compile_fail,E0277
/// fn write(token: &mcp_gateway::key_server::TemporaryToken) -> String {
///     serde_json::to_string(token).expect("a token")
/// }
/// ```
///
/// Reading its fields compiles:
///
/// ```
/// fn jti(token: &mcp_gateway::key_server::TemporaryToken) -> &str {
///     &token.jti
/// }
/// ```
#[derive(Clone)]
pub struct TemporaryToken {
    /// Unique token identifier (used for revocation).
    pub jti: String,
    /// The opaque bearer token value (`mcpgw_<base64>`).
    pub token: String,
    /// Verified identity that requested this token.
    pub identity: VerifiedIdentity,
    /// Allowed scopes for this token.
    pub scopes: TokenScopes,
    /// Issued-at (Unix epoch seconds).
    pub iat: u64,
    /// Expires-at (Unix epoch seconds).
    pub exp: u64,
    /// Client IP at issuance (for audit).
    pub client_ip: Option<IpAddr>,
}

// Manual `Debug` redacts the opaque bearer value (CWE-532, mirrors MIK-6733).
// A derived `Debug` would print a live, usable session credential into logs;
// the `jti` is shown instead for correlation/revocation.
impl std::fmt::Debug for TemporaryToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TemporaryToken")
            .field("jti", &self.jti)
            .field("token", &"<redacted>")
            .field("identity", &self.identity)
            .field("scopes", &self.scopes)
            .field("iat", &self.iat)
            .field("exp", &self.exp)
            .field("client_ip", &self.client_ip)
            .finish()
    }
}

impl TemporaryToken {
    /// Returns `true` if the token has passed its expiry time at `now`
    /// (seconds since the Unix epoch). The caller reads the clock, once, and
    /// refuses on one it cannot read (MIK-8202).
    #[must_use]
    pub fn is_expired(&self, now: u64) -> bool {
        now >= self.exp
    }

    /// Past its expiry on a clock that reads: what eviction, reaping and the
    /// per-identity count go by. A clock it cannot read ages nothing out, so
    /// nothing is deleted on it (MIK-8202); access still refuses.
    fn aged_out(&self) -> bool {
        crate::clock::unix_secs().is_ok_and(|now| now >= self.exp)
    }
}

/// Scopes granted to a temporary token.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TokenScopes {
    /// Allowed backends. `["*"]` means all; an empty slice means none.
    pub backends: Vec<String>,
    /// Allowed tools. Empty slice means "all tools on allowed backends".
    pub tools: Vec<String>,
    /// Per-identity rate limit (requests per minute; 0 = unlimited).
    pub rate_limit: u32,
}

/// What a mint asks to reserve: one slot under the identity's cap, for the
/// token with this JTI. The store sets the pending deadline itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReservationRequest {
    /// The identity's issuer.
    pub issuer: String,
    /// The identity's subject.
    pub subject: String,
    /// The JTI the token will carry.
    pub jti: String,
}

/// An opaque, unique claim on one pending slot. Not `Clone`: exactly one
/// owner can activate or abort it.
#[derive(Debug, PartialEq, Eq, Hash)]
pub struct ReservationId(u64);

impl ReservationId {
    /// A fresh id, unique across every store in the process: no two
    /// reservations, in this store or another, ever share one, and an id
    /// cannot be rebuilt from a number.
    #[must_use]
    pub fn new() -> Self {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        Self(NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed))
    }

    /// The id's number, for a store implementation to key its pending map.
    #[must_use]
    pub fn raw(&self) -> u64 {
        self.0
    }
}

impl Default for ReservationId {
    fn default() -> Self {
        Self::new()
    }
}

/// Why a reservation was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReserveError {
    /// Active plus pending tokens already fill the identity's cap.
    CapReached,
    /// A token or reservation already holds this JTI.
    DuplicateJti,
    /// The pending deadline overflowed.
    Clock,
}

/// Why an activation was refused. The pending slot is released either way.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActivateError {
    /// No pending reservation holds this id: never issued, already
    /// activated, or aborted.
    Missing,
    /// The reservation was revoked (by JTI or by identity) before activation.
    Revoked,
    /// The reservation's deadline passed before activation.
    Expired,
    /// The token's issuer, subject or JTI differs from the reservation's.
    Mismatch,
    /// The token's `iat` is not `now` or its `exp` is not `now` + the store's
    /// frozen TTL.
    Timestamps,
}

/// Trait abstracting the token storage backend.
///
/// Implementations must be `Send + Sync` because the token store is shared
/// across async tasks. A token becomes active only through
/// [`reserve`](Self::reserve) then [`activate`](Self::activate): there is no
/// way to insert one past the identity's cap.
///
/// There is no `insert`:
///
/// ```compile_fail,E0599
/// fn seed(
///     store: &dyn mcp_gateway::key_server::TokenStore,
///     token: mcp_gateway::key_server::TemporaryToken,
///     request: mcp_gateway::key_server::store::ReservationRequest,
/// ) {
///     let _ = (request, store.insert(token));
/// }
/// ```
///
/// The same function with `reserve` in place of `insert` compiles, so the
/// block above fails only for the missing method (stable rustdoc does not
/// check the error code):
///
/// ```
/// fn seed(
///     store: &dyn mcp_gateway::key_server::TokenStore,
///     token: mcp_gateway::key_server::TemporaryToken,
///     request: mcp_gateway::key_server::store::ReservationRequest,
/// ) {
///     let _ = (token, store.reserve(request, 0));
/// }
/// ```
#[async_trait::async_trait]
pub trait TokenStore: Send + Sync + 'static {
    /// Reserve one slot for `request` at `now` (seconds since the epoch) if
    /// the identity's live active plus pending tokens are under the store's
    /// frozen cap. Expired pending slots are reaped first. A pending slot is
    /// invisible to bearer lookup and JTI liveness.
    ///
    /// # Errors
    ///
    /// [`ReserveError`] naming why no slot was reserved.
    fn reserve(&self, request: ReservationRequest, now: u64)
    -> Result<ReservationId, ReserveError>;

    /// Turn the reservation `id` into the active `token`, at `now`: the
    /// identity and JTI must match the reservation, its deadline must not
    /// have passed, and the token must run from `now` for the store's frozen
    /// TTL. On any refusal the pending slot is released.
    ///
    /// # Errors
    ///
    /// [`ActivateError`] naming why the token was not activated.
    fn activate(
        &self,
        id: &ReservationId,
        token: TemporaryToken,
        now: u64,
    ) -> Result<(), ActivateError>;

    /// Release the pending slot `id`, if it is still pending. Idempotent.
    fn abort(&self, id: &ReservationId);

    /// Look up a token by its opaque bearer value.
    ///
    /// Returns `None` if the token does not exist or is expired/revoked.
    async fn get(&self, bearer: &str) -> Option<TemporaryToken>;

    /// Revoke a token by its JTI.
    ///
    /// Returns `true` if the token existed and was removed.
    async fn revoke_by_jti(&self, jti: &str) -> bool;

    /// Whether the token with this JTI exists, unrevoked and unexpired at
    /// `now` (seconds since the Unix epoch): the MCP Events delivery re-check
    /// (MIK-7769), which never holds the token. Expiry is judged on the
    /// supplied `now`, never on a fresh read of the clock: the caller judges
    /// every credential of one check on one reading (MIK-8202).
    async fn live_jti(&self, jti: &str, now: u64) -> bool;

    /// Revoke all tokens for one OIDC identity, `(issuer, subject)` (e.g., on
    /// offboarding). The same `sub` at another issuer is another identity.
    async fn revoke_by_subject(&self, issuer: &str, subject: &str) -> usize;

    /// Count active (non-expired) tokens for one OIDC identity,
    /// `(issuer, subject)`.
    async fn count_for_subject(&self, issuer: &str, subject: &str) -> usize;

    /// Remove all expired tokens. Called periodically by the background reaper.
    async fn reap_expired(&self) -> usize;
}

/// In-memory token store backed by two `DashMap` indices.
///
/// - `by_bearer`: bearer value → `TemporaryToken`  (O(1) validation)
/// - `by_jti`:    JTI string  → bearer value       (O(1) revocation)
pub struct InMemoryTokenStore {
    by_bearer: DashMap<String, TemporaryToken>,
    by_jti: DashMap<String, String>,
    /// Pending reservations. Every change to the pending slots or to either
    /// active index (reserve, activate, abort, revoke, reap, lazy eviction)
    /// takes this lock first, so active plus pending never passes the cap
    /// and a revoke cannot miss a token activated while it runs. Nothing
    /// awaits while it is held.
    pending: std::sync::Mutex<Pending>,
    /// The per-identity cap, frozen at construction.
    cap: usize,
    /// The token lifetime, frozen at construction.
    ttl: u64,
}

/// How long a reservation may stay pending: the mint's audit append must
/// finish inside it. Separate from the token's lifetime.
pub const PENDING_WINDOW_SECS: u64 = 30;

#[derive(Default)]
struct Pending {
    slots: std::collections::HashMap<u64, Slot>,
    /// Why a slot left before its owner claimed it (revoked, or reaped past
    /// its deadline), so `activate` answers the reason. The owner's
    /// `activate` or `abort` clears the entry.
    gone: std::collections::HashMap<u64, ActivateError>,
}

impl Pending {
    /// Remove the slots `matches` selects, remembering `why`; how many went.
    fn remove_where(&mut self, why: ActivateError, matches: impl Fn(&Slot) -> bool) -> usize {
        let ids: Vec<u64> = self
            .slots
            .iter()
            .filter(|(_, slot)| matches(slot))
            .map(|(id, _)| *id)
            .collect();
        for id in &ids {
            self.slots.remove(id);
            self.gone.insert(*id, why);
        }
        ids.len()
    }
}

struct Slot {
    issuer: String,
    subject: String,
    jti: String,
    deadline: u64,
}

impl InMemoryTokenStore {
    /// An empty store whose per-identity cap and token lifetime are frozen:
    /// no caller can reserve past `cap` or activate a token for longer than
    /// `ttl_secs`. A cap of 0 refuses every reservation.
    #[must_use]
    pub fn new(cap: usize, ttl_secs: u64) -> Self {
        Self {
            by_bearer: DashMap::new(),
            by_jti: DashMap::new(),
            pending: std::sync::Mutex::default(),
            cap,
            ttl: ttl_secs,
        }
    }

    /// An empty store frozen at `config`'s per-identity cap and token
    /// lifetime.
    #[must_use]
    pub(crate) fn for_config(config: &crate::config::KeyServerConfig) -> Self {
        Self::new(
            config.max_tokens_per_identity as usize,
            config.token_ttl_secs,
        )
    }

    fn pending(&self) -> std::sync::MutexGuard<'_, Pending> {
        // A panic while holding the lock leaves plain data behind: keep going.
        self.pending
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Remove the active token `jti` from both indices. The caller holds
    /// the pending lock.
    fn remove_active(&self, jti: &str) -> bool {
        match self.by_jti.remove(jti) {
            Some((_, bearer)) => {
                self.by_bearer.remove(&bearer);
                true
            }
            None => false,
        }
    }

    /// Generate a cryptographically random opaque bearer token.
    ///
    /// Format: `mcpgw_<43-char URL-safe base64>` (256 bits of entropy).
    /// The `mcpgw_` prefix makes tokens greppable and detectable by secret
    /// scanners (e.g., `truffleHog`, GitHub secret scanning).
    #[must_use]
    pub fn generate_bearer() -> String {
        crate::random_secret::random_secret("mcpgw_")
    }

    /// Generate a UUID v4 JTI.
    #[must_use]
    pub fn generate_jti() -> String {
        uuid::Uuid::new_v4().to_string()
    }
}

#[async_trait::async_trait]
impl TokenStore for InMemoryTokenStore {
    fn reserve(
        &self,
        request: ReservationRequest,
        now: u64,
    ) -> Result<ReservationId, ReserveError> {
        let mut pending = self.pending();
        pending.remove_where(ActivateError::Expired, |slot| slot.deadline <= now);
        let same =
            |issuer: &str, subject: &str| issuer == request.issuer && subject == request.subject;
        let active = self
            .by_bearer
            .iter()
            .filter(|e| {
                let id = &e.value().identity;
                same(id.issuer(), id.subject()) && !e.value().is_expired(now)
            })
            .count();
        let reserved = pending
            .slots
            .values()
            .filter(|s| same(&s.issuer, &s.subject))
            .count();
        if active + reserved >= self.cap {
            return Err(ReserveError::CapReached);
        }
        if self.by_jti.contains_key(&request.jti)
            || pending.slots.values().any(|s| s.jti == request.jti)
        {
            return Err(ReserveError::DuplicateJti);
        }
        let deadline = now
            .checked_add(PENDING_WINDOW_SECS)
            .ok_or(ReserveError::Clock)?;
        let id = ReservationId::new();
        pending.slots.insert(
            id.raw(),
            Slot {
                issuer: request.issuer,
                subject: request.subject,
                jti: request.jti,
                deadline,
            },
        );
        Ok(id)
    }

    fn activate(
        &self,
        id: &ReservationId,
        token: TemporaryToken,
        now: u64,
    ) -> Result<(), ActivateError> {
        let mut pending = self.pending();
        let Some(slot) = pending.slots.remove(&id.0) else {
            return Err(pending.gone.remove(&id.0).unwrap_or(ActivateError::Missing));
        };
        if now >= slot.deadline {
            return Err(ActivateError::Expired);
        }
        if token.identity.issuer() != slot.issuer
            || token.identity.subject() != slot.subject
            || token.jti != slot.jti
        {
            return Err(ActivateError::Mismatch);
        }
        if token.iat != now || Some(token.exp) != now.checked_add(self.ttl) {
            return Err(ActivateError::Timestamps);
        }
        let bearer = token.token.clone();
        let jti = token.jti.clone();
        self.by_bearer.insert(bearer.clone(), token);
        self.by_jti.insert(jti, bearer);
        // The lock is held until the token is in both indices.
        drop(pending);
        Ok(())
    }

    fn abort(&self, id: &ReservationId) {
        let mut pending = self.pending();
        pending.slots.remove(&id.0);
        pending.gone.remove(&id.0);
    }

    async fn get(&self, bearer: &str) -> Option<TemporaryToken> {
        let entry = self.by_bearer.get(bearer)?;
        let token = entry.clone();
        drop(entry);

        // A clock it cannot read counts as expired (MIK-8202).
        if !crate::clock::unix_secs().is_ok_and(|now| !token.is_expired(now)) {
            // Lazy eviction: remove on access, once really past its expiry.
            if token.aged_out() {
                {
                    let _pending = self.pending();
                    self.by_bearer.remove(bearer);
                    self.by_jti.remove(&token.jti);
                }
                debug!(jti = %token.jti, "Lazy-evicted expired token");
            }
            return None;
        }

        Some(token)
    }

    async fn live_jti(&self, jti: &str, now: u64) -> bool {
        let Some(bearer) = self.by_jti.get(jti).map(|b| b.value().clone()) else {
            return false;
        };
        self.by_bearer
            .get(&bearer)
            .is_some_and(|token| !token.is_expired(now))
    }

    async fn revoke_by_jti(&self, jti: &str) -> bool {
        // A pending reservation for this JTI is revoked too: it can no
        // longer become a token.
        let mut pending = self.pending();
        let was_pending = pending.remove_where(ActivateError::Revoked, |slot| slot.jti == jti) > 0;
        self.remove_active(jti) || was_pending
    }

    async fn revoke_by_subject(&self, issuer: &str, subject: &str) -> usize {
        let mut pending = self.pending();
        let removed_pending = pending.remove_where(ActivateError::Revoked, |slot| {
            slot.issuer == issuer && slot.subject == subject
        });
        let jtis: Vec<String> = self
            .by_bearer
            .iter()
            .filter(|e| {
                let identity = &e.value().identity;
                identity.issuer() == issuer && identity.subject() == subject
            })
            .map(|e| e.value().jti.clone())
            .collect();
        let removed_active = jtis.iter().filter(|jti| self.remove_active(jti)).count();
        removed_active + removed_pending
    }

    async fn count_for_subject(&self, issuer: &str, subject: &str) -> usize {
        self.by_bearer
            .iter()
            .filter(|e| {
                let identity = &e.value().identity;
                identity.issuer() == issuer
                    && identity.subject() == subject
                    && !e.value().aged_out()
            })
            .count()
    }

    async fn reap_expired(&self) -> usize {
        let pending = self.pending();
        let expired_bearers: Vec<String> = self
            .by_bearer
            .iter()
            .filter(|e| e.value().aged_out())
            .map(|e| e.key().clone())
            .collect();
        let count = expired_bearers.len();
        let reaped: Vec<String> = expired_bearers
            .iter()
            .filter_map(|bearer| self.by_bearer.remove(bearer))
            .map(|(_, token)| {
                self.by_jti.remove(&token.jti);
                token.jti
            })
            .collect();
        drop(pending);
        for jti in reaped {
            debug!(jti = %jti, "Reaped expired token");
        }
        count
    }
}

/// Store `token` through the reservation protocol, dated now for `ttl`
/// seconds (the store's frozen lifetime): the one way test fixtures put a
/// token in a store.
#[cfg(test)]
#[allow(
    clippy::disallowed_methods,
    reason = "test fixtures read the host clock"
)]
pub(crate) fn activate_for_test(store: &dyn TokenStore, ttl: u64, mut token: TemporaryToken) {
    let now = crate::clock::unix_secs().expect("a readable clock");
    // The fixture's own window is replaced: refuse one that was meant to be
    // expired rather than silently make it live.
    assert!(
        token.exp > now,
        "an expired fixture token cannot be activated"
    );
    let request = ReservationRequest {
        issuer: token.identity.issuer().to_string(),
        subject: token.identity.subject().to_string(),
        jti: token.jti.clone(),
    };
    let id = store.reserve(request, now).expect("a slot under the cap");
    token.iat = now;
    token.exp = now + ttl;
    store
        .activate(&id, token, now)
        .expect("the reservation activates");
}

/// Spawn a background task that reaps expired tokens every `interval`.
///
/// The task exits when the `shutdown` receiver fires.
pub fn spawn_reaper(
    store: Arc<dyn TokenStore>,
    interval: Duration,
    mut shutdown: tokio::sync::broadcast::Receiver<()>,
) {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(interval);
        loop {
            tokio::select! {
                _ = ticker.tick() => {
                    let reaped = store.reap_expired().await;
                    if reaped > 0 {
                        debug!(count = reaped, "Reaped expired temporary tokens");
                    }
                }
                _ = shutdown.recv() => {
                    debug!("Token reaper shutting down");
                    break;
                }
            }
        }
    });
}

#[cfg(test)]
#[path = "store_tests.rs"]
mod tests;

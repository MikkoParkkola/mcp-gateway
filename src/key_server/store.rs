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
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use dashmap::DashMap;
use rand::Rng;
use serde::{Deserialize, Serialize};
use tracing::debug;

use super::oidc::VerifiedIdentity;

/// A temporary gateway token issued after OIDC verification.
#[derive(Debug, Clone, Serialize, Deserialize)]
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_ip: Option<IpAddr>,
}

impl TemporaryToken {
    /// Returns `true` if the token has passed its expiry time.
    #[must_use]
    pub fn is_expired(&self) -> bool {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::ZERO)
            .as_secs();
        now >= self.exp
    }
}

/// Scopes granted to a temporary token.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TokenScopes {
    /// Allowed backends. Empty slice means "all backends".
    pub backends: Vec<String>,
    /// Allowed tools. Empty slice means "all tools on allowed backends".
    pub tools: Vec<String>,
    /// Per-identity rate limit (requests per minute; 0 = unlimited).
    pub rate_limit: u32,
}

/// Trait abstracting the token storage backend.
///
/// Implementations must be `Send + Sync` because the token store is shared
/// across async tasks.
#[async_trait::async_trait]
pub trait TokenStore: Send + Sync + 'static {
    /// Insert a newly-issued token.
    async fn insert(&self, token: TemporaryToken);

    /// Look up a token by its opaque bearer value.
    ///
    /// Returns `None` if the token does not exist or is expired/revoked.
    async fn get(&self, bearer: &str) -> Option<TemporaryToken>;

    /// Revoke a token by its JTI.
    ///
    /// Returns `true` if the token existed and was removed.
    async fn revoke_by_jti(&self, jti: &str) -> bool;

    /// Revoke all tokens for a given OIDC subject (e.g., on offboarding).
    async fn revoke_by_subject(&self, subject: &str) -> usize;

    /// Count active (non-expired) tokens for a given OIDC subject.
    async fn count_for_subject(&self, subject: &str) -> usize;

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
}

impl InMemoryTokenStore {
    /// Create an empty token store.
    #[must_use]
    pub fn new() -> Self {
        Self {
            by_bearer: DashMap::new(),
            by_jti: DashMap::new(),
        }
    }

    /// Generate a cryptographically random opaque bearer token.
    ///
    /// Format: `mcpgw_<43-char URL-safe base64>` (256 bits of entropy).
    /// The `mcpgw_` prefix makes tokens greppable and detectable by secret
    /// scanners (e.g., `truffleHog`, GitHub secret scanning).
    #[must_use]
    pub fn generate_bearer() -> String {
        let random_bytes: [u8; 32] = rand::rng().random();
        format!(
            "mcpgw_{}",
            base64::Engine::encode(
                &base64::engine::general_purpose::URL_SAFE_NO_PAD,
                random_bytes,
            )
        )
    }

    /// Generate a UUID v4 JTI.
    #[must_use]
    pub fn generate_jti() -> String {
        uuid::Uuid::new_v4().to_string()
    }
}

impl Default for InMemoryTokenStore {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait::async_trait]
impl TokenStore for InMemoryTokenStore {
    async fn insert(&self, token: TemporaryToken) {
        let bearer = token.token.clone();
        let jti = token.jti.clone();
        self.by_bearer.insert(bearer.clone(), token);
        self.by_jti.insert(jti, bearer);
    }

    async fn get(&self, bearer: &str) -> Option<TemporaryToken> {
        let entry = self.by_bearer.get(bearer)?;
        let token = entry.clone();
        drop(entry);

        if token.is_expired() {
            // Lazy eviction: remove on access
            self.by_bearer.remove(bearer);
            self.by_jti.remove(&token.jti);
            debug!(jti = %token.jti, "Lazy-evicted expired token");
            return None;
        }

        Some(token)
    }

    async fn revoke_by_jti(&self, jti: &str) -> bool {
        if let Some((_, bearer)) = self.by_jti.remove(jti) {
            self.by_bearer.remove(&bearer);
            true
        } else {
            false
        }
    }

    async fn revoke_by_subject(&self, subject: &str) -> usize {
        let mut jtis_to_revoke = Vec::new();

        for entry in &self.by_bearer {
            if entry.value().identity.subject == subject {
                jtis_to_revoke.push(entry.value().jti.clone());
            }
        }

        let count = jtis_to_revoke.len();
        for jti in jtis_to_revoke {
            self.revoke_by_jti(&jti).await;
        }
        count
    }

    async fn count_for_subject(&self, subject: &str) -> usize {
        self.by_bearer
            .iter()
            .filter(|e| e.value().identity.subject == subject && !e.value().is_expired())
            .count()
    }

    async fn reap_expired(&self) -> usize {
        let expired_bearers: Vec<String> = self
            .by_bearer
            .iter()
            .filter(|e| e.value().is_expired())
            .map(|e| e.key().clone())
            .collect();

        let count = expired_bearers.len();
        for bearer in expired_bearers {
            if let Some((_, token)) = self.by_bearer.remove(&bearer) {
                self.by_jti.remove(&token.jti);
                debug!(jti = %token.jti, "Reaped expired token");
            }
        }
        count
    }
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
mod tests {
    use super::*;
    use crate::key_server::oidc::VerifiedIdentity;

    fn make_identity(subject: &str, email: &str) -> VerifiedIdentity {
        VerifiedIdentity {
            subject: subject.to_string(),
            email: email.to_string(),
            name: None,
            groups: Vec::new(),
            issuer: "https://accounts.google.com".to_string(),
        }
    }

    fn make_token(subject: &str, email: &str, exp_offset_secs: i64) -> TemporaryToken {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let exp = if exp_offset_secs >= 0 {
            now + exp_offset_secs as u64
        } else {
            now.saturating_sub((-exp_offset_secs) as u64)
        };

        TemporaryToken {
            jti: InMemoryTokenStore::generate_jti(),
            token: InMemoryTokenStore::generate_bearer(),
            identity: make_identity(subject, email),
            scopes: TokenScopes {
                backends: vec!["tavily".to_string()],
                tools: Vec::new(),
                rate_limit: 100,
            },
            iat: now,
            exp,
            client_ip: None,
        }
    }

    #[tokio::test]
    async fn insert_and_get_valid_token() {
        // GIVEN: a token store with one valid token
        let store = InMemoryTokenStore::new();
        let token = make_token("sub123", "alice@company.com", 3600);
        let bearer = token.token.clone();

        // WHEN: we insert then look it up by bearer
        store.insert(token).await;
        let found = store.get(&bearer).await;

        // THEN: the token is returned
        assert!(found.is_some());
        assert_eq!(found.unwrap().identity.email, "alice@company.com");
    }

    #[tokio::test]
    async fn get_returns_none_for_unknown_token() {
        // GIVEN: an empty token store
        let store = InMemoryTokenStore::new();

        // WHEN: we look up a non-existent bearer
        let found = store.get("mcpgw_nonexistent").await;

        // THEN: None is returned
        assert!(found.is_none());
    }

    #[tokio::test]
    async fn get_lazy_evicts_expired_token() {
        // GIVEN: a store with an already-expired token (exp = 1 second ago)
        let store = InMemoryTokenStore::new();
        let token = make_token("sub123", "alice@company.com", -1);
        let bearer = token.token.clone();

        store.insert(token).await;

        // WHEN: we try to retrieve it
        let found = store.get(&bearer).await;

        // THEN: it is evicted and None is returned
        assert!(found.is_none());
        // Both indices cleaned up
        assert_eq!(store.by_bearer.len(), 0);
        assert_eq!(store.by_jti.len(), 0);
    }

    #[tokio::test]
    async fn revoke_by_jti_removes_token() {
        // GIVEN: a store with one valid token
        let store = InMemoryTokenStore::new();
        let token = make_token("sub123", "alice@company.com", 3600);
        let jti = token.jti.clone();
        let bearer = token.token.clone();
        store.insert(token).await;

        // WHEN: we revoke by JTI
        let removed = store.revoke_by_jti(&jti).await;

        // THEN: returns true and token is gone
        assert!(removed);
        assert!(store.get(&bearer).await.is_none());
        assert_eq!(store.by_jti.len(), 0);
    }

    #[tokio::test]
    async fn revoke_by_jti_returns_false_for_unknown() {
        // GIVEN: empty store
        let store = InMemoryTokenStore::new();

        // WHEN: revoke non-existent JTI
        let removed = store.revoke_by_jti("nonexistent-jti").await;

        // THEN: returns false
        assert!(!removed);
    }

    #[tokio::test]
    async fn revoke_by_subject_removes_all_tokens() {
        // GIVEN: two tokens for alice, one for bob
        let store = InMemoryTokenStore::new();
        let t1 = make_token("alice-sub", "alice@company.com", 3600);
        let t2 = make_token("alice-sub", "alice@company.com", 3600);
        let t3 = make_token("bob-sub", "bob@company.com", 3600);

        store.insert(t1).await;
        store.insert(t2).await;
        store.insert(t3).await;

        // WHEN: revoke all for alice
        let count = store.revoke_by_subject("alice-sub").await;

        // THEN: 2 removed, bob's token untouched
        assert_eq!(count, 2);
        assert_eq!(store.by_bearer.len(), 1); // bob's token remains
    }

    #[tokio::test]
    async fn count_for_subject_counts_active_tokens() {
        // GIVEN: two valid + one expired token for the same subject
        let store = InMemoryTokenStore::new();
        let t1 = make_token("alice-sub", "alice@company.com", 3600);
        let t2 = make_token("alice-sub", "alice@company.com", 3600);
        let t_expired = make_token("alice-sub", "alice@company.com", -1);

        store.insert(t1).await;
        store.insert(t2).await;
        store.insert(t_expired).await;

        // WHEN: count active tokens for alice
        let count = store.count_for_subject("alice-sub").await;

        // THEN: only 2 active tokens (expired one not counted)
        assert_eq!(count, 2);
    }

    #[tokio::test]
    async fn reap_expired_removes_only_expired() {
        // GIVEN: one valid + two expired tokens
        let store = InMemoryTokenStore::new();
        let valid = make_token("sub1", "alice@company.com", 3600);
        let expired1 = make_token("sub2", "bob@company.com", -1);
        let expired2 = make_token("sub3", "carol@company.com", -10);

        store.insert(valid).await;
        store.insert(expired1).await;
        store.insert(expired2).await;

        // WHEN: reap expired
        let reaped = store.reap_expired().await;

        // THEN: 2 removed, 1 remains
        assert_eq!(reaped, 2);
        assert_eq!(store.by_bearer.len(), 1);
    }

    #[tokio::test]
    async fn generate_bearer_has_correct_prefix() {
        // GIVEN/WHEN: generate a bearer token
        let bearer = InMemoryTokenStore::generate_bearer();

        // THEN: it starts with the required prefix
        assert!(bearer.starts_with("mcpgw_"));
        // And has 256 bits of entropy (32 bytes = 43 base64url chars)
        assert!(bearer.len() > 40);
    }

    #[test]
    fn is_expired_returns_true_for_past_exp() {
        // GIVEN: token with exp in the past
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let token = TemporaryToken {
            jti: "test".to_string(),
            token: "mcpgw_test".to_string(),
            identity: make_identity("sub", "test@example.com"),
            scopes: TokenScopes::default(),
            iat: now - 7200,
            exp: now - 1,
            client_ip: None,
        };

        // THEN: is_expired returns true
        assert!(token.is_expired());
    }

    #[test]
    fn is_expired_returns_false_for_future_exp() {
        // GIVEN: token with exp in the future
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let token = TemporaryToken {
            jti: "test".to_string(),
            token: "mcpgw_test".to_string(),
            identity: make_identity("sub", "test@example.com"),
            scopes: TokenScopes::default(),
            iat: now,
            exp: now + 3600,
            client_ip: None,
        };

        // THEN: is_expired returns false
        assert!(!token.is_expired());
    }
}

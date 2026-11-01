// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The JWKS and OIDC discovery cache of [`super::OidcVerifier`]: which keys an
//! issuer signs with, where to fetch them, and the fallback to
//! `{issuer}/.well-known/jwks.json` when a derived discovery URL cannot be
//! reached (MIK-8044). Split from `oidc.rs` for size; no behaviour of its own.

use std::sync::Arc;
use std::time::{Duration, Instant};

use dashmap::DashMap;
use jsonwebtoken::jwk::JwkSet;
use tracing::{debug, warn};

use super::{
    OidcDiscoveryDocument, OidcError, built, default_discovery_url, default_jwks_uri,
    is_loopback_http_url, remote_redirect_policy, validate_discovery_document,
};

/// Cached JWKS entry.
struct CachedJwks {
    keys: JwkSet,
    /// The URI the keys came from. Keys are reused only for that URI, so a
    /// fallback's keys stop serving once discovery names another (MIK-8044).
    source: String,
    fetched_at: Instant,
    ttl: Duration,
}

impl CachedJwks {
    fn is_stale(&self) -> bool {
        self.fetched_at.elapsed() >= self.ttl
    }
}

/// Minimal OIDC discovery document (`.well-known/openid-configuration`).
/// Only the fields needed to locate and trust the signing keys are parsed.
/// How long a fallback JWKS URI stands before discovery is tried again.
const FALLBACK_TTL: Duration = Duration::from_secs(300);

/// How long one forced refresh stands before another is tried.
const FORCED_COOLDOWN: Duration = Duration::from_secs(30);

/// Why discovery gave no JWKS URI: it could not be reached (the derived URL
/// may fall back), or it answered with a document that is refused.
enum DiscoveryError {
    Unreachable(OidcError),
    Refused(OidcError),
}

impl DiscoveryError {
    fn into_inner(self) -> OidcError {
        match self {
            Self::Unreachable(e) | Self::Refused(e) => e,
        }
    }
}

/// Cached `jwks_uri` resolved from an issuer's discovery document.
pub(super) struct CachedDiscovery {
    jwks_uri: String,
    fetched_at: Instant,
    pub(super) ttl: Duration,
}

impl CachedDiscovery {
    fn is_stale(&self) -> bool {
        self.fetched_at.elapsed() >= self.ttl
    }
}

/// JWKS cache — one entry per OIDC issuer.
pub struct JwksCache {
    inner: DashMap<String, CachedJwks>,
    /// Resolved `jwks_uri` per issuer, from the OIDC discovery document.
    pub(super) discovery: DashMap<String, CachedDiscovery>,
    /// For `https://` URLs; honours the environment's proxy settings.
    /// `None` when the client could not be built: every fetch then fails
    /// rather than fall back to a client without this policy.
    http: Option<reqwest::Client>,
    /// For `http://` to a loopback host. Never proxied: an inherited
    /// `HTTP_PROXY` would carry the cleartext request off this machine.
    loopback: Option<reqwest::Client>,
    /// How long to cache a fetched JWKS (default 1 hour).
    pub(super) ttl: Duration,
    /// Cap on how long a fallback JWKS URI stands (MIK-8044).
    pub(super) fallback_ttl: Duration,
    /// How long one forced refresh stands before another is tried.
    pub(super) forced_cooldown: Duration,
    /// The last forced attempt per issuer, success or failure.
    forced_at: DashMap<String, Instant>,
    /// One fetch at a time per issuer for forced refreshes.
    force_locks: DashMap<String, Arc<tokio::sync::Mutex<()>>>,
}

impl JwksCache {
    /// Create with default 1-hour TTL.
    #[must_use]
    pub fn new() -> Self {
        Self::with_remote_proxy(None)
    }

    /// The production clients; `proxy`, when given, replaces the
    /// environment's proxy for `https://` fetches only, so a test can show
    /// the loopback client never uses one.
    pub(super) fn with_remote_proxy(proxy: Option<reqwest::Proxy>) -> Self {
        // Not `https_only`: that would refuse the loopback carve-out too.
        // Every fetch picks its client by URL (`client_for`).
        let remote = reqwest::Client::builder()
            .redirect(remote_redirect_policy())
            .timeout(Duration::from_secs(10));
        let remote = match proxy {
            Some(proxy) => remote.proxy(proxy),
            None => remote,
        };
        let remote = crate::debug_trust_roots::extra_roots(remote);
        // A loopback fetch follows no redirect: a hop off the machine would
        // leave unproxied, and nothing legitimate needs one.
        let loopback = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::custom(|attempt| {
                attempt.error("OIDC refuses a redirect from a loopback fetch")
            }))
            .no_proxy()
            .timeout(Duration::from_secs(10));
        let loopback = crate::debug_trust_roots::extra_roots(loopback);
        Self {
            inner: DashMap::new(),
            discovery: DashMap::new(),
            http: built(remote.build()),
            loopback: built(loopback.build()),
            ttl: Duration::from_secs(3600),
            fallback_ttl: FALLBACK_TTL,
            forced_cooldown: FORCED_COOLDOWN,
            forced_at: DashMap::new(),
            force_locks: DashMap::new(),
        }
    }

    /// The client allowed to fetch `url`, or a refusal for a cleartext URL
    /// off this machine. Every fetch goes through here, so none can skip it.
    fn client_for(&self, url: &str) -> Result<&reqwest::Client, OidcError> {
        let client = if crate::gateway::auth::is_https_url(url) {
            &self.http
        } else if is_loopback_http_url(url) {
            &self.loopback
        } else {
            return Err(OidcError::InsecureFetch);
        };
        client.as_ref().ok_or(OidcError::ClientUnavailable)
    }

    /// Test-only constructor injecting a custom HTTP client.
    ///
    /// Lets an in-process integration test point the JWKS fetch at a
    /// self-signed-certificate test server (e.g. the gateway's own
    /// `/auth/token` handler under test, MIK-6729) without weakening the
    /// production client built by [`Self::new`].
    /// Compiled out of non-test builds entirely — there is no way to reach
    /// this constructor from production code.
    #[cfg(test)]
    pub(crate) fn with_http_client(http: reqwest::Client) -> Self {
        Self {
            inner: DashMap::new(),
            discovery: DashMap::new(),
            loopback: Some(http.clone()),
            http: Some(http),
            ttl: Duration::from_secs(3600),
            fallback_ttl: FALLBACK_TTL,
            forced_cooldown: FORCED_COOLDOWN,
            forced_at: DashMap::new(),
            force_locks: DashMap::new(),
        }
    }

    /// Clear the cached JWKS and discovery entries.
    #[cfg(test)]
    pub(super) fn clear_for_test(&self) {
        self.inner.clear();
        self.discovery.clear();
    }

    /// Resolve the `jwks_uri` for `issuer` from its OIDC discovery document
    /// (`discovery_url`, conventionally `{issuer}/.well-known/openid-configuration`).
    ///
    /// The discovered `issuer` field MUST equal the requested issuer (mix-up
    /// defense, `OpenID Connect Discovery` §4.3), and the returned `jwks_uri` must
    /// be HTTPS. Results are cached for the same TTL as JWKS.
    ///
    /// # Errors
    ///
    /// Returns [`OidcError`] on fetch/parse failure, issuer mismatch, or a
    /// non-HTTPS `jwks_uri`.
    pub async fn resolve_jwks_uri(
        &self,
        issuer: &str,
        discovery_url: &str,
    ) -> Result<String, OidcError> {
        if let Some(cached) = self.discovery.get(issuer)
            && !cached.is_stale()
        {
            return Ok(cached.jwks_uri.clone());
        }
        let jwks_uri = self
            .discover(issuer, discovery_url)
            .await
            .map_err(DiscoveryError::into_inner)?;
        self.record_discovery(issuer, &jwks_uri, self.ttl);
        Ok(jwks_uri)
    }

    /// `resolve_jwks_uri` for a discovery URL derived from the issuer: when
    /// discovery cannot be reached (connection, timeout, a non-2xx status, a
    /// body that is not a discovery document), the keys come from
    /// `{issuer}/.well-known/jwks.json`. A document that answers but fails
    /// validation is refused, never fallen back from (MIK-8044).
    pub async fn resolve_derived_jwks_uri(&self, issuer: &str) -> Result<String, OidcError> {
        if let Some(cached) = self.discovery.get(issuer)
            && !cached.is_stale()
        {
            return Ok(cached.jwks_uri.clone());
        }
        match self.discover(issuer, &default_discovery_url(issuer)).await {
            Ok(jwks_uri) => {
                self.record_discovery(issuer, &jwks_uri, self.ttl);
                Ok(jwks_uri)
            }
            Err(DiscoveryError::Refused(e)) => Err(e),
            Err(DiscoveryError::Unreachable(e)) => Ok(self.record_fallback(issuer, &e)),
        }
    }

    /// Fetch and validate the discovery document at `discovery_url`.
    async fn discover(&self, issuer: &str, discovery_url: &str) -> Result<String, DiscoveryError> {
        let client = self
            .client_for(discovery_url)
            .map_err(DiscoveryError::Refused)?;
        debug!(issuer = %issuer, "Fetching OIDC discovery from {discovery_url}");
        let unreachable = |e: reqwest::Error| DiscoveryError::Unreachable(e.into());
        let resp = client
            .get(discovery_url)
            .send()
            .await
            .map_err(unreachable)?;
        // Not `error_for_status`: it passes 3xx, which is no discovery answer.
        if !resp.status().is_success() {
            return Err(DiscoveryError::Unreachable(OidcError::DiscoveryStatus(
                resp.status().as_u16(),
            )));
        }
        let doc: OidcDiscoveryDocument = resp.json().await.map_err(unreachable)?;
        validate_discovery_document(issuer, doc).map_err(DiscoveryError::Refused)
    }

    fn record_discovery(&self, issuer: &str, jwks_uri: &str, ttl: Duration) {
        self.discovery.insert(
            issuer.to_string(),
            CachedDiscovery {
                jwks_uri: jwks_uri.to_string(),
                fetched_at: Instant::now(),
                ttl,
            },
        );
    }

    /// Record `{issuer}/.well-known/jwks.json` as the issuer's JWKS URI for at
    /// most five minutes, so discovery is retried after that. The WARN is
    /// logged only by the call that inserts, so racing first lookups log once.
    fn record_fallback(&self, issuer: &str, why: &OidcError) -> String {
        use dashmap::mapref::entry::Entry;
        let fallback = default_jwks_uri(issuer);
        let ttl = self.ttl.min(self.fallback_ttl);
        match self.discovery.entry(issuer.to_string()) {
            Entry::Occupied(entry) if !entry.get().is_stale() => {
                return entry.get().jwks_uri.clone();
            }
            entry => {
                let record = CachedDiscovery {
                    jwks_uri: fallback.clone(),
                    fetched_at: Instant::now(),
                    ttl,
                };
                match entry {
                    Entry::Occupied(mut slot) => {
                        slot.insert(record);
                    }
                    Entry::Vacant(slot) => {
                        slot.insert(record);
                    }
                }
            }
        }
        // Logged once the map entry, and its shard lock, is released.
        warn!(
            issuer = %issuer,
            error = %why,
            "OIDC discovery for {issuer} failed; using {fallback}"
        );
        fallback
    }

    // A forced refresh inside the cooldown serves the cached keys.
    fn forced_hit(&self, issuer: &str, jwks_uri: &str) -> Option<JwkSet> {
        let last = self.forced_at.get(issuer)?;
        if last.elapsed() >= self.forced_cooldown {
            return None;
        }
        let cached = self.inner.get(issuer)?;
        if cached.source != jwks_uri {
            return None;
        }
        Some(cached.keys.clone())
    }

    fn force_lock(&self, issuer: &str) -> Arc<tokio::sync::Mutex<()>> {
        let slot = self
            .force_locks
            .entry(issuer.to_string())
            .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(())));
        Arc::clone(&slot)
    }

    async fn fetch_store(&self, issuer: &str, jwks_uri: &str) -> Result<JwkSet, OidcError> {
        let client = self.client_for(jwks_uri)?;
        debug!(issuer = %issuer, "Fetching JWKS from {jwks_uri}");
        let jwks: JwkSet = client.get(jwks_uri).send().await?.json().await?;
        self.inner.insert(
            issuer.to_string(),
            CachedJwks {
                keys: jwks.clone(),
                source: jwks_uri.to_string(),
                fetched_at: Instant::now(),
                ttl: self.ttl,
            },
        );
        Ok(jwks)
    }

    pub async fn get_or_fetch(
        &self,
        issuer: &str,
        jwks_uri: &str,
        force_refresh: bool,
    ) -> Result<JwkSet, OidcError> {
        if !force_refresh
            && let Some(cached) = self.inner.get(issuer)
            && !cached.is_stale()
            && cached.source == jwks_uri
        {
            return Ok(cached.keys.clone());
        }
        if force_refresh {
            if let Some(keys) = self.forced_hit(issuer, jwks_uri) {
                return Ok(keys);
            }
            let lock = self.force_lock(issuer);
            let _guard = lock.lock().await;
            if let Some(keys) = self.forced_hit(issuer, jwks_uri) {
                return Ok(keys);
            }
            let fetched = self.fetch_store(issuer, jwks_uri).await;
            self.forced_at.insert(issuer.to_string(), Instant::now());
            return fetched;
        }
        self.fetch_store(issuer, jwks_uri).await
    }
}

impl Default for JwksCache {
    fn default() -> Self {
        Self::new()
    }
}

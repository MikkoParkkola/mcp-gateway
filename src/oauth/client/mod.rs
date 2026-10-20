// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! OAuth Client
//!
//! Main OAuth client implementation with PKCE support.

use super::metadata::{self, AuthorizationServerMetadata, IssuerSource, ProtectedResourceMetadata};
use super::storage::{TokenInfo, TokenStorage};
use crate::{Error, Result};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use parking_lot::RwLock;
use rand::RngExt;
use reqwest::Client;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::sync::Arc;
use tracing::{debug, info};

use identity::ClientIdSource;
pub use identity::{registration_body, storage_key, validate_issuer};

/// OAuth client for a specific backend
pub struct OAuthClient {
    /// HTTP client for token requests
    http_client: Client,

    /// Under `Configured`, the client for `http://` on a loopback host: never
    /// proxied, since the carve-out holds only while the request stays on the
    /// machine. `None` if it could not be built; such a fetch then fails.
    loopback_client: Option<Client>,

    /// Refresh-token clients with redirects off, built on first use: index 0
    /// the policy route, 1 the unproxied loopback route (MIK-8018).
    refresh_clients: [std::sync::OnceLock<Client>; 2],

    /// Whether refreshes go through `refresh_clients` or the caller's own
    /// `http_client` (MIK-8018).
    refresh_route: destination::RefreshRoute,

    /// Backend name (for storage key)
    backend_name: String,

    /// The backend's one-login-at-a-time gate, shared by every client the
    /// backend builds (MIK-7982). `None` authorizes ungated.
    login_gate: Option<Arc<super::login_gate::LoginGate>>,

    /// Resource URL (MCP endpoint)
    resource_url: String,

    /// OAuth server base URL (discovered from metadata)
    oauth_base_url: Option<String>,

    /// Authorization server metadata
    auth_metadata: Option<AuthorizationServerMetadata>,

    /// Protected resource metadata
    resource_metadata: Option<ProtectedResourceMetadata>,

    /// Token storage
    storage: Arc<TokenStorage>,

    /// Current token (cached)
    current_token: RwLock<Option<TokenInfo>>,

    /// Requested scopes
    scopes: Vec<String>,

    /// Client ID (registered or generated)
    client_id: RwLock<Option<String>>,

    /// Provenance of `client_id`. Invariant: `Some` exactly when `client_id`
    /// is `Some` — every write site that sets `client_id` sets this alongside
    /// it. See [`ClientIdSource`] for why this exists.
    client_id_source: RwLock<Option<ClientIdSource>>,

    /// Pre-configured client secret (for providers like Slack / Figma).
    client_secret: Option<String>,

    /// Callback host override (default: "localhost", dual-binds IPv4+IPv6).
    callback_host: Option<String>,

    /// Hands the authorization URL to its approver (the browser; a test in tests).
    open_browser: Box<dyn Fn(&str) -> bool + Send + Sync>,

    /// Fixed callback port (None = OS-assigned).
    callback_port: Option<u16>,

    /// Callback URL path (default: "/oauth/callback").
    callback_path: Option<String>,

    /// Seconds before expiry at which the background task proactively refreshes.
    ///
    /// `None` derives it from the token (see [`refresh_buffer`]).
    token_refresh_buffer_secs: Option<u64>,

    /// Where advertised URLs may point (the backend's destination policy).
    destination: crate::security::ssrf::DestinationPolicy,
}

/// OAuth token response
#[derive(Deserialize)]
struct TokenResponse {
    access_token: String,
    token_type: Option<String>,
    expires_in: Option<u64>,
    refresh_token: Option<String>,
    scope: Option<String>,
}

fn redact_opt(v: &Option<String>) -> &'static str {
    if v.is_some() { "<redacted>" } else { "None" }
}

// Manual `Debug` that redacts the OAuth tokens (CWE-532, mirrors PR #323). A
// derived `Debug` would print `access_token` / `refresh_token` verbatim into
// any trace or error context.
impl std::fmt::Debug for TokenResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TokenResponse")
            .field("access_token", &"<redacted>")
            .field("token_type", &self.token_type)
            .field("expires_in", &self.expires_in)
            .field("refresh_token", &redact_opt(&self.refresh_token))
            .field("scope", &self.scope)
            .finish()
    }
}

/// Client registration response
#[derive(Deserialize)]
struct ClientRegistrationResponse {
    client_id: String,
    #[allow(dead_code)]
    client_secret: Option<String>,
}

// Manual `Debug` that redacts the issued client secret (CWE-532, mirrors PR
// #323). A derived `Debug` would print `client_secret` verbatim into any trace
// or error context; only its presence is surfaced.
impl std::fmt::Debug for ClientRegistrationResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClientRegistrationResponse")
            .field("client_id", &self.client_id)
            .field("client_secret", &redact_opt(&self.client_secret))
            .finish()
    }
}

/// Configuration for constructing an [`OAuthClient`].
///
/// Bundles the optional per-provider settings so that [`OAuthClient::new`]
/// stays within Clippy's argument-count limit.
#[derive(Default)]
pub struct OAuthClientConfig {
    /// Pre-configured client ID.
    pub client_id: Option<String>,
    /// Pre-configured client secret (Slack, Figma, …).
    pub client_secret: Option<String>,
    /// Callback host override (default: `"localhost"`, dual-binds IPv4+IPv6).
    pub callback_host: Option<String>,
    /// Fixed callback port (`None` = OS-assigned).
    pub callback_port: Option<u16>,
    /// Callback URL path (default: `"/oauth/callback"`).
    pub callback_path: Option<String>,
    /// Seconds before expiry to refresh; `None` derives it from the token's
    /// lifetime ([`refresh_buffer`]).
    pub token_refresh_buffer_secs: Option<u64>,
}

// Manual `Debug` that redacts the fixed OAuth client secret (CWE-532, mirrors
// PR #323). A derived `Debug` would print `client_secret` verbatim into any
// trace or error context; only its presence is surfaced.
impl std::fmt::Debug for OAuthClientConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OAuthClientConfig")
            .field("client_id", &self.client_id)
            .field("client_secret", &redact_opt(&self.client_secret))
            .field("callback_host", &self.callback_host)
            .field("callback_port", &self.callback_port)
            .field("callback_path", &self.callback_path)
            .field("token_refresh_buffer_secs", &self.token_refresh_buffer_secs)
            .finish()
    }
}

impl OAuthClient {
    /// Create a new OAuth client for a backend
    #[must_use]
    pub fn new(
        http_client: Client,
        backend_name: String,
        resource_url: String,
        scopes: Vec<String>,
        storage: Arc<TokenStorage>,
        cfg: OAuthClientConfig,
    ) -> Self {
        // A pre-configured client_id is operator config, not a dynamic
        // registration — record its provenance up front so a later
        // `invalid_client` rejection never purges it (Defect 2, MIK-6750 r7).
        let client_id_source = cfg
            .client_id
            .is_some()
            .then_some(ClientIdSource::Configured);
        Self {
            http_client,
            loopback_client: destination::loopback_client().ok(),
            refresh_clients: [std::sync::OnceLock::new(), std::sync::OnceLock::new()],
            refresh_route: destination::RefreshRoute::Supplied,
            backend_name,
            login_gate: None,
            resource_url,
            oauth_base_url: None,
            auth_metadata: None,
            resource_metadata: None,
            storage,
            current_token: RwLock::new(None),
            scopes,
            client_id: RwLock::new(cfg.client_id),
            client_id_source: RwLock::new(client_id_source),
            client_secret: cfg.client_secret,
            callback_host: cfg.callback_host,
            open_browser: Box::new(browser::open_browser),
            callback_port: cfg.callback_port,
            callback_path: cfg.callback_path,
            token_refresh_buffer_secs: cfg.token_refresh_buffer_secs,
            destination: crate::security::ssrf::DestinationPolicy::Configured,
        }
    }

    /// Initialize the OAuth client by discovering metadata
    ///
    /// # Errors
    ///
    /// Returns an error if authorization server metadata discovery fails.
    ///
    /// # Panics
    ///
    /// Panics if `oauth_base_url` is `None` after metadata discovery, which
    /// should not occur since both success and error paths set it.
    pub async fn initialize(&mut self) -> Result<()> {
        let base_url = metadata::base_url(&self.resource_url)?;

        // Which kind of issuer string this ends up with decides how exactly the
        // discovered metadata is held to it: an identifier the resource server
        // published is the authorization server's own spelling, while
        // `base_url()` is one this gateway synthesised. Recorded at each
        // assignment rather than inferred later, because by then only the
        // string is left and the two are indistinguishable.
        let mut issuer_source = IssuerSource::Origin;

        // Which protected-resource document describes this backend, held to
        // the configured resource (MIK-8320, MIK-8324). A mismatch or a policy
        // refusal is an answer, not a missing document: it ends discovery
        // rather than falling back (MIK-7701).
        if let Some(meta) = self.discover_resource_metadata().await? {
            // Read before the macro so its count is graded (MIK-7725).
            let resource = &meta.resource;
            debug!(resource = %resource, "Found protected resource metadata");

            // Get authorization server from metadata
            if let Some(auth_server) = meta.authorization_server() {
                self.oauth_base_url = Some(auth_server.to_string());
                issuer_source = IssuerSource::Advertised;
            } else {
                // Fallback to same base URL
                self.oauth_base_url = Some(base_url.clone());
            }

            // Use scopes from metadata if not specified
            if self.scopes.is_empty() && !meta.scopes_supported.is_empty() {
                self.scopes.clone_from(&meta.scopes_supported);
            }

            self.resource_metadata = Some(meta);
        } else {
            debug!("No protected resource metadata, using base URL");
            self.oauth_base_url = Some(base_url.clone());
        }

        // Discover authorization server metadata
        let auth_base = self.oauth_base_url.as_ref().unwrap();
        self.check_destination(auth_base, "authorization server")?;
        let previous_issuer = self.auth_metadata.as_ref().map(|m| m.issuer.clone());
        let discovered = AuthorizationServerMetadata::discover(
            self.client_for(auth_base)?,
            auth_base,
            issuer_source,
        )
        .await?;
        // Checked before it is kept: a refused document never reaches a request.
        self.check_advertised_endpoints(&discovered)?;
        self.auth_metadata = Some(discovered);

        self.drop_credentials_from_other_issuer(previous_issuer.as_deref());

        // Load any cached token
        if let Some(token) = self
            .storage
            .load(&self.credential_key()?, &self.resource_url)
        {
            *self.current_token.write() = Some(token);
        }

        // Restore a previously-registered dynamic client id so we do NOT
        // re-register (and pop a fresh browser authorize tab) every time the
        // process restarts or a connection is re-established.
        self.restore_persisted_client_id();

        // Read before the macro so its count is graded (MIK-7725).
        let backend = &self.backend_name;
        info!(backend = %backend, "OAuth client initialized");
        Ok(())
    }

    /// The storage key this client's credentials belong under.
    ///
    /// One owner, because the alternative is seven call sites each free to
    /// forget the issuer — and a credential saved under one key and read
    /// under another is not a loud failure, it is a silent re-registration
    /// loop or, worse, a client id presented to a server that never issued
    /// it.
    ///
    /// An error before the authorization server has been discovered: a credential cannot be
    /// attributed to an issuer that is not yet known. There is deliberately no unqualified key to
    /// fall back to, because falling back is precisely the reuse this keying exists to prevent.
    fn credential_key(&self) -> Result<String> {
        let meta = self.auth_metadata.as_ref().ok_or_else(|| {
            Error::OAuth("OAuth not initialized: no issuer to key credentials by".to_string())
        })?;
        Ok(storage_key(&self.backend_name, &meta.issuer))
    }

    /// Drop in-memory credentials when re-initializing lands on a different
    /// authorization server.
    ///
    /// Keying storage by issuer stops the *disk* from crossing that line. In-memory state crosses
    /// it too unless it is dropped here, and a retained client id additionally makes
    /// [`restore_persisted_client_id`](Self::restore_persisted_client_id) a no-op for the new
    /// issuer. A configured client id belongs to the operator rather than to an issuer, so it
    /// stays.
    fn drop_credentials_from_other_issuer(&self, previous_issuer: Option<&str>) {
        let Some(previous) = previous_issuer else {
            return;
        };
        let Some(current) = self.auth_metadata.as_ref().map(|m| m.issuer.as_str()) else {
            return;
        };
        if previous == current {
            return;
        }
        *self.current_token.write() = None;
        if *self.client_id_source.read() == Some(ClientIdSource::Registered) {
            *self.client_id.write() = None;
            *self.client_id_source.write() = None;
        }
    }

    /// Load a previously-registered dynamic `client_id` from storage into
    /// memory, tagging its provenance as [`ClientIdSource::Registered`].
    ///
    /// A no-op when a `client_id` is already in memory: either
    /// `OAuthClientConfig.client_id` was supplied (operator config, which
    /// must never be overwritten by or conflated with a stale disk record),
    /// or this client already registered, generated or restored one. Because
    /// of that guard, any id loaded here is necessarily a prior Dynamic Client
    /// Registration, never operator config (Defect 2, MIK-6750 r7) — safe
    /// to mark `Registered` so a later `invalid_client` rejection may purge
    /// it.
    fn restore_persisted_client_id(&self) {
        if self.client_id.read().is_some() {
            return;
        }
        let Ok(key) = self.credential_key() else {
            return;
        };
        if let Some(cid) = self.storage.load_client_id(&key, &self.resource_url) {
            *self.client_id.write() = Some(cid);
            *self.client_id_source.write() = Some(ClientIdSource::Registered);
        }
    }
}

/// The floor of a derived refresh buffer, and the whole buffer for a token
/// that carries no lifetime.
const REFRESH_BUFFER_FLOOR_SECS: u64 = 300;

/// Seconds before expiry to refresh: the set value, else the larger of 300 s
/// and 10 % of the token's lifetime, else 300 s (MIK-8044). A token shorter
/// than 300 s therefore refreshes at every check, as it did with the fixed
/// 300 s buffer.
pub(crate) fn refresh_buffer(set: Option<u64>, lifetime_secs: Option<u64>) -> u64 {
    set.unwrap_or_else(|| {
        lifetime_secs.map_or(REFRESH_BUFFER_FLOOR_SECS, |life| {
            (life / 10).max(REFRESH_BUFFER_FLOOR_SECS)
        })
    })
}

/// The one clock reading a token request is checked against before it is
/// sent, and that dates the token it returns. A clock that cannot be read
/// (before 1970) refuses the request: nothing is sent, so no token is dated
/// from the epoch and no endpoint is called on a broken clock (MIK-8202).
pub(super) fn issuance_clock() -> Result<u64> {
    crate::clock::unix_secs().map_err(|_| {
        Error::OAuth("the host clock reads before 1970; the token request was not sent".to_string())
    })
}

/// MIK-8207: a token answer whose `expires_in` is above 100 years is
/// malformed. Trusted, it would keep a token for centuries without a refresh;
/// added unchecked, it wrapped to an expiry in the past (a refresh on every
/// call). The answer is refused, naming the endpoint that sent it.
fn refuse_oversized_expires_in(endpoint: &str, expires_in: Option<u64>) -> Result<()> {
    match expires_in {
        Some(secs) if secs > crate::duration_bound::MAX_DURATION.as_secs() => {
            Err(Error::OAuth(format!(
                "the token endpoint {} answered expires_in {secs}, more than 100 years; \
                 the answer is refused as malformed",
                crate::security::sanitize::redact_url_for_diagnostics(endpoint)
            )))
        }
        _ => Ok(()),
    }
}

/// Generate PKCE code verifier and challenge
fn generate_pkce() -> (String, String) {
    // Generate 32 random bytes for verifier
    let verifier_bytes: [u8; 32] = rand::rng().random();
    let verifier = URL_SAFE_NO_PAD.encode(verifier_bytes);

    // SHA256 hash for challenge
    let mut hasher = Sha256::new();
    hasher.update(verifier.as_bytes());
    let challenge_bytes = hasher.finalize();
    let challenge = URL_SAFE_NO_PAD.encode(challenge_bytes);

    (verifier, challenge)
}

/// Generate a random state parameter
fn generate_state() -> String {
    let state_bytes: [u8; 16] = rand::rng().random();
    URL_SAFE_NO_PAD.encode(state_bytes)
}

/// Generate a random client ID
fn generate_client_id() -> String {
    let id_bytes: [u8; 16] = rand::rng().random();
    URL_SAFE_NO_PAD.encode(id_bytes)
}

#[cfg(test)]
mod authorize_tests;
mod browser;
#[cfg(test)]
mod deadline_tests;
pub(crate) mod destination;
mod discovery;
mod identity;
#[cfg(test)]
mod refresh_flight_tests;
#[cfg(test)]
pub(crate) mod token_server_fixture;

#[cfg(test)]
impl OAuthClient {
    /// This client with `open` playing the browser, for a backend test that
    /// builds its client through the backend.
    pub(crate) fn with_open_browser(
        mut self,
        open: std::sync::Arc<dyn Fn(&str) -> bool + Send + Sync>,
    ) -> Self {
        self.open_browser = Box::new(move |url: &str| open(url));
        self
    }
}
#[cfg(test)]
use url::Url;

mod grants;
pub(crate) use grants::OAUTH_AUTHORIZATION_WINDOW;
#[cfg(test)]
mod grants_tests;
mod refresh_flight;
pub(crate) use refresh_flight::{
    RefreshCaller, RefreshRequest, Refreshed, StoredCredential, refresh_stored,
};
#[cfg(test)]
mod issuer_provenance_tests;
#[cfg(test)]
mod prm_discovery_tests;
mod registration;
mod renewal;
#[cfg(test)]
mod tests;
mod token_access;

#[cfg(test)]
mod cwe532_debug_redaction {
    use super::*;

    const SENTINEL: &str = "SENTINEL_SECRET_a1b2c3";

    // TokenResponse::Debug must never surface the access/refresh tokens.
    #[test]
    fn token_response_debug_redacts_tokens() {
        let r = TokenResponse {
            access_token: SENTINEL.to_string(),
            token_type: Some("Bearer".to_string()),
            expires_in: Some(3600),
            refresh_token: Some(format!("{SENTINEL}-refresh")),
            scope: Some("read".to_string()),
        };
        let dbg = format!("{r:?}");
        assert!(!dbg.contains(SENTINEL), "leaked token: {dbg}");
        assert!(
            dbg.contains("<redacted>"),
            "missing redaction marker: {dbg}"
        );
        assert!(
            dbg.contains("Bearer"),
            "token_type should stay visible: {dbg}"
        );
    }

    // ClientRegistrationResponse::Debug must never surface the issued secret.
    #[test]
    fn client_registration_response_debug_redacts_secret() {
        let r = ClientRegistrationResponse {
            client_id: "client-123".to_string(),
            client_secret: Some(SENTINEL.to_string()),
        };
        let dbg = format!("{r:?}");
        assert!(!dbg.contains(SENTINEL), "leaked client_secret: {dbg}");
        assert!(
            dbg.contains("<redacted>"),
            "missing redaction marker: {dbg}"
        );
        assert!(
            dbg.contains("client-123"),
            "client_id should stay visible: {dbg}"
        );
    }

    // OAuthClientConfig::Debug must never surface the fixed client secret.
    #[test]
    fn oauth_client_config_debug_redacts_client_secret() {
        let cfg = OAuthClientConfig {
            client_secret: Some(SENTINEL.to_string()),
            client_id: Some("client-123".to_string()),
            ..Default::default()
        };
        let dbg = format!("{cfg:?}");
        assert!(!dbg.contains(SENTINEL), "leaked client_secret: {dbg}");
        assert!(
            dbg.contains("<redacted>"),
            "missing redaction marker: {dbg}"
        );
        assert!(
            dbg.contains("client-123"),
            "client_id should stay visible: {dbg}"
        );
    }

    // The None branch of the redaction: an absent refresh token prints as
    // the quoted string "None", not as a bare None.
    #[test]
    fn token_response_debug_shows_none_for_an_absent_refresh_token() {
        let r = TokenResponse {
            access_token: SENTINEL.to_string(),
            token_type: Some("Bearer".to_string()),
            expires_in: Some(3600),
            refresh_token: None,
            scope: Some("read".to_string()),
        };
        assert_eq!(
            format!("{r:?}"),
            "TokenResponse { access_token: \"<redacted>\", token_type: Some(\"Bearer\"), expires_in: Some(3600), refresh_token: \"None\", scope: Some(\"read\") }"
        );
    }

    // The None branch of the redaction: an absent issued secret prints as
    // the quoted string "None", not as a bare None.
    #[test]
    fn client_registration_response_debug_shows_none_for_an_absent_secret() {
        let r = ClientRegistrationResponse {
            client_id: "client-123".to_string(),
            client_secret: None,
        };
        assert_eq!(
            format!("{r:?}"),
            "ClientRegistrationResponse { client_id: \"client-123\", client_secret: \"None\" }"
        );
    }

    // The None branch of the redaction: an absent fixed secret prints as
    // the quoted string "None", unlike the bare None of the other options.
    #[test]
    fn oauth_client_config_debug_shows_none_for_an_absent_client_secret() {
        let cfg = OAuthClientConfig {
            client_secret: None,
            client_id: Some("client-123".to_string()),
            ..Default::default()
        };
        assert_eq!(
            format!("{cfg:?}"),
            "OAuthClientConfig { client_id: Some(\"client-123\"), client_secret: \"None\", callback_host: None, callback_port: None, callback_path: None, token_refresh_buffer_secs: None }"
        );
    }
}

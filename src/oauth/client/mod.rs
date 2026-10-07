// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! OAuth Client
//!
//! Main OAuth client implementation with PKCE support.

use super::metadata::{self, AuthorizationServerMetadata, IssuerSource, ProtectedResourceMetadata};
use super::storage::{TokenInfo, TokenStorage};
use crate::security::ssrf::is_ssrf_refusal;
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

/// Provenance of a `client_id` (MIK-6750 r7, Defect 2).
///
/// `purge_client_id_if_invalid` must never clear a [`Configured`](Self::Configured)
/// id: it is operator-supplied config (Slack, Figma, …) and erasing it on an
/// `invalid_client` rejection would delete valid configuration and guarantee
/// every subsequent attempt also fails, using a generated/DCR id the operator
/// never intended. Only a [`Registered`](Self::Registered) id — obtained via
/// Dynamic Client Registration, generated as a DCR fallback, or loaded from a
/// prior registration's persisted record — is safe to purge and re-register.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ClientIdSource {
    /// Came from `OAuthClientConfig.client_id`. Never purgeable.
    Configured,
    /// Obtained via Dynamic Client Registration, a generated fallback, or a
    /// load of a previously dynamically-registered id from storage.
    Registered,
}

/// The Dynamic Client Registration body this gateway sends.
///
/// A free function so it can be asserted without a live authorization server:
/// these fields are what every server the gateway registers with sees, and they
/// were previously observable only by running one.
///
/// `application_type` is required by MCP 2026-07-28 and is not cosmetic.
/// `OpenID` Connect defaults an unstated value to `web`, which constrains
/// redirect URIs to https and forbids a literal loopback address — exactly what
/// a locally-running gateway registers. Saying `native` makes the registration
/// describe this client.
#[must_use]
pub fn registration_body(backend_name: &str, redirect_uri: &str) -> serde_json::Value {
    serde_json::json!({
        "client_name": format!("MCP Gateway - {backend_name}"),
        "application_type": "native",
        "redirect_uris": [redirect_uri],
        "grant_types": ["authorization_code", "refresh_token"],
        "response_types": ["code"],
        "token_endpoint_auth_method": "none"
    })
}

/// Check the `iss` an authorization server returned against the one recorded.
///
/// MCP 2026-07-28, adopting RFC 9207: authorization servers **SHOULD** include
/// `iss` in the authorization response, and MCP clients **MUST** validate a
/// present `iss` against the recorded issuer before redeeming the code.
///
/// The attack is mix-up. A client that talks to several authorization servers
/// receives codes at one redirect endpoint and cannot otherwise tell which
/// server sent one; an attacker who controls a server it trusts can obtain a
/// code from a different one and have the client redeem it at the wrong token
/// endpoint. `state` does not close this — the attacker's own flow carries a
/// state the client itself issued.
///
/// Absence is allowed, deliberately. The specification makes including `iss` a
/// SHOULD and validating a **present** one a MUST; refusing its absence would
/// be a stricter rule than the specification states, imposed on servers this
/// gateway does not control and many of which have not adopted RFC 9207.
///
/// # Errors
///
/// Returns the mismatch when a present `iss` is not the recorded issuer.
pub fn validate_issuer(returned: Option<&str>, recorded: &str) -> std::result::Result<(), String> {
    match returned {
        None => Ok(()),
        // Exact string comparison, as issuer identifiers are defined. A
        // trailing slash, a case change or an explicit default port makes a
        // different identifier, and normalising any of them would reopen the
        // mix-up through a URL that merely looks the same.
        Some(iss) if iss == recorded => Ok(()),
        Some(iss) => Err(format!(
            "authorization response came from issuer '{iss}', not the recorded '{recorded}'; \
             the code was not redeemed"
        )),
    }
}

/// The storage key for a credential, keyed by the issuer that granted it.
///
/// MCP 2026-07-28: a client **MUST** key persisted credentials by the issuer
/// identifier, **MUST NOT** reuse them with a different authorization server,
/// and **MUST** re-register when the authorization server changes.
///
/// Keyed by backend alone, moving a backend from one authorization server to
/// another silently reuses a client id the new server never issued — and the
/// failure surfaces as a confusing rejection later rather than as the
/// re-registration it should have been.
#[must_use]
pub fn storage_key(backend_name: &str, issuer: &str) -> String {
    format!("{backend_name}\u{0}{issuer}")
}

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
    /// The task triggers when `time_until_expiry < max(lifetime * 10%, buffer)`.
    token_refresh_buffer_secs: u64,

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

// Manual `Debug` that redacts the OAuth tokens (CWE-532, mirrors PR #323). A
// derived `Debug` would print `access_token` / `refresh_token` verbatim into
// any trace or error context.
impl std::fmt::Debug for TokenResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let redact_opt = |v: &Option<String>| if v.is_some() { "<redacted>" } else { "None" };
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
        let redact_opt = |v: &Option<String>| if v.is_some() { "<redacted>" } else { "None" };
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
    /// Seconds before expiry to proactively refresh (default: 300).
    pub token_refresh_buffer_secs: u64,
}

// Manual `Debug` that redacts the fixed OAuth client secret (CWE-532, mirrors
// PR #323). A derived `Debug` would print `client_secret` verbatim into any
// trace or error context; only its presence is surfaced.
impl std::fmt::Debug for OAuthClientConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let redact_opt = |v: &Option<String>| if v.is_some() { "<redacted>" } else { "None" };
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
            open_browser: Box::new(open_browser),
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

        // Try to discover protected resource metadata first
        match ProtectedResourceMetadata::discover(self.client_for(&base_url)?, &base_url).await {
            Ok(meta) => {
                debug!(resource = %meta.resource, "Found protected resource metadata");

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
            }
            // A policy refusal is an answer, not a missing document: falling
            // back would walk past it (MIK-7701).
            Err(e) if is_ssrf_refusal(&e) => return Err(e),
            Err(e) => {
                debug!(error = %e, "No protected resource metadata, using base URL");
                self.oauth_base_url = Some(base_url.clone());
            }
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

        info!(backend = %self.backend_name, "OAuth client initialized");
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

    /// Load a previously-registered dynamic `client_id` from storage into
    /// memory, tagging its provenance as [`ClientIdSource::Registered`].
    ///
    /// A no-op when a `client_id` is already set: that only happens when
    /// `OAuthClientConfig.client_id` was supplied, i.e. operator config that
    /// must never be overwritten by (or conflated with) a stale disk record. Because of that guard,
    /// any id loaded here is necessarily a prior Dynamic Client Registration, never operator config
    /// (Defect 2, MIK-6750 r7) — safe to mark `Registered` so a later `invalid_client` rejection
    /// may purge it. Drop in-memory credentials when re-initializing lands on a different
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

    /// Get a valid access token, refreshing or re-authorizing as needed
    ///
    /// # Errors
    ///
    /// Returns an error if token refresh and re-authorization both fail.
    pub async fn get_token(&self) -> Result<String> {
        // Check if we have a valid cached token
        {
            let token = self.current_token.read();
            if let Some(ref t) = *token
                && !t.is_expired()
            {
                return Ok(t.access_token.clone());
            }
        }

        // Try to refresh if we have a refresh token
        let refresh_token_opt = {
            let token = self.current_token.read();
            token.as_ref().and_then(|t| t.refresh_token.clone())
        };

        if let Some(refresh_token) = refresh_token_opt {
            match self.refresh_token(&refresh_token).await {
                Ok(new_token) => return Ok(new_token),
                // A policy refusal is not an expired grant: re-authorizing
                // would only walk past it (MIK-7701).
                Err(e) if is_ssrf_refusal(&e) => return Err(e),
                Err(_) => {}
            }
        }

        // Need to authorize from scratch
        let token = self
            .authorize_shared(super::login_gate::interactive(), None)
            .await?;
        Ok(token)
    }

    /// Return the backend name (used by the background refresh task for logging).
    #[must_use]
    pub fn backend_name(&self) -> &str {
        &self.backend_name
    }

    /// Check if the client has a valid token
    pub fn has_valid_token(&self) -> bool {
        let token = self.current_token.read();
        token.as_ref().is_some_and(|t| !t.is_expired())
    }

    /// Return true if the token should be proactively refreshed.
    ///
    /// Triggers when remaining lifetime is below `max(lifetime * 10%, buffer)`.
    #[must_use]
    pub fn needs_proactive_refresh(&self) -> bool {
        let token = self.current_token.read();
        let Some(ref t) = *token else { return false };

        // Tokens with no expiry never need proactive refresh
        let Some(expires_at) = t.expires_at else {
            return false;
        };

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let remaining = expires_at.saturating_sub(now);

        // Compute 10% of total lifetime using the stored expires_at as a proxy.
        // We don't store issued_at, so approximate lifetime as (expires_at - now + remaining)
        // which simplifies to: use a fixed fraction of the buffer itself.
        // Practical rule: trigger refresh at max(buffer, 10% of remaining_at_last_check).
        // Since we check every 60s, use the simpler form: remaining < buffer.
        remaining < self.token_refresh_buffer_secs
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

/// Open a URL in the system default browser.
///
/// Uses `open` on macOS, `xdg-open` on Linux, and `start` on Windows.
/// Returns `true` if the command was spawned successfully.
fn open_browser(url: &str) -> bool {
    #[cfg(target_os = "macos")]
    let cmd = "open";
    #[cfg(target_os = "linux")]
    let cmd = "xdg-open";
    #[cfg(target_os = "windows")]
    let cmd = "cmd";

    #[cfg(target_os = "windows")]
    let result = std::process::Command::new(cmd)
        .args(["/c", "start", url])
        .spawn();
    #[cfg(not(target_os = "windows"))]
    let result = std::process::Command::new(cmd).arg(url).spawn();

    result.is_ok()
}

#[cfg(test)]
mod authorize_tests;
pub(crate) mod destination;
#[cfg(test)]
mod refresh_flight_tests;

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
mod refresh_flight;
mod registration;
mod renewal;
#[cfg(test)]
mod tests;

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
}

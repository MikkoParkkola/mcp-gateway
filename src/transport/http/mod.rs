// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! HTTP/SSE transport implementation
//!
//! Implements proper MCP SSE client protocol:
//! 1. GET /sse endpoint to establish connection and receive session endpoint
//! 2. POST to the session endpoint (/`messages?session_id=XXX`) for requests
//! 3. SSE stream provides server->client notifications (optional)
//!
//! Supports OAuth 2.0 with PKCE for authenticated backends.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;

use async_trait::async_trait;
use parking_lot::RwLock;
use reqwest::{Client, header};
use serde_json::Value;
use tokio::sync::Mutex as TokioMutex;
use tokio::task::JoinHandle;
use tracing::{debug, info, warn};
use url::Url;

use super::Transport;
use crate::gateway::trace;
use crate::oauth::OAuthClient;
use crate::protocol::{
    JsonRpcNotification, JsonRpcRequest, JsonRpcResponse, PROTOCOL_VERSION, RequestId,
    is_version_mismatch_error, negotiate_best_version, parse_supported_versions_from_error,
};
use crate::security::validate_url_not_ssrf;
use crate::{Error, Result};

/// Origin equality per WHATWG (scheme + host + effective port). Used to enforce
/// that an SSE-advertised message endpoint is same-origin as the SSE stream
/// before any per-user credential is sent to it (SSRF + credential-exfil guard).
fn same_origin(a: &Url, b: &Url) -> bool {
    a.scheme() == b.scheme()
        && a.host_str() == b.host_str()
        && a.port_or_known_default() == b.port_or_known_default()
}

/// Detect the session-expiry signature in a transport error (MIK-5982).
///
/// Matches three observed shapes:
/// - JSON-RPC `-32015` session errors (rust-mcp-sdk servers, e.g. hebb-serve:
///   `HTTP 400 Bad Request: {"code":-32015,...,"message":"Bad Request: Session not found"}`)
/// - any body containing "session not found" (case-insensitive)
/// - bare `HTTP 404` responses, which the MCP Streamable HTTP spec defines as
///   "session terminated or expired" (callers gate this on having had a session)
///
/// This covers the cases where the backend surfaces the expiry as a transport
/// `Err` (non-2xx HTTP status, or a transport-layer failure). When the backend
/// instead returns HTTP 200 with the expiry encoded as a JSON-RPC `error`
/// member, use [`is_session_expired_response`] (MIK-6040, #247).
fn is_session_expired_error(err: &Error) -> bool {
    let Error::Transport(msg) = err else {
        return false;
    };
    let lower = msg.to_lowercase();
    lower.contains("session not found") || msg.contains("-32015") || lower.starts_with("http 404")
}

/// Detect the session-expiry signature in a *successful-transport* JSON-RPC
/// response whose body carries an `error` member (MIK-6040, #247).
///
/// Some remotes (notably OAuth-protected Streamable HTTP servers that invalidate
/// the MCP session on token refresh) return HTTP 200 with the expiry encoded as
/// a JSON-RPC error rather than a non-2xx status. The transport layer sees this
/// as `Ok(JsonRpcResponse)` with `error: Some(..)`, so the [`is_session_expired_error`]
/// classifier — which only inspects transport `Err` strings — never fires. This
/// sibling classifier inspects the embedded error and matches:
/// - code `-32015` (rust-mcp-sdk "Session not found")
/// - code `-32600` (Invalid Request, observed for session-not-found on some remotes)
/// - any `message` containing "session not found" (case-insensitive)
///
/// Per MCP 2025-11-25 §2.5.4 the recovery is identical to the `Err` path: drop
/// the stale `MCP-Session-Id`, send a fresh `InitializeRequest`, and retry once.
fn is_session_expired_response(resp: &JsonRpcResponse) -> bool {
    resp.error.as_ref().is_some_and(|e| {
        e.code == -32015
            || e.code == -32600
            || e.message.to_lowercase().contains("session not found")
    })
}

/// HTTP transport for MCP servers using SSE or Streamable HTTP protocol
pub struct HttpTransport {
    /// HTTP client
    client: Client,
    /// Base URL (SSE endpoint or direct HTTP endpoint)
    base_url: String,
    /// Message endpoint URL (received from SSE handshake, or same as `base_url` for streamable)
    message_url: RwLock<Option<String>>,
    /// Custom headers
    headers: HashMap<String, String>,
    /// Per-caller-identity MCP session ids (MIK-6784).
    ///
    /// A single `HttpTransport` is Arc-shared across every gateway user for a
    /// given backend, so a single `Option<String>` session slot (the prior
    /// design) let the first caller's `MCP-Session-Id` be stamped onto every
    /// other caller's outbound request — a stateful upstream could then serve
    /// one user's session-bound data to another. Partitioning by the caller's
    /// stable identity binding
    /// ([`crate::identity_propagation::PropagatedCredential::cache_binding`])
    /// closes that hole: each identity negotiates and reuses its own upstream
    /// session. The empty-string key is the shared default bucket used by the
    /// no-identity static path (plain [`Transport::request`]), so single-tenant
    /// behavior is byte-for-byte unchanged.
    sessions: RwLock<HashMap<String, String>>,
    /// Set by [`HttpTransport::mark_single_tenant`] when the owning `Backend`
    /// built this instance for a per-user pool slot (MIK-6735 `PoolKey::PerUser`).
    /// `false` (the default) means this instance may be the backend's shared
    /// slot, Arc-shared across every caller — the exact scenario `sessions`
    /// exists to isolate — so it stays multi-entry and load-bearing there;
    /// only when `true` is it safe to assert the map is single-tenant. See
    /// the `debug_assert!` at the session-write site below for the invariant
    /// this hint unlocks.
    single_tenant_hint: AtomicBool,

    /// Request ID counter
    request_id: AtomicU64,
    /// Connected flag
    connected: AtomicBool,
    /// Request timeout (used in client builder)
    #[allow(dead_code)]
    timeout: Duration,
    /// Use Streamable HTTP (direct POST, no SSE handshake)
    streamable_http: bool,
    /// OAuth client for authenticated backends (Arc allows background refresh task to share it)
    oauth_client: Option<Arc<TokioMutex<OAuthClient>>>,
    /// Background token-refresh task handle, set during `initialize()`.
    /// Stored in a lock so `initialize(&self)` can assign it after construction.
    refresh_task: RwLock<Option<JoinHandle<()>>>,
    /// Protocol version override (if `None`, uses `PROTOCOL_VERSION` with fallback)
    protocol_version: RwLock<Option<String>>,
}

/// Outgoing header modes for the HTTP transport call-sites.
#[derive(Clone, Copy)]
enum HeaderMode<'a> {
    Sse,
    Request { method: &'a str },
    Notify,
    Close,
}

impl HttpTransport {
    /// Create a new HTTP transport
    ///
    /// If `streamable_http` is true, uses direct POST without SSE handshake.
    /// Otherwise uses SSE protocol (GET for endpoint, POST for messages).
    ///
    /// # Errors
    ///
    /// Returns an error if the HTTP client cannot be built.
    pub fn new(
        url: &str,
        headers: HashMap<String, String>,
        timeout: Duration,
        streamable_http: bool,
    ) -> Result<Arc<Self>> {
        Self::new_with_oauth(url, headers, timeout, streamable_http, None, None)
    }

    /// Create a new HTTP transport with optional OAuth client and protocol version
    ///
    /// # Errors
    ///
    /// Returns an error if the HTTP client cannot be built.
    pub fn new_with_oauth(
        url: &str,
        headers: HashMap<String, String>,
        timeout: Duration,
        streamable_http: bool,
        oauth_client: Option<OAuthClient>,
        protocol_version: Option<String>,
    ) -> Result<Arc<Self>> {
        let client = Client::builder()
            .timeout(timeout)
            .pool_max_idle_per_host(10)
            .pool_idle_timeout(Duration::from_secs(90))
            .tcp_keepalive(Duration::from_secs(30))
            .tcp_nodelay(true)
            .redirect(reqwest::redirect::Policy::custom(|attempt| {
                if attempt.previous().len() >= 5 {
                    return attempt.stop();
                }
                if let Err(e) = validate_url_not_ssrf(attempt.url().as_str()) {
                    return attempt.error(e.to_string());
                }
                attempt.follow()
            }))
            .build()
            .map_err(|e| Error::Transport(e.to_string()))?;

        Ok(Arc::new(Self {
            client,
            base_url: url.to_string(),
            message_url: RwLock::new(None),
            headers,
            sessions: RwLock::new(HashMap::new()),
            single_tenant_hint: AtomicBool::new(false),
            request_id: AtomicU64::new(1),
            connected: AtomicBool::new(false),
            timeout,
            streamable_http,
            oauth_client: oauth_client.map(|c| Arc::new(TokioMutex::new(c))),
            refresh_task: RwLock::new(None),
            protocol_version: RwLock::new(protocol_version),
        }))
    }

    /// Store a new OAuth refresh task, aborting any prior one.
    ///
    /// `initialize()` is re-entered on reconnect/session-expiry (see
    /// `request()`), so the refresh-task slot must be idempotent: dropping a
    /// `JoinHandle` does not cancel the spawned task, so a plain overwrite would
    /// orphan the previous refresh loop — keeping the OAuth-client `Arc` alive
    /// and continuing to persist a gateway-held token (F3, MIK-6746).
    fn store_refresh_task(&self, handle: tokio::task::JoinHandle<()>) {
        if let Some(old) = self.refresh_task.write().replace(handle) {
            old.abort();
        }
    }

    /// Mark this instance as built for a per-user pool slot (MIK-6735).
    ///
    /// `Backend::start_entry` calls this immediately after construction, and
    /// only for a `PoolKey::PerUser` slot, whose transport is dedicated to
    /// one caller identity for its whole lifetime — no other identity is ever
    /// routed through it. That is what makes the `sessions` single-tenant
    /// `debug_assert!` provably safe to enable: it must stay OFF (the
    /// default) for a `Shared`-slot instance, which is Arc-shared across
    /// every caller and relies on `sessions` staying multi-entry.
    pub(crate) fn mark_single_tenant(&self) {
        self.single_tenant_hint.store(true, Ordering::Relaxed);
    }

    /// Initialize the connection
    ///
    /// For SSE mode: establishes SSE handshake to get message endpoint
    /// For Streamable HTTP: uses URL directly (trailing slash only for localhost/Starlette)
    /// For OAuth-enabled backends: initializes OAuth client and obtains token first
    ///
    /// # Errors
    ///
    /// Returns an error if OAuth authorization fails, SSE handshake fails,
    /// or protocol version negotiation is unsuccessful.
    #[allow(clippy::too_many_lines)] // MIK-4486 OAuth detach adds ~2 lines
    pub async fn initialize(&self) -> Result<()> {
        // Initialize OAuth client if configured
        if let Some(ref oauth_arc) = self.oauth_client {
            // MIK-4486: Detach the OAuth handshake from the calling request
            // future. The interactive browser flow can take 10-30s, and most
            // MCP clients time out at 15-30s. Without `tokio::spawn`, dropping
            // the outer future would also drop the callback server, discarding
            // any browser auth that completes after the cancel. By spawning,
            // the task continues to completion and persists the token to disk
            // even when the original request is gone — so a follow-up call
            // finds a valid token and skips re-authorization.
            let oauth_arc_for_task = Arc::clone(oauth_arc);
            let base_url_for_task = self.base_url.clone();
            let oauth_task = tokio::spawn(async move {
                let mut oauth = oauth_arc_for_task.lock().await;
                oauth.initialize().await?;

                // If we don't have a valid token, trigger authorization flow
                if !oauth.has_valid_token() {
                    info!(url = %base_url_for_task, "OAuth required - initiating authorization flow");
                    oauth.authorize().await?;
                }

                Ok::<String, crate::Error>(oauth.backend_name().to_string())
            });

            let backend_name = match oauth_task.await {
                Ok(Ok(name)) => name,
                Ok(Err(e)) => return Err(e),
                Err(join_err) => {
                    return Err(crate::Error::OAuth(format!(
                        "OAuth task failed to join: {join_err}"
                    )));
                }
            };

            // Spawn background refresh task now that we have a valid token.
            // Reconnect/session-expiry re-enters initialize() (see request()),
            // so abort any prior refresh task before replacing it: dropping a
            // JoinHandle does NOT cancel the spawned task, and an orphaned
            // refresh loop keeps the OAuth-client Arc alive and keeps persisting
            // a gateway-held token (F3, MIK-6746).
            let handle = OAuthClient::spawn_refresh_task(Arc::clone(oauth_arc), backend_name);
            self.store_refresh_task(handle);
        }

        if self.streamable_http {
            // Streamable HTTP: use URL directly
            // Never add trailing slash — Dart/shelf (Pieces) returns 404 for trailing slash.
            // Starlette compatibility was the original reason, but it handles both.
            let url = self.base_url.clone();
            *self.message_url.write() = Some(url.clone());
            info!(url = %url, oauth = self.oauth_client.is_some(), "Streamable HTTP mode - direct POST");
        } else {
            // SSE mode: GET the SSE endpoint to receive the message endpoint
            let message_endpoint = self.establish_sse_connection().await?;
            let full_message_url = self.resolve_message_url(&message_endpoint)?;
            *self.message_url.write() = Some(full_message_url.clone());
            info!(sse_url = %self.base_url, message_url = %full_message_url, oauth = self.oauth_client.is_some(), "SSE handshake complete");
        }

        // Send initialize request via the message endpoint
        // Use configured protocol version if set, otherwise use latest
        let version = self
            .protocol_version
            .read()
            .clone()
            .unwrap_or_else(|| PROTOCOL_VERSION.to_string());

        let request = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            id: RequestId::Number(0),
            method: "initialize".to_string(),
            params: Some(serde_json::json!({
                "protocolVersion": version,
                "capabilities": {},
                "clientInfo": {
                    "name": "mcp-gateway",
                    "version": env!("CARGO_PKG_VERSION")
                }
            })),
        };

        let response = self.send_request(&request).await?;

        // Check for protocol version mismatch error
        if let Some(ref error) = response.error {
            let error_msg = &error.message;

            // If server rejected our protocol version, try to negotiate
            if is_version_mismatch_error(error_msg) {
                // Try to extract supported versions from error message
                if let Some(negotiated_version) = self.negotiate_protocol_version(error_msg).await {
                    warn!(
                        url = %self.base_url,
                        rejected_version = %version,
                        negotiated_version = %negotiated_version,
                        "Server rejected protocol version, retrying with negotiated version"
                    );

                    // Update our protocol version
                    *self.protocol_version.write() = Some(negotiated_version.clone());

                    // Retry initialize with new version
                    let retry_request = JsonRpcRequest {
                        jsonrpc: "2.0".to_string(),
                        id: RequestId::Number(0),
                        method: "initialize".to_string(),
                        params: Some(serde_json::json!({
                            "protocolVersion": negotiated_version,
                            "capabilities": {},
                            "clientInfo": {
                                "name": "mcp-gateway",
                                "version": env!("CARGO_PKG_VERSION")
                            }
                        })),
                    };

                    let retry_response = self.send_request(&retry_request).await?;

                    if retry_response.error.is_some() {
                        return Err(Error::Protocol(format!(
                            "Initialize failed with negotiated version {}: {:?}",
                            negotiated_version, retry_response.error
                        )));
                    }

                    // Success with negotiated version
                    info!(url = %self.base_url, version = %negotiated_version, "Successfully negotiated protocol version");
                } else {
                    return Err(Error::Protocol(format!(
                        "Protocol version negotiation failed: {error_msg}"
                    )));
                }
            } else {
                return Err(Error::Protocol(format!("Initialize failed: {error:?}")));
            }
        }

        // Some Streamable HTTP backends either close the initialize request
        // immediately or do not implement client notifications. The gateway
        // can still use request/response tools in that case, so notification
        // delivery must not make backend startup fail.
        if let Err(error) = self.notify("notifications/initialized", None).await {
            debug!(url = %self.base_url, error = %error, "Initialized notification failed (ignored)");
        }

        self.connected.store(true, Ordering::Relaxed);
        debug!(url = %self.base_url, streamable = %self.streamable_http, "HTTP transport initialized");

        Ok(())
    }

    /// Build an [`header::HeaderMap`] according to `mode`.
    ///
    /// This is the single source of truth for all outgoing request headers in
    /// this transport. The four behavioral variants are captured in
    /// [`HeaderMode`] so the asymmetries stay explicit.
    async fn build_mcp_headers(
        &self,
        mode: HeaderMode<'_>,
        identity_key: Option<&str>,
    ) -> Result<header::HeaderMap> {
        let version = self
            .protocol_version
            .read()
            .clone()
            .unwrap_or_else(|| PROTOCOL_VERSION.to_string());

        let mut headers = header::HeaderMap::new();

        if matches!(mode, HeaderMode::Request { .. } | HeaderMode::Notify) {
            headers.insert(header::CONTENT_TYPE, "application/json".parse().unwrap());
        }

        if matches!(mode, HeaderMode::Sse) {
            headers.insert(header::ACCEPT, "text/event-stream".parse().unwrap());
        } else {
            headers.insert(
                header::ACCEPT,
                "application/json, text/event-stream".parse().unwrap(),
            );
        }

        headers.insert("MCP-Protocol-Version", version.parse().unwrap());

        // OAuth token — SSE path emits an extra debug line.
        //
        // ADR-008 INV-2 (MIK-6752): this is the gateway's own static OAuth login
        // to the backend (gateway->backend), a single shared credential. Whether
        // a caller is allowed to ride it is decided UPSTREAM at dispatch by the
        // per-user isolation guard (`validate_oauth_isolation` /
        // `MetaMcp::enforce_oauth_isolation`); by the time we build headers the
        // isolation decision has already been made. `insert` replaces (never
        // appends) Authorization, so no caller-supplied header is duplicated.
        if let Some(token) = self.get_oauth_token().await? {
            headers.insert(
                header::AUTHORIZATION,
                format!("Bearer {token}").parse().unwrap(),
            );
            if matches!(mode, HeaderMode::Sse) {
                debug!(url = %self.base_url, "SSE connection with OAuth token");
            }
        }

        // Session ID — selected from the caller's identity bucket (MIK-6784)
        // so one caller's upstream session is never stamped onto another's
        // request. `None` selects the shared default bucket (`""`). send_request
        // logs whether session is present or absent; notify includes the header
        // silently; SSE skips it entirely.
        let session = self
            .sessions
            .read()
            .get(Self::bucket_key(identity_key))
            .cloned();
        if let Some(session_id) = session {
            match mode {
                HeaderMode::Request { method } => {
                    debug!(session_id = %session_id, method = %method, "Sending request with session ID");
                    headers.insert("MCP-Session-Id", session_id.parse().unwrap());
                }
                HeaderMode::Notify | HeaderMode::Close => {
                    headers.insert("MCP-Session-Id", session_id.parse().unwrap());
                }
                HeaderMode::Sse => {}
            }
        } else if let HeaderMode::Request { method } = mode {
            debug!(method = %method, "Sending request without session ID");
        }

        // User-supplied custom headers apply to all calls, including
        // notifications, because some backends require the same auth header for
        // `notifications/initialized` as for normal requests.
        for (key, value) in &self.headers {
            if let (Ok(k), Ok(v)) = (
                key.parse::<reqwest::header::HeaderName>(),
                value.parse::<reqwest::header::HeaderValue>(),
            ) {
                headers.insert(k, v);
            }
        }

        // Ambient trace ID (send_request only; not SSE or notify).
        if matches!(mode, HeaderMode::Request { .. })
            && let Some(trace_id) = trace::current()
            && let Ok(v) = trace_id.parse::<reqwest::header::HeaderValue>()
        {
            headers.insert("x-trace-id", v);
        }

        Ok(headers)
    }

    /// Get OAuth access token if OAuth is configured
    async fn get_oauth_token(&self) -> Result<Option<String>> {
        if let Some(ref oauth_mutex) = self.oauth_client {
            let oauth = oauth_mutex.lock().await;
            let token = oauth.get_token().await?;
            Ok(Some(token))
        } else {
            Ok(None)
        }
    }

    /// Negotiate protocol version from error message.
    ///
    /// Delegates to shared helpers in [`crate::protocol::negotiate`].
    #[allow(clippy::unused_async)] // async for future network-based negotiation
    async fn negotiate_protocol_version(&self, error_msg: &str) -> Option<String> {
        let supported_versions = parse_supported_versions_from_error(error_msg)?;

        debug!(
            url = %self.base_url,
            server_versions = ?supported_versions,
            "Negotiating protocol version"
        );

        let result = negotiate_best_version(&supported_versions);

        if result.is_none() {
            warn!(
                url = %self.base_url,
                server_versions = ?supported_versions,
                "No compatible protocol version found"
            );
        }

        result.map(str::to_string)
    }

    /// Establish SSE connection and get the message endpoint
    async fn establish_sse_connection(&self) -> Result<String> {
        use futures::StreamExt;

        let headers = self.build_mcp_headers(HeaderMode::Sse, None).await?;

        debug!(url = %self.base_url, "Establishing SSE connection");

        let response = self
            .client
            .get(&self.base_url)
            .headers(headers)
            .send()
            .await
            .map_err(|e| Error::Transport(format!("SSE connection failed: {e}")))?;

        let status = response.status();
        if !status.is_success() {
            return Err(Error::Transport(format!("SSE endpoint returned: {status}")));
        }

        // Stream the SSE response to find the endpoint event
        // We only need to read until we get the endpoint event, then stop
        let mut stream = response.bytes_stream();
        let mut buffer = String::new();
        let mut event_type: Option<String> = None;

        // Bound the unparsed handshake buffer at 64 KiB. The endpoint event is
        // a single short SSE line; complete lines are drained below, so a
        // well-behaved backend never approaches this. A compromised/misbehaving
        // backend streaming bytes without a newline is capped here rather than
        // growing `buffer` without limit (trusted-backend DoS defence in depth).
        let max_sse_handshake_buffer: usize = 64 * 1024;

        while let Some(chunk_result) = stream.next().await {
            let chunk = chunk_result
                .map_err(|e| Error::Transport(format!("Failed to read SSE chunk: {e}")))?;

            buffer.push_str(&String::from_utf8_lossy(&chunk));

            if buffer.len() > max_sse_handshake_buffer {
                return Err(Error::Transport(format!(
                    "SSE handshake exceeded {max_sse_handshake_buffer}-byte buffer without an endpoint event"
                )));
            }

            // Process complete lines in the buffer
            while let Some(newline_pos) = buffer.find('\n') {
                let line = buffer[..newline_pos].trim().to_string();
                buffer = buffer[newline_pos + 1..].to_string();

                if line.is_empty() {
                    event_type = None;
                    continue;
                }

                if let Some(event) = line.strip_prefix("event:") {
                    event_type = Some(event.trim().to_string());
                } else if let Some(data) = line.strip_prefix("data:") {
                    let data = data.trim();

                    if event_type.as_deref() == Some("endpoint") {
                        debug!(endpoint = %data, "Received message endpoint from SSE");

                        // Extract session_id from the endpoint URL if present.
                        // The SSE handshake is connection-level (not per-caller),
                        // so an endpoint-embedded session lands in the shared
                        // default bucket (MIK-6784).
                        if let Ok(url) = Url::parse(data)
                            .or_else(|_| Url::parse(&format!("http://localhost{data}")))
                        {
                            for (key, value) in url.query_pairs() {
                                if key == "session_id" {
                                    self.sessions
                                        .write()
                                        .insert(String::new(), value.to_string());
                                    debug!(session_id = %value, "Extracted session ID");
                                }
                            }
                        }

                        return Ok(data.to_string());
                    }
                }
            }
        }

        Err(Error::Transport(
            "SSE stream ended without endpoint event. Server may not support MCP SSE protocol."
                .to_string(),
        ))
    }

    /// Resolve a potentially relative message URL against the SSE URL.
    ///
    /// The `endpoint` value is backend-controlled (it arrives on the SSE
    /// stream). Per the MCP SSE spec the message endpoint MUST be same-origin
    /// as the SSE stream. Every endpoint — absolute, relative, network-path
    /// (`//host/x`), backslash (`\\host`, `/\host`), or scheme-relative
    /// (`https:/\/\host`) — is **resolved against the base URL first**, then the
    /// *resolved* origin is checked. Classifying by string prefix instead
    /// (`starts_with("http://")`) is unsafe: WHATWG URL resolution normalizes
    /// backslashes to slashes and treats `//host` as an authority-relative
    /// reference, so `base.join("//169.254.169.254/x")` REPLACES the authority
    /// and yields a cross-origin URL despite not starting with a scheme. Without
    /// checking the resolved origin, a malicious backend could return
    /// `data: //169.254.169.254/latest/meta-data/...` and the gateway would POST
    /// the JSON-RPC request together with the per-user identity credential
    /// headers (`Authorization: Bearer <assertion>`, MIK-6704) to an
    /// attacker-chosen internal / metadata host — an SSRF + credential-exfil
    /// vector. Same-origin equality (rather than the outbound SSRF guard) is
    /// used deliberately: legitimate MCP backends commonly bind to loopback,
    /// which a private/loopback SSRF reject would break — the real defect is a
    /// *cross-origin* redirect of credentials, which same-origin equality stops.
    fn resolve_message_url(&self, endpoint: &str) -> Result<String> {
        let base_url = Url::parse(&self.base_url)
            .map_err(|e| Error::Transport(format!("Invalid SSE URL: {e}")))?;

        // Resolve every endpoint shape against the base, then validate the
        // *resolved* origin. `Url::join` handles absolute and relative inputs
        // alike, so absolute and relative branches collapse into one path — and
        // authority-replacing shapes (`//host`, `\\host`, `https:/\/\host`) can
        // no longer slip past a prefix-based classifier.
        let resolved = base_url
            .join(endpoint)
            .map_err(|e| Error::Transport(format!("Failed to resolve endpoint URL: {e}")))?;

        if !same_origin(&base_url, &resolved) {
            return Err(Error::Transport(
                "SSE message endpoint is cross-origin to the SSE stream; \
                 refusing to send credentials to a different host"
                    .to_string(),
            ));
        }

        Ok(resolved.to_string())
    }

    /// Get the message URL, falling back to SSE URL if not set
    fn get_message_url(&self) -> String {
        self.message_url
            .read()
            .clone()
            .unwrap_or_else(|| self.base_url.clone())
    }

    /// Send a raw request to the message endpoint
    async fn send_request(&self, request: &JsonRpcRequest) -> Result<JsonRpcResponse> {
        self.send_request_with_headers(request, &[], None).await
    }

    /// Send a raw request, merging `extra_headers` into the outbound header set
    /// after the standard headers are built. Used for per-request identity
    /// credentials (MIK-6704): the credential is applied here, on the value
    /// passed down the call stack, never on shared `&self` state.
    ///
    /// `identity_key` selects the caller's `MCP-Session-Id` bucket (MIK-6784):
    /// the request is stamped with — and the response's session id is stored
    /// under — that caller's key, so a stateful upstream cannot serve one
    /// user's session-bound data to another. `None` uses the shared default
    /// bucket, preserving single-tenant behavior.
    async fn send_request_with_headers(
        &self,
        request: &JsonRpcRequest,
        extra_headers: &[(String, String)],
        identity_key: Option<&str>,
    ) -> Result<JsonRpcResponse> {
        let message_url = self.get_message_url();

        let mut headers = self
            .build_mcp_headers(
                HeaderMode::Request {
                    method: &request.method,
                },
                identity_key,
            )
            .await?;
        // Per-request identity credential headers (e.g. Authorization: Bearer
        // <assertion>) override any static header of the same name for this call.
        for (k, v) in extra_headers {
            if let (Ok(name), Ok(value)) = (
                k.parse::<header::HeaderName>(),
                v.parse::<header::HeaderValue>(),
            ) {
                headers.insert(name, value);
            }
        }

        let response = self
            .client
            .post(&message_url)
            .headers(headers)
            .json(request)
            .send()
            .await
            .map_err(|e| Error::Transport(format!("Request failed: {e}")))?;

        // Extract session ID from response headers if this caller's bucket is
        // empty (MIK-6784: store under the caller's identity key, never a shared
        // slot). The first request for a new identity has no session; the
        // upstream mints one and we bind it to that identity for reuse.
        let bucket = Self::bucket_key(identity_key);
        if self.sessions.read().contains_key(bucket) {
            debug!("Using existing session ID for caller bucket");
        } else if let Some(session_id) = response.headers().get("mcp-session-id") {
            if let Ok(id) = session_id.to_str() {
                info!(session_id = %id, url = %message_url, "Stored session ID from response");
                self.sessions
                    .write()
                    .insert(bucket.to_string(), id.to_string());
                // Maintainability guard (MIK-6735 fix 2): under a per-user
                // pool slot this instance serves exactly one caller identity
                // for life, so `sessions` is provably <=1 entry — do NOT
                // "simplify" this map to a single `Option<String>` on the
                // strength of that; it stays multi-entry and load-bearing
                // for the Shared slot (Stateless-mode backends and the
                // no-identity path), which is Arc-shared across every caller
                // and relies on this map to keep each identity's
                // `MCP-Session-Id` isolated (MIK-6784).
                debug_assert!(
                    !self.single_tenant_hint.load(Ordering::Relaxed)
                        || self.sessions.read().len() <= 1,
                    "per-user pool slot's transport must never accumulate more \
                     than one caller identity's session"
                );
            }
        } else {
            // Debug: log all headers to find session ID
            debug!(url = %message_url, "No session ID in response. Headers: {:?}",
                response.headers().iter()
                    .map(|(k, v)| format!("{}: {}", k, v.to_str().unwrap_or("?")))
                    .collect::<Vec<_>>()
            );
        }

        let status = response.status();
        if !status.is_success() {
            let body = response.text().await.unwrap_or_default();
            return Err(Error::Transport(format!("HTTP {status}: {body}")));
        }

        // Check Content-Type to determine response format
        let content_type = response
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");

        if content_type.contains("text/event-stream") {
            // Parse SSE response - extract JSON from "data:" line
            let text = response
                .text()
                .await
                .map_err(|e| Error::Transport(format!("Failed to read SSE response: {e}")))?;

            // Find the data line and extract JSON
            for line in text.lines() {
                if let Some(data) = line.strip_prefix("data:") {
                    let json_str = data.trim();
                    return serde_json::from_str(json_str)
                        .map_err(|e| Error::Transport(format!("Failed to parse SSE data: {e}")));
                }
            }
            Err(Error::Transport("No data in SSE response".to_string()))
        } else {
            // Parse JSON response
            response
                .json()
                .await
                .map_err(|e| Error::Transport(format!("Failed to parse response: {e}")))
        }
    }

    /// Get next request ID
    #[allow(clippy::cast_possible_wrap)] // request IDs won't exceed i64::MAX
    fn next_id(&self) -> RequestId {
        RequestId::Number(self.request_id.fetch_add(1, Ordering::Relaxed) as i64)
    }

    /// Map an optional caller identity key to its session-bucket key (MIK-6784).
    ///
    /// `None` (the no-identity static path) maps to the shared default bucket
    /// (`""`), so single-tenant behavior is byte-for-byte unchanged; a present
    /// key selects that caller's private bucket.
    fn bucket_key(identity_key: Option<&str>) -> &str {
        identity_key.unwrap_or("")
    }
}

#[async_trait]
impl Transport for HttpTransport {
    async fn request(&self, method: &str, params: Option<Value>) -> Result<JsonRpcResponse> {
        self.request_with_headers(method, params, &[], None).await
    }

    async fn request_with_headers(
        &self,
        method: &str,
        params: Option<Value>,
        extra_headers: &[(String, String)],
        identity_key: Option<&str>,
    ) -> Result<JsonRpcResponse> {
        let request = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            id: self.next_id(),
            method: method.to_string(),
            params,
        };

        let result = self
            .send_request_with_headers(&request, extra_headers, identity_key)
            .await;

        // MIK-5982 / MIK-6040: when the backend's session expires (daemon restart,
        // or a remote invalidating the MCP session on OAuth token refresh), every
        // request — including circuit-breaker half-open probes — keeps failing
        // until we re-handshake (observed live 2026-06-11: hebb unreachable 6.5h
        // while healthy). Recovery lives here, inside `request`, so it also rescues
        // half-open probes and is not gated behind the Backend failsafe/CB.
        //
        // The expiry arrives in one of two shapes, handled by one coherent path:
        //   1. transport `Err` — non-2xx HTTP (404, or -32015 body) or a transport
        //      failure, classified by `is_session_expired_error` (MIK-5982).
        //   2. `Ok(JsonRpcResponse)` whose `error` member signals expiry even with
        //      a 200 status (e.g. remotes returning `-32600`/`-32015`/"session not
        //      found"), classified by `is_session_expired_response` (MIK-6040, #247).
        //
        // On either signature: drop the session, re-run the initialize handshake,
        // and retry the original request exactly once. Only this caller's session
        // bucket is dropped (MIK-6784) — one identity's expiry must not evict
        // another's live session. `initialize()` calls `send_request` directly
        // (not `request`), so this cannot recurse.
        let bucket = Self::bucket_key(identity_key);
        let had_session = self.sessions.read().contains_key(bucket);
        let session_expired = match &result {
            Err(err) => is_session_expired_error(err),
            Ok(resp) => is_session_expired_response(resp),
        };
        if had_session && session_expired {
            warn!(
                url = %self.base_url,
                method = %method,
                "Backend session expired; re-initializing and retrying once"
            );
            self.sessions.write().remove(bucket);
            self.initialize().await?;
            return self
                .send_request_with_headers(&request, extra_headers, identity_key)
                .await;
        }

        result
    }

    // MIK-6710: HTTP is the only transport whose `request_with_headers`
    // actually applies `extra_headers` to the wire (see
    // `send_request_with_headers` above) — the identity-propagation dispatch
    // gate relies on this override to allow a `required` backend to proceed.
    fn carries_identity_headers(&self) -> bool {
        true
    }

    async fn notify(&self, method: &str, params: Option<Value>) -> Result<()> {
        self.notify_with_headers(method, params, None).await
    }

    // MIK-6735 fix 2: threads `identity_key` into `build_mcp_headers` so a
    // notification for a per-user identity selects that same identity's
    // `MCP-Session-Id` bucket — previously every notification hardcoded
    // `HeaderMode::Notify, None`, i.e. the shared bucket, even when it
    // correlated a request that had gone out on a per-user session.
    async fn notify_with_headers(
        &self,
        method: &str,
        params: Option<Value>,
        identity_key: Option<&str>,
    ) -> Result<()> {
        let message_url = self.get_message_url();

        let notification = JsonRpcNotification {
            jsonrpc: "2.0".to_string(),
            method: method.to_string(),
            params,
        };

        let headers = self
            .build_mcp_headers(HeaderMode::Notify, identity_key)
            .await?;

        let response = self
            .client
            .post(&message_url)
            .headers(headers)
            .json(&notification)
            .send()
            .await
            .map_err(|e| Error::Transport(format!("Notification failed: {e}")))?;

        if !response.status().is_success() {
            // Many HTTP backends (e.g. exa, beeper) do not support MCP
            // notifications and return 4xx. This is expected behaviour — log at
            // DEBUG so it does not spam the operator logs.
            debug!(
                status = %response.status(),
                url = %message_url,
                method = method,
                "Notification not supported by backend (ignored)"
            );
        }

        Ok(())
    }

    fn is_connected(&self) -> bool {
        self.connected.load(Ordering::Relaxed)
    }

    async fn close(&self) -> Result<()> {
        self.connected.store(false, Ordering::Relaxed);

        // Abort the OAuth token-refresh background task, if any. Otherwise a
        // stopped or hot-reloaded backend leaves an orphaned task that still
        // owns the OAuth client Arc and can refresh + persist a gateway-held
        // backend token via TokenStorage::save without ever re-entering
        // create_oauth_client — the F3 reload sink-completeness hole (MIK-6746).
        if let Some(handle) = self.refresh_task.write().take() {
            handle.abort();
        }

        // Send session termination for every per-identity session (MIK-6784).
        // Each caller negotiated its own upstream session, so closing the
        // transport must terminate all of them, not just one shared slot.
        let sessions: Vec<(String, String)> = self
            .sessions
            .read()
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        let message_url = self.get_message_url();

        for (bucket, id) in sessions {
            let request = match self
                .build_mcp_headers(HeaderMode::Close, Some(&bucket))
                .await
            {
                Ok(headers) => self.client.delete(&message_url).headers(headers),
                Err(error) => {
                    warn!(
                        error = %error,
                        url = %message_url,
                        "Failed to build full close headers; falling back to session header only"
                    );
                    self.client
                        .delete(&message_url)
                        .header("MCP-Session-Id", &id)
                }
            };

            let _ = request.send().await;
        }

        Ok(())
    }
}

// ADR-008 / F3 (MIK-6746): RAII backstop — a discarded/partial-init transport
// must not leak a token-refresh loop. `initialize()` stores the refresh
// `JoinHandle` before `establish_sse_connection().await?`; if that `?` fails, or
// the transport is otherwise dropped without an awaited `close()`, the handle is
// dropped, which *detaches* (does not cancel) the tokio task — orphaning a loop
// that keeps refreshing + persisting a gateway-held OAuth token. Aborting on drop
// closes that no-close path. Composes with `close()`: after close the slot is
// `None`, so this abort is a no-op (no double abort).
impl Drop for HttpTransport {
    fn drop(&mut self) {
        if let Some(handle) = self.refresh_task.get_mut().take() {
            handle.abort();
        }
    }
}

#[cfg(test)]
mod tests;

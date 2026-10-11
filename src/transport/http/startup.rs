// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Connection startup: initialize, the legacy SSE handshake and version negotiation.

use std::sync::Arc;
use std::sync::atomic::Ordering;

use reqwest::header;
use serde_json::Value;
use tracing::{debug, info, warn};
use url::Url;

use super::super::sanitize_url_for_diagnostics;
use super::{HTTP_TARGET, HeaderMode, HttpTransport, same_origin};
use crate::oauth::OAuthClient;
use crate::protocol::era::Era;
use crate::protocol::meta::MODERN_VERSIONS;
use crate::protocol::{
    JsonRpcRequest, JsonRpcResponse, PROTOCOL_VERSION, RequestId, Selectable, checked_selection,
    is_version_mismatch_error, negotiate_best_version, parse_supported_versions_from_error,
};
use crate::security::http_diagnostics::safe_request_error;
use crate::{Error, Result};

/// The OAuth task's join failure (it panicked or was cancelled) as the error
/// `connect` returns for it.
fn join_failure(join_err: &tokio::task::JoinError) -> crate::Error {
    crate::Error::OAuth(format!("OAuth task failed to join: {join_err}"))
}

impl HttpTransport {
    /// Initialize the connection
    ///
    /// For SSE mode: establishes SSE handshake to get message endpoint
    /// For Streamable HTTP: uses URL directly (trailing slash only for localhost/Starlette)
    /// For OAuth-enabled backends: initializes OAuth client and obtains token first
    ///
    /// Still the legacy startup, whole: [`Self::connect`] then the handshake.
    /// The start path no longer calls it (it asks first — see
    /// [`Self::finish_startup`]), but the session-expiry recovery in
    /// `request_with_headers` re-enters exactly this, and a peer that issued a
    /// session is by definition one we handshook with.
    ///
    /// # Errors
    ///
    /// Returns an error if OAuth authorization fails, SSE handshake fails,
    /// or protocol version negotiation is unsuccessful.
    pub async fn initialize(&self) -> Result<()> {
        self.connect().await?;
        self.handshake().await
    }

    /// Everything a request needs before one can be sent: the OAuth token and
    /// its refresh task, and the message endpoint.
    ///
    /// Split out of [`Self::initialize`] for RFC-0061 §2.4: the era probe is a
    /// real request, so it needs a credential and an endpoint, and it must go
    /// out *before* any handshake decision. Re-running the whole of
    /// `initialize` for the probe and again for the fallback would run the
    /// OAuth flow twice per start and replace a refresh task that is already
    /// the right one.
    ///
    /// # Errors
    ///
    /// Returns an error if OAuth authorization or the SSE handshake fails.
    pub(crate) async fn connect(&self) -> Result<()> {
        // Initialize OAuth client if configured
        if let Some(ref oauth_arc) = self.oauth_client {
            // MIK-4486: Detach the OAuth handshake from the calling request future. The interactive
            // browser flow can take 10-30s, and most MCP clients time out at 15-30s. Without
            // `tokio::spawn`, dropping the outer future would also drop the callback server,
            // discarding any browser auth that completes after the cancel. By spawning, the task
            // continues to completion and persists the token to disk even when the original request
            // is gone — so a follow-up call finds a valid token and skips re-authorization.
            let oauth_arc_for_task = Arc::clone(oauth_arc);
            let base_url_for_task = self.base_url.clone();
            // Read here: the spawned task does not inherit the caller's scope.
            let interactive = crate::oauth::login_gate::interactive();
            // Captured here, before the task queues on anything (MIK-8339): a
            // start's own set-out epoch and cohort, else the gate's now. A
            // restart or stop after this point refuses this login.
            let gate = self.login_gate.clone();
            let set_out = gate.as_ref().map(|gate| gate.set_out_now());
            let since = set_out.as_ref().map(|set_out| set_out.since);
            let cohort = set_out.as_ref().map(|set_out| Arc::clone(&set_out.cohort));
            let deadline = set_out.as_ref().map(|set_out| set_out.deadline);
            let refused_name = sanitize_url_for_diagnostics(&self.base_url);
            let oauth_task = tokio::spawn(async move {
                let cancelled = || crate::Error::AuthorizationCancelled {
                    backend: refused_name.clone(),
                };
                // A pre-login stage that outlived the start's deadline: the
                // cohort's recorded failure if there is one.
                let timed_out = |gate: &crate::oauth::login_gate::LoginGate| {
                    let otherwise = crate::Error::BackendTimeout(refused_name.clone());
                    match &cohort {
                        Some(cohort) => gate.classify(cohort, &refused_name, otherwise),
                        None => otherwise,
                    }
                };
                // A non-interactive caller (the health probe) never waits on
                // the client mutex a login holds for minutes (MIK-7982 C2).
                // An interactive one waits under the start's revocation and
                // the authorization window (MIK-8339).
                let mut oauth = if !interactive {
                    oauth_arc_for_task.try_lock().map_err(|_| {
                        crate::Error::AuthorizationRequired {
                            backend: refused_name.clone(),
                        }
                    })?
                } else if let (Some(gate), Some(since), Some(deadline)) = (&gate, since, deadline) {
                    tokio::select! {
                        biased;
                        () = gate.revoked_since(since) => return Err(cancelled()),
                        () = tokio::time::sleep_until(crate::oauth::login_gate::stage_end(
                            crate::oauth::OAUTH_AUTHORIZATION_WINDOW,
                            deadline,
                        )) => return Err(timed_out(gate)),
                        oauth = oauth_arc_for_task.lock() => oauth,
                    }
                } else {
                    oauth_arc_for_task.lock().await
                };
                // Discovery, before any login: a restart or stop ends it, and
                // so does the start's deadline.
                if let (Some(gate), Some(since)) = (&gate, since) {
                    tokio::select! {
                        biased;
                        () = gate.revoked_since(since) => return Err(cancelled()),
                        () = crate::oauth::login_gate::past(deadline) => return Err(timed_out(gate)),
                        initialized = oauth.initialize() => initialized?,
                    }
                } else {
                    oauth.initialize().await?;
                }

                // If we don't have a valid token, trigger authorization flow
                if !oauth.has_valid_token() {
                    // Computed before the macro, so its head line holds no call (MIK-7725).
                    let url = sanitize_url_for_diagnostics(&base_url_for_task);
                    info!(target: HTTP_TARGET, url = %url, "OAuth required - initiating authorization flow");
                    oauth
                        .authorize_shared_with(interactive, since, cohort.as_ref(), deadline)
                        .await?;
                }

                Ok::<String, crate::Error>(oauth.backend_name().to_string())
            });

            let backend_name = oauth_task.await.map_err(|e| join_failure(&e))??;

            // Spawn background refresh task now that we have a valid token.
            // Reconnect/session-expiry re-enters initialize() (see request()),
            // so abort any prior refresh task before replacing it: dropping a
            // JoinHandle does NOT cancel the spawned task, and an orphaned
            // refresh loop keeps the OAuth-client Arc alive and keeps persisting
            // a gateway-held token (F3, MIK-6746).
            let handle = OAuthClient::spawn_refresh_task(Arc::clone(oauth_arc), backend_name);
            self.store_refresh_task(handle);
        }

        self.switched.store(false, Ordering::Relaxed);
        if *self.streamable_http.read() == Some(false) {
            let Err(sse_error) = self.connect_sse().await else {
                return Ok(());
            };
            // Configs written before detection existed say `false` for
            // servers that only speak Streamable HTTP; such a server refuses
            // the GET, so try the other transport once.
            let Some(status) = refused_as_wrong_transport(&sse_error) else {
                return Err(sse_error);
            };
            let url = sanitize_url_for_diagnostics(&self.base_url);
            info!(target: HTTP_TARGET, url = %url, status, "SSE GET refused; trying Streamable HTTP");
            *self.streamable_http.write() = Some(true);
            self.switched.store(true, Ordering::Relaxed);
        }
        // Streamable HTTP, or a flavour not yet detected: the MCP
        // backwards-compatibility rule POSTs first, and `handshake` falls back.
        // Never add trailing slash — Dart/shelf (Pieces) returns 404 for trailing slash.
        // Starlette compatibility was the original reason, but it handles both.
        let url = self.base_url.clone();
        *self.message_url.write() = Some(url.clone());
        let (diagnostic_url, oauth) = (
            sanitize_url_for_diagnostics(&url),
            self.oauth_client.is_some(),
        );
        info!(target: HTTP_TARGET, url = %diagnostic_url, oauth, "Streamable HTTP mode - direct POST");
        Ok(())
    }

    /// SSE mode: GET the SSE endpoint to receive the message endpoint.
    async fn connect_sse(&self) -> Result<()> {
        let message_endpoint = self.establish_sse_connection().await?;
        let full_message_url = self.resolve_message_url(&message_endpoint)?;
        *self.message_url.write() = Some(full_message_url.clone());
        info!(target: HTTP_TARGET, sse_url = %sanitize_url_for_diagnostics(&self.base_url), message_url = %sanitize_url_for_diagnostics(full_message_url.as_str()), oauth = self.oauth_client.is_some(), "SSE handshake complete");
        Ok(())
    }

    /// [`Self::legacy_handshake`], with the MCP backwards-compatibility
    /// fallback: a 4xx refusal of the `initialize` POST means a legacy
    /// HTTP+SSE server, so open its SSE stream and handshake over the endpoint
    /// it names. It applies to an explicit `streamable_http: true` as well, so
    /// a wrong flag costs one refused request rather than the backend. At most
    /// one switch per start: not after [`Self::connect`] already switched, and
    /// never away from an SSE endpoint that answered.
    async fn handshake(&self) -> Result<()> {
        if *self.streamable_http.read() == Some(false) {
            return self.legacy_handshake().await;
        }
        let Err(post_error) = self.legacy_handshake().await else {
            *self.streamable_http.write() = Some(true);
            return Ok(());
        };
        if self.switched.load(Ordering::Relaxed) {
            return Err(post_error);
        }
        let Some(status) = refused_as_wrong_transport(&post_error) else {
            return Err(post_error);
        };
        info!(target: HTTP_TARGET, url = %sanitize_url_for_diagnostics(&self.base_url), status, "Streamable HTTP POST refused; falling back to the legacy SSE transport");
        // Both answers, so a mistyped URL is not reported as an SSE fault alone.
        self.connect_sse().await.map_err(|sse_error| {
            Error::Transport(format!(
                "POST initialize returned HTTP {status}, and the legacy SSE fallback failed: {sse_error}"
            ))
        })?;
        *self.streamable_http.write() = Some(false);
        self.switched.store(true, Ordering::Relaxed);
        self.legacy_handshake().await
    }

    /// The flavour this transport connected with, once known: `Some(true)`
    /// for Streamable HTTP, `Some(false)` for the legacy SSE handshake.
    pub(crate) fn streamable(&self) -> Option<bool> {
        *self.streamable_http.read()
    }

    /// Finish a connected start in the dialect `era` names (RFC-0061 §2.4).
    ///
    /// `Modern` is the whole point of asking first: the 2026 revision removed
    /// the handshake, so a modern peer is usable the moment the transport is
    /// connected, and sending it an `initialize` it must reject is what kept
    /// this gateway off every stateless backend. Anything else — a legacy
    /// answer, an unrecognised error, silence — takes the handshake unchanged.
    ///
    /// The caller awaits the era cache commit and passes the resolved verdict
    /// explicitly, keeping the handshake decision tied to that probe.
    ///
    /// # Errors
    ///
    /// Returns an error if the legacy handshake fails. The modern branch has
    /// nothing left to fail at.
    pub(crate) async fn finish_startup(&self, era: Era) -> Result<()> {
        match era {
            Era::Modern => {
                // A modern answer came over a POST: the peer is streamable.
                let mut flavour = self.streamable_http.write();
                if flavour.is_none() {
                    *flavour = Some(true);
                }
                drop(flavour);
                self.connected.store(true, Ordering::Relaxed);
                debug!(target: HTTP_TARGET,
                    url = %sanitize_url_for_diagnostics(&self.base_url),
                    "Modern peer: started without a handshake"
                );
                Ok(())
            }
            Era::Legacy => self.handshake().await,
        }
    }

    /// The 2025 handshake: `initialize`, version negotiation, `initialized`.
    ///
    /// Unchanged from the body `initialize()` has always run. It assumes
    /// [`Self::connect`] has already resolved the endpoint and the credential.
    #[allow(clippy::too_many_lines)] // MIK-4486 OAuth detach adds ~2 lines
    pub(super) async fn legacy_handshake(&self) -> Result<()> {
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

        // A status-level rejection carries the server's supported list and nothing else the gateway
        // may repeat. Negotiate from it and retry once, which is the same move the JSON-RPC-error
        // branch below makes for backends that reject in band. Both rejection branches write
        // `protocol_version` before their retry, because the outbound header is built from it. A
        // handshake that then fails must not leave the transport claiming a version no backend ever
        // agreed to, so the negotiation runs inside one block whose single error exit restores what
        // was there before.
        let previous_version = self.protocol_version.read().clone();
        let negotiated: Result<JsonRpcResponse> = async {
        let response = match self.send_request(&request).await {
            Ok(response) => response,
            Err(Error::ProtocolVersionRejected { supported }) => {
                let Some(negotiated) = negotiate_best_version(&supported) else {
                    return Err(Error::Protocol(format!(
                        "Backend rejected protocol version {version} and shares none this gateway speaks; it supports: {}",
                        supported.join(", ")
                    )));
                };
                warn!(target: HTTP_TARGET,
                    url = %sanitize_url_for_diagnostics(&self.base_url),
                    rejected_version = %version,
                    negotiated_version = %negotiated,
                    "Backend rejected protocol version by HTTP status, retrying with negotiated version"
                );
                // The proposal is edited, not rebuilt: a second construction
                // site drifts from the first the moment either grows a field,
                // and this retry is the one path that must present the same
                // client as the attempt that was refused.
                let mut retry = request.clone();
                if let Some(params) = retry.params.as_mut() {
                    params["protocolVersion"] = Value::String(negotiated.to_string());
                }
                // Set before the send because the outbound header is built
                // from it; the block's error exit restores it if this fails.
                *self.protocol_version.write() = Some(negotiated.to_string());
                self.send_request(&retry).await?
            }
            Err(other) => return Err(other),
        };

        // Check for protocol version mismatch error
        let Some(error) = response.error.as_ref() else {
            return Ok(response);
        };
        let error_msg = &error.message;
        if !is_version_mismatch_error(error_msg) {
            // Code only. The message and data are backend-controlled and may
            // quote back credentials the gateway sent.
            return Err(Error::Protocol(format!(
                "Initialize failed: backend error code {}",
                error.code
            )));
        }
        let Some(negotiated_version) = self.negotiate_protocol_version(error_msg).await else {
            return Err(Error::Protocol(format!(
                // Code only. `error_msg` is the backend's own text and may
                // quote back a credential the gateway sent it.
                "Protocol version negotiation failed: backend error code {}",
                error.code
            )));
        };
        warn!(target: HTTP_TARGET,
            url = %sanitize_url_for_diagnostics(&self.base_url),
            rejected_version = %version,
            negotiated_version = %negotiated_version,
            "Server rejected protocol version, retrying with negotiated version"
        );

        // Set before the send because the outbound header is built from it;
        // the block's error exit restores it if the retry fails.
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

        if let Some(err) = &retry_response.error {
            return Err(Error::Protocol(format!(
                "Initialize failed with negotiated version {}: backend error code {}",
                negotiated_version, err.code
            )));
        }

        let url = sanitize_url_for_diagnostics(&self.base_url);
        info!(target: HTTP_TARGET, url = %url, version = %negotiated_version, "Successfully negotiated protocol version");
        // The retry is the handshake that succeeded, so it carries the
        // selection to adopt. Reading the rejection instead would leave the
        // server's choice on the retry neither validated nor adopted.
        Ok(retry_response)
        }
        .await;

        let response = match negotiated {
            Ok(response) => response,
            Err(error) => {
                *self.protocol_version.write() = previous_version;
                return Err(error);
            }
        };

        // The client proposes and the server selects. Whatever it selected
        // governs the `MCP-Protocol-Version` header from here on; without this
        // the gateway kept announcing its own latest to a backend that had
        // already told it otherwise, which is the gateway violating the
        // negotiation it opened.
        if let Some(selected) = checked_selection(response.result.as_ref(), Selectable::Legacy)? {
            *self.protocol_version.write() = Some(selected.to_string());
        }

        // Some Streamable HTTP backends either close the initialize request
        // immediately or do not implement client notifications. The gateway
        // can still use request/response tools in that case, so notification
        // delivery must not make backend startup fail.
        //
        // `send_notification` with era `None`, not `notify`: this notification
        // is the second half of the handshake, and `initialize()` is re-entered
        // on reconnect and on session expiry — by which time the era cache can
        // already say `Modern`. Shaping it by era would send a 2026-shaped
        // `initialized` beside a 2025 `initialize`, to a peer we are still
        // introducing ourselves to. `send_request` refuses the era here for the
        // same reason.
        if let Err(error) = self
            .send_notification("notifications/initialized", None, &[], None, None)
            .await
        {
            let url = sanitize_url_for_diagnostics(&self.base_url);
            debug!(target: HTTP_TARGET, url = %url, error = %error, "Initialized notification failed (ignored)");
        }

        self.connected.store(true, Ordering::Relaxed);
        let (url, streamable) = (
            sanitize_url_for_diagnostics(&self.base_url),
            *self.streamable_http.read(),
        );
        debug!(target: HTTP_TARGET, url = %url, streamable = ?streamable, "HTTP transport initialized");

        Ok(())
    }

    /// Negotiate protocol version from error message.
    ///
    /// Delegates to shared helpers in [`crate::protocol::negotiate`].
    #[allow(unknown_lints, clippy::unused_async, clippy::unused_async_trait_impl)] // async for future network-based negotiation
    pub(super) async fn negotiate_protocol_version(&self, error_msg: &str) -> Option<String> {
        let supported_versions = parse_supported_versions_from_error(error_msg)?;

        debug!(target: HTTP_TARGET,
            url = %sanitize_url_for_diagnostics(&self.base_url),
            server_versions = ?supported_versions,
            "Negotiating protocol version"
        );

        let result = negotiate_best_version(&supported_versions);

        if result.is_none() {
            warn!(target: HTTP_TARGET,
                url = %sanitize_url_for_diagnostics(&self.base_url),
                server_versions = ?supported_versions,
                "No compatible protocol version found"
            );
        }

        result.map(str::to_string)
    }

    /// Establish SSE connection and get the message endpoint
    ///
    /// `initialize()` re-enters this on session expiry, by which time
    /// `outbound_era()` may already read `Modern` (MIK-7214.HEADER.9a/.9b,
    /// `docs/design/2026-09-03-header-9-era-conditional-outbound.md`). The
    /// builder always writes the legacy handshake version, so a reconnect to
    /// an already-classified peer is re-asserted here, after the builder's
    /// static-header merge — the same ordering the `Request`/`Notify`
    /// finalisation needs, and for the same reason: sited earlier, an
    /// operator's pinned header would win. Two headers only, not the full
    /// `finalise_modern_headers` set: `Mcp-Method`/`Mcp-Name` mirror a
    /// JSON-RPC body field and this `GET` has no body to mirror.
    /// `MCP-Session-Id` is removed rather than merely left unminted —
    /// `build_mcp_headers`'s `Sse` arm never mints one, but an
    /// operator-configured static header would otherwise reach a modern peer,
    /// which `MIK-7215.STATELESS.3a` prohibits outright. The first connection
    /// is unaffected: the era is unresolved before the first `initialize()`,
    /// `outbound_era()` reads `None`, and the GET stays legacy-shaped.
    pub(super) async fn establish_sse_connection(&self) -> Result<String> {
        use futures::StreamExt;

        let mut headers = self.build_mcp_headers(HeaderMode::Sse, None).await?;
        if self.outbound_era() == Some(Era::Modern) {
            headers.insert(
                "MCP-Protocol-Version",
                header::HeaderValue::from_static(MODERN_VERSIONS[0]),
            );
            headers.remove("MCP-Session-Id");
        }

        let diagnostic_url = sanitize_url_for_diagnostics(&self.base_url);
        debug!(target: HTTP_TARGET, url = %diagnostic_url, "Establishing SSE connection");

        let response = self
            .client
            .get(&self.base_url)
            .headers(headers)
            .send()
            .await
            .map_err(|e| safe_request_error("SSE connection failed", &e))?;

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
            let chunk =
                chunk_result.map_err(|e| safe_request_error("Failed to read SSE chunk", &e))?;

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
                        // Computed before the macro: tracing compiles its arguments
                        // twice, and the coverage instrument reads the copy that
                        // never runs (MIK-7324).
                        let endpoint = sanitize_url_for_diagnostics(data);
                        debug!(target: HTTP_TARGET, endpoint = %endpoint, "Received message endpoint from SSE");

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
                                    debug!(target: HTTP_TARGET, "Extracted session ID");
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
    pub(super) fn resolve_message_url(&self, endpoint: &str) -> Result<String> {
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
    pub(super) fn get_message_url(&self) -> String {
        self.message_url
            .read()
            .clone()
            .unwrap_or_else(|| self.base_url.clone())
    }
}

/// The status of a 4xx the HTTP transport reported as `HTTP <status>` (a
/// POST) or `SSE endpoint returned: <status>` (the SSE GET) text,
/// when it says "wrong transport" rather than "wrong credential" or "not now":
/// 401/403/407 are about the credential, and 408/429 invite a retry. Those
/// keep their own error rather than becoming an SSE fault. A 4xx whose body
/// is a JSON-RPC error for this request arrives as `Error::JsonRpc` and never
/// matches: a peer that answers a POST in JSON-RPC speaks Streamable HTTP.
///
/// Both `Transport` and `TransportPermanent` are read: a 4xx answer is built
/// as the latter since MIK-7979, and a 405 must still fall back. It runs only
/// while connecting, before a session exists, so it never competes with
/// session-expiry recovery, which reads `Transport` text on a live session.
fn refused_as_wrong_transport(error: &Error) -> Option<u16> {
    let (Error::Transport(text) | Error::TransportPermanent(text)) = error else {
        return None;
    };
    let status: u16 = text
        .strip_prefix("HTTP ")
        .or_else(|| text.strip_prefix("SSE endpoint returned: "))?
        .get(..3)?
        .parse()
        .ok()?;
    ((400..500).contains(&status) && !matches!(status, 401 | 403 | 407 | 408 | 429))
        .then_some(status)
}

#[cfg(test)]
mod wrong_transport_tests {
    use super::*;

    #[test]
    fn only_a_transport_shaped_4xx_falls_back() {
        let status = |text: &str| refused_as_wrong_transport(&Error::Transport(text.into()));
        assert_eq!(status("HTTP 405 Method Not Allowed"), Some(405));
        assert_eq!(status("HTTP 404 Not Found"), Some(404));
        assert_eq!(
            status("SSE endpoint returned: 405 Method Not Allowed"),
            Some(405)
        );
        assert_eq!(status("SSE endpoint returned: 401 Unauthorized"), None);
        for kept in [
            "HTTP 401 Unauthorized",
            "HTTP 403 Forbidden",
            "HTTP 429 Too Many Requests",
        ] {
            assert_eq!(status(kept), None, "{kept}");
        }
        assert_eq!(status("HTTP 500 Internal Server Error"), None);
        assert_eq!(status("connection refused"), None);
        assert_eq!(
            refused_as_wrong_transport(&Error::Protocol("HTTP 405".into())),
            None
        );
    }

    /// MIK-7979: a 405 is now `TransportPermanent`; it still falls back.
    #[test]
    fn a_typed_4xx_still_falls_back() {
        let typed = Error::TransportPermanent("HTTP 405 Method Not Allowed".into());
        assert_eq!(refused_as_wrong_transport(&typed), Some(405));
    }
}

#[cfg(test)]
mod join_failure_tests {
    use super::*;

    /// A panicked OAuth task maps to the OAuth error `connect` has always
    /// returned for it, naming the join failure.
    #[tokio::test]
    async fn a_panicked_oauth_task_is_an_oauth_error() {
        let panicked: tokio::task::JoinHandle<Result<String>> =
            tokio::spawn(async { panic!("the OAuth task panicked") });
        let join_err = panicked.await.expect_err("the task panicked");
        let Error::OAuth(message) = join_failure(&join_err) else {
            panic!("not an OAuth error");
        };
        assert!(
            message.starts_with("OAuth task failed to join: "),
            "{message}"
        );
        assert!(message.contains("panicked"), "{message}");
    }
}

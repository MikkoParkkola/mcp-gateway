// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Outbound requests and notifications, and the headers they carry.

use std::sync::atomic::Ordering;

use reqwest::header;
use serde_json::Value;
use tracing::{debug, info};
use url::Url;

use super::super::sanitize_url_for_diagnostics;
use super::cancel_guard::CancelOnDrop;
use super::extra_headers::merge_extra_headers;
use super::modern_meta::{finalise_modern_headers, is_era_probe, with_modern_meta};
use super::{
    HTTP_TARGET, HeaderMode, HttpTransport, bearer_header_value, is_session_expired_error,
    peer_refusal, require_secure_oauth_target,
};
use crate::gateway::trace;
use crate::protocol::era::Era;
use crate::protocol::meta::MODERN_VERSIONS;
use crate::protocol::{
    JsonRpcNotification, JsonRpcRequest, JsonRpcResponse, PROTOCOL_VERSION, RequestId,
    is_version_mismatch_error, parse_supported_versions_from_error,
};
use crate::security::http_diagnostics::{
    RedirectEvidence, is_deterministic_refusal, safe_request_error, safe_request_error_for,
    status_refusal,
};
use crate::{Error, Result};

impl HttpTransport {
    /// Build an [`header::HeaderMap`] according to `mode`.
    ///
    /// This is the single source of truth for all outgoing request headers in
    /// this transport. The four behavioral variants are captured in
    /// [`HeaderMode`] so the asymmetries stay explicit.
    pub(super) async fn build_mcp_headers(
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

        if matches!(mode, HeaderMode::Sse | HeaderMode::SessionStream) {
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
            // A token carrying bytes illegal in an HTTP header value must fail as
            // a clean auth error, never panic the request path (MIK-6909).
            headers.insert(header::AUTHORIZATION, bearer_header_value(&token)?);
            if matches!(mode, HeaderMode::Sse) {
                let diagnostic_url = sanitize_url_for_diagnostics(&self.base_url);
                debug!(target: HTTP_TARGET, url = %diagnostic_url, "SSE connection with OAuth token");
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
                    // Presence, not value: a session ID is replayable.
                    debug!(target: HTTP_TARGET, method = %method, "Sending request with session ID");
                    headers.insert("MCP-Session-Id", session_id.parse().unwrap());
                }
                HeaderMode::Notify | HeaderMode::Close | HeaderMode::SessionStream => {
                    headers.insert("MCP-Session-Id", session_id.parse().unwrap());
                }
                HeaderMode::Sse => {}
            }
        } else if let HeaderMode::Request { method } = mode {
            debug!(target: HTTP_TARGET, method = %method, "Sending request without session ID");
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

        // MIK-7214.HEADER.9a/9b: the GET stream is built here and never reaches
        // `finalise_modern_headers`, so without this it carries whatever the
        // legacy handshake negotiated even after the peer has been observed to
        // be modern. Last, so it outranks an operator static exactly as
        // `finalise_modern_headers` outranks one on the POST paths. A `None`
        // era (not yet probed, or legacy) leaves the handshake version alone.
        if matches!(mode, HeaderMode::Sse)
            && self.outbound_era() == Some(crate::protocol::era::Era::Modern)
        {
            headers.insert(
                "MCP-Protocol-Version",
                header::HeaderValue::from_static(MODERN_VERSIONS[0]),
            );
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
    pub(super) async fn get_oauth_token(&self) -> Result<Option<String>> {
        if let Some(ref oauth_mutex) = self.oauth_client {
            // The barrier between the token and the socket: every caller of
            // `build_mcp_headers` posts to `get_message_url`, so checking it
            // here covers the base URL and the SSE-advertised endpoint alike.
            let target = self.get_message_url();
            let parsed = Url::parse(&target).map_err(|e| {
                Error::TransportPermanent(format!(
                    "refusing to send an OAuth token to an unparseable target: {e}"
                ))
            })?;
            require_secure_oauth_target(&parsed)?;

            // A non-interactive caller (the health probe) never waits on the
            // client mutex a login holds for minutes (MIK-7982 C2).
            let oauth = if crate::oauth::login_gate::interactive() {
                oauth_mutex.lock().await
            } else {
                oauth_mutex
                    .try_lock()
                    .map_err(|_| Error::AuthorizationRequired {
                        backend: sanitize_url_for_diagnostics(&self.base_url),
                    })?
            };
            let token = oauth.get_token().await?;
            // Past the request-time token step: a deadline from here is the
            // backend's, not a login's (MIK-7982 C3).
            crate::oauth::login_gate::Provenance::mark_dispatched();
            Ok(Some(token))
        } else {
            Ok(None)
        }
    }

    /// Send a raw request to the message endpoint
    pub(super) async fn send_request(&self, request: &JsonRpcRequest) -> Result<JsonRpcResponse> {
        // `None`, not `self.outbound_era()`: this is the handshake, and a
        // modern-shaped `initialize` is a message the peer we are still
        // introducing ourselves to may be unable to parse.
        self.send_request_with_headers(request, &[], None, None)
            .await
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
    pub(super) async fn send_request_with_headers(
        &self,
        request: &JsonRpcRequest,
        extra_headers: &[(String, String)],
        identity_key: Option<&str>,
        era: Option<Era>,
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
        merge_extra_headers(&mut headers, extra_headers);
        // AFTER every merge this path runs. Placed inside `build_mcp_headers`
        // it would be overridden by the loop just above.
        if era == Some(Era::Modern) {
            finalise_modern_headers(&mut headers, &request.method, request.params.as_ref())?;
        }

        // Armed before the POST, disarmed with no await between the read and
        // the disarm: a drop in between is a drop before the reply was read.
        let cancel = CancelOnDrop::arm(&self.client, &message_url, &headers, request, era);
        let result = self
            .post_and_read(request, headers, &message_url, identity_key)
            .await;
        cancel.disarm();
        result
    }

    /// POST `request` with `headers` and read its reply.
    async fn post_and_read(
        &self,
        request: &JsonRpcRequest,
        headers: header::HeaderMap,
        message_url: &str,
        identity_key: Option<&str>,
    ) -> Result<JsonRpcResponse> {
        // Sample the redirect counter either side of the send: an unchanged
        // count is the proof that a connect failure here is pre-dispatch
        // (MIK-7272.SUB.4). Sampled as late as possible so a peer request's
        // hop has the narrowest window to inflate the delta.
        let redirects_before = self.redirects_followed.load(Ordering::SeqCst);
        let response = self
            .client
            .post(message_url)
            .headers(headers)
            .json(request)
            .send()
            .await
            .map_err(|e| {
                let evidence = if self.redirects_followed.load(Ordering::SeqCst) == redirects_before
                {
                    RedirectEvidence::NoRedirectFollowed
                } else {
                    RedirectEvidence::MayHaveRedirected
                };
                safe_request_error_for("Request failed", &e, evidence)
            })?;

        // Extract session ID from response headers if this caller's bucket is
        // empty (MIK-6784: store under the caller's identity key, never a shared
        // slot). The first request for a new identity has no session; the
        // upstream mints one and we bind it to that identity for reuse.
        //
        // The probe is exempt. It runs before the handshake decision now, so a
        // session minted on its response would be one no handshake negotiated:
        // a legacy fallback would then send its `initialize` already carrying a
        // session id, which is not the message this gateway has ever sent, and
        // a modern peer's shape strips the header anyway.
        let bucket = Self::bucket_key(identity_key);
        if is_era_probe(&request.method) {
            debug!(target: HTTP_TARGET, "Era probe: not binding a session before the handshake decision");
        } else if self.sessions.read().contains_key(bucket) {
            debug!(target: HTTP_TARGET, "Using existing session ID for caller bucket");
        } else if let Some(session_id) = response.headers().get("mcp-session-id") {
            if let Ok(id) = session_id.to_str() {
                // Presence, not value: an MCP session ID is replayable, so a log
                // reader who sees one can resume another caller's session.
                // Computed before the macro, as above (MIK-7324).
                let diagnostic_url = sanitize_url_for_diagnostics(message_url);
                info!(target: HTTP_TARGET, url = %diagnostic_url, "Stored session ID from response");
                self.sessions
                    .write()
                    .insert(bucket.to_string(), id.to_string());
                // Maintainability guard (MIK-6735 fix 2): under a per-user pool slot this instance
                // serves exactly one caller identity for life, so `sessions` is provably <=1 entry
                // — do NOT "simplify" this map to a single `Option<String>` on the strength of
                // that; it stays multi-entry and load-bearing for the Shared slot (Stateless-mode
                // backends and the no-identity path), which is Arc-shared across every caller and
                // relies on this map to keep each identity's
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
            // Header NAMES only. Values are backend-controlled and routinely
            // carry `set-cookie`, `authorization` echoes and bearer material.
            // Computed before the macro, as above (MIK-7324).
            let diagnostic_url = sanitize_url_for_diagnostics(message_url);
            let names: Vec<&str> = response
                .headers()
                .keys()
                .map(header::HeaderName::as_str)
                .collect();
            debug!(target: HTTP_TARGET, url = %diagnostic_url, "No session ID in response. Header names: {:?}", names);
        }

        let status = response.status();
        if !status.is_success() {
            // A11-b/g: a deterministic refusal is typed by its STATUS alone.
            let typed = response.error_for_status_ref().err();
            let body = response.text().await.unwrap_or_default();
            // Some servers refuse a protocol version with a status, not a
            // JSON-RPC error, so the body with the supported versions is read
            // first. Three signals together, because this parser sees every
            // non-2xx body: the status a version refusal uses, the in-band
            // phrasing, and a parseable list; a proxy page with a date is none.
            if matches!(
                status,
                reqwest::StatusCode::BAD_REQUEST | reqwest::StatusCode::UPGRADE_REQUIRED
            ) && is_version_mismatch_error(&body)
                && let Some(supported) = parse_supported_versions_from_error(&body)
            {
                return Err(Error::ProtocolVersionRejected { supported });
            }
            if let Some(refusal) = peer_refusal(&body, &request.id, status) {
                // A11-b: a credential refusal is typed by its status, whatever
                // the peer wrote, so the managed-account refresh sees it
                // (MIK-7717). Only an expiry, judged by the classifier that
                // performs the recovery, keeps the peer's answer. The typed
                // status is returned directly: a body-text scan must not
                // overrule the parsed verdict.
                if is_deterministic_refusal(status)
                    && !is_session_expired_error(&refusal)
                    && let Some(typed) = typed
                {
                    return Err(Error::Http(typed.without_url()));
                }
                return Err(refusal);
            }
            return Err(status_refusal(typed, status, &body));
        }

        // Check Content-Type to determine response format
        let content_type = response
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");

        if content_type.contains("text/event-stream") {
            // Decoded incrementally, not buffered. A backend that interleaves
            // notifications ahead of its result holds the body open until the
            // result exists, so `.text()` here could not observe a
            // notification until the call it belongs to had already finished
            // -- the liveness `MIK-7272.SUB.2b` asks for is unreachable from a
            // complete body. Each frame is published as its chunk arrives.
            use futures::TryStreamExt;
            let stream = response
                .bytes_stream()
                .map_err(|e| safe_request_error("Failed to read SSE response", &e));
            super::sse_decoder::decode_sse_exchange(stream).await
        } else {
            // Parse JSON response
            response
                .json()
                .await
                .map_err(|e| safe_request_error("Failed to parse response", &e))
        }
    }

    /// Get next request ID
    #[allow(clippy::cast_possible_wrap)] // request IDs won't exceed i64::MAX
    pub(super) fn next_id(&self) -> RequestId {
        RequestId::Number(self.request_id.fetch_add(1, Ordering::Relaxed) as i64)
    }

    /// Map an optional caller identity key to its session-bucket key (MIK-6784).
    ///
    /// `None` (the no-identity static path) maps to the shared default bucket
    /// (`""`), so single-tenant behavior is byte-for-byte unchanged; a present
    /// key selects that caller's private bucket.
    pub(super) fn bucket_key(identity_key: Option<&str>) -> &str {
        identity_key.unwrap_or("")
    }

    // MIK-6735 fix 2: threads `identity_key` into `build_mcp_headers` so a
    // notification for a per-user identity selects that same identity's
    // `MCP-Session-Id` bucket — previously every notification hardcoded
    // `HeaderMode::Notify, None`, i.e. the shared bucket, even when it
    // correlated a request that had gone out on a per-user session.
    /// Send a notification to the message endpoint, shaped for `era`.
    ///
    /// `era` is a parameter rather than a read of `self.outbound_era()`, for
    /// the reason `send_request` takes one: the handshake's own
    /// `notifications/initialized` must stay legacy-shaped even once the cache
    /// says `Modern`, and a path that reads the era for itself cannot make that
    /// exception. Ordinary notifications pass `outbound_era()`.
    pub(super) async fn send_notification(
        &self,
        method: &str,
        params: Option<Value>,
        extra_headers: &[(String, String)],
        identity_key: Option<&str>,
        era: Option<Era>,
    ) -> Result<()> {
        let message_url = self.get_message_url();
        let params = if era == Some(Era::Modern) {
            with_modern_meta(method, params)?
        } else {
            params
        };

        let notification = JsonRpcNotification {
            jsonrpc: "2.0".to_string(),
            method: method.to_string(),
            params,
        };

        let mut headers = self
            .build_mcp_headers(HeaderMode::Notify, identity_key)
            .await?;
        // The caller's credential, as on a request (#2292).
        merge_extra_headers(&mut headers, extra_headers);
        if era == Some(Era::Modern) {
            finalise_modern_headers(&mut headers, method, notification.params.as_ref())?;
        }

        let response = self
            .client
            .post(&message_url)
            .headers(headers)
            .json(&notification)
            .send()
            .await
            .map_err(|e| safe_request_error("Notification failed", &e))?;

        if !response.status().is_success() {
            // Many HTTP backends (e.g. exa, beeper) do not support MCP
            // notifications and return 4xx. This is expected behaviour — log at
            // DEBUG so it does not spam the operator logs.
            debug!(target: HTTP_TARGET,
                status = %response.status(),
                url = %sanitize_url_for_diagnostics(message_url.as_str()),
                method = method,
                "Notification not supported by backend (ignored)"
            );
        }

        Ok(())
    }
}

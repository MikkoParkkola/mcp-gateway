// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Outbound requests and notifications, and the headers they carry.

use std::sync::Arc;
use std::sync::atomic::Ordering;

use tokio::sync::Mutex as TokioMutex;

use reqwest::header;
use serde_json::Value;
use tracing::{debug, info};
use url::Url;

use super::super::lender::counted_refusal;
use super::super::sanitize_url_for_diagnostics;
use super::cancel_guard::CancelOnDrop;
use super::extra_headers::merge_extra_headers;
use super::modern_meta::{finalise_modern_headers, is_era_probe, with_modern_meta};
use super::{
    HTTP_TARGET, HeaderMode, HttpTransport, bearer_header_value, is_session_expired_error,
    peer_refusal, require_secure_oauth_target,
};
use crate::gateway::trace;
use crate::oauth::OAuthClient;
use crate::oauth::login_gate::{self, Provenance};
use crate::protocol::era::PeerEra;
use crate::protocol::meta::MODERN_VERSIONS;
use crate::protocol::param_headers::is_param_header;
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
        call: &[(String, String)],
    ) -> Result<header::HeaderMap> {
        self.build_headers(mode, identity_key, CredentialOrigin::Gateway, call)
            .await
    }

    /// [`Self::build_mcp_headers`] for a request whose credential a
    /// [`CredentialSource`](crate::transport::upstream_tap::CredentialSource)
    /// lends: protocol headers only. It never reads the
    /// gateway's OAuth token, so it never starts a login, and never adds the
    /// operator's static headers; the source's own headers are merged later.
    pub(super) async fn build_lent_headers(
        &self,
        mode: HeaderMode<'_>,
        identity_key: Option<&str>,
    ) -> Result<header::HeaderMap> {
        self.build_headers(mode, identity_key, CredentialOrigin::Lent, &[])
            .await
    }

    async fn build_headers(
        &self,
        mode: HeaderMode<'_>,
        identity_key: Option<&str>,
        origin: CredentialOrigin,
        call: &[(String, String)],
    ) -> Result<header::HeaderMap> {
        // A lent-only per-user slot sends nothing of the gateway's: no static
        // header and no gateway token, only the loan the call's own headers
        // select, merged last. A call whose credential is not lent, or whose
        // loan's check refuses, is not sent. A send whose credential a source lends (an
        // event listener's stream) already carries nothing of the gateway's,
        // and its source is its lender.
        let lent = if self.is_lent_only() && origin == CredentialOrigin::Gateway {
            Some(self.lent_for(call).await?)
        } else {
            None
        };
        let origin = if lent.is_some() {
            CredentialOrigin::Lent
        } else {
            origin
        };
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
        let token = match origin {
            CredentialOrigin::Gateway => self.get_oauth_token().await?,
            CredentialOrigin::Lent => None,
        };
        if let Some(token) = token {
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
        let session = self.sessions.read().get(self.bucket(identity_key)).cloned();
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
        let statics = match origin {
            CredentialOrigin::Gateway => self.headers.iter().collect::<Vec<_>>(),
            CredentialOrigin::Lent => Vec::new(),
        };
        for (key, value) in statics {
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
            && self.outbound_era() == Some(crate::protocol::era::PeerEra::Modern)
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

        if let Some(lent) = lent {
            super::extra_headers::merge_extra_headers(&mut headers, &lent);
        }

        Ok(headers)
    }

    /// Merge a call's own headers into `headers`. On a lent-only slot the
    /// credential part is already the loan's, merged by the builder, so only
    /// the gateway-owned `Mcp-Param-*` mirrors are taken from the call: never
    /// the caller's copy of the credential.
    fn merge_call_headers(&self, headers: &mut header::HeaderMap, call: &[(String, String)]) {
        if self.is_lent_only() {
            let mirrors: Vec<_> = call
                .iter()
                .filter(|(name, _)| is_param_header(name))
                .cloned()
                .collect();
            merge_extra_headers(headers, &mirrors);
        } else {
            merge_extra_headers(headers, call);
        }
    }

    /// The headers a lent-only slot's send carries, from the slot's lender
    /// ([`Lender::lent_for`](crate::transport::Lender::lent_for)).
    ///
    /// # Errors
    ///
    /// A refusal when the slot has no lender or the lender refuses the call.
    pub(super) async fn lent_for(
        &self,
        call: &[(String, String)],
    ) -> Result<Vec<(String, String)>> {
        let Some(lender) = self.lender.get() else {
            return Err(counted_refusal("no_lender", "this slot has no lender"));
        };
        lender.lent_for(call).await
    }

    /// The call this transport's slot start sends with: resolved at each send
    /// to the oldest dispatch still waiting on the start
    /// ([`Lender::start_call`](crate::transport::Lender::start_call)), empty on
    /// a slot that lends nothing. Only the start's own sends pass it.
    pub(crate) fn start_call(&self) -> Vec<(String, String)> {
        self.lender
            .get()
            .map(|lender| lender.start_call())
            .unwrap_or_default()
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
            // client mutex a login holds for minutes, and never detaches
            // (MIK-7982 C2, MIK-8339).
            if !login_gate::interactive() {
                let oauth = oauth_mutex
                    .try_lock()
                    .map_err(|_| Error::AuthorizationRequired {
                        backend: sanitize_url_for_diagnostics(&self.base_url),
                    })?;
                let token = oauth.get_token().await?;
                Provenance::mark_dispatched();
                return Ok(Some(token));
            }
            // Fast path: a live token, read without waiting on the mutex. The
            // guard is dropped before anything detaches.
            if let Ok(oauth) = oauth_mutex.try_lock()
                && let Some(token) = oauth.live_token()
            {
                drop(oauth);
                Provenance::mark_dispatched();
                return Ok(Some(token));
            }
            let gate = &self.login_gate;
            // Captured here, synchronously, before anything queues: a start's
            // own set-out epoch wins, else the gate's now.
            let set_out = gate.set_out_now();
            // Mark a login wait only when a login is actually open: this
            // caller will queue behind it (MIK-7982 C3).
            if gate.in_flight() {
                Provenance::mark_waited();
            }
            let token = detach_token_step(
                Arc::clone(oauth_mutex),
                Arc::clone(gate),
                set_out,
                sanitize_url_for_diagnostics(&self.base_url),
            )
            .await?;
            // Past the request-time token step: a deadline from here is the
            // backend's, not a login's (MIK-7982 C3).
            Provenance::mark_dispatched();
            Ok(Some(token))
        } else {
            Ok(None)
        }
    }

    /// Send a raw request to the message endpoint inside a call: `call` is that call's headers, so
    /// a lent-only slot picks the loan the call carries.
    pub(super) async fn send_request_as(
        &self,
        request: &JsonRpcRequest,
        call: &[(String, String)],
    ) -> Result<JsonRpcResponse> {
        // `None`, not `self.outbound_era()`: this is the handshake, and a
        // modern-shaped `initialize` is a message the peer we are still
        // introducing ourselves to may be unable to parse.
        self.send_request_with_headers(request, call, None, None)
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
        era: Option<PeerEra>,
    ) -> Result<JsonRpcResponse> {
        // SSE mode: the request takes its place on the live stream before its
        // POST, and is sent to that stream's own endpoint (design B16, B18).
        let mut channel = self.live_sse_channel(extra_headers).await?;
        let mut waiting = channel
            .as_ref()
            .map(|c| c.register(&request.id))
            .transpose()?;
        #[cfg(test)]
        if channel.is_some() {
            self.before_sse_post.pause().await;
        }
        if channel.as_ref().is_some_and(|c| c.is_closed()) {
            // Closed between the check and the registration: replace it, once.
            drop(waiting);
            channel = self.live_sse_channel(extra_headers).await?;
            waiting = channel
                .as_ref()
                .map(|c| c.register(&request.id))
                .transpose()?;
        }
        let message_url = channel
            .as_ref()
            .map_or_else(|| self.get_message_url(), |c| c.endpoint().to_owned());

        let mut headers = self
            .build_mcp_headers(
                HeaderMode::Request {
                    method: &request.method,
                },
                identity_key,
                extra_headers,
            )
            .await?;
        self.merge_call_headers(&mut headers, extra_headers);
        // AFTER every merge this path runs. Placed inside `build_mcp_headers`
        // it would be overridden by the loop just above.
        if era == Some(PeerEra::Modern) {
            finalise_modern_headers(&mut headers, &request.method, request.params.as_ref())?;
        }

        // Armed before the POST, disarmed with no await between the read and
        // the disarm: a drop in between is a drop before the reply was read.
        // A lent-only slot sends nothing once its dispatch is gone, so a
        // dropped call is not followed by a cancel carrying its credential.
        let cancel = if self.is_lent_only() {
            CancelOnDrop::unarmed()
        } else {
            CancelOnDrop::arm(&self.client, &message_url, &headers, request, era)
        };
        let result = self
            .post_and_read(request, headers, &message_url, identity_key, waiting)
            .await;
        cancel.disarm();
        result
    }

    /// Keep the failed send's whole error chain and kind flags (MIK-8359): the
    /// sanitized `Error` says only "request failed", which hides whether a
    /// connection was reset, closed early or refused.
    #[cfg(test)]
    fn record_send_error(&self, error: &reqwest::Error) {
        use std::fmt::Write as _;
        let mut chain = String::new();
        let mut source: Option<&(dyn std::error::Error + 'static)> = Some(error);
        while let Some(layer) = source {
            let _ = write!(chain, "[{layer:?}] <- ");
            source = layer.source();
        }
        *self.last_send_error.lock() = Some(format!(
            "connect={} timeout={} redirect={} request={} body={} decode={} :: {chain}",
            error.is_connect(),
            error.is_timeout(),
            error.is_redirect(),
            error.is_request(),
            error.is_body(),
            error.is_decode(),
        ));
    }

    /// POST `request` with `headers` and read its reply.
    async fn post_and_read(
        &self,
        request: &JsonRpcRequest,
        headers: header::HeaderMap,
        message_url: &str,
        identity_key: Option<&str>,
        waiting: Option<super::sse_channel::Waiting>,
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
                #[cfg(test)]
                self.record_send_error(&e);
                let evidence = if self.redirects_followed.load(Ordering::SeqCst) == redirects_before
                {
                    RedirectEvidence::NoRedirectFollowed
                } else {
                    RedirectEvidence::MayHaveRedirected
                };
                safe_request_error_for("Request failed", &e, evidence)
            })?;
        // The response head is in: a task worker's rescue poll can now only
        // receive (MIK-7642 R10.1). A no-op unless a submission is armed.
        crate::transport::submit_mark::response_head_received();

        self.read_answer(request, response, message_url, identity_key, waiting)
            .await
    }

    /// The answer to `request` from its `response`: the caller's session id
    /// bound to its bucket, a refusal typed, and a JSON or SSE body read. Split
    /// from [`Self::post_and_read`] so a send a credential source makes is
    /// read the same way.
    pub(super) async fn read_answer(
        &self,
        request: &JsonRpcRequest,
        response: reqwest::Response,
        message_url: &str,
        identity_key: Option<&str>,
        waiting: Option<super::sse_channel::Waiting>,
    ) -> Result<JsonRpcResponse> {
        let answer = self
            .read_answer_unscrubbed(request, response, message_url, identity_key, waiting)
            .await;
        match self.needles.get() {
            Some(needles) => crate::security::needles::scrub_answer(needles, answer),
            None => answer,
        }
    }

    /// [`Self::read_answer`] before the backend's injected values are removed:
    /// every JSON, SSE and refusal body is parsed here, and only the wrapper
    /// hands the result on.
    async fn read_answer_unscrubbed(
        &self,
        request: &JsonRpcRequest,
        response: reqwest::Response,
        message_url: &str,
        identity_key: Option<&str>,
        waiting: Option<super::sse_channel::Waiting>,
    ) -> Result<JsonRpcResponse> {
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
        let bucket = self.bucket(identity_key);
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
                // Maintainability guard (MIK-6735 fix 2): a lent-only per-user pool slot (the
                // single-tenant hint) serves exactly one caller identity for life, so `sessions`
                // is provably <=1 entry. An optional binding's per-user slot also holds its
                // start's gateway session, so it is not hinted and may hold two
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
            let body = self.error_body(response).await?;
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
            match self.body_budget.get() {
                Some(budget) => {
                    super::sse_decoder::decode_sse_exchange(
                        budget.metered(stream),
                        self.needles.get().map(AsRef::as_ref),
                    )
                    .await
                }
                None => {
                    super::sse_decoder::decode_sse_exchange(
                        stream,
                        self.needles.get().map(AsRef::as_ref),
                    )
                    .await
                }
            }
        } else if let Some(waiting) = waiting {
            self.body_or_stream(status, response, waiting).await
        } else {
            self.json_body(response).await
        }
    }

    /// A non-2xx body as text. Under a byte budget an over-budget body is
    /// that refusal, never an empty body read past; without one, an unreadable
    /// body is empty, as before.
    async fn error_body(&self, response: reqwest::Response) -> Result<String> {
        Ok(match self.body_budget.get() {
            Some(budget) => String::from_utf8_lossy(&budget.read(response).await?).into_owned(),
            None => response.text().await.unwrap_or_default(),
        })
    }

    /// A 2xx JSON body, counted against the byte budget when one is set.
    async fn json_body(&self, response: reqwest::Response) -> Result<JsonRpcResponse> {
        match self.body_budget.get() {
            Some(budget) => serde_json::from_slice(&budget.read(response).await?)
                .map_err(|e| Error::Transport(format!("Failed to parse response: {e}"))),
            None => response
                .json()
                .await
                .map_err(|e| safe_request_error("Failed to parse response", &e)),
        }
    }

    /// A 2xx answer in SSE mode: its body when it carries one, else the
    /// response its stream pairs with the request (MIK-8835.SSE.2).
    async fn body_or_stream(
        &self,
        status: reqwest::StatusCode,
        response: reqwest::Response,
        waiting: super::sse_channel::Waiting,
    ) -> Result<JsonRpcResponse> {
        // A 2024-11-05 SSE peer answers 202 and puts the response on the
        // session stream (MIK-8835.SSE.2); a JSON body, if one came, is the
        // answer as before.
        let body = match self.body_budget.get() {
            Some(budget) => budget.read(response).await?,
            None => response
                .bytes()
                .await
                .map_err(|e| safe_request_error("Failed to read response", &e))?,
        };
        // 202 is "the answer comes on the stream" whatever its body (the
        // TS SDK's SSE server writes "Accepted"); an empty 2xx is too.
        if status == reqwest::StatusCode::ACCEPTED || body.iter().all(u8::is_ascii_whitespace) {
            let answer = tokio::time::timeout(self.timeout, waiting.response())
                .await
                .map_err(|_| {
                    Error::Transport("timed out waiting for the SSE stream's response".to_owned())
                })??;
            // This peer answers on its stream: a closed stream is replaced
            // before the next call from now on.
            self.sse_stream_answers
                .store(true, std::sync::atomic::Ordering::SeqCst);
            return Ok(answer);
        }
        serde_json::from_slice(&body)
            .map_err(|e| Error::Transport(format!("Failed to parse response: {e}")))
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
        era: Option<PeerEra>,
    ) -> Result<()> {
        let message_url = self.get_message_url();
        let params = if era == Some(PeerEra::Modern) {
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
            .build_mcp_headers(HeaderMode::Notify, identity_key, extra_headers)
            .await?;
        // The caller's credential, as on a request (#2292).
        self.merge_call_headers(&mut headers, extra_headers);
        if era == Some(PeerEra::Modern) {
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

/// Run an interactive caller's token step in a task of its own (MIK-8339):
/// the login it may lead belongs to the task, so a caller whose deadline
/// fires drops only its wait, and a person who approves later still stores a
/// token. The caller's scopes are carried in, so the task's marks land on the
/// caller's own Provenance. Before it holds the client, the task observes a
/// restart or stop and ends at the authorization window; no timeout ever
/// wraps a live Lead (the Lead stage bounds itself, in `authorize_until`).
async fn detach_token_step(
    oauth: Arc<TokioMutex<OAuthClient>>,
    gate: Arc<crate::oauth::login_gate::LoginGate>,
    set_out: crate::oauth::login_gate::SetOut,
    backend: String,
) -> Result<String> {
    let crate::oauth::login_gate::SetOut {
        since,
        cohort,
        deadline,
    } = set_out;
    #[cfg(test)]
    gate.note_detached();
    let carried = crate::oauth::login_gate::carry_scopes();
    let task = tokio::spawn(carried.run(async move {
        let client = tokio::select! {
            biased;
            () = gate.revoked_since(since) => {
                return Err(Error::AuthorizationCancelled { backend });
            }
            () = tokio::time::sleep_until(crate::oauth::login_gate::stage_end(
                crate::oauth::OAUTH_AUTHORIZATION_WINDOW,
                deadline,
            )) => {
                return Err(gate.classify(&cohort, &backend, Error::BackendTimeout(backend.clone())));
            }
            client = oauth.lock_owned() => client,
        };
        client.get_token_detached(true, since, &cohort, deadline).await
    }));
    task.await
        .map_err(|e| Error::OAuth(format!("the detached token step failed: {e}")))?
}

/// Whose credential a request's headers carry.
#[derive(Clone, Copy, PartialEq, Eq)]
enum CredentialOrigin {
    /// The gateway's own: its OAuth login and the operator's static headers.
    Gateway,
    /// A subscriber's, lent per request by a credential source: neither.
    Lent,
}

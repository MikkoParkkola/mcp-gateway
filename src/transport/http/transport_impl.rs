// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The `Transport` trait implementation for `HttpTransport`.

use std::sync::atomic::Ordering;

use async_trait::async_trait;
use serde_json::Value;
use tracing::warn;

use super::super::sanitize_url_for_diagnostics;
use super::super::{ResendPermission, Transport, resend_permission};
use super::modern_meta::{
    TASK_CAPABILITY_METHODS, is_era_probe, with_modern_meta, with_task_capability_meta,
};
use super::{
    HTTP_TARGET, HeaderMode, HttpTransport, is_session_expired_error, is_session_expired_response,
};
use crate::protocol::era::Era;
use crate::protocol::{JsonRpcRequest, JsonRpcResponse};
use crate::{Error, Result};

#[async_trait]
impl Transport for HttpTransport {
    async fn request(&self, method: &str, params: Option<Value>) -> Result<JsonRpcResponse> {
        // This entry point carries no tool context, so it runs the shared
        // predicate against an EMPTY permitted set: every `tools/call` is
        // denied, while the side-effect-free methods that actually reach here
        // (metadata discovery's `tools/list`, lifecycle's `ping`) keep the
        // session recovery MIK-5982/MIK-6040 added for them.
        let permission =
            resend_permission(method, params.as_ref(), &std::collections::HashSet::new());
        self.request_with_headers(method, params, &[], None, permission)
            .await
    }

    async fn request_with_headers(
        &self,
        method: &str,
        params: Option<Value>,
        extra_headers: &[(String, String)],
        identity_key: Option<&str>,
        resend: ResendPermission,
    ) -> Result<JsonRpcResponse> {
        // Read the era once, here, and carry it into the send. Reading it
        // inside the header builder instead would leave the body half of the
        // envelope decided somewhere else, and the two must agree about which
        // dialect this one message is written in.
        //
        // The probe is the one request that cannot wait for the era it is
        // resolving, and an undetermined era shapes everything else legacy.
        // `server/discover` exists only in the 2026 revision, so a legacy-shaped
        // probe asks a modern peer a question in a dialect that peer may refuse
        // — the probe has to be a *valid* 2026 request to be evidence of
        // anything. Legacy peers may return a non-modern answer or time out;
        // the existing classifier then selects the legacy fallback. A
        // determined verdict still takes precedence over this probe default.
        if identity_key.is_none() {
            // A stream open's 404 dropped the shared session; heal it first.
            let _ = self.reinit_if_needed().await;
        }
        let era = self
            .outbound_era()
            .or_else(|| is_era_probe(method).then_some(Era::Modern));
        let params = if era == Some(Era::Modern) {
            with_modern_meta(method, params)?
        } else {
            params
        };

        let request = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            id: self.next_id(),
            method: method.to_string(),
            params,
        };

        let result = self
            .send_request_with_headers(&request, extra_headers, identity_key, era)
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
            // Heal the session on BOTH branches: it really is dead, and leaving
            // the stale bucket in place poisons every later call through this
            // identity — including the ones that ARE allowed to be resent.
            let healed = if identity_key.is_none() {
                // The shared bucket heals through the one recovery path the
                // stream opens use, so the two never undo each other.
                let current = self.sessions.read().get(bucket).cloned();
                match current {
                    Some(current) => {
                        let _ = self.session_expired(&current).await;
                    }
                    None => {
                        let _ = self.reinit_if_needed().await;
                    }
                }
                self.sessions.read().contains_key(bucket)
            } else {
                self.sessions.write().remove(bucket);
                self.initialize().await.is_ok()
            };
            if !healed {
                // The caller asked about their request, not about our
                // handshake; surfacing the re-initialization's error instead
                // would hide what actually failed.
                return result;
            }
            if resend == ResendPermission::Denied {
                let tool = request
                    .params
                    .as_ref()
                    .and_then(|params| params.get("name"))
                    .and_then(Value::as_str)
                    .unwrap_or("-");
                warn!(target: HTTP_TARGET,
                    url = %sanitize_url_for_diagnostics(&self.base_url),
                    method = %method,
                    tool = %tool,
                    reason = "no explicit readOnlyHint/idempotentHint annotation",
                    "Backend session expired; session healed but the call was NOT resent"
                );
                telemetry_metrics::counter!(
                    "mcp_resend_denied_total",
                    "site" => "http_session_expiry",
                    "method" => method.to_string()
                )
                .increment(1);
                return result;
            }
            warn!(target: HTTP_TARGET,
                url = %sanitize_url_for_diagnostics(&self.base_url),
                method = %method,
                "Backend session expired; re-initializing and retrying once"
            );
            return self
                .send_request_with_headers(&request, extra_headers, identity_key, era)
                .await;
        }

        result
    }

    /// The typed upstream-tasks entry point. See the trait method for why this
    /// is its own method and not a flag.
    ///
    /// Three refusals, all local, all before anything reaches the wire:
    ///
    /// 1. A method outside `TASK_CAPABILITY_METHODS`.
    /// 2. A peer not *known* to be modern. `outbound_era()` reads a determined
    ///    era only — `None` (undetermined, or a probe in flight) is legacy, and
    ///    a legacy peer has no `_meta` envelope to read the opt-in from, so it
    ///    would run the call synchronously and hand back a result the caller
    ///    would then have to mistake for a task handle.
    /// 3. A `params`/`_meta` that cannot carry the envelope (from
    ///    `with_task_capability_meta`).
    ///
    /// It sends through `send_request_with_headers` rather than
    /// `request_with_headers`: that wrapper re-runs `with_modern_meta` (which
    /// would overwrite the declaration with empty capabilities) and owns the
    /// session-expiry re-handshake, which resubmits the identical request. A
    /// resubmitted `tools/call` is a second upstream task, orphaning the first,
    /// so this path never retries — a caller that must retry is the one that
    /// knows whether its submission is idempotent. Passing `Some(Era::Modern)`
    /// keeps the final modern-header writer running exactly once, as it does
    /// for every other modern request, and `extra_headers`/`identity_key` reach
    /// it unchanged so the caller's credential and session bucket still apply.
    async fn request_with_task_capability(
        &self,
        method: &str,
        params: Option<Value>,
        extra_headers: &[(String, String)],
        identity_key: Option<&str>,
    ) -> Result<JsonRpcResponse> {
        if !TASK_CAPABILITY_METHODS.contains(&method) {
            return Err(Error::Protocol(format!(
                "refusing to send `{method}` with the upstream tasks capability: only {allowed} \
                 may carry it",
                allowed = TASK_CAPABILITY_METHODS.join(" and "),
            )));
        }
        if self.outbound_era() != Some(Era::Modern) {
            return Err(Error::Protocol(format!(
                "refusing to send `{method}` with the upstream tasks capability: the peer is not \
                 known to speak a 2026 revision, which is the only dialect that can carry the \
                 declaration"
            )));
        }

        let request = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            id: self.next_id(),
            method: method.to_string(),
            params: with_task_capability_meta(method, params)?,
        };

        self.send_request_with_headers(&request, extra_headers, identity_key, Some(Era::Modern))
            .await
    }

    // MIK-6710: HTTP is the only transport whose `request_with_headers`
    // actually applies `extra_headers` to the wire (see
    // `send_request_with_headers` above) — the identity-propagation dispatch
    // gate relies on this override to allow a `required` backend to proceed.
    fn carries_identity_headers(&self) -> bool {
        true
    }

    async fn notify(&self, method: &str, params: Option<Value>) -> Result<()> {
        self.notify_with_headers(method, params, &[], None).await
    }

    async fn notify_with_headers(
        &self,
        method: &str,
        params: Option<Value>,
        extra_headers: &[(String, String)],
        identity_key: Option<&str>,
    ) -> Result<()> {
        self.send_notification(
            method,
            params,
            extra_headers,
            identity_key,
            self.outbound_era(),
        )
        .await
    }

    fn is_connected(&self) -> bool {
        self.connected.load(Ordering::Relaxed)
    }

    async fn close(&self) -> Result<()> {
        self.connected.store(false, Ordering::Relaxed);
        self.listen_cancel.cancel();

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
                    warn!(target: HTTP_TARGET,
                        error = %error,
                        url = %sanitize_url_for_diagnostics(message_url.as_str()),
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

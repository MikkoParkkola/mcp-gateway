// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Request/notify dispatch through the per-identity pool on
//! [`super::Backend`]. The status and health-metric accessors live in
//! `status.rs`.

use std::sync::atomic::Ordering;

use serde_json::Value;

use super::Backend;
use crate::failsafe::{RetryPolicy, with_retry_unless};
use crate::protocol::JsonRpcResponse;
use crate::protocol::param_headers::{is_param_header, mirror_headers};
use crate::transport::{ResendPermission, resend_permission};
use crate::{Error, Result};

/// Which transport entry point one outbound request takes, and how many times.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Attempts {
    /// The ordinary path: the slot's retry policy decides.
    WithRetry,
    /// The upstream-tasks declaration, sent exactly once. A duplicate would
    /// create durable state upstream that this gateway could not then own.
    TaskCapabilityOnce,
}

impl Backend {
    /// Send a request to the backend
    ///
    /// # Errors
    ///
    /// Returns an error if the backend is unavailable, the concurrency limit
    /// is reached, or the request itself fails after retries.
    #[tracing::instrument(
        skip(self, params),
        fields(
            backend = %self.name,
            method = %method,
            request_id = %uuid::Uuid::new_v4()
        )
    )]
    pub async fn request(&self, method: &str, params: Option<Value>) -> Result<JsonRpcResponse> {
        self.request_with_headers_lent(
            method,
            params,
            crate::transport::LentCredential::default(),
            None,
        )
        .await
    }

    /// This backend's end-user identity-propagation config, if configured
    /// (MIK-6704 / ADR-007). `None` -> static-credential behavior unchanged.
    #[must_use]
    pub fn identity_propagation_config(
        &self,
    ) -> Option<&crate::identity_propagation::IdentityPropagationConfig> {
        self.config.identity_propagation.as_ref()
    }

    /// The `accounts.descriptors` key this backend is bound to, if any.
    ///
    /// The descriptor's logical id — the account key's `backend_id` — and never
    /// this backend's registry name, which is [`Backend::name`]. Present only
    /// when the operator wrote an `account` reference that resolved at load.
    #[must_use]
    pub fn account_descriptor_id(&self) -> Option<&str> {
        self.config.account.as_deref()
    }

    /// Whether this backend's configured transport can carry per-request
    /// outbound headers, e.g. a propagated end-user identity credential
    /// (MIK-6710).
    ///
    /// Delegates to [`TransportConfig::carries_identity_headers`](crate::config::TransportConfig::carries_identity_headers), which is
    /// evaluated from config alone -- valid before [`Backend::start`] has ever
    /// run. The identity-propagation dispatch gate
    /// (`MetaMcp::resolve_caller_credential`, the direct backend route's
    /// passthrough branch) checks this BEFORE minting or forwarding a
    /// credential, so a `required` backend bound to a transport that would
    /// silently drop `extra_headers` (stdio, websocket) is refused instead of
    /// running unauthenticated.
    #[must_use]
    pub fn transport_carries_identity_headers(&self) -> bool {
        self.config.transport.carries_identity_headers()
    }

    /// Whether this backend relies on a single gateway-held OAuth token that is
    /// NOT blessed for shared use (ADR-008 INV-2).
    ///
    /// `true` means the gateway stores one token for this backend and would
    /// attach it to any caller's request -- unsafe on a multi-user gateway
    /// unless a per-user credential is supplied instead. The dispatch guard
    /// uses this to fail closed. `oauth.shared_account = true` opts out (the
    /// operator has declared the account genuinely shared).
    #[must_use]
    pub fn oauth_requires_per_user_isolation(&self) -> bool {
        self.config
            .oauth
            .as_ref()
            .is_some_and(|o| o.enabled && !o.shared_account)
    }

    /// Builds the outbound header set for one call: the caller's own headers
    /// minus anything in the gateway-owned `Mcp-Param-` namespace, plus the
    /// mirrors this `tools/call` declares (MIK-7214.HEADER.5).
    ///
    /// The strip runs on every method, so a caller-supplied `Mcp-Param-*`
    /// header can never reach a backend as though a schema had declared it —
    /// the annotation is a server-side declaration, never a caller parameter.
    ///
    /// THE SCHEMA COMES OFF `identity_key`'S OWN SLOT (MIK-7334.CATALOGUE.1):
    /// the shared one holds a catalogue this caller was never shown once a
    /// `stateless` backend lists per caller. Read non-blocking — a cold cache
    /// mirrors nothing rather than a `tools/list` under this request's permit.
    /// Since F13 a `tools/call` rarely finds it cold: R2's check lists a cold
    /// slot before dispatch, holding no backend permit, so the first call is
    /// mirrored too.
    fn param_header_set(
        &self,
        method: &str,
        params: Option<&Value>,
        extra_headers: &[(String, String)],
        identity_key: Option<&str>,
    ) -> Vec<(String, String)> {
        let mut headers: Vec<(String, String)> = extra_headers
            .iter()
            .filter(|(name, _)| !is_param_header(name))
            .cloned()
            .collect();

        if method != "tools/call" {
            return headers;
        }
        let Some(params) = params else {
            return headers;
        };
        let (Some(name), Some(arguments)) = (
            params.get("name").and_then(Value::as_str),
            params.get("arguments"),
        ) else {
            return headers;
        };
        let mirrors = self.with_cached_tool_for(identity_key, name, |tool| {
            mirror_headers(&tool.input_schema, arguments)
        });
        headers.extend(mirrors.into_iter().flatten());
        headers
    }

    /// The params and headers a call is sent with: this backend's `secrets:`
    /// rules applied, and the arguments its tool's schema declares mirrored.
    ///
    /// The keys the rules own are dropped before the mirror reads the
    /// arguments, and the values are added after it, so neither a caller's
    /// value for such a key nor the secret is mirrored into a header.
    /// Synchronous, so nothing it builds is held in the send's future.
    ///
    /// SEP-2243 (MIK-7214.HEADER.5): the mirror sits here, not in each
    /// dispatcher, because every tools/call — the MCP provider, meta-MCP
    /// invoke, the router's direct backend route — funnels through
    /// [`Self::request_attempted`], so a per-caller mirror would leave the
    /// siblings unmirrored.
    fn outbound(
        &self,
        method: &str,
        params: Option<Value>,
        extra_headers: &[(String, String)],
        identity_key: Option<&str>,
    ) -> Result<super::secret_send::Outbound> {
        let secrets = self.prepare_secrets(method, params)?;
        let headers =
            self.param_header_set(method, secrets.params.as_ref(), extra_headers, identity_key);
        Ok(secrets.apply(headers))
    }

    /// This request's resend decision: the permission the transport carries,
    /// and the retry policy this layer may resend under.
    ///
    /// ADR-012 consequence 2: a call is retried only where the resend
    /// predicate grants permission, because a failure that is not provably
    /// pre-dispatch may have left the side effect committed. The decision is
    /// made here rather than in `is_retryable` because only this level knows
    /// the method and the tool: the primitive is shared with
    /// `send_with_retry`, whose callers must keep retrying.
    ///
    /// The permission comes from [`resend_permission`], the same predicate the
    /// transport's session-expiry recovery uses, so the two resend sites cannot
    /// drift apart. Both halves come out of ONE derivation, so the retry policy
    /// and the recovery beneath it cannot disagree about one request.
    ///
    /// THE PERMITTED SET COMES OFF THE SLOT, not off the backend
    /// (MIK-7334.CATALOGUE.1 R1). It is derived from that slot's `tools/list`,
    /// so reading a backend-wide one here would let the identity whose fill ran
    /// last decide whether THIS caller's non-idempotent call may be resent. The
    /// caller already holds the `PooledEntry` it is dispatching over, so the
    /// retry decision and the catalogue it rests on come from one object.
    fn resend_decision(
        entry: &super::pool::PooledEntry,
        method: &str,
        params: Option<&Value>,
    ) -> (ResendPermission, RetryPolicy) {
        let permission = resend_permission(method, params, &entry.resend_permitted.read());
        let configured = &entry.failsafe.retry_policy;
        let policy = match permission {
            ResendPermission::Permitted => configured.clone(),
            ResendPermission::Denied => RetryPolicy {
                enabled: false,
                ..configured.clone()
            },
        };
        (permission, policy)
    }

    /// Send a request, adding per-request outbound headers (e.g. a propagated
    /// end-user identity credential -- MIK-6704). The headers are forwarded by
    /// value to the transport's `request_with_headers`, never stored on the
    /// backend, so concurrent per-user requests stay isolated (IDP.3).
    ///
    /// `identity_key` is the caller's stable identity binding (MIK-6784); the
    /// transport uses it to partition upstream `MCP-Session-Id` state so one
    /// user's session is never reused for another. `None` selects the shared
    /// default bucket (single-tenant behavior unchanged).
    ///
    /// # Errors
    ///
    /// Returns an error if the backend is unavailable, the concurrency limit
    /// is reached, or the request itself fails after retries.
    pub async fn request_with_headers(
        &self,
        method: &str,
        params: Option<Value>,
        extra_headers: &[(String, String)],
        identity_key: Option<&str>,
    ) -> Result<JsonRpcResponse> {
        self.request_with_headers_lent(
            method,
            params,
            crate::transport::LentCredential::unchecked(extra_headers),
            identity_key,
        )
        .await
    }

    /// [`Self::request_with_headers`] for a credential the mint core produced, which may
    /// carry the send check the plain-slice entry cannot express.
    pub(crate) async fn request_with_headers_lent(
        &self,
        method: &str,
        params: Option<Value>,
        extra_headers: crate::transport::LentCredential,
        identity_key: Option<&str>,
    ) -> Result<JsonRpcResponse> {
        self.send_in_scope(
            method,
            params,
            extra_headers,
            identity_key,
            Attempts::WithRetry,
        )
        .await
    }

    /// The same request, declaring the gateway's upstream tasks extension and
    /// sent EXACTLY ONCE.
    ///
    /// Two properties, both structural rather than promised.
    ///
    /// The declaration is made by the transport
    /// ([`crate::transport::Transport::request_with_task_capability`]), not by a
    /// marker in `params`: a JSON flag would be forgeable by anything that can
    /// reach the ordinary request path, including caller-supplied arguments.
    /// That method also refuses any method outside its own allow-list and any
    /// peer not known to be modern, locally, before the wire.
    ///
    /// One attempt, because `with_retry` cannot tell a lost response from a
    /// request the peer never saw: retrying a task-augmented `tools/call` would
    /// create a second upstream job and leave this gateway holding only the
    /// second handle, with the first running unowned. No later layer can undo
    /// a second submission, so it must not be possible to make one.
    ///
    /// Everything else is unchanged: the same pool slot, failsafe gate,
    /// concurrency permit, activity guard and outcome recording.
    ///
    /// # Errors
    ///
    /// Returns an error if the backend is unavailable, the concurrency limit
    /// is reached, the transport cannot declare the extension, or the single
    /// attempt fails.
    pub async fn request_with_task_capability(
        &self,
        method: &str,
        params: Option<Value>,
        extra_headers: &[(String, String)],
        identity_key: Option<&str>,
    ) -> Result<JsonRpcResponse> {
        self.request_with_task_capability_lent(
            method,
            params,
            crate::transport::LentCredential::unchecked(extra_headers),
            identity_key,
        )
        .await
    }

    /// [`Self::request_with_task_capability`] for a credential the mint core produced, which may
    /// carry the send check the plain-slice entry cannot express.
    pub(crate) async fn request_with_task_capability_lent(
        &self,
        method: &str,
        params: Option<Value>,
        extra_headers: crate::transport::LentCredential,
        identity_key: Option<&str>,
    ) -> Result<JsonRpcResponse> {
        self.send_in_scope(
            method,
            params,
            extra_headers,
            identity_key,
            Attempts::TaskCapabilityOnce,
        )
        .await
    }

    pub(super) async fn request_attempted(
        &self,
        method: &str,
        params: Option<Value>,
        extra_headers: crate::transport::LentCredential,
        identity_key: Option<&str>,
        attempts: Attempts,
    ) -> Result<JsonRpcResponse> {
        let start_time = std::time::Instant::now();

        // Every send funnels through here, so a withheld tool (#1441) and any
        // send by an instance other than the one an exempt call was judged on
        // (MIK-8154 F2: a reload; nothing sent, so "unavailable") stop here.
        if let Some(refusal) = self.blocked_call_refusal(method, params.as_ref(), identity_key) {
            return Err(refusal);
        }

        // MIK-7272.SUB.2b / ADR-014 §2: never hand a backend the client's own
        // progress token. This sits here for the same reason the param mirror
        // below does -- meta-MCP invoke and the router's direct backend route
        // both funnel through this function, and minting in one dispatcher
        // would leave the sibling route forwarding the caller's token.
        let params = substitute_progress_token(params);

        // This backend's `secrets:` rules and the `Mcp-Param-*` mirror, both here because every
        // route's tools/call passes through. Resolved before the call is admitted, so a value that
        // does not resolve holds no permit. The caller's own credential is taken first, before the
        // rules or the mirror add anything: a slot's start lends only that.
        let credential = extra_headers;
        let (params, extra_headers) =
            self.outbound(method, params, &credential.headers, identity_key)?;

        // Derive the per-identity pool slot FIRST (MIK-6735 fix 1, adversarial
        // review of commit bfd62b91). Each slot owns its own circuit breaker +
        // rate limiter + health tracker, so which slot's failsafe to gate on
        // must be known before the `admit()` check runs -- gating on a
        // single backend-wide `Failsafe` let one caller identity's outage trip
        // the breaker for every other identity sharing the backend, the exact
        // cross-tenant blast radius this pool exists to eliminate. A backend
        // without identity propagation, or a propagating request without a
        // resolved identity, collapses to the shared canonical slot (IDP.5); an
        // identified request gets its own transport/session/failsafe so users
        // never collide (IDP.7).
        let key = self.pool_key_for(identity_key);
        let entry = self.pooled_entry(&key)?;

        // Check THIS slot's failsafe, not the backend's.
        entry.failsafe.admit(&self.name).inspect_err(|e| {
            tracing::warn!(backend = %self.name, "Request rejected: {e}");
        })?;

        // Acquire semaphore
        let _permit = self.semaphore.acquire().await.map_err(|_| {
            tracing::warn!("Concurrency limit reached");
            Error::BackendUnavailable("Concurrency limit reached".to_string())
        })?;

        self.request_count.fetch_add(1, Ordering::Relaxed);

        // Mark CLIENT activity for the idle clock, and hold this slot safe from
        // being stopped for the whole request. Released when the guard drops.
        let activity = self.begin_activity(&key)?;
        // The entry just claimed, which the idle reaper cannot take while this
        // request holds it. The one captured above may already be evicted, and
        // the start and dispatch outcomes belong to the slot actually used (#2261).
        let entry = std::sync::Arc::clone(activity.entry());
        // This dispatch's credential is what a lent-only slot sends as, its
        // start included, for as long as the dispatch runs.
        let loan = self.lend_to_slot(&key, &entry, &credential)?;

        // Ensure this slot's transport is live. The start sends no call's
        // headers, so a lent-only slot sends it as this dispatch's loan.
        let transport = {
            let _starting = loan.as_ref().map(|held| entry.lender.starting(held.id()));
            self.start_judged(&key, &entry, start_time, method).await?
        };

        // Execute with retry
        let name = self.name.clone();
        // Own the identity key so each send can hand a borrow to its future
        // without tying the closure to the caller's borrow lifetime (MIK-6784).
        let identity_key = identity_key.map(str::to_string);
        let (perm, policy) = Self::resend_decision(&entry, method, params.as_ref());
        let send = |params: Option<Value>, extra_headers: Vec<(String, String)>| {
            let transport = std::sync::Arc::clone(&transport);
            let method = method.to_string();
            let identity_key = identity_key.clone();
            async move {
                match attempts {
                    Attempts::WithRetry => {
                        transport
                            .request_with_headers(
                                &method,
                                params,
                                &extra_headers,
                                identity_key.as_deref(),
                                perm,
                            )
                            .await
                    }
                    Attempts::TaskCapabilityOnce => {
                        transport
                            .request_with_task_capability(
                                &method,
                                params,
                                &extra_headers,
                                identity_key.as_deref(),
                            )
                            .await
                    }
                }
            }
        };
        // A call sent at most once (as `with_retry` sends under a disabled
        // policy) moves its payload in; only a resend copies (NFR.WORKLOAD.1).
        let mut result = if matches!(attempts, Attempts::TaskCapabilityOnce) || !policy.enabled {
            send(params, extra_headers).await
        } else {
            // A refused credential repeats its refusal: stop once this
            // dispatch's own loan was marked.
            let refused = || loan.as_ref().is_some_and(|held| held.refused().is_some());
            with_retry_unless(&policy, &name, refused, || {
                send(params.clone(), extra_headers.clone())
            })
            .await
        };
        // Every backend answer enters here, so this is the one place a
        // backend's copy of a gateway-only member, and a protocol member it
        // sent where the protocol does not let it, is removed, before any
        // gate, cache or store reads the answer. Only the task-augmented send
        // declares the tasks extension upstream, so only it may be answered
        // with a task handle; any other such answer is refused.
        let declared = match attempts {
            Attempts::TaskCapabilityOnce => crate::protocol::member_scope::Declared::Tasks,
            Attempts::WithRetry => crate::protocol::member_scope::Declared::Nothing,
        };
        if let Ok(response) = &result
            && let Some(refusal) = response.result.as_ref().and_then(|answer| {
                crate::protocol::member_scope::undeclared_task(method, answer, declared)
            })
        {
            tracing::warn!(backend = %self.name, method, "{refusal}");
            result = Err(Error::Protocol(format!(
                "backend '{}': {refusal}",
                self.name
            )));
        }
        if let Ok(response) = &mut result {
            crate::protocol::reserved_members::strip_ingress(
                &self.name, method, declared, response,
            );
        }

        // Calculate latency
        let latency = start_time.elapsed();

        // Record success/failure against the SAME slot's failsafe used for the
        // `admit()` gate above, so gating and recording are always
        // symmetric even if a concurrent idle-eviction later replaces this
        // slot's `PooledEntry` for `key` (MIK-6735 fix 1).
        self.record_attempt_outcome(&entry, latency, &result);

        // An ordinary answer can contradict the era we probed for: a peer that
        // rejects this call with a 2026-only code is modern whatever its
        // `server/discover` did. Correct the verdict: off the request path,
        // except on a lent-only slot, whose probe needs this dispatch's loan.
        if let Ok(response) = &result {
            self.reprobe_if_contradicted(method, response, &transport, &credential.headers)
                .await;
        }

        result
    }

    /// Start (or reuse) the slot's transport. Both the request and the notify path
    /// start here, on every transport: a failed spawn, upgrade or `initialize` is
    /// recorded on the slot's failsafe (F17) so the breaker names it, then returned
    /// as the pre-send refusal it is ([`super::lifecycle::pre_send_start_error`]).
    pub(super) async fn start_recorded(
        &self,
        key: &super::pool::PoolKey,
        entry: &super::PooledEntry,
        started_at: std::time::Instant,
    ) -> Result<std::sync::Arc<dyn crate::transport::Transport>> {
        let started = self.ensure_entry_started(key).await;
        started
            .inspect_err(|e| self.record_dispatch_error(entry, started_at.elapsed(), e, "Start"))
            .map_err(|e| super::lifecycle::pre_send_start_error(&self.name, e))
    }

    /// Record a failed dispatch against the slot's failsafe, log it, and count
    /// it; `exchange` is the log line's noun. A login in progress is not one.
    fn record_dispatch_error(
        &self,
        entry: &super::PooledEntry,
        latency: std::time::Duration,
        error: &Error,
        exchange: &'static str,
    ) {
        if error.is_authorization_wait() {
            // The backend was never asked: someone must sign in.
            entry
                .auth_wait
                .store(true, std::sync::atomic::Ordering::Relaxed);
            return;
        }
        // A busy credential lock is not a backend failure either: the token
        // step never reached the wire, so it takes no breaker sample.
        if crate::oauth::client::is_credential_lock_busy(error) {
            return;
        }
        let rate_limited =
            super::fill_check::record_request_failure(entry, &error.to_string(), latency);
        if rate_limited {
            tracing::warn!(
                code = error.to_rpc_code(),
                latency_ms = latency.as_millis(),
                "{exchange} rate limited"
            );
        } else {
            tracing::error!(
                code = error.to_rpc_code(),
                latency_ms = latency.as_millis(),
                "{exchange} failed"
            );
        }
        self.count_outcome(if rate_limited {
            "rate_limited"
        } else {
            "error"
        });
    }

    /// Count one dispatch outcome under its `status` label.
    fn count_outcome(&self, status: &'static str) {
        telemetry_metrics::counter!(
            "mcp_backend_requests_total",
            "backend" => self.metric_label.clone(),
            "status" => status
        )
        .increment(1);
    }

    /// Record how long one dispatch took, whatever its outcome.
    fn record_dispatch_latency(&self, latency: std::time::Duration) {
        telemetry_metrics::histogram!(
            "mcp_backend_request_duration_seconds",
            "backend" => self.metric_label.clone()
        )
        .record(latency.as_secs_f64());
    }

    /// Record the outcome of one dispatch attempt against the slot's failsafe and
    /// the request-duration metrics; split out of [`Self::request_attempted`] for
    /// its line budget, logic and ordering unchanged.
    fn record_attempt_outcome(
        &self,
        entry: &super::PooledEntry,
        latency: std::time::Duration,
        result: &Result<JsonRpcResponse>,
    ) {
        match result {
            Ok(response) => {
                tracing::info!(
                    latency_ms = latency.as_millis(),
                    "Request completed successfully"
                );
                // A throttle can also arrive as a JSON-RPC success carrying
                // `isError: true`; reaching `record_success` with one would break
                // a real failure streak and could close a half-open circuit.
                let throttled = response.result.as_ref().is_some_and(|result| {
                    result
                        .get("isError")
                        .and_then(serde_json::Value::as_bool)
                        .unwrap_or(false)
                        && crate::gateway::recovery::is_rate_limited(&result.to_string())
                });
                if throttled {
                    tracing::warn!(latency_ms = latency.as_millis(), "Request rate limited");
                    entry.failsafe.record_rate_limited("rate limited", latency);
                } else {
                    super::fill_check::record_request_success(entry, latency);
                }
                self.count_outcome(if throttled { "rate_limited" } else { "ok" });
            }
            Err(e) => self.record_dispatch_error(entry, latency, e, "Request"),
        }
        self.record_dispatch_latency(latency);
    }

    /// Send a notification to the backend via the canonical shared slot's
    /// session (callers without a private slot; single-tenant behavior unchanged).
    ///
    /// # Errors
    ///
    /// Returns an error if the backend is unavailable, the concurrency limit
    /// is reached, or the notification cannot be sent.
    pub async fn notify(&self, method: &str, params: Option<Value>) -> Result<()> {
        self.notify_with_headers_lent(
            method,
            params,
            crate::transport::LentCredential::default(),
            None,
        )
        .await
    }

    /// Send a notification carrying the caller's identity key so it is routed
    /// through the SAME pool slot -- and the SAME upstream `MCP-Session-Id`
    /// bucket -- that a prior `request_with_headers` call for that identity
    /// used (MIK-6735 fix 2, adversarial review of commit bfd62b91).
    ///
    /// Before this fix, every notification hardcoded `ensure_started()` (the
    /// canonical Shared slot) regardless of the caller's identity, so on a
    /// `PerUser` backend a notification correlating a request that went
    /// through a per-user slot (e.g. `notifications/cancelled`) went out on
    /// the wrong upstream session -- or, even once routed to the right
    /// transport instance, with no session ID at all, since
    /// [`crate::transport::Transport::notify`] never threaded an identity key
    /// through to the transport's session-bucket lookup either. Both layers
    /// are fixed together here: `identity_key` selects the same `PoolKey` as
    /// `request_with_headers` (IDP.7), and is forwarded to
    /// [`crate::transport::Transport::notify_with_headers`] so an HTTP
    /// transport selects the matching `MCP-Session-Id` bucket. `None`
    /// preserves the unchanged Shared-slot path (IDP.5).
    ///
    /// # Errors
    ///
    /// Returns an error if the backend is unavailable, the concurrency limit
    /// is reached, or the notification cannot be sent.
    pub async fn notify_with_headers(
        &self,
        method: &str,
        params: Option<Value>,
        extra_headers: &[(String, String)],
        identity_key: Option<&str>,
    ) -> Result<()> {
        self.notify_with_headers_lent(
            method,
            params,
            crate::transport::LentCredential::unchecked(extra_headers),
            identity_key,
        )
        .await
    }

    /// [`Self::notify_with_headers`] for a credential the mint core produced,
    /// which may carry the send check the plain-slice entry cannot express.
    // `identity_key` is the caller's pool binding, for an A2A caller an
    // unkeyed hash of its principal: never a span field (MIK-8697).
    #[tracing::instrument(
        skip(self, params, extra_headers, identity_key),
        fields(
            backend = %self.name,
            method = %method,
            request_id = %uuid::Uuid::new_v4()
        )
    )]
    pub(crate) async fn notify_with_headers_lent(
        &self,
        method: &str,
        params: Option<Value>,
        extra_headers: crate::transport::LentCredential,
        identity_key: Option<&str>,
    ) -> Result<()> {
        let start_time = std::time::Instant::now();

        // A tool call sent as a notification is refused as a request is: the
        // backend never receives a withheld tool (#1441).
        if let Some(refusal) = self.blocked_call_refusal(method, params.as_ref(), identity_key) {
            return Err(refusal);
        }

        // Derive the same slot `request_with_headers` would use for this
        // identity, and gate/record against ITS failsafe (mirrors fix 1).
        let key = self.pool_key_for(identity_key);
        let entry = self.pooled_entry(&key)?;

        entry.failsafe.admit(&self.name).inspect_err(|e| {
            tracing::warn!(backend = %self.name, "Notification rejected: {e}");
        })?;

        let _permit = self.semaphore.acquire().await.map_err(|_| {
            tracing::warn!("Concurrency limit reached");
            Error::BackendUnavailable("Concurrency limit reached".to_string())
        })?;

        self.request_count.fetch_add(1, Ordering::Relaxed);

        // See `request_with_headers`: client activity marking + stop protection.
        let activity = self.begin_activity(&key)?;
        // As in `request_attempted`: record on the claimed entry (#2261).
        let entry = std::sync::Arc::clone(activity.entry());
        let loan = self.lend_to_slot(&key, &entry, &extra_headers)?;

        let transport = {
            let _starting = loan.as_ref().map(|held| entry.lender.starting(held.id()));
            self.start_recorded(&key, &entry, start_time).await?
        };

        let result = transport
            .notify_with_headers(method, params, &extra_headers.headers, identity_key)
            .await;
        let latency = start_time.elapsed();

        match &result {
            Ok(()) => {
                tracing::info!(
                    latency_ms = latency.as_millis(),
                    "Notification sent successfully"
                );
                entry.failsafe.record_success(latency);
                self.count_outcome("ok");
            }
            Err(e) => self.record_dispatch_error(&entry, latency, e, "Notification"),
        }
        self.record_dispatch_latency(latency);

        result
    }

    /// The refusal for a `tools/call` naming a withheld tool, shared by the
    /// request and notification paths so neither can skip it (#1441).
    fn blocked_call_refusal(
        &self,
        method: &str,
        params: Option<&Value>,
        identity_key: Option<&str>,
    ) -> Option<crate::Error> {
        if let Some(reloaded) = crate::gateway::changed_instance(self) {
            return Some(crate::Error::BackendUnavailable(reloaded));
        }
        if method != "tools/call" {
            return None;
        }
        let tool = params.and_then(|p| p.get("name")).and_then(Value::as_str)?;
        self.blocked_tool_refusal(identity_key, tool)
            .map(crate::Error::Protocol)
    }
}

/// Replace the caller's `_meta.progressToken` with a gateway-minted one,
/// recording the pair so the notification carrying it back can be restored.
///
/// `params` travels unchanged when the request carries no progress token, or
/// when the call runs outside a request scope -- health probes, warm-up
/// handshakes and the reaper have no client to translate back to.
fn substitute_progress_token(params: Option<Value>) -> Option<Value> {
    let mut params = params?;
    let client = params
        .get("_meta")
        .and_then(|meta| meta.get("progressToken"))
        .cloned();
    let Some(client) = client else {
        return Some(params);
    };
    let Some(minted) = crate::transport::notification_sink::mint_progress_token(&client) else {
        // A caller token reaching a backend unsubstituted is exactly what this
        // function exists to prevent, so say so. Expected for the probe and
        // reaper routes, which have no client; on a client-carrying route it
        // is a wiring gap, and only a log makes it visible before the backend
        // starts echoing a token the gateway cannot attribute.
        // ci-allow-secret-log: an MCP progress token is a caller-chosen correlation id, not a credential; the value is what makes the miss attributable
        tracing::debug!(
            token = %client,
            "outbound call carries a caller progress token but runs outside a request scope; forwarding it unchanged"
        );
        return Some(params);
    };
    if let Some(Value::Object(meta)) = params.get_mut("_meta") {
        meta.insert("progressToken".to_string(), Value::String(minted));
    }
    Some(params)
}

#[cfg(test)]
#[path = "progress_token_substitution_tests.rs"]
mod progress_token_substitution_tests;

// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The prelude of `meta_mcp_dispatch` (MIK-8143): identity, body, session,
//! signing, parse, request checks and owners, derived once per request.
//!
//! Moved verbatim from the dispatcher; each early `return <response>` became
//! `return Err(<response>)`, which the dispatcher returns unchanged.

use std::sync::Arc;

use axum::{
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
};
use serde_json::{Value, json};
use tracing::{debug, warn};

use super::{
    TASKS_EXTENSION, events, listened_task_ids, owner::request_session_owner,
    reaches_tasks_extension, request_checks, session_id_header, tasks,
};
use crate::gateway::auth::AuthenticatedClient;
use crate::gateway::meta_mcp::signing::SigningInvocationContext;
use crate::gateway::oauth::AgentIdentity as OAuthAgentIdentity;
use crate::gateway::recovery::SurfaceRequest;
use crate::gateway::router::AppState;
use crate::gateway::router::helpers::{
    build_accepted_response, build_error_response, build_error_response_with_data,
    build_http_error_response, build_response, extract_tools_call_params_ref, parse_request_ref,
};
use crate::gateway::session_id::SessionId;
use crate::key_server::oidc::VerifiedIdentity;
use crate::mtls::CertIdentity;
use crate::protocol::RequestId;
use crate::security::{
    AgentIdentity, extract_agent_identity, log_agent_identity, sanitize_json_value,
    validate_agent_identity,
};

/// What the prelude hands the frame judge: consumed by value on the listen
/// arm, read by the postlude on every other.
pub(super) struct JudgeInputs {
    pub(super) read_guard: Option<Arc<crate::gateway::outbound::Guard>>,
    pub(super) read_key: Option<String>,
}

/// The facts the prelude derives, owned, for the method arms and the postlude.
pub(super) struct Intake<'r> {
    pub(super) headers: HeaderMap,
    pub(super) client: Option<AuthenticatedClient>,
    pub(super) cert_identity: Option<CertIdentity>,
    pub(super) oauth_agent_identity: Option<OAuthAgentIdentity>,
    pub(super) verified_identity: Option<VerifiedIdentity>,
    pub(super) presented: events::Presented,
    pub(super) agent_identity: AgentIdentity,
    pub(super) code_mode_url_active: bool,
    pub(super) surface_request: SurfaceRequest,
    pub(super) grant_subject: Option<crate::identity_grants::GrantSubject>,
    pub(super) session_id: String,
    // Read only by the firewall's per-caller controls.
    #[cfg_attr(not(feature = "firewall"), allow(dead_code))]
    pub(super) existing_session_id: Option<String>,
    pub(super) chain_nonce: Option<String>,
    pub(super) request: Value,
    narrowed_listen: Option<Value>,
    pub(super) id: RequestId,
    pub(super) method: String,
    pub(super) era: crate::protocol::meta::Era,
    pub(super) is_modern: bool,
    pub(super) declared_capabilities: crate::protocol::meta::Declared,
    pub(super) protocol_revision_owned: Option<String>,
    pub(super) header_profile: Option<String>,
    pub(super) owner: String,
    pub(super) events_owner: String,
    pub(super) admission_owner: String,
    pub(super) external_tool: String,
    // Held, never read: the in-flight permit drops when the dispatcher
    // returns. The dispatcher binds `Intake` after `JudgeInputs`, so the
    // permit drops before the read guard, as the two locals did.
    _inflight_permit: Result<tokio::sync::SemaphorePermit<'r>, tokio::sync::AcquireError>,
}

impl Intake<'_> {
    /// The request's params, or the private copy a `subscriptions/listen`
    /// narrowed to the caller's own tasks.
    pub(super) fn params(&self) -> Option<&Value> {
        self.narrowed_listen
            .as_ref()
            .or_else(|| self.request.get("params"))
    }
}

/// The prelude, run once per request. `Err` is a finished answer the
/// dispatcher returns as it is.
#[allow(
    clippy::too_many_lines,
    clippy::type_complexity,
    clippy::result_large_err
)]
pub(super) async fn intake(
    state: &Arc<AppState>,
    http_request: axum::http::Request<axum::body::Body>,
) -> Result<(JudgeInputs, Option<SigningInvocationContext>, Intake<'_>), axum::response::Response> {
    // Extract headers and authenticated client from request
    let headers = http_request.headers().clone();
    let client = http_request
        .extensions()
        .get::<AuthenticatedClient>()
        .cloned();
    // Extract mTLS certificate identity (present when mTLS is active and a valid
    // client certificate was presented during the TLS handshake).
    let cert_identity = http_request.extensions().get::<CertIdentity>().cloned();
    let oauth_agent_identity = http_request
        .extensions()
        .get::<OAuthAgentIdentity>()
        .cloned();
    let verified_identity = http_request.extensions().get::<VerifiedIdentity>().cloned();
    // MCP Events caps a subscription at the credential's own expiry.
    let presented = events::Presented::capture(&http_request);

    // === OWASP ASI03: per-agent identity ===
    //
    // Resolve what the request PROVED (mTLS subject, verified JWT `sub`) from
    // what it merely DECLARED (X-Agent-ID, agent_id query param). The bearer
    // string is deliberately NOT passed: a payload decoded without checking the
    // signature is the caller's own assertion, and the verified `sub` is
    // already in extensions via `agent_auth_middleware`.
    let query_str = http_request.uri().query();
    let agent_identity = extract_agent_identity(
        &headers,
        query_str,
        cert_identity.as_ref(),
        oauth_agent_identity.as_ref().map(|a| a.client_id.as_str()),
    );

    // Per-connection Code Mode override (issue #146).
    // Accepted value: ?codemode=search_and_execute
    // When the static config already enables Code Mode, this is a no-op.
    let code_mode_url_active = query_str.is_some_and(|q| {
        q.split('&')
            .any(|pair| pair == "codemode=search_and_execute")
    });
    let surface_request = SurfaceRequest::from_url(code_mode_url_active);
    // The refusal arm emits its own audit record. Before this change it
    // returned silently, so a proved-A-claimed-B refusal left no trace on the
    // one path an attacker is most likely to be on.
    match validate_agent_identity(&agent_identity, &state.agent_identity_config) {
        Ok(audit) => {
            log_agent_identity(&agent_identity, audit, None);
        }
        Err(reason) => {
            log_agent_identity(
                &agent_identity,
                crate::security::IdentityAudit::Clean,
                Some(&reason),
            );
            return Err(
                build_http_error_response(None, -32600, reason, StatusCode::FORBIDDEN)
                    .into_response(),
            );
        }
    }

    // The caller as a grant subject, resolved once and before the body is
    // read, so a refused identity header reaches no dispatch, cache or idempotency work.
    let (grant_subject, caller_owner) =
        match request_session_owner(state, &headers, http_request.extensions(), client.as_ref())
            .await
        {
            Ok(resolved) => resolved,
            Err(refusal) => return Err(refusal),
        };
    // MIN.2: the caller every frame of this request is judged for, formed
    // only when the verdict is on (the default config allocates nothing).
    let read_guard = crate::gateway::router::helpers::read_guard(state);
    let read_key = crate::gateway::outbound::judges(read_guard.as_deref())
        .then(|| {
            crate::gateway::router::identity::caller_key(
                grant_subject.as_ref(),
                cert_identity.as_ref(),
                client.as_ref(),
            )
        })
        .filter(|key| !key.is_empty());
    if let Some(key) = &read_key {
        crate::transport::notification_sink::bind_reader(|| key.clone());
    }

    // Parse JSON body
    let body_bytes = match crate::gateway::router::helpers::read_body(http_request).await {
        Ok(bytes) => bytes,
        Err(refusal) => return Err(refusal.into_response()),
    };

    let mut request: Value = match serde_json::from_slice(&body_bytes) {
        Ok(v) => v,
        Err(e) => {
            return Err(build_http_error_response(
                None,
                -32700,
                format!("Invalid JSON: {e}"),
                StatusCode::BAD_REQUEST,
            )
            .into_response());
        }
    };
    // Track in-flight request for graceful drain
    let inflight_permit = state.inflight.acquire().await;

    if !state.meta_mcp_enabled {
        return Err((
            [(
                axum::http::header::HeaderName::from_static("content-type"),
                axum::http::header::HeaderValue::from_static("application/json"),
            )],
            build_http_error_response(None, -32600, "Meta-MCP disabled", StatusCode::FORBIDDEN),
        )
            .into_response());
    }

    // 2026-07-28 removed protocol-level sessions, so a request written against
    // it gets none — and answering it with a session header would hand a
    // stateless client state the revision deleted, and an intermediary a value
    // to route on.
    //
    // Decided from the header, before the body is parsed, because the session
    // is created first; the mirrored-header check refuses a modern request
    // without `MCP-Protocol-Version`. Any modern declaration counts, even an
    // unsupported 2026 revision: it is stateless and about to be refused.
    // Read duplicate-safe and ONCE (`headers.get` returns the FIRST value): a
    // doubled header takes the modern reading and reaches the refusal with no
    // session behind it.
    let mut version_headers = headers.get_all("mcp-protocol-version").iter();
    let declared_version = match (version_headers.next(), version_headers.next()) {
        (Some(only), None) => only.to_str().ok(),
        (None, _) => None,
        (Some(_), Some(_)) => Some(crate::protocol::meta::MODERN_VERSIONS[0]),
    };
    let declares_modern_by_header =
        declared_version.is_some_and(crate::protocol::meta::declares_modern_era);

    // Get or create session for this client
    let existing_session_id = session_id_header(&headers).map(String::from);

    // Not a stream reader, so no branch subscribes: a held subscription
    // fakes a deliverable prompt.
    let opened = if declares_modern_by_header {
        // No session, and none minted. Minting one per request grew a table of
        // sessions nothing could reach, and handed the sequence-anomaly
        // detector a fresh identity every call — a detector that sees a first
        // request every time keeps running and stops protecting.
        None
    } else {
        // The identity that owns the session. A caller with neither a subject
        // nor a credential is "anonymous", so a single-user gateway behaves
        // exactly as before.
        let held = crate::gateway::auth::live::held_credential(&headers);
        let existing = existing_session_id.as_deref();
        Some(
            if !crate::gateway::router::hardened_elicitation::is_hardened(state) {
                state
                    .multiplexer
                    .get_or_create_session_id_scoped(existing, &caller_owner, held)
            } else if crate::gateway::router::hardened_elicitation::is_initialize(&request) {
                // Hardened (row 10): refused before anything is minted.
                if !crate::gateway::router::hardened_elicitation::declares_elicitation(&request) {
                    return Err(
                        crate::gateway::router::hardened_elicitation::refusal().into_response()
                    );
                }
                state
                    .multiplexer
                    .get_or_create_session_id_scoped(existing, &caller_owner, held)
            } else {
                // Hardened: only a declaring `initialize` opens a legacy session.
                match state
                    .multiplexer
                    .resume_session_id_scoped(existing, &caller_owner, held)
                {
                    Some(id) => id,
                    None => {
                        return Err(
                            crate::gateway::router::hardened_elicitation::refusal().into_response()
                        );
                    }
                }
            },
        )
    };
    // The empty id is the router's "no session"; its fingerprint is empty too.
    let session_id = opened
        .as_ref()
        .map_or_else(String::new, |id| id.expose_secret().to_owned());
    // MIK-8161: the notification screen's verdicts name this caller and session.
    let screen_caller = client.as_ref().map_or("anonymous", |c| c.name.as_str());
    crate::transport::notification_sink::bind_screen(screen_caller, &session_id);

    let raw_id = crate::protocol::mrtr::raw_request_id(&request);
    // A failed grant-decision write refuses under this id (MIK-7663.GH2409.3).
    crate::gateway::meta_mcp::grant_audit::note_answer_id(raw_id.as_ref());
    // Hardened signs every `tools/call` here, not only `gateway_invoke`
    // (GH1942.HARDEN.1 row 7).
    let mut signing_context = state.meta_mcp.signing_enabled().then(|| {
        use crate::gateway::meta_mcp::signing::{SigningInvocationContext, SigningScope};
        let scope = SigningScope::of(state.live_config.running().security.posture);
        SigningInvocationContext::capture_scoped(&mut request, scope)
    });
    // Off the request before sanitization can rewrite or reject its bytes
    // (ASI07 A3); a malformed one is refused here, with the request's own id.
    let chain_nonce = match crate::protocol::mrtr::take_chain_nonce(&mut request) {
        Ok(nonce) => nonce,
        Err(error) => {
            let message = crate::gateway::meta_mcp::signing::wire_error_message(&error);
            let code = error.to_rpc_code();
            return Err(build_error_response(
                raw_id,
                code,
                message,
                &session_id,
                StatusCode::BAD_REQUEST,
            ));
        }
    };
    // Optionally sanitize input
    let mut request = if state.sanitize_input {
        match sanitize_json_value(&request) {
            Ok(sanitized) => sanitized,
            Err(e) => {
                return Err(build_error_response(
                    None,
                    -32600,
                    e.to_string(),
                    &session_id,
                    StatusCode::BAD_REQUEST,
                ));
            }
        }
    } else {
        request
    };

    if let Some(context) = signing_context.as_mut()
        && let Err(error) = context.restore(&mut request)
    {
        return Err(build_error_response(
            None,
            error.to_rpc_code(),
            crate::gateway::meta_mcp::signing::wire_error_message(&error),
            &session_id,
            StatusCode::BAD_REQUEST,
        ));
    }
    if let Some(error) = signing_context
        .as_ref()
        .and_then(|context| context.refuse_malformed_nonce_early().err())
    {
        return Err(build_error_response(
            raw_id,
            error.to_rpc_code(),
            crate::gateway::meta_mcp::signing::wire_error_message(&error),
            &session_id,
            StatusCode::BAD_REQUEST,
        ));
    }

    // Detect client POST-back responses (has "result" or "error" but no "method").
    // These are replies to server-to-client requests such as `sampling/createMessage`.
    // Must be handled BEFORE `parse_request`, which rejects messages without "method".
    if request.get("method").is_none()
        && (request.get("result").is_some() || request.get("error").is_some())
        && let Some(resp_id) = request.get("id").and_then(|v| v.as_str())
        && crate::gateway::input_bridge::is_bridge_reply_id(resp_id)
    {
        debug!(id = %resp_id, body = %request, "Received sampling/elicitation response POST-back");
        let resolved = state
            .proxy_manager
            .resolve_pending(resp_id, &session_id, request.clone());
        if resolved {
            debug!(id = %resp_id, "Routed proxy response to caller");
        } else {
            warn!(id = %resp_id, "No pending request for response");
        }
        return Err(build_accepted_response(&session_id));
    }

    // Parse request
    let (id, method, params) = match parse_request_ref(&request) {
        Ok((id, method, params)) => (id, method.to_string(), params),
        Err(response) => {
            return Err(build_response(
                response,
                &session_id,
                StatusCode::BAD_REQUEST,
            ));
        }
    };

    let protocol_header = headers
        .get("mcp-protocol-version")
        .and_then(|value| value.to_str().ok());
    crate::protocol_revision_telemetry::observe_inbound_request(
        &request,
        params,
        &method,
        protocol_header,
        Some(session_id.as_str()),
        crate::protocol_revision_telemetry::Transport::Http,
    );

    // Which protocol generation is this request written against? Decided per
    // request, not per connection: 2026-07-28 removed the handshake precisely so
    // one connection can carry both.
    //
    // The header is read as well as the body: a `2026-07-28` header with no
    // body metadata would otherwise classify legacy and pass the feature gate.
    // It was read once, duplicate-safe, above the session decision, so the two
    // readings cannot disagree; a doubled header is refused below.
    // NFR.OBS.1 is recorded by the classifier itself, so the HTTP and stdio
    // dispatchers cannot drift apart on what a request declared.
    let shape = crate::protocol::meta::classify_and_observe(
        &method,
        params,
        declared_version,
        // HTTP echoes the revision in a header on every request, so there
        // is nothing for a session lookup to add.
        None,
    );
    if let crate::protocol::meta::RequestShape::Malformed { ref missing } = shape {
        // Declared itself modern and then omitted a required field. The
        // specification is specific about both halves of the answer: -32602,
        // and 400 on HTTP.
        return Err(build_error_response(
            id,
            -32602,
            format!("missing required request metadata: {}", missing.join(", ")),
            &session_id,
            StatusCode::BAD_REQUEST,
        ));
    }
    // One derivation, two consumers. `era` is what `initialize` advertises
    // against and `is_modern` is what the method gate refuses on; deriving the
    // second from the first is what keeps them from becoming two predicates
    // that can disagree (`protocol::meta::classify_request`).
    let era = shape.era();
    let is_modern = era == crate::protocol::meta::Era::Modern;

    // Derived alongside `is_modern` so every shape-derived fact is read once,
    // here, rather than re-classified where the caller context is built. This
    // is not the per-method capability check further down: that one answers
    // "did the client declare the capability THIS method needs" for a method
    // the *client* called; this one is consulted before the gateway asks the
    // *client* for something. Owned rather than borrowed because `shape` is
    // moved by the per-method check below, ~100 lines before the caller context
    // is built.
    let declared_capabilities = shape.declared_capabilities();
    // Same reason, and the same parser the classifier used: the gate below once
    // ran its own `pointer()` read that asked only whether the identifier was
    // *present*, so `{"…/tasks": 3}` passed a gate that
    // `ExtensionSet::from_capabilities` would have refused. One parser, one
    // answer.
    let declared_extensions = shape.declared_extensions();
    // The other half of the extension exchange. `server/discover` states what
    // this gateway speaks; this reads back what the client declared, so
    // adoption is measured on the live path rather than assumed. Reads the
    // parsed set rather than `declared_capabilities`, which is a name list and
    // cannot tell a valid settings object from a bare number.
    crate::protocol_revision_telemetry::observe_client_extensions(&declared_extensions);
    // Owned: `shape` is moved ~100 lines before the caller is built. Classifier
    // output, never the duplicate-header sentinel.
    //
    // Verified evidence only: the echoed `MCP-Protocol-Version` header, which
    // the transport has already OWS-stripped, or the revision this session's
    // `initialize` was answered with — bound once at the single negotiation
    // site (`protocol_revision_telemetry::bind_session_revision`). The request
    // body is not consulted: `params.protocolVersion` is not a `tools/call`
    // field, so reading it would let a header-less caller pick the revision
    // bucket its response is stored in and read from. With neither piece of
    // evidence this is `None` and the request bypasses both caches.
    let session_revision =
        crate::protocol_revision_telemetry::session_negotiated_revision(Some(session_id.as_str()));
    let protocol_revision_owned =
        crate::protocol::meta::cache_protocol_revision(&shape, declared_version, session_revision)
            .map(str::to_owned);

    // ADR-014 §4. Set here, beside the other shape-derived facts and above
    // every early return Err(below), so a later reordering cannot silently darken
    // the emitter: the dispatch this scopes is already inside the sink opened
    // by `meta_mcp_handler`, and a request that never reaches the checks below
    // still declared what it declared.
    crate::transport::notification_sink::set_request_log_level(shape.declared_log_level());

    // Read before the macro so its count is graded (MIK-7725).
    let session = opened.as_ref().map_or("", SessionId::fp);
    debug!(method = %method, session_id = %session, "Meta-MCP request");

    if let Some((rpc, status)) = request_checks::request_check_refusal(
        state,
        &headers,
        &shape,
        declared_version,
        &method,
        params,
        id.as_ref(),
    ) {
        return Err(build_response(rpc, &session_id, status));
    }

    // Validated first, answered second. A notification carries no id and gets no
    // response body, but "no body" is not "no checks": returning 202 before the
    // era, version, mirrored-header and removed-method checks ran accepted a
    // malformed or disabled modern notification as though it had been honoured.
    if method.starts_with("notifications/") {
        debug!(notification = %method, "Handling notification");
        return Err(build_accepted_response(&session_id));
    }

    // For requests, id is guaranteed to exist (checked in parse_request)
    let id = id.expect("id should exist for non-notification requests");

    // Extract optional profile hint from X-MCP-Profile header (used at initialize time).
    let header_profile: Option<String> = headers
        .get("x-mcp-profile")
        .and_then(|v| v.to_str().ok())
        .map(String::from);

    if !is_modern && crate::protocol::meta::ADDED_IN_2026_07_28.contains(&method.as_str()) {
        // A 2026 method reached by a 2025 client. Serving it would tell that
        // client the gateway speaks a revision it cannot hold up its end of.
        return Err(build_error_response(
            Some(id.clone()),
            -32601,
            format!("method '{method}' requires MCP 2026-07-28"),
            &session_id,
            StatusCode::NOT_FOUND,
        ));
    }

    // A request reaching the tasks extension must DECLARE it, on that request.
    // Handing a task handle to a client that never said it could hold one
    // strands the work: the client reads a handle it will never redeem.
    if reaches_tasks_extension(method.as_str(), params)
        && !declared_extensions.contains(crate::protocol::extensions::Extension::Tasks)
    {
        return Err(build_error_response_with_data(
            Some(id.clone()),
            crate::protocol::era::MISSING_REQUIRED_CLIENT_CAPABILITY,
            format!("'{method}' requires the '{TASKS_EXTENSION}' extension to be declared"),
            json!({ "requiredCapabilities": { "extensions": { TASKS_EXTENSION: {} } } }),
            &session_id,
            StatusCode::BAD_REQUEST,
        ));
    }

    // Resolved ONCE, here, and reused by creation, retrieval, cancellation,
    // idempotent replay and subscription ownership below.
    let (owner, events_owner, admission_owner) = tasks::route_owners(
        state,
        verified_identity.as_ref(),
        oauth_agent_identity.as_ref(),
        (
            grant_subject.as_ref(),
            cert_identity.as_ref(),
            client.as_ref(),
        ),
    );

    // An empty owner key is not an identity (`task_owner_key`); the firewall
    // refuses on it too. On a gateway that HAS identities, every credential-less
    // caller would own every other one's tasks. `/mcp` is public in the shipped
    // presets: exactly where credentialled and unattributed callers meet.
    //
    // Auth DISABLED is not a defect: a validated agent JWT owns its tasks apart
    // (`route_task_owner`) and every other caller shares one pool, the
    // operator's own choice (`anonymous_client`) that a refusal would break.
    let unattributed = owner.is_empty() && state.auth_config.enabled;

    // The refusal names nothing. An unattributed caller must not be able to
    // tell "no task here is yours" from "that task does not exist", which is
    // the same disclosure `missing_task_error` exists to prevent — so it is the
    // same answer, and `subscriptions/listen` is excluded because on that path
    // silence IS the refusal (see below).
    if unattributed
        && method != "subscriptions/listen"
        && reaches_tasks_extension(method.as_str(), params)
    {
        // The early return Err(skips the tail that counts every other JSON-RPC
        // answer), so the refusal is counted here or it is invisible: an
        // operator watching this counter would see the task probes of a
        // credential-less caller as no traffic at all. `record_client_failure`
        // is deliberately NOT called — the caller has no identity to hold a
        // breaker against, which is the whole reason it is being refused.
        telemetry_metrics::counter!(
            "mcp_jsonrpc_requests_total",
            "method" => method.clone(),
            "status" => "error"
        )
        .increment(1);
        return Err(build_response(
            crate::gateway::task_route::missing_task_error(id),
            &session_id,
            StatusCode::OK,
        ));
    }

    // A `subscriptions/listen` naming tasks and nothing else HAS said what it
    // wants, so the empty notification filter is synthesised rather than
    // refused. Ownership narrows the stream in silence: a task another
    // principal owns must be indistinguishable from one that never existed, and
    // a refusal would announce the difference. A caller with no credential
    // under authentication is refused at the listen arm, whatever ids it names.
    // Borrowed from `request` for every method but this one, which narrows a
    // private copy; `tools/call` payloads are never duplicated here.
    let mut narrowed_listen: Option<Value> = None;
    if method == "subscriptions/listen" {
        let ids = listened_task_ids(params);
        if !ids.is_empty() {
            let caller_holds_ids =
                !unattributed && state.tasks.owns_all(&owner, ids.iter().map(String::as_str));
            narrowed_listen = params.cloned();
            if let Some(map) = narrowed_listen.as_mut().and_then(Value::as_object_mut) {
                map.entry("notifications").or_insert_with(|| json!({}));
                if !caller_holds_ids {
                    // Both placements: a copy left standing would opt the
                    // stream into a task the caller does not own.
                    map.insert("taskIds".into(), json!([]));
                    if let Some(filter) = map
                        .get_mut("notifications")
                        .and_then(Value::as_object_mut)
                        .filter(|filter| filter.contains_key("taskIds"))
                    {
                        filter.insert("taskIds".into(), json!([]));
                    }
                }
            }
        }
    }

    let params = narrowed_listen.as_ref().or(params);

    let external_tool = if method == "tools/call" {
        extract_tools_call_params_ref(params).0.to_owned()
    } else {
        method.clone()
    };

    Ok((
        JudgeInputs {
            read_guard,
            read_key,
        },
        signing_context,
        Intake {
            headers,
            client,
            cert_identity,
            oauth_agent_identity,
            verified_identity,
            presented,
            agent_identity,
            code_mode_url_active,
            surface_request,
            grant_subject,
            session_id,
            existing_session_id,
            chain_nonce,
            request,
            narrowed_listen,
            id,
            method,
            era,
            is_modern,
            declared_capabilities,
            protocol_revision_owned,
            header_profile,
            owner,
            events_owner,
            admission_owner,
            external_tool,
            _inflight_permit: inflight_permit,
        },
    ))
}

// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

use super::{
    AppState, Arc, AuthenticatedClient, CertIdentity, Intake, IntoResponse, JudgeInputs,
    OAuthAgentIdentity, SessionId, SigningInvocationContext, StatusCode, SurfaceRequest,
    TASKS_EXTENSION, Value, VerifiedIdentity, build_accepted_response, build_error_response,
    build_error_response_with_data, build_http_error_response, build_response, debug, events,
    extract_agent_identity, json, listened_task_ids, log_agent_identity, mcp_cancel_key,
    parse_request_ref, reaches_tasks_extension, request_checks, request_session_owner,
    session_id_header, tasks, validate_agent_identity, view_facts, warn,
};
use crate::error::rpc_codes::{INVALID_PARAMS, INVALID_REQUEST, METHOD_NOT_FOUND, PARSE_ERROR};

/// The prelude, run once per request. `Err` is a finished answer the
/// dispatcher returns as it is.
#[allow(
    clippy::too_many_lines,
    clippy::type_complexity,
    clippy::result_large_err
)]
pub(in crate::gateway::router::handlers) async fn intake(
    state: &Arc<AppState>,
    http_request: axum::http::Request<axum::body::Body>,
) -> Result<(JudgeInputs, Option<SigningInvocationContext>, Intake<'_>), axum::response::Response> {
    // Extract the authenticated client from the request.
    let client = http_request
        .extensions()
        .get::<AuthenticatedClient>()
        .cloned();
    // ADR-023: judged by the generation pinned on arrival, never the current
    // one, so a reload mid-request cannot change what this request sees.
    let Some(generation) = crate::gateway::router::pinned_generation(http_request.extensions())
    else {
        return Err((
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            crate::gateway::router::UNPINNED,
        )
            .into_response());
    };
    let sanitize_input = generation.sanitize_input();
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
    // The headers are taken, not copied. `Presented::capture` above is the last
    // reader of the request's own headers; below, the request is read only for
    // its URI, its extensions and its body, and the body read takes its limit
    // from the extensions (`DefaultBodyLimit`), not from a header.
    let (mut parts, body) = http_request.into_parts();
    let headers = std::mem::take(&mut parts.headers);
    let http_request = axum::http::Request::from_parts(parts, body);

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
    let code_mode_url_active = crate::gateway::router::view_judge::code_mode_requested(query_str);
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
            return Err(build_http_error_response(
                None,
                INVALID_REQUEST,
                reason,
                StatusCode::FORBIDDEN,
            )
            .into_response());
        }
    }

    // The caller as a grant subject, resolved once and before the body is
    // read, so a refused identity header reaches no dispatch, cache or idempotency work.
    let (admission, caller_owner) =
        match request_session_owner(state, &headers, http_request.extensions(), client.as_ref())
            .await
        {
            Ok(resolved) => resolved,
            Err(refusal) => return Err(refusal),
        };
    let grant_subject = admission.subject;
    let view_facts = view_facts::ViewFacts::capture(http_request.extensions(), admission.source);
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
                PARSE_ERROR,
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
            build_http_error_response(
                None,
                INVALID_REQUEST,
                "Meta-MCP disabled",
                StatusCode::FORBIDDEN,
            ),
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

    // MIK-8154 S2': the protocol fields are validated before anything reads
    // them (the session and hardened checks below; signing and the chain
    // nonce take theirs off later), and never rewritten. No session yet.
    if sanitize_input
        && let Err(e) = crate::security::sanitize::validate_protocol_fields(
            &request,
            &crate::gateway::PROTOCOL_NONCES,
            crate::security::sanitize::ProtocolRoute::Meta,
        )
    {
        return Err(build_error_response(
            None,
            INVALID_REQUEST,
            e.to_string(),
            "",
            StatusCode::BAD_REQUEST,
        ));
    }
    // Not a stream reader, so no branch subscribes: a held subscription
    // fakes a deliverable prompt.
    let (opened, session_hold, session_degraded) = super::session::open_request_session(
        state,
        &request,
        &headers,
        existing_session_id.as_deref(),
        &caller_owner,
        (declared_version, declares_modern_by_header),
    )
    .map_err(|refusal| *refusal)?;
    // The empty id is the router's "no session"; its fingerprint is empty too.
    let session_id = opened
        .as_ref()
        .map_or_else(String::new, |id| id.expose_secret().to_owned());
    // MIK-8161: the notification screen's verdicts name this caller and session.
    let screen_caller = client.as_ref().map_or("anonymous", |c| c.name.as_str());
    crate::transport::notification_sink::bind_screen(screen_caller, &session_id);
    // This caller's hiding judgment, before any per-caller lookup (the
    // sanitize exemption below among them) reads the scoped view.
    crate::gateway::meta_mcp::hiding::record_caller(
        crate::gateway::router::caller_hiding::RouterHiding::caller(
            Arc::clone(state),
            crate::gateway::router::OwnedRouterAuthorizer::capture(
                client.as_ref(),
                oauth_agent_identity.as_ref(),
                cert_identity.as_ref(),
            ),
            (!session_id.is_empty()).then(|| session_id.clone()),
        ),
    );

    let raw_id = crate::protocol::mrtr::raw_request_id(&request);
    // A failed grant-decision write refuses under this id (MIK-7663.GH2409.3).
    crate::gateway::meta_mcp::grant_audit::note_answer_id(raw_id.as_ref());
    // MIK-8382 intake: judged on the request as sent, before signing capture
    // takes its id off (restored later); answered after the chain nonce.
    let task_caller = tasks::owner::TaskCaller {
        verified_identity: verified_identity.as_ref(),
        agent: oauth_agent_identity.as_ref(),
        subject: grant_subject.as_ref(),
        cert: cert_identity.as_ref(),
        client: client.as_ref(),
    };
    let owners = tasks::owner::route_owners(state, &task_caller);
    let intake_error = intake_judgement(state, &request, &task_caller, &owners);
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
    // MIK-8382 intake: the refusal judged above is answered here, after the
    // chain nonce (kept first) and before target mapping, sanitizing and
    // every check, so its answer is one for every target and nothing
    // reaches a backend.
    if let Some(error) = intake_error {
        return Err(answer_intake(
            state,
            &request,
            (client.as_ref(), grant_subject.as_ref()),
            (raw_id, &session_id),
            &error,
        )
        .await);
    }
    // MIK-8154 SAN.1: one sanitize step, after the call's backend targets are
    // mapped on the caller's view (a surfaced name judged through the request's
    // visibility memo) and before restore and every check; a request whose
    // every target is `passthrough` is exempt (option (a)).
    let exempt = sanitize_input && {
        let authorizer = super::super::super::RouterAuthorizer {
            state,
            generation: &generation,
            client: client.as_ref(),
            oauth_agent_identity: oauth_agent_identity.as_ref(),
            cert_identity: cert_identity.as_ref(),
            principal: super::super::super::authorization::refusal_principal(
                client.as_ref(),
                oauth_agent_identity.as_ref(),
                cert_identity.as_ref(),
            ),
        };
        let scope = crate::gateway::meta_mcp::InvokeScope {
            authorizer: &authorizer,
            is_admin: client.as_ref().is_some_and(|c| c.admin),
            api_key_name: client.as_ref().map(|c| c.name.as_str()),
            grant_key: client
                .as_ref()
                .and_then(AuthenticatedClient::api_key_identity),
            agent_id: agent_identity.proven_agent_id(),
            grant_subject: grant_subject.as_ref(),
            caller: crate::identity_propagation::CallerProof::new(
                verified_identity.as_ref(),
                crate::identity_propagation::CallerProvenance::classify(
                    client
                        .as_ref()
                        .map(|client| client.principal.storage_form()),
                ),
            ),
        };
        let view = crate::gateway::meta_mcp::visible::TargetView::Caller(scope, Some(&session_id));
        super::super::super::sanitize_exempt(&state.meta_mcp, &request, view)
    };
    // Intake has judged; the window a catalogue change must not reach (NP3).
    #[cfg(test)]
    crate::gateway::meta_mcp::visible::seams::intake_judged();
    // In place (MIK-8499): a clean request is not copied. On an error the
    // request is refused here, so a partly rewritten tree is never used.
    if sanitize_input
        && !exempt
        && let Err(e) = crate::security::sanitize::sanitize_request_in_place(
            &mut request,
            crate::security::sanitize::ProtocolRoute::Meta,
        )
    {
        // The protocol fields passed validation, so the id is answered.
        return Err(build_error_response(
            raw_id.clone(),
            e.to_rpc_code(),
            e.to_string(),
            &session_id,
            StatusCode::BAD_REQUEST,
        ));
    }

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

    // MIK-8499: carry the client's `params._meta` into a meta tool's own
    // arguments here, where the request is owned, so `tools_call`'s merge
    // borrows them instead of copying the whole argument tree.
    crate::gateway::router::helpers::move_client_meta_into_arguments(&mut request, |name| {
        state.meta_mcp.exposes_meta_tool(name)
    });

    // Detect client POST-back responses (has "result" or "error" but no "method").
    // These are replies to server-to-client requests such as `sampling/createMessage`.
    // Must be handled BEFORE `parse_request`, which rejects messages without "method".
    if request.get("method").is_none()
        && (request.get("result").is_some() || request.get("error").is_some())
        && let Some(resp_id) = request.get("id").and_then(|v| v.as_str())
        && crate::gateway::input_bridge::is_bridge_reply_id(resp_id)
    {
        debug!(target: super::DISPATCH_INTAKE_TARGET, id = %resp_id, body = %request, "Received sampling/elicitation response POST-back");
        let resolved = state
            .proxy_manager
            .resolve_pending(resp_id, &session_id, request.clone());
        if resolved {
            debug!(target: super::DISPATCH_INTAKE_TARGET, id = %resp_id, "Routed proxy response to caller");
        } else {
            warn!(target: super::DISPATCH_INTAKE_TARGET, id = %resp_id, "No pending request for response");
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

    let sealed = &state.meta_mcp.window_seal;
    if !crate::gateway::router::helpers::observe_http(
        &request,
        params,
        &method,
        &headers,
        Some(session_id.as_str()),
        sealed,
    ) {
        return Err(
            crate::gateway::router::helpers::window_sealed_response(&request).into_response(),
        );
    }

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
            INVALID_PARAMS,
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
    // every early return below, so a later reordering cannot silently darken
    // the emitter: the dispatch this scopes is already inside the sink opened
    // by `meta_mcp_handler`, and a request that never reaches the checks below
    // still declared what it declared.
    crate::transport::notification_sink::set_request_log_level(shape.declared_log_level());

    // Read before the macro so its count is graded (MIK-7725).
    let session = opened.as_ref().map_or("", SessionId::fp);
    debug!(target: super::DISPATCH_INTAKE_TARGET, method = %method, session_id = %session, "Meta-MCP request");

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
        // MIK-7642 PR.C: a cancel aborts this caller's own in-flight call
        // under that id, if one is running; never forwarded (MIK-8072).
        if method == "notifications/cancelled" {
            let aborted = request
                .get("params")
                .and_then(|params| params.get("requestId"))
                .and_then(|id| {
                    let caller = (
                        grant_subject.as_ref(),
                        cert_identity.as_ref(),
                        client.as_ref(),
                    );
                    mcp_cancel_key(caller, &session_id, id)
                })
                .is_some_and(|key| state.meta_mcp.inflight_calls().cancel(&key));
            debug!(target: super::DISPATCH_INTAKE_TARGET, aborted, "Client cancel never forwarded");
        }
        debug!(target: super::DISPATCH_INTAKE_TARGET, notification = %method, "Handling notification");
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
            METHOD_NOT_FOUND,
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

    // Resolved ONCE, above, and reused by creation, retrieval, cancellation,
    // idempotent replay and subscription ownership below.

    // An empty owner key is not an identity (`task_owner_key`); the firewall
    // refuses on it too. On a gateway that HAS identities, every credential-less
    // caller would own every other one's tasks. `/mcp` is public in the shipped
    // presets: exactly where credentialled and unattributed callers meet.
    //
    // Auth DISABLED is not a defect: a validated agent JWT owns its tasks apart
    // (`route_task_owner`) and every other caller shares one pool, the
    // operator's own choice (`anonymous_client`) that a refusal would break.
    let unattributed = owners.task.is_empty() && state.auth_config.enabled;

    // The refusal names nothing. An unattributed caller must not be able to
    // tell "no task here is yours" from "that task does not exist", which is
    // the same disclosure `missing_task_error` exists to prevent — so it is the
    // same answer, and `subscriptions/listen` is excluded because on that path
    // silence IS the refusal (see below).
    if unattributed
        && method != "subscriptions/listen"
        && reaches_tasks_extension(method.as_str(), params)
    {
        // The early return skips the tail that counts every other JSON-RPC
        // answer, so the refusal is counted here or it is invisible: an
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
            let caller_holds_ids = !unattributed
                && state
                    .tasks
                    .owns_all(&owners.task, ids.iter().map(String::as_str));
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

    Ok((
        JudgeInputs {
            read_guard,
            read_key,
        },
        signing_context,
        Intake {
            generation,
            headers,
            client,
            cert_identity,
            oauth_agent_identity,
            view_facts,
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
            owner: owners.task,
            events_owner: owners.events,
            admission_owner: owners.admission,
            _inflight_permit: inflight_permit,
            _session_hold: session_hold,
            session_degraded,
        },
    ))
}

/// MIK-8382 UNIFY.1a′: whether the `/mcp` intake refuses this request, a
/// keyed `tools/call` with an id from a caller with no execution principal,
/// except a task submit on a gateway with authentication off.
/// The routed owner and caller key are the ones admission reads
/// (`route_owners`, `identity::caller_key`), through the shared function.
pub(super) fn intake_judgement(
    state: &AppState,
    request: &Value,
    task_caller: &tasks::owner::TaskCaller<'_>,
    owners: &tasks::owner::TaskOwners,
) -> Option<crate::Error> {
    // Lead ruling 2026-10-17 (B): a gateway with authentication off keeps
    // pooled anonymous task ownership (MIK-7272.TASK.1.20, design 2026-09-08),
    // so a task submit there is left to the task path, which admits it under
    // the pooled owner. A submit the task path declines runs as a sync call,
    // whose admission still refuses it -32003.
    // `params.task` by key, not by JSON pointer (MIK-8014 PERF.11).
    let task = request.get("params").and_then(|params| params.get("task"));
    if !state.auth_config.enabled && task.is_some() {
        return None;
    }
    let caller_key = crate::gateway::router::identity::caller_key(
        task_caller.subject,
        task_caller.cert,
        task_caller.client,
    );
    crate::gateway::meta_mcp::intake_refusal(
        request,
        crate::gateway::meta_mcp::AdmissionOwner::routed(&owners.admission),
        task_caller
            .client
            .map(|client| client.principal.storage_form()),
        task_caller.subject,
        Some(caller_key.as_str()).filter(|key| !key.is_empty()),
    )
}

/// The `/mcp` intake refusal of `error`, recorded as the direct route
/// records it (`invalid`), then answered -32003 / 400 with the request's id.
async fn answer_intake(
    state: &AppState,
    request: &Value,
    (client, grant_subject): (
        Option<&AuthenticatedClient>,
        Option<&crate::identity_grants::GrantSubject>,
    ),
    (id, session_id): (Option<crate::protocol::RequestId>, &str),
    error: &crate::Error,
) -> axum::response::Response {
    let empty = Value::Object(serde_json::Map::new());
    let params = request.get("params");
    let name = params
        .and_then(|params| params.get("name"))
        .and_then(Value::as_str)
        .unwrap_or_default();
    let arguments = params
        .and_then(|params| params.get("arguments"))
        .unwrap_or(&empty);
    // ponytail: the target as the request spells it, `gateway_invoke`'s
    // server and tool else the called name; a surfaced name is recorded
    // unmapped, since mapping is the backend-touching step this precedes.
    let field = |key: &str| {
        arguments
            .get(key)
            .and_then(Value::as_str)
            .unwrap_or_default()
    };
    let target = if name == "gateway_invoke" {
        (field("server"), field("tool"))
    } else {
        ("", name)
    };
    crate::gateway::router::meta_refusal_audit::Refused::of(
        arguments,
        client,
        grant_subject,
        session_id,
        state.auth_config.record_key(),
    )
    .answer_intake(state, target, id, error)
    .await
}

// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Stages 4 and 5 of the direct backend route: what is refused before a
//! credential is minted, and the credential itself.
//!
//! The order of every check is the order `backend_handler_inner` always had,
//! and it is security-relevant: attestation precedes the propagation mint, so
//! an unattested call mints nothing and writes no mint audit row.

use crate::error::rpc_codes::METHOD_NOT_FOUND;
use crate::error::rpc_codes::{INTERNAL_ERROR, INVALID_PARAMS};
use crate::gateway::meta_mcp::invoke::egress::Egressed;
use axum::http::StatusCode;

use super::super::AppState;
use super::super::direct_guards::refusal;
use super::super::helpers::{build_http_error_response, build_http_response};
use super::direct_caller::{Caller, Envelope, Rejection, Route};
use crate::protocol::RequestId;

/// Whether the caller may see this direct-route target: the refusal code of
/// the authorizer or the routing profile, and whether a description block
/// withholds it too. Each notes the check that decided it.
pub(super) fn withheld_verdict(
    state: &AppState,
    auth: super::BackendAuthContext<'_>,
    target: super::super::authorization::ToolTarget<'_>,
    (backend, session_id): (&crate::backend::Backend, Option<&str>),
) -> (Option<i32>, bool) {
    use crate::gateway::meta_mcp::invoke::audit::note_refused_by;
    use crate::security::decision_record::DecisionKind;
    let (backend_name, tool_name) = (target.server, target.tool);
    let withheld_code = super::super::authorization::authorize_tool_target(
        state,
        auth.generation,
        auth.client,
        auth.oauth_agent_identity,
        auth.cert_identity,
        target,
    )
    .err()
    .map(|refusal| {
        note_refused_by(refusal.kind, None);
        refusal.code
    })
    .or_else(|| {
        state
            .meta_mcp
            .profile_refusal(backend_name, tool_name, session_id)
            .map(|refusal| {
                note_refused_by(DecisionKind::RoutingProfile, None);
                refusal.to_rpc_code()
            })
    });
    // A name its description withholds is the gate's too, judged here before
    // any credential (the caller verdict leaves it to the gate).
    let withheld = withheld_code.is_some() || {
        let blocked = backend.blocked_tool_refusal(None, tool_name).is_some();
        if blocked {
            note_refused_by(backend.blocked_tool_kind(tool_name), None);
        }
        blocked
    };
    (withheld_code, withheld)
}

/// What stage 4 decided for this request.
pub(super) struct Preflight {
    pub(super) retry: crate::protocol::mrtr::RetryFields,
    pub(super) chain_nonce: Option<String>,
    pub(super) signing_scope: crate::gateway::meta_mcp::signing::SigningScope,
    pub(super) signs: bool,
    pub(super) signing_nonce: Option<String>,
    pub(super) challenge: Option<String>,
    pub(super) isolation_guarded: bool,
}

/// The chain nonce and the signing nonce come off the params after the intake
/// sanitize step validated them, never rewritten (MIK-8154 S2'; ASI07). Hardened signs every `tools/call` here too
/// (GH1942.HARDEN.1 row 7); its nonce is checked as the meta route checks it.
fn take_nonces(
    state: &AppState,
    envelope: &mut Envelope,
    id: &RequestId,
) -> Result<
    (
        Option<String>,
        crate::gateway::meta_mcp::signing::SigningScope,
        bool,
        Option<String>,
    ),
    Rejection,
> {
    let params = &mut envelope.params;
    let chain_nonce = crate::protocol::mrtr::take_chain_nonce_params(params.as_mut())
        .ok()
        .flatten();
    let signing_scope = crate::gateway::meta_mcp::signing::SigningScope::of(
        state.live_config.running().security.posture,
    );
    let signs = envelope.method == "tools/call"
        && state.meta_mcp.signing_enabled()
        && signing_scope == crate::gateway::meta_mcp::signing::SigningScope::EveryToolCall;
    let signing_nonce = if signs {
        match crate::gateway::meta_mcp::signing::take_direct_nonce(params.as_mut()) {
            Ok(nonce) => nonce,
            Err(e) => {
                let message = crate::gateway::meta_mcp::signing::wire_error_message(&e);
                crate::gateway::meta_mcp::invoke::audit::note_refused_by(
                    crate::security::decision_record::DecisionKind::Syntax,
                    None,
                );
                return Err(build_http_error_response(
                    Some(id.clone()),
                    e.to_rpc_code(),
                    message,
                    StatusCode::BAD_REQUEST,
                ));
            }
        }
    } else {
        None
    };
    Ok((chain_nonce, signing_scope, signs, signing_nonce))
}

/// MIK-8226 SCAN.4: the meta route's one parse
/// ([`crate::gateway::meta_mcp_helpers::parse_tool_arguments_cow`]) applied to
/// a direct `tools/call`: a JSON string becomes its object and is forwarded as
/// that object; anything that is not an object (or a string of one) is
/// refused -32602 before anything is sent, as F7b refuses it on the meta
/// route. Absent `arguments` are left as they are.
fn parse_direct_arguments(envelope: &mut Envelope, id: &RequestId) -> Result<(), Rejection> {
    let Some(params) = envelope.params.as_mut() else {
        return Ok(());
    };
    if params.get("arguments").is_none() {
        return Ok(());
    }
    let parsed = match crate::gateway::meta_mcp_helpers::parse_tool_arguments_cow(params) {
        Ok(std::borrow::Cow::Borrowed(_)) => return Ok(()),
        Ok(std::borrow::Cow::Owned(parsed)) => parsed,
        Err(e) => {
            crate::gateway::meta_mcp::invoke::audit::note_refused_by(
                crate::security::decision_record::DecisionKind::Syntax,
                None,
            );
            return Err(build_http_error_response(
                Some(id.clone()),
                e.to_rpc_code(),
                e.to_string(),
                StatusCode::BAD_REQUEST,
            ));
        }
    };
    if let Some(map) = params.as_object_mut() {
        map.insert("arguments".to_owned(), parsed);
    }
    Ok(())
}

/// MIK-7570.ATTEST.1: every method that reaches the backend is attested, on
/// the same predicate as identity propagation, and BEFORE it: an unattested
/// call must not mint a per-user credential or write a mint audit row. Also
/// ahead of the idempotency guard, so a replay needs a token too.
fn check_attestation(
    state: &AppState,
    caller: &Caller,
    envelope: &Envelope,
    id: &RequestId,
) -> Result<(), Rejection> {
    let scope = super::direct_route_attestation_scope(&envelope.method, envelope.params.as_ref());
    let agent = caller.client.as_ref().map(|c| c.name.as_str());
    if let Err(e) = state.meta_mcp.check_attestation_scoped(
        envelope.attestation.as_deref(),
        scope,
        agent,
        "direct_route",
    ) {
        let (code, message) = (e.to_rpc_code(), e.to_string());
        crate::gateway::meta_mcp::invoke::audit::note_refused_by(
            crate::security::decision_record::DecisionKind::Attestation,
            None,
        );
        return Err(build_http_error_response(
            Some(id.clone()),
            code,
            message,
            StatusCode::FORBIDDEN,
        ));
    }
    Ok(())
}

/// Stage 4: the refusals that need no credential. `&mut Envelope`: the chain
/// nonce, signing nonce and chain challenge edit `params` in place.
pub(super) fn preflight(
    state: &AppState,
    caller: &Caller,
    envelope: &mut Envelope,
    route: &Route<'_>,
    id: &RequestId,
) -> Result<Preflight, Rejection> {
    // F1 (#1442): task access is never forwarded. Callers sharing this
    // backend's static credential are one principal to it, so a forwarded
    // `tasks/get` or `tasks/cancel` would read or cancel another caller's
    // task. The owner-checked task arms serve `/mcp` only. Refused before
    // propagation, attestation and idempotency, so a refusal mints nothing.
    if super::is_task_method(&envelope.method, envelope.params.as_ref()) {
        crate::gateway::meta_mcp::invoke::audit::note_refused_by(
            crate::security::decision_record::DecisionKind::Syntax,
            None,
        );
        return Err(build_http_error_response(
            Some(id.clone()),
            METHOD_NOT_FOUND,
            format!(
                "{} is not served on /mcp/{{name}}; use /mcp",
                envelope.method
            ),
            StatusCode::OK,
        ));
    }

    // MIK-7272.SUB.4 §P3: an unusable retry field is refused with -32602, as on
    // route 1, after the notification branch (no id to answer). Ignoring it
    // would fake the replay protection a destructive call asked for.
    let retry = crate::protocol::mrtr::RetryFields::from_params(envelope.params.as_ref());
    if retry.is_malformed() {
        crate::gateway::meta_mcp::invoke::audit::note_refused_by(
            crate::security::decision_record::DecisionKind::Syntax,
            None,
        );
        return Err(build_http_error_response(
            Some(id.clone()),
            INVALID_PARAMS,
            format!("malformed request fields: {}", retry.malformed.join(", ")),
            StatusCode::BAD_REQUEST,
        ));
    }
    let (chain_nonce, signing_scope, signs, signing_nonce) = take_nonces(state, envelope, id)?;
    // MIK-8226 SCAN.4 (with MIK-8351): string-form arguments become the object
    // the backend would parse, before any check reads them, so the entry scan,
    // the chokepoint and the send judge one value, as on the meta route.
    if envelope.method == "tools/call" {
        parse_direct_arguments(envelope, id)?;
    }
    // Then this dispatch's own challenge for a chained backend (ASI07 R7).
    let mut challenge = None;
    if let (Some(sent), "tools/call") = (envelope.params.as_mut(), envelope.method.as_str()) {
        match state
            .meta_mcp
            .chain_challenge(route.backend.chain_policy().0, sent)
        {
            Ok(minted) => challenge = minted,
            Err(e) => {
                return Err(build_http_response(
                    &Egressed::gateway_own(refusal(Some(id.clone()), &e)),
                    StatusCode::OK,
                ));
            }
        }
    }

    // Applies to every caller-data method, not just `tools/call` (F2,
    // MIK-6746, MIK-6728). Exempt: the handshake (`initialize`, `ping`) and
    // `notifications/*` (answered before this stage). `tools/list` is
    // guarded: a catalogue is identity-dependent (MIK-7546).
    let isolation_guarded = !matches!(envelope.method.as_str(), "initialize" | "ping")
        && !envelope.method.starts_with("notifications/");
    if isolation_guarded {
        check_attestation(state, caller, envelope, id)?;
    }
    Ok(Preflight {
        retry,
        chain_nonce,
        signing_scope,
        signs,
        signing_nonce,
        challenge,
        isolation_guarded,
    })
}

/// The credential stage 5 resolved for the backend call.
pub(super) struct Propagation {
    /// The caller's stable identity binding (MIK-6784) for per-identity
    /// upstream session partitioning. Set only when a minting strategy (or
    /// passthrough) resolves a binding; otherwise `None`: the shared default
    /// session bucket.
    pub(super) identity_key: Option<String>,
    /// A11-e': the managed lease the headers were released under, for the 401
    /// site.
    pub(super) managed: Option<crate::personal_accounts::ManagedLease>,
    /// Wiped on drop: the caller's credential never leaves a zeroizing
    /// holder on this route.
    pub(super) headers: zeroize::Zeroizing<Vec<(String, String)>>,
    /// The check every send of `headers` runs first (the mint core's, or a
    /// forwarded credential's own); `None` when no credential was resolved.
    pub(super) check: Option<crate::transport::SendCheck>,
    /// The backend's admitted list fills when propagation began, so nonce
    /// admission can tell whether anything before it filled a tool list
    /// (MIK-8379).
    pub(super) fills_before: u64,
    /// A mint was attempted, whatever came of it (MIK-8379 H1).
    pub(super) attempted: bool,
    /// This propagation-configured backend attached no per-caller credential
    /// (an optional mint's static fallback, or a passthrough call that
    /// forwarded none), so a stored per-user result is not served to it; the
    /// refusal it answers with (MIK-8434). Set at stage 5 before the A2A
    /// override, which binds a caller but proves no account.
    pub(super) unproven: Option<crate::Error>,
}

impl Propagation {
    /// The resolved headers with the check that guards their every send.
    pub(super) fn lent(&self) -> crate::transport::LentCredential {
        crate::transport::LentCredential {
            headers: self.headers.clone(),
            check: self.check.clone(),
        }
    }
}

type IdpConfig = crate::identity_propagation::IdentityPropagationConfig;
/// The headers to forward, or the refusal text.
type Headers = Result<zeroize::Zeroizing<Vec<(String, String)>>, String>;

/// What resolving the headers produced, before the audit decides whether the
/// call may proceed.
struct Resolution {
    result: Headers,
    check: Option<crate::transport::SendCheck>,
    identity_key: Option<String>,
    managed: Option<crate::personal_accounts::ManagedLease>,
    typed: Option<crate::Error>,
    attempted: bool,
    unproven: Option<crate::Error>,
}

/// Passthrough (ADR-008 rung 2, MIK-6746) forwards the caller's OWN credential
/// verbatim, nothing minted or stored (INV-4); other strategies use the shared
/// minting chokepoint. Isolation (INV-3) holds: each request forwards its own
/// header, with no per-user cache.
async fn resolve_headers(
    state: &AppState,
    name: &str,
    caller: &Caller,
    route: &Route<'_>,
    idp_cfg: Option<&IdpConfig>,
) -> Resolution {
    let mut resolution = Resolution {
        result: Ok(zeroize::Zeroizing::default()),
        check: None,
        identity_key: None,
        managed: None,
        typed: None,
        attempted: false,
        unproven: None,
    };
    let passthrough_cfg = idp_cfg.filter(|c| {
        c.strategy == crate::identity_propagation::PropagationStrategyKind::Passthrough
    });
    if let Some(cfg) = passthrough_cfg {
        resolution.result = match super::resolve_passthrough_headers(
            cfg,
            &caller.inbound_headers,
            route.backend.transport_carries_identity_headers(),
        ) {
            Ok((headers, binding)) => {
                resolution.unproven = binding.is_none().then(|| unforwarded_refusal(name));
                // Bind the upstream session bucket to this passthrough caller
                // (MIK-6785): keyed by the SHA-256 of the forwarded credential,
                // so distinct callers never share a stateful upstream's
                // session-bound data. `None` on the no-credential path keeps
                // the shared default bucket.
                resolution.identity_key = super::charged_binding(
                    state,
                    &route.backend,
                    caller.proof(),
                    caller.slot.as_deref(),
                    binding,
                );
                let lent = crate::identity_propagation::send_check::dispatch_scoped(headers);
                resolution.check = lent.check;
                Ok(lent.headers)
            }
            Err(e) => Err(e),
        };
        return resolution;
    }
    resolution.result = match state
        .meta_mcp
        .resolve_propagation_credential_attempted_for(name, Some(&route.backend), caller.proof())
        .await
    {
        Ok(((headers, binding, held), attempted, unproven)) => {
            // Bind the upstream session bucket to this caller (MIK-6784).
            resolution.identity_key = binding;
            resolution.managed = held;
            resolution.attempted = attempted;
            resolution.unproven = unproven;
            resolution.check = headers.check;
            Ok(headers.headers)
        }
        Err(e) => {
            let text = crate::personal_accounts::refusal::refusal_text(&e);
            resolution.typed = Some(e);
            Err(text)
        }
    };
    resolution
}

/// The refusal a passthrough call that forwarded no credential answers a
/// stored per-user result with: the meta route's unminted refusal
/// (`stored_proof::unminted_refusal`, private to `invoke`), word for word,
/// so a client sees one refusal however the backend propagates.
fn unforwarded_refusal(name: &str) -> crate::Error {
    crate::Error::Config(format!(
        "identity propagation minted no credential for backend '{name}'; \
         a stored result is not served without one"
    ))
}

/// The generic client-facing answer when the mint audit cannot be written
/// (CWE-209: the operational detail stays in the server log).
fn audit_unavailable(id: &RequestId) -> Rejection {
    build_http_error_response(
        Some(id.clone()),
        INTERNAL_ERROR,
        "identity-propagation audit unavailable".to_string(),
        StatusCode::INTERNAL_SERVER_ERROR,
    )
}

/// Audit what stage 5 resolved, then release the headers or refuse.
///
/// A successful resolution that yields no headers is the unchanged
/// static-credential fallback (IDP.5), not a mint: only audit when a per-user
/// credential was actually attached. A minted credential must never reach the
/// caller without a durable audit record, so an audit-write failure aborts the
/// mint. The audit helper treats a missing logger as a no-op `Ok(())`, which on
/// a `required` backend would ship a per-user credential with NO audit record,
/// so that case fails closed on the same error path. A refusal is audited
/// best-effort: a failed write there is logged, not fatal.
async fn audit_mint(
    state: &AppState,
    name: &str,
    (caller, route): (&Caller, &Route<'_>),
    id: &RequestId,
    (idp_cfg, result, typed): (Option<&IdpConfig>, Headers, Option<crate::Error>),
) -> Result<zeroize::Zeroizing<Vec<(String, String)>>, Rejection> {
    // The principal resolved for (passthrough: the verified identity).
    let subject = state
        .meta_mcp
        .audit_subject_for(&route.backend, caller.proof());
    let audience = idp_cfg.map(|c| c.audience.as_str());
    match result {
        Ok(headers) => {
            if headers.is_empty() {
                return Ok(headers);
            }
            let required = idp_cfg.is_some_and(|c| c.required);
            if required && state.transparency_log.is_none() {
                tracing::warn!(
                    backend = %name,
                    "identity-propagation required but no transparency log is \
                     configured; refusing to mint without a durable audit record"
                );
                return Err(audit_unavailable(id));
            }
            if let Err(audit_err) = super::audit_identity_propagation(
                state.transparency_log.as_ref(),
                "idp_mint",
                &subject,
                name,
                audience,
                None,
            )
            .await
            {
                // CWE-209: the audit error can name a filesystem path; it
                // stays in the server log, the client gets a generic message.
                tracing::warn!(
                    backend = %name,
                    error = %audit_err,
                    "identity-propagation mint audit write failed; failing closed"
                );
                return Err(audit_unavailable(id));
            }
            Ok(headers)
        }
        Err(e) => {
            if let Err(audit_err) = super::audit_identity_propagation(
                state.transparency_log.as_ref(),
                "idp_refuse",
                &subject,
                name,
                audience,
                Some(&e),
            )
            .await
            {
                tracing::warn!(
                    backend = %name,
                    error = %audit_err,
                    "identity-propagation refuse audit write failed"
                );
            }
            // The caller's identity standing (MIK-8914.API2A.13): no kind
            // names it yet.
            crate::gateway::meta_mcp::invoke::audit::note_refused_by(
                crate::security::decision_record::DecisionKind::Unrecorded,
                None,
            );
            let who = caller.verified_identity.as_ref();
            Err(state
                .meta_mcp
                .direct_refusal(Some(id.clone()), e, typed, who)
                .await)
        }
    }
}

/// Stage 5: end-user identity propagation for the direct backend route
/// (MIK-6704 / ADR-007). Parity with the meta dispatch path: for a
/// propagation-configured backend, resolve the per-user credential; fail
/// closed (403) for a `required` backend with no verified identity rather
/// than silently forwarding with only the static credential. Empty for a
/// non-propagation backend: the static path is unchanged (IDP.5).
pub(super) async fn propagate_identity(
    state: &AppState,
    name: &str,
    caller: &Caller,
    route: &Route<'_>,
    preflight: &Preflight,
    id: &RequestId,
) -> Result<Propagation, Rejection> {
    let mut propagation = Propagation {
        identity_key: None,
        managed: None,
        headers: zeroize::Zeroizing::default(),
        check: None,
        fills_before: route.backend.list_fills(),
        attempted: false,
        unproven: None,
    };
    if !preflight.isolation_guarded {
        return Ok(propagation);
    }
    let idp_cfg = route.backend.identity_propagation_config();
    let Resolution {
        result,
        check,
        identity_key,
        managed,
        typed,
        attempted,
        unproven,
    } = resolve_headers(state, name, caller, route, idp_cfg).await;
    propagation.identity_key = identity_key;
    propagation.attempted = attempted;
    propagation.unproven = unproven;
    // MIK-8063: an A2A agent's question (an opaque, one-shot token) is bound
    // to the caller this gateway authenticated whenever no propagated identity
    // names them. The continuation seal (MIK-8078) binds the same callers; this
    // keeps the agent's own token bound even if the seal's rule changes.
    if propagation.identity_key.is_none() && route.backend.is_a2a() {
        propagation.identity_key = a2a_round_binding(caller);
    }
    propagation.managed = managed;
    propagation.check = check;
    propagation.headers =
        audit_mint(state, name, (caller, route), id, (idp_cfg, result, typed)).await?;

    // ADR-008 INV-2: the direct backend route bypasses `invoke_tool_traced`, so
    // it must enforce the same fail-closed OAuth-isolation guard for every
    // caller-data method that forwards with the gateway-held token. A per-user
    // credential was resolved above iff the headers are non-empty, so a
    // per-user OAuth backend on a multi-user gateway is refused rather than
    // served the shared token.
    if let Err(e) = state.meta_mcp.enforce_oauth_isolation_for(
        &route.backend,
        name,
        !propagation.headers.is_empty(),
    ) {
        // Identity propagation's isolation: no kind names it yet.
        crate::gateway::meta_mcp::invoke::audit::note_refused_by(
            crate::security::decision_record::DecisionKind::Unrecorded,
            None,
        );
        return Err(build_http_error_response(
            Some(id.clone()),
            e.to_rpc_code(),
            e.to_string(),
            StatusCode::FORBIDDEN,
        ));
    }
    Ok(propagation)
}

/// Who an A2A input round on this route belongs to: the caller's verified
/// identity, else the authenticated client principal. `None` only for an
/// unauthenticated caller, where every caller is the same principal anyway.
fn a2a_round_binding(caller: &Caller) -> Option<String> {
    crate::protocol::mrtr::principal_fingerprint(caller.verified_identity.as_ref()).or_else(|| {
        caller
            .client
            .as_ref()
            .and_then(|client| client.credential_principal())
            .map(|principal| {
                crate::hashing::sha256_hex(
                    format!("a2a-client:{}", principal.storage_form()).as_bytes(),
                )
            })
    })
}

#[cfg(test)]
mod mik_8659_preflight_tests {
    use super::super::direct_caller::Caller;

    fn caller_with(client: Option<crate::gateway::auth::AuthenticatedClient>) -> Caller {
        Caller {
            generation: crate::config_reload::LiveConfig::new(crate::config::Config::default())
                .generation(),
            client,
            cert_identity: None,
            oauth_agent_identity: None,
            proven: None,
            slot: None,
            verified_identity: None,
            inbound_headers: axum::http::HeaderMap::new(),
            grant_subject: None,
            spend_key: String::new(),
            agent_identity: None,
        }
    }

    fn client(authenticated: bool, principal: &str) -> crate::gateway::auth::AuthenticatedClient {
        crate::gateway::auth::AuthenticatedClient {
            name: "k".to_owned(),
            rate_limit: 0,
            backends: vec!["*".to_owned()],
            allowed_tools: None,
            denied_tools: None,
            admin: false,
            // MIK-6704.IDENT.1a: a synthetic fixture, not an authorization path.
            principal: crate::gateway::record_principal::InternalPrincipal::new(
                principal.to_owned(),
            ),
            quota_principal: None,
            authenticated,
            credential_kind: crate::security::audit::CredentialKind::ApiKey,
        }
    }

    /// MIK-8659 T2 (RED): `{authenticated: true, principal: ""}` binds to
    /// nothing. Today only `authenticated` is checked, so an empty principal
    /// still mints a binding.
    #[test]
    fn t2_empty_principal_binds_to_nothing() {
        let caller = caller_with(Some(client(true, "")));
        assert_eq!(super::a2a_round_binding(&caller), None);
    }

    /// MIK-8659 T2 controls (GREEN): `{true, "p"}` binds, `{false, "p"}`
    /// does not.
    #[test]
    fn t2_binding_controls() {
        assert!(
            super::a2a_round_binding(&caller_with(Some(client(true, "p")))).is_some(),
            "authenticated non-empty binds"
        );
        assert_eq!(
            super::a2a_round_binding(&caller_with(Some(client(false, "p")))),
            None,
            "unauthenticated binds to nothing"
        );
    }
}

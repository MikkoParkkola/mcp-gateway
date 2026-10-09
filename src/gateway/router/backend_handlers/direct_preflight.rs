// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Stages 4 and 5 of the direct backend route: what is refused before a
//! credential is minted, and the credential itself.
//!
//! The order of every check is the order `backend_handler_inner` always had,
//! and it is security-relevant: attestation precedes the propagation mint, so
//! an unattested call mints nothing and writes no mint audit row.

use axum::http::StatusCode;

use super::super::AppState;
use super::super::direct_guards::refusal;
use super::super::helpers::{build_http_error_response, build_http_response};
use super::direct_caller::{Caller, Envelope, Rejection, Route};
use crate::protocol::RequestId;

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

/// The chain nonce and the signing nonce come off the params before
/// sanitization (ASI07). Hardened signs every `tools/call` here too
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
        return Err(build_http_error_response(
            Some(id.clone()),
            crate::protocol::era::METHOD_NOT_FOUND_CODE,
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
        return Err(build_http_error_response(
            Some(id.clone()),
            -32602,
            format!("malformed request fields: {}", retry.malformed.join(", ")),
            StatusCode::BAD_REQUEST,
        ));
    }
    let (chain_nonce, signing_scope, signs, signing_nonce) = take_nonces(state, envelope, id)?;
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
                    &refusal(Some(id.clone()), &e),
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
    pub(super) headers: Vec<(String, String)>,
}

type IdpConfig = crate::identity_propagation::IdentityPropagationConfig;
/// The headers to forward, or the refusal text.
type Headers = Result<Vec<(String, String)>, String>;

/// What resolving the headers produced, before the audit decides whether the
/// call may proceed.
struct Resolution {
    result: Headers,
    identity_key: Option<String>,
    managed: Option<crate::personal_accounts::ManagedLease>,
    typed: Option<crate::Error>,
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
        result: Ok(Vec::new()),
        identity_key: None,
        managed: None,
        typed: None,
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
                Ok(headers)
            }
            Err(e) => Err(e),
        };
        return resolution;
    }
    resolution.result = match state
        .meta_mcp
        .resolve_propagation_credential_held_for(name, Some(&route.backend), caller.proof())
        .await
    {
        Ok((headers, binding, held)) => {
            // Bind the upstream session bucket to this caller (MIK-6784).
            resolution.identity_key = binding;
            resolution.managed = held;
            Ok(headers)
        }
        Err(e) => {
            let text = crate::personal_accounts::refusal::refusal_text(&e);
            resolution.typed = Some(e);
            Err(text)
        }
    };
    resolution
}

/// The generic client-facing answer when the mint audit cannot be written
/// (CWE-209: the operational detail stays in the server log).
fn audit_unavailable(id: &RequestId) -> Rejection {
    build_http_error_response(
        Some(id.clone()),
        -32603,
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
) -> Result<Vec<(String, String)>, Rejection> {
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
        headers: Vec::new(),
    };
    if !preflight.isolation_guarded {
        return Ok(propagation);
    }
    let idp_cfg = route.backend.identity_propagation_config();
    let Resolution {
        result,
        identity_key,
        managed,
        typed,
    } = resolve_headers(state, name, caller, route, idp_cfg).await;
    propagation.identity_key = identity_key;
    // MIK-8063: an A2A agent's question (an opaque, one-shot token) is bound
    // to the caller this gateway authenticated whenever no propagated identity
    // names them. The continuation seal (MIK-8078) binds the same callers; this
    // keeps the agent's own token bound even if the seal's rule changes.
    if propagation.identity_key.is_none() && route.backend.is_a2a() {
        propagation.identity_key = a2a_round_binding(caller);
    }
    propagation.managed = managed;
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
            .filter(|client| client.authenticated)
            .map(|client| {
                crate::hashing::sha256_hex(format!("a2a-client:{}", client.principal).as_bytes())
            })
    })
}

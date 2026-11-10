// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The direct route's security checks: authorize and the firewall before a
//! call's credential, the argument-key check after it, and the attestation
//! scope and token a direct request carries. Moved from `backend_handlers.rs`;
//! the code is unchanged, and the comments state their rules without ticket
//! references.

use crate::error::rpc_codes::{INVALID_PARAMS, INVALID_REQUEST};
use axum::http::StatusCode;
use serde_json::Value;
use tracing::warn;

use super::super::AppState;
use super::super::authorization::ToolTarget;
use super::super::direct_guards::refusal;
use super::super::helpers::{RpcHttp, build_http_error_response};
#[cfg(feature = "firewall")]
use super::relay::{direct_control_identity, relay_refusal};
use super::{
    BackendAuthContext, BackendRejection, BackendSecurityResult, DirectFailure, direct_preflight,
    key_check,
};
#[cfg(feature = "firewall")]
use crate::gateway::auth::AuthenticatedClient;
use crate::protocol::RequestId;
#[cfg(feature = "firewall")]
use crate::security::firewall::FirewallAction;
#[cfg(feature = "firewall")]
use crate::security::response_policy::{KeyOf, RuleTarget, ServerOf};
use crate::security::validate_tool_name;

/// The check a direct `tools/call` meets once its credential is resolved:
/// the argument-key check (R2, F13). Authorize and the firewall ran before
/// the credential, in [`guard_tool_call`].
///
/// Returns `Ok(Some(params))` when the check passes, `Ok(None)` for a
/// passthrough backend, or `Err(response)` when a check fails and the caller
/// should return an HTTP error immediately.
///
/// Sanitization is not here: the whole request is sanitized at intake
/// (`direct_caller::read_envelope`).
#[allow(clippy::result_large_err)]
pub(super) async fn apply_backend_tool_call_security(
    state: &AppState,
    backend_name: &str,
    params: Option<&Value>,
    id: &RequestId,
    backend: &crate::backend::Backend,
    (slot, failed): (key_check::CallerSlot<'_>, &DirectFailure<'_>),
) -> BackendSecurityResult {
    let Some(params) = params else {
        return Err(unnamed_call(id));
    };
    // The argument-key check (R2), F13: above the passthrough return, so a
    // passthrough backend is checked too.
    let lens = crate::backend::Lens::Catalogue;
    if let Some(rejection) =
        key_check::key_refusal(backend, (slot, failed), params, (id, lens)).await
    {
        return Err(rejection);
    }

    if backend.passthrough() {
        return Ok(None);
    }

    let _ = (state, backend_name);
    // The request was sanitized as a whole at intake when the setting is on
    // (`direct_caller::read_envelope`); these are the params
    // to forward.
    Ok(Some(params.clone()))
}

/// The refusal of a `tools/call` with no params or no tool name (400,
/// -32602): with no name there is nothing to authorize, so forwarding it
/// would skip the per-tool check (D2).
fn unnamed_call(id: &RequestId) -> BackendRejection {
    let message = "tools/call requires params.name";
    build_http_error_response(
        Some(id.clone()),
        INVALID_PARAMS,
        message,
        StatusCode::BAD_REQUEST,
    )
}

/// The checks a direct `tools/call` meets before any credential is resolved
/// in `meta_mcp_handler`'s order:
/// 1. `validate_tool_name` rejects dangerous names before any policy lookup;
/// 2. authorize: a refusal means the caller's listing hides the tool, so it
///    takes the missing name's path (it is not refused for its reason here);
/// 3. the request firewall and the relay rule, for a withheld and a missing
///    name alike;
/// 4. the gate: a withheld name is answered as a name the catalogue lacks,
///    with no credential and no fill on a per-user backend.
#[allow(clippy::result_large_err)]
pub(super) async fn guard_tool_call(
    state: &AppState,
    backend_name: &str,
    auth: BackendAuthContext<'_>,
    (params, id, session_id): (Option<&Value>, &RequestId, Option<&str>),
    (backend, failed): (&crate::backend::Backend, &DirectFailure<'_>),
) -> Result<Option<BackendRejection>, BackendRejection> {
    let named = params.and_then(|params| Some((params, params.get("name")?.as_str()?)));
    let Some((params, tool_name)) = named.filter(|(_, tool)| !tool.is_empty()) else {
        crate::gateway::meta_mcp::invoke::audit::note_refused_by(
            crate::security::decision_record::DecisionKind::Syntax,
            None,
        );
        return Err(unnamed_call(id));
    };

    if let Err(e) = validate_tool_name(tool_name) {
        crate::gateway::meta_mcp::invoke::audit::note_refused_by(
            crate::security::decision_record::DecisionKind::Syntax,
            None,
        );
        warn!(backend = %backend_name, tool = %tool_name, "Tool name rejected by validation");
        return Err(backend_security_error(id, &e));
    }

    let arguments = params.get("arguments").unwrap_or(params);
    let target = ToolTarget {
        server: backend_name,
        tool: tool_name,
        arguments,
    };
    // Test builds: the witness hook runs before the first generation read on this route
    // (the withheld verdict's authorization, then `firewall_refusal` and the relay check
    // under it, read it).
    #[cfg(all(test, feature = "firewall"))]
    crate::security::firewall::relay_witness_hook::run();
    let (withheld_code, withheld) =
        direct_preflight::withheld_verdict(state, auth, target, (backend, session_id));
    if let Some(code) = withheld_code {
        // The call's one record names it.
        crate::gateway::meta_mcp::visible::memo::note_denial_code(
            backend_name,
            tool_name,
            code,
            crate::gateway::meta_mcp::invoke::audit::take_refusal(),
        );
        warn!(backend = %backend_name, tool = %tool_name, "Tool withheld by authorization; answered as absent");
    }

    #[cfg(feature = "firewall")]
    if let Some(rejection) = firewall_refusal(
        state,
        auth,
        id,
        (backend_name, tool_name),
        (params, arguments),
        backend,
    ) {
        return Err(rejection);
    }

    // The kill switch says nothing about the name, so it is answered alike
    // for every name, before any fill (K2). A capability disabled for its
    // error rate names the tool: it is met at dispatch, by a caller who can
    // see it.
    // A per-user backend keeps its own order: the caller's own catalogue
    // decides first, with no fill for a withheld name anyway.
    if !backend.keeps_per_user_catalogues()
        && let Err(e) = state.meta_mcp.admit_backend_wide(backend_name)
    {
        return Err(super::super::helpers::build_http_response(
            &crate::gateway::meta_mcp::invoke::egress::Egressed::gateway_own(refusal(
                Some(id.clone()),
                &e,
            )),
            StatusCode::OK,
        ));
    }
    if !withheld {
        return Ok(None);
    }
    // Answered as absent, so neither the frame nor its outcome marks it: the
    // gateway refused this call, and the record says so.
    crate::gateway::delivery_facts::raise(crate::gateway::delivery_facts::ResponseEffect::Refused);
    let answered = key_check::withheld_refusal(backend, failed, params, id);
    // A withheld name is always answered (`Some`); were it not, it is still
    // never sent.
    Ok(Some(
        answered
            .await
            .unwrap_or(key_check::absent_response(id, tool_name)),
    ))
}

/// The request firewall and the relay rule for a direct call, for a withheld
/// and a missing name alike: the refusal to answer with, if either refuses.
#[cfg(feature = "firewall")]
fn firewall_refusal(
    state: &AppState,
    auth: BackendAuthContext<'_>,
    id: &RequestId,
    (backend_name, tool_name): (&str, &str),
    (params, arguments): (&Value, &Value),
    backend: &crate::backend::Backend,
) -> Option<BackendRejection> {
    let fw = state.firewall.as_ref()?;
    let caller_name = auth.client.map_or("anonymous", |c| c.name.as_str());
    let session_id = format!("direct:{backend_name}");
    let control_identity = direct_control_identity(state, auth, &session_id);
    let target = RuleTarget {
        server: ServerOf::Backend(backend_name),
        tool: tool_name,
        key: KeyOf::of_client(auth.client.and_then(AuthenticatedClient::api_key_identity)),
    };
    let (verdict, rule) = fw.check_request_attributed(
        auth.generation.firewall_policy(),
        &session_id,
        target,
        arguments,
        caller_name,
        &control_identity,
        Some(backend),
    );
    if verdict.action == FirewallAction::Warn {
        warn!(
            backend = %backend_name,
            tool = %tool_name,
            findings = verdict.findings.len(),
            "Firewall: direct backend request warning"
        );
    }
    if let Some((code, message)) = verdict.request_refusal() {
        crate::gateway::meta_mcp::invoke::audit::note_refused_by(
            crate::security::decision_record::DecisionKind::Firewall,
            rule,
        );
        crate::gateway::meta_mcp::invoke::audit::counting::note_request_firewall();
        // The shared wording's code, ASI10's -32002 included, with this
        // route's own HTTP status (403).
        return Some(backend_security_error_with_status(
            id,
            code,
            &message,
            StatusCode::FORBIDDEN,
        ));
    }
    let target = (backend_name, tool_name);
    let audit = (session_id.as_str(), caller_name);
    relay_refusal(fw, auth, id, target, params, audit)
}

/// What a direct-route call's token must grant.
///
/// A missing target field is matched as the empty capability, which only a
/// `"*"` token satisfies: a malformed call never falls back to authenticity.
/// A method outside the table needs `"*"`, so a narrowly scoped token cannot
/// drive a vendor method whose side effects the gateway cannot see.
pub(super) fn direct_route_attestation_scope<'a>(
    method: &str,
    params: Option<&'a Value>,
) -> crate::attestation::validator::AttestationScope<'a> {
    use crate::attestation::validator::AttestationScope;
    let field = |name: &str| {
        let value = params.and_then(|p| p.get(name));
        value.and_then(Value::as_str).unwrap_or_default()
    };
    match method {
        "tools/call" | "prompts/get" => AttestationScope::Capability(field("name")),
        "resources/read" | "resources/subscribe" | "resources/unsubscribe" => {
            AttestationScope::Capability(field("uri"))
        }
        "tools/list"
        | "resources/list"
        | "resources/templates/list"
        | "prompts/list"
        | "completion/complete"
        | "logging/setLevel" => AttestationScope::AuthenticOnly,
        _ => AttestationScope::Capability("*"),
    }
}

/// Remove the attestation token from `params._meta` and return it if a string.
pub(super) fn take_attestation_token(params: Option<&mut Value>) -> Option<String> {
    let meta = params?.get_mut("_meta")?.as_object_mut()?;
    let token = meta.remove(crate::protocol::mrtr::ATTESTATION_META)?;
    token.as_str().map(str::to_owned)
}

/// Build a `403 Forbidden` JSON-RPC error response for security rejections.
fn backend_security_error(id: &RequestId, message: &str) -> RpcHttp {
    build_http_error_response(
        Some(id.clone()),
        INVALID_REQUEST,
        message,
        StatusCode::FORBIDDEN,
    )
}

#[cfg(feature = "firewall")]
pub(super) fn backend_security_error_with_status(
    id: &RequestId,
    code: i32,
    message: &str,
    status: StatusCode,
) -> RpcHttp {
    build_http_error_response(Some(id.clone()), code, message, status)
}

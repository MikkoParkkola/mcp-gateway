// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Direct-route guard chain (design doc `2026-09-27-direct-route-guards.md`
//! §2.2): the per-backend route's one pre- and post-dispatch chain. Each step
//! composes the shared `MetaMcp` stage methods; none re-implements a control.

use serde_json::Value;

use super::AppState;
use crate::gateway::auth::AuthenticatedClient;
use crate::gateway::meta_mcp::MetaMcp;
use crate::gateway::meta_mcp::invoke::dispatch_guards::{BackendCall, DirectOutcome};
use crate::protocol::{JsonRpcResponse, RequestId};
use crate::{Error, Result};

/// G7: with message signing on, the signed envelope is `gateway_invoke`-only.
const SIGNING_REFUSAL: &str = "message signing is enabled; use gateway_invoke";

/// Namespace for the direct-route stage calls; a unit type rather than free
/// functions so call sites read `DirectRouteGuards::before_dispatch(..)`
/// alongside the `MetaMcp` stage methods it wraps.
pub(crate) struct DirectRouteGuards;

impl DirectRouteGuards {
    /// S1 policy, then the G7 signing refusal. Runs before the idempotency
    /// reservation, so a refused call reserves nothing and a cached result is
    /// never served past a refusal.
    pub(crate) fn run(meta: &MetaMcp, call: &BackendCall<'_>) -> Result<()> {
        meta.admit_target(call)?;
        if meta.signing_enabled() {
            return Err(Error::json_rpc(-32001, SIGNING_REFUSAL));
        }
        Ok(())
    }

    /// S2 spend, once, immediately before an actual backend dispatch (after
    /// the idempotency short-circuit: a replay spends nothing).
    pub(crate) fn before_dispatch(meta: &MetaMcp, call: &BackendCall<'_>) -> Result<Vec<String>> {
        meta.admit_spend_for(call)
    }

    /// S3 accounting on every dispatch; on an answered call, S4 payload gates,
    /// the S2 warnings, the response firewall verdict and client accounting.
    /// A transport failure is returned unchanged for the caller's failure arm.
    pub(crate) fn after_dispatch(
        state: &AppState,
        call: &BackendCall<'_>,
        params: Option<&Value>,
        client: Option<&AuthenticatedClient>,
        warnings: &[String],
        forward: Result<JsonRpcResponse>,
    ) -> Result<JsonRpcResponse> {
        let meta = &state.meta_mcp;
        meta.account_dispatch(call, DirectOutcome::from_response(&forward));
        let mut response = forward?;
        if let Some(result) = response.result.take() {
            match meta.gate_payload(call, result) {
                Ok((mut result, effect)) => {
                    if !warnings.is_empty()
                        && let Some(obj) = result.as_object_mut()
                    {
                        obj.insert("_cost_warnings".to_string(), serde_json::json!(warnings));
                    }
                    response.result = Some(result);
                    // A3: only a gated-through backend answer can be linked.
                    if effect
                        == crate::gateway::meta_mcp::response_security::GateEffect::PassedThrough
                    {
                        response.chain_source = crate::protocol::ChainSource::Backend;
                    }
                }
                // A post-dispatch refusal: the backend ran and was accounted;
                // the caller gets the gate's error with HTTP 200, settled.
                Err(e) => response = refusal(response.id.clone(), &e),
            }
        }
        if response_blocked(state, call.server, params, client, &mut response) {
            response = refusal(response.id.clone(), &Error::ResponseFirewallRefused);
        }
        // Success only on an answered result, as on meta (`handlers.rs`): a
        // gate refusal must not reset a breaker the caller had tripped.
        if response.error.is_none()
            && !response.excludes_client_accounting()
            && let Some(client) = client
        {
            state.auth_config.record_client_success(&client.name);
        }
        Ok(response)
    }
}

/// The JSON-RPC error a direct-route refusal answers with (HTTP 200). A
/// firewall refusal carries the delivery-refusal projection, as on meta.
pub(super) fn refusal(id: Option<RequestId>, error: &Error) -> JsonRpcResponse {
    match error {
        Error::ResponseFirewallRefused => {
            JsonRpcResponse::delivery_refusal_error(id, error.to_rpc_code(), &error.to_string())
        }
        Error::JsonRpc { code, message, .. } => JsonRpcResponse::error(id, *code, message.clone()),
        _ => JsonRpcResponse::error(id, error.to_rpc_code(), error.to_string()),
    }
}

/// Response firewall scan of a direct `tools/call` result (redaction in
/// place). Returns `true` when the verdict blocks delivery.
#[cfg(feature = "firewall")]
fn response_blocked(
    state: &AppState,
    backend_name: &str,
    params: Option<&Value>,
    client: Option<&AuthenticatedClient>,
    response: &mut JsonRpcResponse,
) -> bool {
    use crate::security::firewall::FirewallAction;
    let Some(ref fw) = state.firewall else {
        return false;
    };
    let Some(tool_name) = params.and_then(|p| p.get("name")).and_then(Value::as_str) else {
        return false;
    };
    let Some(ref mut result) = response.result else {
        return false;
    };
    let caller_name = client.map_or("anonymous", |c| c.name.as_str());
    let session_id = format!("direct:{backend_name}");
    let verdict = fw.check_response(&session_id, backend_name, tool_name, result, caller_name);
    if verdict.action == FirewallAction::Warn {
        tracing::warn!(
            backend = %backend_name,
            tool = %tool_name,
            findings = verdict.findings.len(),
            "Firewall: direct backend response warning"
        );
    }
    !verdict.allowed
}

#[cfg(not(feature = "firewall"))]
fn response_blocked(
    _state: &AppState,
    _backend_name: &str,
    _params: Option<&Value>,
    _client: Option<&AuthenticatedClient>,
    _response: &mut JsonRpcResponse,
) -> bool {
    false
}

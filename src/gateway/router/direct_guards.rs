// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Direct-route guard chain (design doc `2026-09-27-direct-route-guards.md`
//! §2.2): the per-backend route's one pre- and post-dispatch chain. Each step
//! composes the shared `MetaMcp` stage methods; none re-implements a control.

use super::AppState;
use crate::gateway::auth::AuthenticatedClient;
use crate::gateway::meta_mcp::MetaMcp;
use crate::gateway::meta_mcp::invoke::dispatch_guards::{Admission, BackendCall, DirectOutcome};
use crate::gateway::meta_mcp::signing::SigningScope;
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
    ///
    /// G7 applies where the signed envelope is `gateway_invoke`-only. Under
    /// `hardened` this route signs its own results (GH1942.HARDEN.1 row 7).
    pub(crate) fn run(meta: &MetaMcp, call: &BackendCall<'_>, scope: SigningScope) -> Result<()> {
        meta.admit_target(call)?;
        if meta.signing_enabled() && scope == SigningScope::InvokeOnly {
            return Err(Error::json_rpc(-32001, SIGNING_REFUSAL));
        }
        Ok(())
    }

    /// Admit a hardened direct call's nonce in the replay store the meta route uses, keyed by the meta route's own
    /// derivation (an authenticated key, then an OAuth agent, then a
    /// certificate), so one caller has one bucket on both.
    pub(crate) fn admit_nonce(
        state: &AppState,
        (client, oauth_agent_identity, cert_identity): (
            Option<&AuthenticatedClient>,
            Option<&crate::gateway::oauth::AgentIdentity>,
            Option<&crate::mtls::CertIdentity>,
        ),
        nonce: Option<&str>,
    ) -> Result<()> {
        let authorizer = super::authorization::RouterAuthorizer {
            state,
            client,
            oauth_agent_identity,
            cert_identity,
            principal: None,
        };
        let principal = crate::gateway::authz::ToolAuthorizer::quota_principal(&authorizer).map_or(
            "anonymous",
            crate::gateway::auth::QuotaPrincipal::as_store_key,
        );
        state.meta_mcp.admit_signing_nonce(nonce, principal)
    }

    /// S2 spend, once, immediately before an actual backend dispatch (after
    /// the idempotency short-circuit: a replay spends nothing).
    ///
    /// The caller passes the admission to `after_dispatch`, which settles its
    /// reservation with the spend, then drops it (MIK-7763, MIK-7903).
    pub(crate) fn before_dispatch(meta: &MetaMcp, call: &BackendCall<'_>) -> Result<Admission> {
        meta.admit_spend_for(call)
    }

    /// S3 accounting on every dispatch; on an answered call, the interim
    /// seal, S4 payload gates, the S2 warnings, the response firewall verdict
    /// and client accounting. A transport failure is returned unchanged for
    /// the caller's failure arm.
    ///
    /// `seal` is the caller's verified identity and the params as sent: what
    /// an interim answer's continuation is bound to (MIK-8078).
    pub(crate) async fn after_dispatch(
        state: &AppState,
        ((call, challenge), (identity, sent)): ((&BackendCall<'_>, Option<&str>), Seal<'_>),
        client: Option<&AuthenticatedClient>,
        admission: &Admission,
        forward: Result<JsonRpcResponse>,
    ) -> Result<JsonRpcResponse> {
        let meta = &state.meta_mcp;
        meta.account_dispatch(call, DirectOutcome::from_response(&forward), admission);
        let warnings = &admission.warnings;
        let mut response = forward?;
        // ASI07 inc3 raw receipt: verify before the gates read the reply,
        // against the challenge this dispatch minted (never read back).
        let slot = crate::gateway::meta_mcp::response_security::chain_receipt::ChainSlot::default();
        if let Some(result) = response.result.as_mut() {
            meta.chain_receive_for(call.server, result, challenge, &slot)?;
        }
        let receipt = std::mem::take(&mut *slot.lock());
        // MIK-8078 (MRTR.2a): the backend's state is sealed after the raw
        // receipt is checked and before any gate reads or rewrites the answer,
        // the meta route's order, so no gate can copy the raw state into what
        // the client receives.
        if let Some(result) = response.result.as_mut()
            && let Err(e) = meta
                .seal_direct_interim(identity, (call.server, sent), result)
                .await
        {
            return Ok(refusal(response.id.clone(), &e));
        }
        if let Some(result) = response.result.take() {
            match meta.gate_payload(call, result) {
                Ok((mut result, effect)) => {
                    if !warnings.is_empty()
                        && let Some(obj) = result.as_object_mut()
                    {
                        obj.insert("_cost_warnings".to_string(), serde_json::json!(warnings));
                    }
                    response.result = Some(result);
                    // A3 and inc3 D4: a gated-through backend answer, with
                    // its checked upstream outcome when the backend is chained.
                    let (source, upstream) =
                        crate::gateway::meta_mcp::response_security::chain_after_gates(
                            effect,
                            receipt.eligibility(),
                            receipt.into_upstream(),
                        );
                    (response.chain_source, response.chain_upstream) = (source, upstream);
                }
                // A post-dispatch refusal: the backend ran and was accounted;
                // the caller gets the gate's error with HTTP 200, settled.
                Err(e) => response = refusal(response.id.clone(), &e),
            }
        }
        if response_blocked(state, call, client, &mut response) {
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

/// What an interim answer's continuation is bound to (MIK-8078): the caller's
/// verified identity and the params as the client sent them.
pub(crate) type Seal<'a> = (
    Option<&'a crate::key_server::oidc::VerifiedIdentity>,
    Option<&'a serde_json::Value>,
);

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
    call: &BackendCall<'_>,
    client: Option<&AuthenticatedClient>,
    response: &mut JsonRpcResponse,
) -> bool {
    use crate::security::firewall::FirewallAction;
    // The route refuses a `tools/call` without `params.name` before dispatch,
    // so `call.tool` is the named tool on every path that reaches here.
    let (backend_name, tool_name) = (call.server, call.tool);
    let Some(ref fw) = state.firewall else {
        return false;
    };
    let Some(ref mut result) = response.result else {
        return false;
    };
    let caller_name = client.map_or("anonymous", |c| c.name.as_str());
    let session_id = format!("direct:{backend_name}");
    let verdict = fw.check_response(&session_id, backend_name, tool_name, result, caller_name);
    if verdict.action == FirewallAction::Warn {
        let findings = verdict.findings.len();
        tracing::warn!(
            backend = %backend_name,
            tool = %tool_name,
            findings,
            "Firewall: direct backend response warning"
        );
    }
    !verdict.allowed
}

#[cfg(not(feature = "firewall"))]
fn response_blocked(
    _state: &AppState,
    _call: &BackendCall<'_>,
    _client: Option<&AuthenticatedClient>,
    _response: &mut JsonRpcResponse,
) -> bool {
    false
}

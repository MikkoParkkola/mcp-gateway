// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Direct-route guard chain (design doc `2026-09-27-direct-route-guards.md`
//! §2.2): the per-backend route's one pre- and post-dispatch chain. Each step
//! composes the shared `MetaMcp` stage methods; none re-implements a control.

use super::AppState;
use crate::gateway::auth::AuthenticatedClient;
use crate::gateway::meta_mcp::MetaMcp;
use crate::gateway::meta_mcp::invoke::dispatch_guards::{Admission, BackendCall, DirectOutcome};
use crate::gateway::meta_mcp::invoke::egress::{ContentChecks, EgressOutcome};
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
    ) -> Result<Option<AdmittedNonce>> {
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
        let stamp = state.meta_mcp.admit_signing_nonce(nonce, principal)?;
        Ok(stamp.zip(nonce).map(|(stamp, nonce)| AdmittedNonce {
            nonce: nonce.to_owned(),
            principal: principal.to_owned(),
            stamp,
        }))
    }

    /// Give back the nonce a call admitted when it is refused before its
    /// backend runs, so a refused call consumes none (MIK-7698).
    pub(crate) fn release_nonce(state: &AppState, admitted: Option<AdmittedNonce>) {
        if let Some(admitted) = admitted {
            let AdmittedNonce {
                nonce,
                principal,
                stamp,
            } = admitted;
            state
                .meta_mcp
                .release_signing_nonce(&nonce, &principal, stamp);
        }
    }

    /// S2 spend, once, immediately before an actual backend dispatch (after
    /// the idempotency short-circuit: a replay spends nothing).
    ///
    /// The caller passes the admission to `after_dispatch`, which settles its
    /// reservation with the spend, then drops it (MIK-7763, MIK-7903).
    pub(crate) fn before_dispatch(meta: &MetaMcp, call: &BackendCall<'_>) -> Result<Admission> {
        meta.admit_spend_for(call)
    }

    /// S3 accounting on every dispatch but one its own caller cancelled
    /// (`cancel_entry`, MIK-7642 PR.C); on an answered call, the interim
    /// seal, S4 payload gates, the S2 warnings, the response firewall verdict
    /// and client accounting. A transport failure is returned unchanged for
    /// the caller's failure arm.
    ///
    /// `seal` is the caller's verified identity and the params as sent: what
    /// an interim answer's continuation is bound to (MIK-8078). `sealed`
    /// receives the sealed envelope and its hold key; the delivery tail gives
    /// the slot back unless the answer that leaves still carries it.
    pub(crate) async fn after_dispatch(
        state: &AppState,
        ((call, challenge), (who, (sent, instance, declared))): (
            (&BackendCall<'_>, Option<&str>),
            Seal<'_>,
        ),
        (client, sealed): (Option<&AuthenticatedClient>, &mut Option<(String, String)>),
        (admission, cancel_entry): (
            &Admission,
            Option<&crate::gateway::router::inflight_calls::Registered>,
        ),
        forward: Result<JsonRpcResponse>,
    ) -> Result<JsonRpcResponse> {
        let meta = &state.meta_mcp;
        // MIK-7642 PR.C: a call its caller cancelled says nothing about the
        // backend's health, so it is no error-budget sample: one caller's
        // cancels must not disable a capability or kill a backend for all.
        // A failed dispatch spends nothing, so nothing else is skipped.
        if crate::gateway::router::inflight_calls::cancelled_by_caller(
            cancel_entry,
            forward.as_ref().err(),
        ) {
            return forward;
        }
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
        if let Some(result) = response.result.as_mut() {
            match meta
                .seal_direct_interim(who, (call.server, Some(instance), sent, declared), result)
                .await
            {
                Ok(minted) => *sealed = minted,
                // The meta route's serializer: a capability refusal keeps the
                // `data` that names what to declare (MIK-8089). The upstream id
                // is replaced by the caller's own on delivery, so an id-less
                // backend answer still gets the data-keeping serializer.
                Err(e) => {
                    let id = response.id.clone();
                    let placeholder = crate::protocol::RequestId::Number(0);
                    let mut refused = crate::gateway::meta_mcp::error_response_preserving_status(
                        id.clone().unwrap_or(placeholder),
                        &e,
                    );
                    refused.id = id;
                    return Ok(refused);
                }
            }
        }
        let mut warned = false;
        if let Some(result) = response.result.take() {
            match meta.gate_payload(call, result) {
                Ok((mut result, effect)) => {
                    if !warnings.is_empty()
                        && let Some(obj) = result.as_object_mut()
                    {
                        obj.insert("_cost_warnings".to_string(), serde_json::json!(warnings));
                        warned = true;
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
        let outcome = scan_direct_egress(
            state,
            (call, ContentChecks::Dispatched),
            client,
            &mut response,
        );
        if outcome != EgressOutcome::Refused
            && warned
            && let Some(result) = response.result.as_ref()
        {
            // The warnings are the gateway's, as the scan left them (a
            // redaction stays bound to the text the caller gets): noted, so
            // the receipt leaves them out and a replay restores the note.
            use crate::gateway::gateway_writes::{Layer, note};
            note(Layer::Value, &["_cost_warnings"], result);
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

/// The signing nonce a direct call registered: what a refusal before dispatch
/// gives back (`DirectRouteGuards::release_nonce`).
pub(crate) struct AdmittedNonce {
    nonce: String,
    principal: String,
    stamp: std::time::Instant,
}

/// What an interim answer's continuation is bound to (MIK-8078): the caller's
/// verified identity, the params as the client sent them and the instance of
/// the backend object the call went to (MIK-8168); and what the client
/// declared it can be asked (MIK-8089).
pub(crate) type Seal<'a> = (
    (
        Option<&'a crate::key_server::oidc::VerifiedIdentity>,
        (
            Option<&'a str>,
            Option<&'a crate::identity_grants::GrantSubject>,
        ),
        Option<&'a crate::gateway::auth::AuthenticatedClient>,
    ),
    (
        Option<&'a serde_json::Value>,
        u64,
        crate::protocol::meta::Declared,
    ),
);

/// The JSON-RPC error a direct-route refusal answers with (HTTP 200). A
/// firewall refusal carries the delivery-refusal projection, as on meta.
///
/// Every caller passes a gate's own error, raised before dispatch or by a
/// post-dispatch gate, never a backend's: the frame carries gateway text and
/// is born marked, so no later exit scans it (and no content check records
/// data classes on a refusal).
pub(super) fn refusal(id: Option<RequestId>, error: &Error) -> JsonRpcResponse {
    let mut frame = match error {
        Error::ResponseFirewallRefused => {
            JsonRpcResponse::delivery_refusal_error(id, error.to_rpc_code(), &error.to_string())
        }
        Error::JsonRpc { code, message, .. } => JsonRpcResponse::error(id, *code, message.clone()),
        _ => JsonRpcResponse::error(id, error.to_rpc_code(), error.to_string()),
    };
    frame.egress_scanned = true;
    frame
}

/// The egress scan (design `2026-10-08-one-egress-scan.md`) on a direct-route
/// frame: `call`'s backend and tool (the method, for a non-tool answer) are
/// the policy target, `content` says whether dispatch already ran the content
/// checks, and the scan marks the frame so a later exit skips it.
pub(super) fn scan_direct_egress(
    state: &AppState,
    (call, content): (&BackendCall<'_>, ContentChecks),
    client: Option<&AuthenticatedClient>,
    response: &mut JsonRpcResponse,
) -> EgressOutcome {
    use crate::gateway::meta_mcp::invoke::egress::Egress;
    use crate::security::response_policy::{ResponseCorrelation, ResponsePolicyTarget};
    let session_id = format!("direct:{}", call.server);
    let targets = [ResponsePolicyTarget {
        server: call.server.to_owned(),
        tool: call.tool.to_owned(),
    }];
    let correlation = ResponseCorrelation {
        session_id: &session_id,
        caller: client.map_or("anonymous", |c| c.name.as_str()),
        external_server: call.server,
        external_tool: call.tool,
        subject: None,
    };
    // The router's own instance judges the direct route (MIK-7669).
    #[cfg(feature = "firewall")]
    let firewall = state.firewall.as_deref();
    #[cfg(not(feature = "firewall"))]
    let firewall = None;
    let at = Egress {
        content,
        targets: &targets,
        correlation: &correlation,
        api_key_name: client.map(|c| c.name.as_str()),
        firewall,
    };
    state.meta_mcp.scan_egress(response, &at)
}

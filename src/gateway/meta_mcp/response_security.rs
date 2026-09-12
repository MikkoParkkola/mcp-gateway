// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! Final response security contract shared by external transport adapters.

pub(crate) use crate::security::response_policy::{ResponseCorrelation, ResponsePolicyTarget};

/// Map an authenticated external operation to its response-policy targets.
pub(crate) fn meta_response_targets(
    external_tool: &str,
    targets: &[crate::gateway::authz::OwnedToolTarget],
) -> Vec<ResponsePolicyTarget> {
    let discovery = matches!(
        external_tool,
        "tools/list" | "gateway_list_tools" | "gateway_search_tools" | "gateway_search"
    );
    if discovery || targets.is_empty() {
        return vec![ResponsePolicyTarget {
            server: "gateway".to_owned(),
            tool: if discovery {
                "tools/list"
            } else {
                external_tool
            }
            .to_owned(),
        }];
    }
    let mut targets: Vec<_> = targets
        .iter()
        .map(|target| ResponsePolicyTarget {
            server: target.server.clone(),
            tool: target.tool.clone(),
        })
        .collect();
    targets.sort();
    targets.dedup();
    targets
}

/// Server-owned delivery metadata supplied after wrapping and protocol shaping.
pub(crate) struct ResponseDeliveryContext<'a> {
    pub method: &'a str,
    pub targets: &'a [ResponsePolicyTarget],
    pub correlation: ResponseCorrelation<'a>,
    pub mutation: crate::security::response_policy::ResponseMutationPolicy,
    pub signing: Option<&'a super::signing::SigningInvocationContext>,
}

impl super::MetaMcp {
    /// Complete all output mutations before recording the attempted response.
    pub(crate) fn finalize_response_for_delivery(
        &self,
        mut response: crate::protocol::JsonRpcResponse,
        context: &ResponseDeliveryContext<'_>,
    ) -> crate::protocol::JsonRpcResponse {
        use crate::protocol::JsonRpcResponse;

        #[cfg(feature = "firewall")]
        if matches!(context.method, "tools/call" | "tools/list")
            && response.error.is_none()
            && let Some(result) = response.result.as_mut()
            && let Some(firewall) = &self.firewall
        {
            use crate::security::firewall::FirewallAction;
            use crate::security::response_policy::ResponseArtifactKind;

            let verdict = firewall.check_response_artifact(
                result,
                context.targets,
                &context.correlation,
                ResponseArtifactKind::FinalResponse,
                context.mutation,
            );
            if !verdict
                .is_ok_and(|verdict| verdict.allowed && verdict.action != FirewallAction::Block)
            {
                response = JsonRpcResponse::delivery_refusal_error(
                    response.id,
                    -32600,
                    "Response blocked by security firewall",
                );
            }
        }
        #[cfg(not(feature = "firewall"))]
        let _ = (context.method, context.targets, context.mutation);

        // A disabled signer and ordinary/admission/refusal errors must never
        // validate captured nonce state or increment finalization failures.
        if self.message_signer.is_some()
            && response.error.is_none()
            && response.result.is_some()
            && let Some(signing) = context.signing
        {
            let signed = match signing.delivery() {
                Ok(super::signing::SigningDelivery::Unsigned) => Ok(()),
                Ok(super::signing::SigningDelivery::GatewayInvoke { nonce }) => {
                    // Primitive failures count themselves; do not count twice.
                    self.finalize_gateway_invoke_response(&mut response, nonce)
                }
                Err(error) => {
                    #[cfg(feature = "metrics")]
                    telemetry_metrics::counter!("mcp_message_signing_failures_total").increment(1);
                    Err(error)
                }
            };
            if signed.is_err() {
                response = JsonRpcResponse::delivery_refusal_error(
                    response.id,
                    -32603,
                    "Response signing failed",
                );
            }
        }

        // Logging applies to every actual response, including unscanned methods.
        self.record_response_delivery_attempt(&response, &context.correlation);
        response
    }

    /// Append evidence of the final output attempt; never a client receipt.
    fn record_response_delivery_attempt(
        &self,
        response: &crate::protocol::JsonRpcResponse,
        correlation: &ResponseCorrelation<'_>,
    ) {
        use sha2::{Digest, Sha256};

        let Some(logger) = &self.transparency_logger else {
            return;
        };
        let encoded = serde_json::to_value(response).and_then(|value| serde_json::to_vec(&value));
        let Ok(encoded) = encoded else {
            tracing::warn!("Failed to encode response delivery attempt for transparency log");
            return;
        };
        let hash = format!("sha256:{}", hex::encode(Sha256::digest(encoded)));
        let mut fields = serde_json::Map::new();
        fields.insert("event".into(), "response_delivery_attempt".into());
        fields.insert("response_stage".into(), "transport_finalized".into());
        fields.insert("response_hash_encoding".into(), "sorted-json-v1".into());
        fields.insert("response_hash".into(), hash.into());
        fields.insert("timestamp".into(), chrono::Utc::now().to_rfc3339().into());
        fields.insert("session_id".into(), correlation.session_id.into());
        fields.insert("caller".into(), correlation.caller.into());
        fields.insert("server".into(), correlation.external_server.into());
        fields.insert("tool".into(), correlation.external_tool.into());
        if let Err(error) = logger.append_event(fields) {
            tracing::warn!(
                error_kind = ?error.kind(),
                "Failed to append response delivery attempt to transparency log"
            );
        }
    }
}

impl super::MetaMcp {
    /// Admit the whole client-visible question artifact without rewriting it.
    /// The bridge supplies authenticated targets and excludes opaque state.
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "Implemented and tested, but never called from the response \
                      dispatch path. The legacy-client elicitation bridge it guards is \
                      MIK-7212.MRTR.7a/7b, a hard release gate under NFR.COMPAT.1 \
                      (docs/requirements/RELEASE-4.0.0-blocking-rollup.md:190): 4.0.0 \
                      must not ship serving the modern revision by default while that \
                      bridge is unreachable from production. The gate tracks the \
                      wiring; delete this suppression by hand when it lands."
        )
    )]
    pub(crate) fn enforce_firewall_challenge(
        &self,
        challenge: &serde_json::Value,
        targets: &[ResponsePolicyTarget],
        correlation: &ResponseCorrelation<'_>,
    ) -> crate::Result<()> {
        #[cfg(feature = "firewall")]
        if let Some(firewall) = &self.firewall {
            use crate::security::firewall::FirewallAction;
            use crate::security::response_policy::{ResponseArtifactKind, ResponseMutationPolicy};

            let mut inspected = challenge.clone();
            let verdict = firewall
                .check_response_artifact(
                    &mut inspected,
                    targets,
                    correlation,
                    ResponseArtifactKind::BridgeChallenge,
                    ResponseMutationPolicy::Immutable,
                )
                .map_err(|_| crate::Error::ResponseFirewallRefused)?;
            if !verdict.allowed || verdict.action == FirewallAction::Block {
                return Err(crate::Error::ResponseFirewallRefused);
            }
        }
        #[cfg(not(feature = "firewall"))]
        let _ = (challenge, targets, correlation);
        Ok(())
    }
}

#[cfg(all(test, feature = "firewall"))]
#[path = "response_challenge_tests.rs"]
mod challenge_tests;

#[cfg(all(test, feature = "firewall"))]
#[path = "response_delivery_tests.rs"]
mod delivery_tests;

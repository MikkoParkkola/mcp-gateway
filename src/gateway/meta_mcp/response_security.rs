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

/// Whether delivery must inspect the result, or an earlier pass on the same
/// dispatch already inspected this exact artifact.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DeliveryInspection {
    /// Inspect at delivery. Every caller that cannot prove an earlier pass.
    /// The stdio caller (`server/mod.rs`) has no router pre-pass and relies
    /// on this: delivery is its only inspection.
    Required,
    /// The HTTP `tools/call` arm ran the response firewall on this artifact
    /// and resolved its verdict; a second pass here re-ran the detectors on
    /// the already-sanitized result and could not change the outcome.
    #[cfg_attr(
        not(feature = "firewall"),
        expect(dead_code, reason = "only the firewall-gated router pass inspects")
    )]
    AlreadyInspected,
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
        response: crate::protocol::JsonRpcResponse,
        context: &ResponseDeliveryContext<'_>,
    ) -> crate::protocol::JsonRpcResponse {
        self.finalize_response_after_inspection(response, context, DeliveryInspection::Required)
    }

    /// [`Self::finalize_response_for_delivery`] for a caller that may already
    /// have run the response firewall on this exact artifact.
    pub(crate) fn finalize_response_after_inspection(
        &self,
        mut response: crate::protocol::JsonRpcResponse,
        context: &ResponseDeliveryContext<'_>,
        inspection: DeliveryInspection,
    ) -> crate::protocol::JsonRpcResponse {
        use crate::protocol::JsonRpcResponse;

        #[cfg(feature = "firewall")]
        if matches!(context.method, "tools/call" | "tools/list")
            && inspection == DeliveryInspection::Required
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
        let _ = (
            context.method,
            context.targets,
            context.mutation,
            inspection,
        );

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
        // With auth on, a response whose delivery cannot be audited is withheld.
        if !self.record_response_delivery_attempt(&response, &context.correlation) {
            let error = crate::Error::AuditUnavailable;
            response = match response.id {
                Some(id) => super::error_response_preserving_status(id, &error),
                None => crate::protocol::JsonRpcResponse::error(
                    None,
                    error.to_rpc_code(),
                    error.to_string(),
                ),
            };
        }
        response
    }

    /// Append evidence of the final output attempt; never a client receipt.
    ///
    /// Returns `false` only when the append failed under
    /// [`AuditFailurePolicy::FailClosed`](crate::security::audit::AuditFailurePolicy),
    /// meaning the response must not be delivered.
    fn record_response_delivery_attempt(
        &self,
        response: &crate::protocol::JsonRpcResponse,
        correlation: &ResponseCorrelation<'_>,
    ) -> bool {
        use crate::security::audit::{AuditEnvelope, AuditFailurePolicy, AuditOutcome, AuditWho};

        use sha2::{Digest, Sha256};

        let Some(logger) = &self.transparency_logger else {
            return true;
        };
        let fail_closed = logger.failure_policy() == AuditFailurePolicy::FailClosed;
        let encoded = serde_json::to_value(response).and_then(|value| serde_json::to_vec(&value));
        let Ok(encoded) = encoded else {
            tracing::warn!("Failed to encode response delivery attempt for transparency log");
            return !fail_closed;
        };
        let hash = format!("sha256:{}", hex::encode(Sha256::digest(encoded)));
        let mut fields = serde_json::Map::new();
        fields.insert("event".into(), "response_delivery_attempt".into());
        fields.insert("response_stage".into(), "transport_finalized".into());
        fields.insert("response_hash_encoding".into(), "sorted-json-v1".into());
        fields.insert("response_hash".into(), hash.into());
        fields.insert("timestamp".into(), chrono::Utc::now().to_rfc3339().into());
        // A fingerprint: the id is its anonymous holder's credential (F9).
        let session_id = correlation.session_id.to_string();
        fields.insert("session_id".into(), session_id.into());
        fields.insert("caller".into(), correlation.caller.into());
        fields.insert("server".into(), correlation.external_server.into());
        fields.insert("tool".into(), correlation.external_tool.into());
        let envelope = AuditEnvelope {
            outcome: response
                .error
                .as_ref()
                .map_or(AuditOutcome::Ok, |e| AuditOutcome::Error(e.code)),
            ..AuditEnvelope::ok(AuditWho::from_actor_id(correlation.caller))
        };
        if let Err(error) = logger.append_event(fields, &envelope) {
            tracing::warn!(
                error_kind = ?error.kind(),
                "Failed to append response delivery attempt to transparency log"
            );
            return !fail_closed;
        }
        true
    }
}

impl super::MetaMcp {
    /// Admit the whole client-visible question artifact without rewriting it.
    /// The bridge supplies authenticated targets and excludes opaque state.
    #[cfg_attr(
        not(feature = "firewall"),
        allow(clippy::unused_self, clippy::unnecessary_wraps)
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

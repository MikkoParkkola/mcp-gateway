// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! Final response security contract shared by external transport adapters.

pub(crate) use crate::security::response_policy::{ResponseCorrelation, ResponsePolicyTarget};

use std::sync::Arc;

use super::MetaMcp;
use crate::attestation::BnautAttestationSigner;

/// Result-shaping signers, set once at startup before the router serves calls.
impl MetaMcp {
    /// Enable signed runtime provenance stamping (MIK-6905, rung 1.2).
    ///
    /// When set, every aggregated tool result is stamped with a signed
    /// `_meta.provenance` receipt. Off by default; the field is `None` unless
    /// this is called, so the stamping branch never runs on the hot path
    /// otherwise.
    pub fn enable_provenance_stamping(&mut self, signer: BnautAttestationSigner) {
        self.provenance_signer = Some(Arc::new(signer));
    }

    /// Enable ASI07 origin-link emission, with increment-3 defaults for the
    /// verification trust (no trusted keys, 8 links, 300 s window).
    pub(crate) fn set_chain_signer(
        &mut self,
        signer: crate::security::signature_chain::ChainSigner,
        emit: crate::config::ChainEmit,
    ) {
        self.chain_signer = Some(Arc::new(ChainIdentity {
            signer,
            emit,
            max_links: 8,
            trusted_keys: std::collections::BTreeMap::new(),
            replay_window: 300,
        }));
    }

    /// Set what upstream chains are verified against (inc3 D3).
    pub(crate) fn set_chain_trust(
        &mut self,
        max_links: usize,
        trusted_keys: TrustedKeys,
        replay_window: u64,
    ) {
        if let Some(identity) = self.chain_signer.as_mut().and_then(Arc::get_mut) {
            identity.max_links = max_links;
            identity.trusted_keys = trusted_keys;
            identity.replay_window = replay_window;
        }
    }

    /// Enable shadow claim capture (MIK-6908, rung 3.1).
    ///
    /// Only has an observable effect once `provenance_signer` is also
    /// `Some` — capture runs alongside stamping at the same chokepoint, not
    /// independently of it.
    pub fn enable_claim_capture(&mut self, sink: Arc<crate::trust::ClaimCaptureSink>) {
        self.claim_capture = Some(sink);
    }
}

/// A `gateway_invoke` result with its chain eligibility and upstream outcome.
pub(crate) type Sourced = (
    serde_json::Value,
    ChainSource,
    Option<std::sync::Arc<crate::protocol::UpstreamChain>>,
);

/// `security.remote_server_signing.trusted_keys`.
pub(crate) type TrustedKeys = std::collections::BTreeMap<
    String,
    crate::security::remote_provenance::TrustedRemoteServerKeyConfig,
>;

/// This gateway's chain identity and what it verifies upstream chains
/// against (ASI07 increments 2 and 3).
pub(crate) struct ChainIdentity {
    pub(crate) signer: crate::security::signature_chain::ChainSigner,
    pub(crate) emit: crate::config::ChainEmit,
    /// `security.signature_chain.max_links`.
    pub(crate) max_links: usize,
    pub(crate) trusted_keys: TrustedKeys,
    /// `security.message_signing.replay_window`, seconds.
    pub(crate) replay_window: u64,
}

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

pub(crate) use crate::protocol::{ChainSource, UpstreamState};

/// Server-owned delivery metadata supplied after wrapping and protocol shaping.
pub(crate) struct ResponseDeliveryContext<'a> {
    pub method: &'a str,
    pub targets: &'a [ResponsePolicyTarget],
    pub correlation: ResponseCorrelation<'a>,
    pub signing: Option<&'a super::signing::SigningInvocationContext>,
    /// Eligibility of this result for a chain link.
    pub chain_source: ChainSource,
    /// `io.mcp-gateway/chain-nonce` captured from the request, if any.
    pub chain_nonce: Option<&'a str>,
}

impl super::MetaMcp {
    /// A read judge for one stream written to `key` (MIK-7116.MIN.2).
    pub(crate) fn stream_judge(
        &self,
        guard: Option<std::sync::Arc<crate::gateway::outbound::Guard>>,
        key: Option<String>,
    ) -> crate::gateway::outbound::StreamJudge {
        let judge = crate::gateway::outbound::StreamJudge::new(
            guard,
            self.rejection_audit(),
            self.transparency_logger.clone(),
        );
        if let Some(key) = key {
            judge.bind(key);
        }
        judge
    }

    /// The stdio transport's read judge, over this Meta-MCP's firewall
    /// (MIK-7116.MIN.2).
    pub(crate) fn stdio_reads(&self) -> crate::gateway::outbound::StdioReads {
        #[cfg(feature = "firewall")]
        let guard = self.firewall.clone();
        #[cfg(not(feature = "firewall"))]
        let guard = None;
        crate::gateway::outbound::StdioReads::new(
            guard,
            self.rejection_audit(),
            self.transparency_logger.clone(),
        )
    }

    /// Complete all output mutations before recording the attempted response.
    /// Test-only since stdio records after its judge (MIK-7920).
    #[cfg(test)]
    pub(crate) async fn finalize_response_for_delivery(
        &self,
        response: crate::protocol::JsonRpcResponse,
        context: &ResponseDeliveryContext<'_>,
    ) -> crate::protocol::JsonRpcResponse {
        let response = self.finalize_content(response, context);
        self.record_delivery(response, &context.correlation, None)
            .await
    }

    /// Everything of the finalization that decides the delivered content:
    /// firewall, scope clamp, chain, signing. The delivery record is not
    /// written here, so a caller can judge the finalized answer first and put
    /// its verdict in that record (MIK-7799).
    #[allow(clippy::too_many_lines)]
    pub(crate) fn finalize_content(
        &self,
        mut response: crate::protocol::JsonRpcResponse,
        context: &ResponseDeliveryContext<'_>,
    ) -> crate::protocol::JsonRpcResponse {
        use crate::protocol::JsonRpcResponse;

        let sealed = self.sealed_question(&response);
        // One egress scan, every method and every part (MIK-8139 family):
        // a frame another pass already screened carries the mark.
        let at = super::invoke::egress::Egress {
            content: super::invoke::egress::ContentChecks::for_method(context.method),
            targets: context.targets,
            correlation: &context.correlation,
            api_key_name: None,
            firewall: self.firewall.as_deref(),
        };
        self.scan_egress(&mut response, &at);
        // MIK-7211.PARENT.6: the scope is settled before the chain link and the
        // MAC, which authenticate this in-memory result; a clamp left to the
        // serializer would change bytes they already cover.
        if let Some(result) = response.result.as_mut() {
            crate::protocol::cacheable::clamp_delivered_scope(result);
        }
        // After the firewall, before the v2 HMAC: the link covers the final
        // content and the MAC covers the link.
        // Egress: no result leaves with a chain this gateway did not just sign.
        if let Some(result) = response.result.as_mut() {
            crate::security::signature_chain::strip_chain(result);
        }
        let invoke_nonce =
            (context.signing).and_then(super::signing::SigningInvocationContext::invoke_nonce);
        self.emit_origin_link(
            &mut response,
            context.chain_source,
            context.chain_nonce,
            invoke_nonce,
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
                Ok(super::signing::SigningDelivery::Signed { nonce }) => {
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
        // MIK-8131: a sealed question this finalization did not let out
        // (refused or replaced) leaves its slot for the caller to give back.
        if let Some((envelope, hold_key)) = sealed {
            let state = response.result.as_ref().and_then(|r| r.get("requestState"));
            if state.and_then(serde_json::Value::as_str) != Some(envelope.as_str()) {
                response.unsent_hold = Some(hold_key);
            }
        }
        response
    }
}

impl super::MetaMcp {
    /// Inspect a task's result once, at settlement, under the targets the
    /// synchronous call would have used (#2351), through the egress scan's
    /// result step: an interim task result keeps its question and handle
    /// whole. `tasks/get` serves what is settled, so a refusal here is what
    /// every read sees.
    ///
    /// # Errors
    /// [`crate::Error::ResponseFirewallRefused`] when the verdict refuses.
    pub(crate) fn inspect_task_result(
        &self,
        targets: &[ResponsePolicyTarget],
        task_id: &str,
        result: &mut serde_json::Value,
    ) -> crate::Result<()> {
        use super::invoke::egress::{Egress, EgressOutcome, firewall_result};
        let (server, tool) = targets.first().map_or(("gateway", "tasks/get"), |t| {
            (t.server.as_str(), t.tool.as_str())
        });
        let correlation = ResponseCorrelation {
            session_id: task_id,
            caller: "task",
            external_server: server,
            external_tool: tool,
            subject: None,
        };
        // A task's result is a `tools/call` result: its content gates ran at
        // dispatch.
        let at = Egress {
            content: super::invoke::egress::ContentChecks::Dispatched,
            targets,
            correlation: &correlation,
            api_key_name: None,
            firewall: self.firewall.as_deref(),
        };
        if firewall_result(result, &at) == EgressOutcome::Refused {
            tracing::warn!(task_id, "Firewall: task result blocked");
            return Err(crate::Error::ResponseFirewallRefused);
        }
        Ok(())
    }

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

impl super::MetaMcp {
    /// Attach this gateway's origin link to an eligible success result: on
    /// every one under `emit: always`, else only when the request carried a
    /// chain nonce. The `gateway_invoke` nonce is a fallback value, never a
    /// trigger. A result that cannot carry a link is refused, not delivered
    /// unlinked.
    fn emit_origin_link(
        &self,
        response: &mut crate::protocol::JsonRpcResponse,
        source: ChainSource,
        chain_nonce: Option<&str>,
        invoke_nonce: Option<&str>,
    ) {
        use crate::security::signature_chain::{Hop, LinkSource, Upstream, attach_link};
        let upstream = response.chain_upstream.clone();
        let Some(ChainIdentity {
            signer,
            emit,
            max_links,
            ..
        }) = self.chain_signer.as_deref()
        else {
            return;
        };
        let src = match source {
            ChainSource::Backend => LinkSource::Live,
            ChainSource::Replay => LinkSource::Replay,
            ChainSource::NotEligible => return,
        };
        let triggered = *emit == crate::config::ChainEmit::Always || chain_nonce.is_some();
        let Some(result) = response.result.as_mut() else {
            return;
        };
        if response.error.is_some() || !triggered {
            return;
        }
        let nonce = chain_nonce.or(invoke_nonce);
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        // No upstream outcome: an origin link. Otherwise preserve the verified
        // upstream links and append, or declare the upstream unverified.
        let hop = match upstream.as_deref() {
            None => Hop {
                prefix: &[],
                up: Upstream::None,
                input: None,
            },
            Some(u) => Hop {
                prefix: if u.state == UpstreamState::Verified {
                    &u.links
                } else {
                    &[]
                },
                up: match u.state {
                    UpstreamState::Verified => Upstream::Verified,
                    UpstreamState::Unverified => Upstream::Unverified,
                },
                input: Some(u.received.clone()),
            },
        };
        if let Err(rule) = attach_link(signer, result, &hop, src, nonce, ts, *max_links) {
            *response = crate::protocol::JsonRpcResponse::delivery_refusal_error(
                response.id.take(),
                -32001,
                &format!("Result cannot carry a signature chain link: {rule:?}"),
            );
        }
    }
}

/// Whether the response gates passed a result through or replaced or
/// transformed it (A3 R2'). Server-owned: never read back from the payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum GateEffect {
    /// The backend's answer, unchanged by the gates.
    PassedThrough,
    /// Context integrity withheld, refused or transformed the result.
    Enforced,
}

impl super::MetaMcp {
    /// Finish a direct-route response after its idempotency settle, so the
    /// stored body never carries a link: strip any chain from every method's
    /// result, then link a `tools/call` result the response gates passed
    /// through (`chain_source` set by the direct guards). A replay from the
    /// direct store records no origin and is never linked (A3 L1).
    pub(crate) fn finish_direct(
        &self,
        response: &mut crate::protocol::JsonRpcResponse,
        method: &str,
        chain_nonce: Option<&str>,
    ) {
        if let Some(result) = response.result.as_mut() {
            // PARENT.6: settle the scope before the link covers the content.
            crate::protocol::cacheable::clamp_delivered_scope(result);
            crate::security::signature_chain::strip_chain(result);
        }
        if method == "tools/call" && !response.delivery_refusal {
            let source = response.chain_source;
            self.emit_origin_link(response, source, chain_nonce, None);
        }
    }
}

/// Shape a meta-tool result into its reply. Only a success result takes the
/// dispatch's chain source (A3 R5); every error stays `NotEligible`.
pub(super) fn shape_meta_result(
    id: crate::protocol::RequestId,
    tool_name: &str,
    result: crate::Result<serde_json::Value>,
    shape: super::ResultShape,
    declared: crate::protocol::meta::Declared,
    chain: (
        ChainSource,
        Option<std::sync::Arc<crate::protocol::UpstreamChain>>,
    ),
) -> crate::protocol::JsonRpcResponse {
    let mut response = match result {
        Ok(content) => match shape {
            // MRTR.11a: an interim round must not be pretty-printed into
            // `content[0].text`. `wrap_tool_success` reads only a
            // top-level `isError` and buries `resultType` inside a JSON string, where
            // neither a protocol client nor the firewall's
            // `PreserveInputRequired` policy can read it — a question
            // committed as an answer. The task worker already escapes via
            // `super::ResultShape::Native`; this is the same escape for the
            // synchronous thread, gated so a backend cannot mint one.
            super::ResultShape::Wrapped => {
                match super::interim_promotion::promote_interim(&content, declared) {
                    super::interim_promotion::Promotion::Native => {
                        crate::protocol::JsonRpcResponse::success(id, content)
                    }
                    super::interim_promotion::Promotion::Wrap => {
                        let has_output_schema = tool_name == "gateway_search_tools";
                        crate::gateway::meta_mcp_helpers::wrap_tool_success(
                            id,
                            &content,
                            has_output_schema,
                        )
                    }
                    super::interim_promotion::Promotion::UpstreamFault(message) => {
                        super::error_response_preserving_status(
                            id,
                            &crate::Error::json_rpc(-32603, message),
                        )
                    }
                }
            }
            super::ResultShape::Native => crate::protocol::JsonRpcResponse::success(id, content),
        },
        Err(e) => super::error_response_preserving_status(id, &e),
    };
    if response.error.is_none() && response.result.is_some() {
        (response.chain_source, response.chain_upstream) = chain;
    }
    response
}

/// The chain outcome a gated result may keep (A3 R2', inc3 D4): a result the
/// gates replaced or transformed keeps neither eligibility nor upstream links.
pub(crate) fn chain_after_gates(
    effect: GateEffect,
    source: ChainSource,
    upstream: Option<std::sync::Arc<crate::protocol::UpstreamChain>>,
) -> (
    ChainSource,
    Option<std::sync::Arc<crate::protocol::UpstreamChain>>,
) {
    match effect {
        GateEffect::PassedThrough => (source, upstream),
        GateEffect::Enforced => (ChainSource::NotEligible, None),
    }
}

mod delivery_record;
pub(crate) use delivery_record::record_answer_delivery;

#[path = "chain_receipt.rs"]
pub(crate) mod chain_receipt;

#[cfg(all(test, feature = "firewall"))]
#[path = "response_challenge_tests.rs"]
mod challenge_tests;

#[cfg(all(test, feature = "firewall"))]
#[path = "response_delivery_tests.rs"]
mod delivery_tests;

#[cfg(test)]
#[path = "chain_emission_tests.rs"]
mod chain_emission_tests;

impl super::MetaMcp {
    /// The process's bounded auditor of withheld frames (MIK-7116.MIN.2).
    pub(crate) fn rejection_audit(&self) -> Arc<crate::gateway::outbound::RejectionAudit> {
        Arc::clone(self.rejection_audit.get_or_init(|| {
            Arc::new(crate::gateway::outbound::RejectionAudit::new(
                self.transparency_logger.clone(),
                crate::gateway::outbound::REJECTION_AUDIT_PERMITS,
            ))
        }))
    }

    /// The transparency log, if enabled.
    pub(crate) fn transparency_log(&self) -> Option<&Arc<crate::security::TransparencyLogger>> {
        self.transparency_logger.as_ref()
    }
}

/// The error a recovered task result settles on when the gateway's own
/// processing refuses it: a firewall refusal as a native task and the
/// synchronous call report it (-32600, MIK-7667), anything else as internal.
pub(crate) fn recovered_result_error(error: &crate::Error) -> crate::protocol::JsonRpcError {
    if matches!(error, crate::Error::ResponseFirewallRefused)
        && let Some(refusal) = crate::protocol::JsonRpcResponse::delivery_refusal_error(
            None,
            error.to_rpc_code(),
            &error.to_string(),
        )
        .error
    {
        return refusal;
    }
    crate::protocol::JsonRpcError {
        code: -32603,
        message: error.to_string(),
        data: None,
    }
}

/// Turn a dispatch error into a JSON-RPC error response, keeping the HTTP
/// status when the error is an authorization refusal.
///
/// The refusal already knows its status; every other error does not carry one
/// and gets the caller's default. The status rides in the error's optional
/// `data` because that is the only channel that survives this conversion —
/// `JsonRpcResponse` has no status of its own, and re-deriving one at the HTTP
/// boundary from the JSON-RPC code cannot work: eight of the nine refusal
/// branches emit the generic `-32600`, and `-32003` already means something
/// else elsewhere.
pub(crate) fn error_response_preserving_status(
    id: crate::protocol::RequestId,
    error: &crate::Error,
) -> crate::protocol::JsonRpcResponse {
    let mut response = match error {
        crate::Error::ResponseFirewallRefused => {
            crate::protocol::JsonRpcResponse::delivery_refusal_error(
                Some(id),
                error.to_rpc_code(),
                &error.to_string(),
            )
        }
        _ => crate::protocol::JsonRpcResponse::error(
            Some(id),
            error.to_rpc_code(),
            error.to_string(),
        ),
    };
    if let Some(ref mut rpc_error) = response.error {
        // Written unconditionally, so this function is the sole authority on
        // the field. `JsonRpcResponse::error` starts it at `None` and nothing
        // else in the gateway writes it today, but a future path that forwarded
        // a backend's error data could otherwise hand a backend the power to
        // choose the gateway's HTTP status. Assigning both arms closes that
        // without depending on the audit staying true.
        rpc_error.data = match error {
            crate::Error::Forbidden { status, .. } => Some(serde_json::json!({
                crate::gateway::authz::HTTP_STATUS_DATA_KEY: status,
            })),
            // D1-f: the log is down, not the caller wrong. 503 so an operator
            // and a load balancer read it as unavailability.
            crate::Error::AuditUnavailable => Some(serde_json::json!({
                crate::gateway::authz::HTTP_STATUS_DATA_KEY: 503,
            })),
            // A gateway-authored refusal may carry a recovery payload the
            // client needs: MRTR.9 names the capability an input request would
            // have required and MRTR.9a the mode, which is the difference
            // between a client that can fix its declaration and retry and one
            // that only sees prose. Named keys only, never the whole object:
            // `invoke_tool` puts a *backend's* error data into this variant, and
            // forwarding it wholesale would hand a backend the status field.
            crate::Error::JsonRpc {
                data: Some(data), ..
            } => {
                let forwarded: serde_json::Map<String, serde_json::Value> = [
                    super::invoke::REQUIRED_CAPABILITIES_DATA_KEY,
                    super::invoke::UNSUPPORTED_ELICITATION_MODE_DATA_KEY,
                ]
                .into_iter()
                .filter_map(|key| Some((key.to_string(), data.get(key)?.clone())))
                .collect();
                // `None` rather than `{}`: a backend error carrying none of these
                // keys leaves `data` absent exactly as when one key was forwarded.
                (!forwarded.is_empty()).then_some(serde_json::Value::Object(forwarded))
            }
            _ => None,
        };
        // A connect offer only under the gateway's own seal (MIK-6745, ADR-008).
        // An offer's text is the gateway's own, so it goes out without the
        // JSON-RPC prefix Display adds. Gated on the offer keys, not the seal:
        // a sealed upstream rejection forwards `{}` and keeps its text, as does
        // any unsealed error (MIK-7559).
        let offer = crate::personal_accounts::refusal::offer_data(error);
        let is_offer = offer
            .as_ref()
            .and_then(serde_json::Value::as_object)
            .is_some_and(|keys| !keys.is_empty());
        if let (true, crate::Error::JsonRpc { message, .. }) = (is_offer, error) {
            rpc_error.message.clone_from(message);
        }
        rpc_error.data = offer.or(rpc_error.data.take());
    }
    response
}

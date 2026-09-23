// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! The router's own response-firewall pass on a Meta-MCP `tools/call`.
//!
//! It runs before delivery and returns whether it inspected the artifact, so
//! delivery does not re-inspect what this pass already resolved
//! (NFR.WORKLOAD.1; design note `docs/internal/design/2026-09-23-workload-1-single-response-inspection.md`).

use tracing::warn;

use crate::gateway::meta_mcp::response_security::DeliveryInspection;
use crate::protocol::JsonRpcResponse;
use crate::security::firewall::{Firewall, FirewallAction};
use crate::security::response_policy::{
    ResponseArtifactKind, ResponseCorrelation, ResponseMutationPolicy, ResponsePolicyTarget,
};

/// Post-invocation response scan + credential redaction for one `tools/call`.
///
/// A refusing verdict must stop the scan and replace the result here: this
/// pass mutates the artifact under `Redact`, so letting a refused response
/// continue would launder it past the delivery chokepoint.
///
/// ONE inspection for the whole artifact, then the strongest action over EVERY
/// authenticated target. Scanning per target in a loop was order-dependent
/// under `Redact`: the first target's pass redacts the credential in place, so
/// a later target whose policy blocks on that finding inspects an
/// already-cleaned artifact and returns Allow — the block silently depended on
/// which target sorted first.
///
/// Returns [`DeliveryInspection::AlreadyInspected`] only when this pass ran on
/// the result; with no firewall or no result, delivery must still inspect.
pub(super) fn inspect_tools_call_response(
    firewall: Option<&Firewall>,
    call_response: &mut JsonRpcResponse,
    response_targets: &[ResponsePolicyTarget],
    correlation: &ResponseCorrelation<'_>,
) -> DeliveryInspection {
    let (Some(fw), Some(result_val)) = (firewall, call_response.result.as_mut()) else {
        return DeliveryInspection::Required;
    };
    let refused = if let Ok(verdict) = fw.check_response_artifact(
        result_val,
        response_targets,
        correlation,
        ResponseArtifactKind::FinalResponse,
        ResponseMutationPolicy::Redact,
    ) {
        if !verdict.allowed || verdict.action == FirewallAction::Block {
            warn!(
                targets = response_targets.len(),
                findings = verdict.findings.len(),
                "Firewall: response blocked"
            );
            true
        } else {
            if verdict.action == FirewallAction::Warn {
                warn!(
                    targets = response_targets.len(),
                    findings = verdict.findings.len(),
                    "Firewall: response warning"
                );
            }
            false
        }
    } else {
        // No authenticated target means nothing can admit this artifact; fail
        // closed exactly as a Block would.
        warn!(
            targets = response_targets.len(),
            "Firewall: response inspection lacked a policy target"
        );
        true
    };
    if refused {
        // Not an early HTTP return: the shared owned-execution finalization
        // still runs on this response.
        *call_response = JsonRpcResponse::delivery_refusal_error(
            call_response.id.take(),
            -32600,
            "Response blocked by security firewall",
        );
    }
    DeliveryInspection::AlreadyInspected
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::RequestId;
    use crate::security::firewall::FirewallConfig;
    use serde_json::json;

    fn correlation() -> ResponseCorrelation<'static> {
        ResponseCorrelation {
            session_id: "session-a",
            caller: "caller-a",
            external_server: "demo",
            external_tool: "probe",
        }
    }

    fn targets() -> Vec<ResponsePolicyTarget> {
        vec![ResponsePolicyTarget {
            server: "demo".into(),
            tool: "probe".into(),
        }]
    }

    fn firewall() -> Firewall {
        Firewall::from_config(
            FirewallConfig {
                enabled: true,
                scan_responses: true,
                ..FirewallConfig::default()
            },
            None,
        )
    }

    /// Delivery may skip only after this pass actually inspected: with no
    /// firewall, or no result to inspect, the answer is Required.
    #[test]
    fn required_unless_this_pass_inspected() {
        let mut ok = JsonRpcResponse::success(RequestId::Number(1), json!({"content": []}));
        assert_eq!(
            inspect_tools_call_response(None, &mut ok, &targets(), &correlation()),
            DeliveryInspection::Required
        );

        let fw = firewall();
        let mut failed = JsonRpcResponse::error(Some(RequestId::Number(2)), -32000, "backend");
        assert_eq!(
            inspect_tools_call_response(Some(&fw), &mut failed, &targets(), &correlation()),
            DeliveryInspection::Required
        );
        assert_eq!(fw.response_inspection_counts().inspections, 0);

        assert_eq!(
            inspect_tools_call_response(Some(&fw), &mut ok, &targets(), &correlation()),
            DeliveryInspection::AlreadyInspected
        );
        assert_eq!(fw.response_inspection_counts().inspections, 1);
    }
}

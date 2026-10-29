// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The never-delivered receipt copy leaves the open delivery's effect and
//! write record alone (own file: `relay_delivery_tests.rs` sits at the
//! 800-line ceiling).

use super::*;

/// A context-integrity kernel that enforces `kind` on every finding.
fn enforcing(
    kind: crate::context_integrity::ContextIntegrityDecisionKind,
) -> crate::context_integrity::ContextIntegrityKernel {
    use crate::context_integrity::{
        ContextIntegrityKernel, ContextIntegrityPolicy, ContextIntegrityPolicyMode,
    };
    ContextIntegrityKernel::new(ContextIntegrityPolicy {
        mode: ContextIntegrityPolicyMode::Enforce,
        untrusted_instruction_decision: kind,
        guarded_material_decision: kind,
        personal_data_decision: kind,
        destructive_instruction_decision: kind,
        tool_poisoning_decision: kind,
        high_risk_action_decision: kind,
        allow_benign_read_only: false,
        non_bypassable: false,
    })
}

/// The receipt copy is never delivered, so classifying it leaves the
/// delivery's effect alone: a verdict attached in monitor mode raises no
/// `annotated` and notes no write, an enforced malformed round raises no
/// `refused`, and an enforced rebuild of the copy raises no `rewritten`. Its audit classes are still noted: they describe the text the
/// client receives (RELAY.5).
#[tokio::test]
async fn a_recorded_prompt_leaves_the_open_delivery_unchanged() {
    use crate::context_integrity::ContextIntegrityDecisionKind;
    let pii = "Contact: keeper@orchardcoop.fi";
    let monitored = MetaMcp::new(Arc::new(crate::backend::BackendRegistry::new()));
    let enforced = MetaMcp::new(Arc::new(crate::backend::BackendRegistry::new()))
        .with_context_integrity_kernel(enforcing(ContextIntegrityDecisionKind::Strip));
    let attached =
        json!({"contents": [{"uri": "res://orchard", "text": format!("{PROSE} {pii}")}]});
    let malformed = json!({"content": [{"type": "text", "text": pii}], "resultType": 5});
    // An enforced rebuild: the copy is rewritten, the prompt the client gets
    // is not, so nothing is recorded as rewritten.
    let rebuilt = json!({"content": [{"type": "text", "text": format!("{PROSE} {pii}")}]});
    for (meta, prompt, enforcing) in [
        (&monitored, attached, false),
        (&enforced, malformed, true),
        (&enforced, rebuilt, true),
    ] {
        let ((recorded, effect, writes), notes) =
            super::super::super::audit::with_dispatch_scope(crate::gateway::delivery_facts::scope(
                super::super::super::gateway_writes::scope(async {
                    // The open delivery already holds a finding and a write:
                    // both must survive the copy unchanged.
                    crate::gateway::delivery_facts::found(
                        "firewall:seed".into(),
                        crate::security::Severity::Low,
                        crate::gateway::delivery_facts::Part::Result,
                    );
                    super::super::super::gateway_writes::note(
                        super::super::super::gateway_writes::Layer::Value,
                        &["_trace_id"],
                        &json!({"_trace_id": "t-seed"}),
                    );
                    let recorded = meta.recorded_prompt(
                        ("alpha", "resources/read"),
                        None,
                        "catalogue",
                        &prompt,
                    );
                    let mut fields = serde_json::Map::new();
                    crate::gateway::delivery_facts::record_fields(
                        crate::gateway::delivery_facts::snapshot().as_ref(),
                        false,
                        &mut fields,
                    );
                    let writes = super::super::super::gateway_writes::recorded();
                    let findings = fields["response_findings"].clone();
                    (
                        recorded,
                        (fields["response_effect"].clone(), findings),
                        writes,
                    )
                }),
            ))
            .await;
        assert!(
            recorded.get("_context_integrity").is_some(),
            "premise: classified: {recorded}"
        );
        assert_eq!(
            recorded["_context_integrity"]["policy"]["enforcement_applied"],
            json!(enforcing),
            "premise: enforcement on the copy: {recorded}"
        );
        let (effect, findings) = effect;
        assert_eq!(effect, "delivered", "{prompt}");
        assert_eq!(
            findings,
            json!([{"kind": "firewall:seed", "severity": "low", "where": "result"}]),
            "{prompt}"
        );
        let writes = serde_json::to_value(&writes).expect("serializes");
        assert_eq!(
            writes.as_array().map(Vec::len),
            Some(1),
            "{prompt}: only the seeded write: {writes}"
        );
        assert!(
            format!("{notes:?}").contains("personal_data"),
            "{prompt}: {notes:?}"
        );
    }
}

// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The strip must run before a redaction that can hide a seal.

use super::*;

// The greedy DSN eats the nested seal's name up to the space, hiding its surviving payload.
#[tokio::test]
async fn strip_before_redaction_catches_a_seal_the_redaction_would_hide() {
    let mut meta = sealing_meta();
    let (sealed, writes) = sealed_result(&meta).await;
    let payload = sealed
        .pointer("/_meta/provenance/public_signature/payload")
        .and_then(Value::as_str)
        .expect("the real seal's base64 payload");
    let text = format!(r#"{{"postgres://u:pw@db.local/app":0,"sealed":{sealed}}}"#);
    let text = text.replacen("\"public_signature\":", "\"public_signature\": ", 1);
    let mut value = SealSite::ChainStep.wrap(Value::String(text), &writes);
    assert_eq!(seals_in(&value).len(), 1, "premise: one real nested seal");
    install_firewall(&mut meta, true);
    let targets = [ResponsePolicyTarget::routed("remote_docs", "search")];
    let delivery = delivery_ctx(&targets, "tools/call", "gateway_invoke");
    assert_eq!(
        meta.firewall_result(&mut value, &firewall_at(&meta, &delivery)),
        crate::gateway::meta_mcp::invoke::egress::EgressOutcome::Rewritten,
    );
    assert_no_public_signature(&value, "strip before redaction leaves no seal");
    let wire = value.to_string();
    assert!(!wire.contains("public_signature"), "{wire}");
    assert!(!wire.contains(payload), "hidden seal: {wire}");
    assert!(wire.contains("[REDACTED:credential]"), "no rewrite: {wire}");
}

// A question the firewall holds immutable keeps its seal; the answer's
// other members still lose theirs and are redacted.
#[tokio::test]
async fn an_interim_questions_seal_survives_a_redaction_elsewhere_in_the_answer() {
    let mut meta = sealing_meta();
    let (sealed, _writes) = sealed_result(&meta).await;
    assert!(
        sealed
            .pointer("/_meta/provenance/public_signature")
            .is_some(),
        "premise: the question holds a real seal"
    );
    // The question holds a real seal but not the credential: a finding
    // inside it would refuse the whole answer, which is a different row.
    let mut question = sealed.clone();
    question["content"] = serde_json::json!([{"type": "text", "text": "which file?"}]);
    let mut value = serde_json::json!({
        "content": [{"type": "text", "text": canary()}],
        "inputRequests": question.clone(),
        "requestState": "state-handle",
        "_meta": sealed["_meta"].clone(),
    });
    install_firewall(&mut meta, true);
    let targets = [ResponsePolicyTarget::routed("remote_docs", "search")];
    let delivery = delivery_ctx(&targets, "tools/call", "gateway_invoke");
    assert_eq!(
        meta.firewall_result(&mut value, &firewall_at(&meta, &delivery)),
        crate::gateway::meta_mcp::invoke::egress::EgressOutcome::Rewritten,
    );
    assert_eq!(value["inputRequests"], question, "the question stays whole");
    assert_eq!(value["requestState"], "state-handle");
    assert!(
        value
            .pointer("/_meta/provenance/public_signature")
            .is_none(),
        "a seal outside the question still comes off: {value}"
    );
    assert!(
        !value.to_string().contains(&canary()),
        "the credential is redacted: {value}"
    );
}

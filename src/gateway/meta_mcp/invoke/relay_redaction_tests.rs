// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A redaction keeps the relay receipts of the text the caller still got.

use super::*;

/// A redaction that changes part of a delivered result drops
/// only the text that was removed. The text the caller still got keeps its
/// receipt, so relaying it is still caught.
#[tokio::test]
async fn a_redaction_keeps_the_receipt_for_the_text_still_delivered() {
    let (meta, firewall) = relay_meta();
    let both = text_result(&format!("{PROSE} {OTHER_PROSE}"));
    let delivered = text_result(PROSE);
    let ((), staged) = meta
        .collecting_staged(async {
            meta.stage_relay_receipt(RelayKey::new("alice", true), ("alpha", "send"), &both);
            let snapshot = meta.relay_snapshot(&both);
            meta.restage_if_changed(snapshot, Some(&delivered), AnswerShape::Literal);
        })
        .await;
    staged.commit(true);
    assert!(
        relayed_by_bob(&firewall, PROSE),
        "delivered text lost its receipt"
    );
    assert!(
        !relayed_by_bob(&firewall, OTHER_PROSE),
        "redacted text kept a receipt"
    );
}

/// A `gateway_invoke` answer carries the backend value as one
/// pretty-printed text block. Rebuilt from that block as written, multi-line
/// text would be fingerprinted with its newlines escaped, and relaying the
/// lines the caller read would go unmatched.
#[tokio::test]
async fn a_redacted_wrapped_answer_keeps_the_receipt_for_its_lines() {
    let (meta, firewall) = relay_meta();
    // Lines shorter than a fingerprint: every window crosses a newline.
    let lines = PROSE
        .split(' ')
        .collect::<Vec<_>>()
        .chunks(4)
        .map(|words| words.join(" "))
        .collect::<Vec<_>>()
        .join("\n");
    let both = text_result(&format!("{lines}\n{OTHER_PROSE}"));
    let delivered = crate::gateway::meta_mcp_helpers::wrap_tool_success(
        RequestId::Number(1),
        &text_result(&lines),
        false,
    )
    .result
    .expect("a success carries a result");
    let ((), staged) = meta
        .collecting_staged(async {
            meta.stage_relay_receipt(RelayKey::new("alice", true), ("alpha", "send"), &both);
            let snapshot = meta.relay_snapshot(&both);
            meta.restage_if_changed(snapshot, Some(&delivered), AnswerShape::InvokeWrapped);
        })
        .await;
    staged.commit(true);
    assert!(
        relayed_by_bob(&firewall, &lines),
        "wrapped lines lost their receipt"
    );
    assert!(
        !relayed_by_bob(&firewall, OTHER_PROSE),
        "redacted text kept a receipt"
    );
}

/// A native result whose text happens to be JSON keeps its text as
/// delivered in the rebuilt receipt; decoding alone would drop a number in it.
#[tokio::test]
async fn a_native_json_text_keeps_its_numbers_in_the_receipt() {
    let (meta, firewall) = relay_meta();
    // Long enough for several winnowed fingerprints.
    let digits: String = (1000..1050).map(|n: u32| n.to_string()).collect();
    let both = text_result(&format!(r#"{{"n": {digits}, "s": "{OTHER_PROSE}"}}"#));
    let delivered = text_result(&format!(r#"{{"n": {digits}}}"#));
    let ((), staged) = meta
        .collecting_staged(async {
            meta.stage_relay_receipt(RelayKey::new("alice", true), ("alpha", "send"), &both);
            let snapshot = meta.relay_snapshot(&both);
            meta.restage_if_changed(snapshot, Some(&delivered), AnswerShape::Literal);
        })
        .await;
    staged.commit(true);
    assert!(
        relayed_by_bob(&firewall, &digits),
        "the number lost its receipt"
    );
}

/// Several staged receipts that no plan step staged cannot be told
/// apart by a change, so they are dropped, as before (a plan's are kept to
/// its final answer: see `plan`).
#[tokio::test]
async fn a_redaction_over_several_receipts_drops_them() {
    let (meta, firewall) = relay_meta();
    let both = text_result(PROSE);
    let ((), staged) = meta
        .collecting_staged(async {
            let alice = RelayKey::new("alice", true);
            meta.stage_relay_receipt(alice, ("alpha", "send"), &both);
            meta.stage_relay_receipt(alice, ("alpha", "other"), &text_result(OTHER_PROSE));
            let snapshot = meta.relay_snapshot(&both);
            meta.restage_if_changed(
                snapshot,
                Some(&text_result("changed")),
                AnswerShape::Literal,
            );
        })
        .await;
    staged.commit(true);
    assert!(!relayed_by_bob(&firewall, PROSE));
    assert!(!relayed_by_bob(&firewall, OTHER_PROSE));
}

/// An unchanged result keeps every staged receipt.
#[tokio::test]
async fn an_unchanged_result_keeps_its_receipts() {
    let (meta, firewall) = relay_meta();
    let value = text_result(PROSE);
    let ((), staged) = meta
        .collecting_staged(async {
            meta.stage_relay_receipt(RelayKey::new("alice", true), ("alpha", "send"), &value);
            let snapshot = meta.relay_snapshot(&value);
            meta.restage_if_changed(snapshot, Some(&value.clone()), AnswerShape::Literal);
        })
        .await;
    staged.commit(true);
    assert!(relayed_by_bob(&firewall, PROSE));
}

/// A rebuild from the redacted copy keeps the
/// sensitivity the original delivery was judged to have, even when the
/// redaction removed the classification marker.
#[tokio::test]
async fn a_redaction_keeps_the_sensitivity_verdict_of_the_delivery() {
    let (meta, firewall) = classified_only_meta();
    let marker = json!({"classification": {"data_classes": ["personal_data"]}});
    let mut classified = text_result(&format!("{PROSE} {OTHER_PROSE}"));
    classified["_context_integrity"] = marker;
    let delivered = text_result(PROSE);
    let ((), staged) = meta
        .collecting_staged(async {
            meta.stage_relay_receipt(RelayKey::new("alice", true), ("alpha", "send"), &classified);
            let snapshot = meta.relay_snapshot(&classified);
            meta.restage_if_changed(snapshot, Some(&delivered), AnswerShape::Literal);
        })
        .await;
    staged.commit(true);
    assert!(relayed_by_bob(&firewall, PROSE), "the verdict was lost");
}

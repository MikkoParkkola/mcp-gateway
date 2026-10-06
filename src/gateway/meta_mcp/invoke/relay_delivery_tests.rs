// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-7887.RECEIPT.3/.4: a receipt follows delivery, and describes the
//! answer as it was delivered.

use super::*;

/// MIK-7887.RECEIPT.3: a bridged prompt is receipted only once the channel
/// confirms delivery. A send that finds no session reached nobody.
#[tokio::test]
async fn a_bridged_prompt_with_no_session_leaves_no_receipt() {
    use crate::gateway::input_bridge::{ClientChannel as _, DeliveryError};
    let inner = Scripted::Reply(Err(DeliveryError::NoSession));
    let (meta, firewall) = relay_meta();
    let channel = RecordingChannel {
        inner: &inner,
        meta: &meta,
        who: RelayKey::new("alice", true),
        target: ("alpha", "send"),
        api_key_name: None,
        trace_id: "t",
    };
    let sent = channel
        .send_request(
            "s",
            "1",
            "elicitation/create",
            Some(json!({"message": PROSE})),
        )
        .await;
    assert!(matches!(sent, Err(DeliveryError::NoSession)), "{sent:?}");
    assert!(
        !relayed_by_bob(&firewall, PROSE),
        "a prompt nobody was shown must leave no receipt"
    );
}

/// MIK-7887.RECEIPT.3: a send cancelled before the channel committed the
/// frame leaves no receipt. The inner channel parks before it delivers
/// anything, and the future is dropped there.
#[tokio::test]
async fn a_bridged_prompt_cancelled_before_commit_leaves_no_receipt() {
    use crate::gateway::input_bridge::ClientChannel as _;
    let inner = Scripted::Hang;
    let (meta, firewall) = relay_meta();
    let channel = RecordingChannel {
        inner: &inner,
        meta: &meta,
        who: RelayKey::new("alice", true),
        target: ("alpha", "send"),
        api_key_name: None,
        trace_id: "t",
    };
    {
        let send = channel.send_request(
            "s",
            "1",
            "elicitation/create",
            Some(json!({"message": PROSE})),
        );
        let mut send = std::pin::pin!(send);
        // One poll runs the send up to the inner channel's park; the block's
        // end then drops it there.
        assert!(futures::poll!(send.as_mut()).is_pending());
    }
    assert!(
        !relayed_by_bob(&firewall, PROSE),
        "a send dropped before commit delivered nothing"
    );
}

/// A channel that commits the delivery, as a real channel does once the frame
/// is out, and then waits for a reply that never comes.
struct DeliversThenHangs;

#[async_trait::async_trait]
impl crate::gateway::input_bridge::ClientChannel for DeliversThenHangs {
    async fn send_request(
        &self,
        _session_id: &str,
        _id: &str,
        _method: &str,
        _params: Option<Value>,
    ) -> Result<Value, crate::gateway::input_bridge::DeliveryError> {
        std::future::pending().await
    }

    async fn send_request_committing(
        &self,
        _session_id: &str,
        _id: &str,
        _method: &str,
        _params: Option<Value>,
        commit: Option<crate::gateway::input_bridge::DeliveryCommit>,
    ) -> Result<Value, crate::gateway::input_bridge::DeliveryError> {
        if let Some(commit) = commit {
            commit.commit();
        }
        std::future::pending().await
    }
}

/// MIK-7887.RECEIPT.3: a prompt the channel delivered keeps its receipt while
/// the reply is pending (no second caller can relay it during the wait) and
/// after the wait is cancelled (the client saw it).
#[tokio::test]
async fn a_delivered_bridged_prompt_is_receipted_before_the_reply_and_after_cancel() {
    use crate::gateway::input_bridge::ClientChannel as _;
    let inner = DeliversThenHangs;
    let (meta, firewall) = relay_meta();
    let channel = RecordingChannel {
        inner: &inner,
        meta: &meta,
        who: RelayKey::new("alice", true),
        target: ("alpha", "send"),
        api_key_name: None,
        trace_id: "t",
    };
    {
        let send = channel.send_request(
            "s",
            "1",
            "elicitation/create",
            Some(json!({"message": PROSE})),
        );
        let mut send = std::pin::pin!(send);
        assert!(futures::poll!(send.as_mut()).is_pending());
        assert!(
            relayed_by_bob(&firewall, PROSE),
            "receipted while the reply is pending"
        );
    }
    assert!(
        relayed_by_bob(&firewall, PROSE),
        "still receipted after the wait is cancelled"
    );
}

/// MIK-7887.RECEIPT.3 guard: an answered prompt was delivered, so it keeps its
/// receipt whatever the answer.
#[tokio::test]
async fn an_answered_bridged_prompt_is_receipted() {
    use crate::gateway::input_bridge::{ClientChannel as _, DeliveryError};
    for inner in [
        Scripted::Reply(Ok(json!({"action": "accept"}))),
        Scripted::Reply(Err(DeliveryError::Declined {
            action: "decline".into(),
        })),
    ] {
        let (meta, firewall) = relay_meta();
        let channel = RecordingChannel {
            inner: &inner,
            meta: &meta,
            who: RelayKey::new("alice", true),
            target: ("alpha", "send"),
            api_key_name: None,
            trace_id: "t",
        };
        let _ = channel
            .send_request(
                "s",
                "1",
                "elicitation/create",
                Some(json!({"message": PROSE})),
            )
            .await;
        assert!(relayed_by_bob(&firewall, PROSE));
    }
}

/// Backend text long enough to fill a receipt's cap on its own: distinct
/// sentences, so every part of it fingerprints.
fn filler(tag: &str) -> String {
    use std::fmt::Write as _;
    (0..400).fold(String::new(), |mut text, n| {
        let _ = write!(
            text,
            "The {tag} inventory line {n} lists crate {} of pressed cider. ",
            n * 7 + 3
        );
        text
    })
}

/// A tools/call result carrying `PROSE`, plus backend `stuffing` placed in a
/// member a late rewrite replaces.
fn stuffed(member: &str, stuffing: &str) -> Value {
    let mut result = text_result(PROSE);
    match member {
        "serverInfo" => {
            result["_meta"] =
                json!({ crate::protocol::meta::KEY_SERVER_INFO: { "name": stuffing } });
        }
        "cacheScope" => result["cacheScope"] = json!(stuffing),
        other => panic!("no such member {other}"),
    }
    result
}

/// Stage `staged`, then rebuild from `delivered` as the delivery point does.
async fn receipt_after_rebuild(
    meta: &Arc<MetaMcp>,
    staged: &Value,
    delivered: &Value,
    stamps: GatewayStamps,
) {
    let ((), receipts) = meta
        .collecting_staged(async {
            meta.stage_relay_receipt(RelayKey::new("alice", true), ("alpha", "send"), staged);
            meta.rebuild_receipt_from_final(Some(delivered), stamps, AnswerShape::Literal);
        })
        .await;
    receipts.commit(true);
}

/// MIK-7887.RECEIPT.4: a modern answer's `serverInfo` is the gateway's own.
/// Backend text stuffed there never reaches the caller, so it is not
/// receipted, and it no longer pushes the delivered text out of the cap.
#[tokio::test]
async fn a_replaced_server_info_is_not_receipted_and_keeps_the_delivered_text() {
    let (meta, firewall) = relay_meta();
    let stuffing = filler("north");
    let staged = stuffed("serverInfo", &stuffing);
    let mut delivered = text_result(PROSE);
    delivered["_meta"] =
        json!({ crate::protocol::meta::KEY_SERVER_INFO: crate::protocol::meta::server_info() });
    receipt_after_rebuild(&meta, &staged, &delivered, GatewayStamps::Modern).await;
    assert!(
        relayed_by_bob(&firewall, PROSE),
        "delivered text lost its receipt"
    );
    let piece: String = stuffing.chars().take(400).collect();
    assert!(
        !relayed_by_bob(&firewall, &piece),
        "undelivered stuffing was receipted"
    );
}

/// MIK-7887.RECEIPT.4: the scope clamp replaces a backend `cacheScope`, on
/// every route.
#[tokio::test]
async fn a_clamped_cache_scope_is_not_receipted_and_keeps_the_delivered_text() {
    let (meta, firewall) = relay_meta();
    let stuffing = filler("south");
    let staged = stuffed("cacheScope", &stuffing);
    let mut delivered = staged.clone();
    crate::protocol::cacheable::clamp_delivered_scope(&mut delivered);
    receipt_after_rebuild(&meta, &staged, &delivered, GatewayStamps::Legacy).await;
    assert!(
        relayed_by_bob(&firewall, PROSE),
        "delivered text lost its receipt"
    );
    let piece: String = stuffing.chars().take(400).collect();
    assert!(
        !relayed_by_bob(&firewall, &piece),
        "undelivered stuffing was receipted"
    );
}

/// MIK-7887.RECEIPT.4: on a legacy answer the backend's `serverInfo` reaches
/// the caller as sent, so it stays in the receipt.
#[tokio::test]
async fn a_legacy_server_info_the_caller_receives_stays_receipted() {
    let (meta, firewall) = relay_meta();
    let delivered = stuffed("serverInfo", OTHER_PROSE);
    receipt_after_rebuild(&meta, &delivered, &delivered, GatewayStamps::Legacy).await;
    assert!(
        relayed_by_bob(&firewall, OTHER_PROSE),
        "delivered serverInfo lost its receipt"
    );
}

/// MIK-7887.RECEIPT.4: a `gateway_invoke` answer that is a promoted interim
/// result is delivered as it stands, `inputRequests` included, even when its
/// one text block is pretty JSON; it is not read as a wrapper.
#[tokio::test]
async fn an_interim_invoke_answer_keeps_its_input_requests_in_the_receipt() {
    let (meta, firewall) = relay_meta();
    let block = serde_json::to_string_pretty(&json!({"note": "waiting"})).unwrap();
    let delivered = json!({
        "content": [{"type": "text", "text": block}],
        "inputRequests": {"ask": {"method": "elicitation/create", "params": {"message": PROSE}}},
    });
    let ((), receipts) = meta
        .collecting_staged(async {
            meta.stage_relay_receipt(RelayKey::new("alice", true), ("alpha", "send"), &delivered);
            meta.rebuild_receipt_from_final(
                Some(&delivered),
                GatewayStamps::Modern,
                AnswerShape::InvokeWrapped,
            );
        })
        .await;
    receipts.commit(true);
    assert!(
        relayed_by_bob(&firewall, PROSE),
        "a delivered input request lost its receipt"
    );
}

/// MIK-7887.RECEIPT.4: a task envelope's retained result has its scope
/// clamped on the way out, so backend text stuffed in that nested
/// `cacheScope` is not receipted.
#[tokio::test]
async fn a_nested_task_result_scope_is_not_receipted() {
    let (meta, firewall) = relay_meta();
    let stuffing = filler("nested");
    let envelope = json!({
        "taskId": "t-1",
        "status": "completed",
        "result": {"content": [{"type": "text", "text": PROSE}], "cacheScope": stuffing},
    });
    receipt_after_rebuild(&meta, &envelope, &envelope, GatewayStamps::Legacy).await;
    assert!(
        relayed_by_bob(&firewall, PROSE),
        "delivered text lost its receipt"
    );
    let piece: String = stuffing.chars().take(400).collect();
    assert!(
        !relayed_by_bob(&firewall, &piece),
        "undelivered nested scope text was receipted"
    );
}

/// MIK-7906 (MIK-7887R.SHAPE.1): a surfaced tool's text that is exactly a
/// pretty-printed JSON object is read as delivered, not decoded as though the
/// gateway had wrapped it, so the numbers in it keep their receipt after a
/// redaction.
#[tokio::test]
async fn a_native_pretty_printed_json_text_keeps_its_numbers() {
    let (meta, firewall) = relay_meta();
    let numbers: Vec<u32> = (1000..1060).collect();
    let text = serde_json::to_string_pretty(&json!({ "n": numbers })).unwrap();
    let both = text_result(&format!("{text}\n{OTHER_PROSE}"));
    let delivered = text_result(&text);
    let ((), staged) = meta
        .collecting_staged(async {
            meta.stage_relay_receipt(RelayKey::new("alice", true), ("alpha", "send"), &both);
            let snapshot = meta.relay_snapshot(&both);
            meta.restage_if_changed(snapshot, Some(&delivered), AnswerShape::Literal);
        })
        .await;
    staged.commit(true);
    assert!(
        relayed_by_bob(&firewall, &text),
        "the numbers lost their receipt"
    );
}

/// MIK-7906: only a `gateway_invoke` answer is wrapped; a surfaced tool's
/// answer, whatever its name, is read as delivered.
#[test]
fn only_a_gateway_invoke_answer_is_wrapped() {
    assert_eq!(
        AnswerShape::of("gateway_invoke"),
        AnswerShape::InvokeWrapped
    );
    for tool in ["send", "gateway_search", "alpha__send"] {
        assert_eq!(AnswerShape::of(tool), AnswerShape::Literal, "{tool}");
    }
}

/// MIK-7942 D6.CATALOGUE.1/.3/.5: a recorded catalogue result is classified
/// as it is delivered. Personal data only in the signature-chain member, which
/// delivery strips, sets no context-integrity verdict; the same data in a
/// delivered text block does (control).
#[test]
fn a_recorded_prompt_is_classified_without_the_stripped_chain() {
    use crate::security::signature_chain::CHAIN_META;
    let meta = MetaMcp::new(Arc::new(crate::backend::BackendRegistry::new()));
    let pii = "Contact: keeper@orchardcoop.fi";
    let only_in_chain = json!({
        "contents": [{"uri": "res://orchard", "text": PROSE}],
        "_meta": {CHAIN_META: {"link": pii}},
    });
    let recorded = meta.recorded_prompt(
        ("alpha", "resources/read"),
        None,
        "catalogue",
        &only_in_chain,
    );
    assert!(recorded.get("_context_integrity").is_none(), "{recorded}");
    let delivered = json!({
        "contents": [{"uri": "res://orchard", "text": format!("{PROSE} {pii}")}],
    });
    let recorded = meta.recorded_prompt(("alpha", "resources/read"), None, "catalogue", &delivered);
    assert!(
        recorded.get("_context_integrity").is_some(),
        "control: {recorded}"
    );
}

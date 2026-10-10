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

/// MIK-7906: a `gateway_invoke` answer is wrapped, and so is a single-tool
/// `gateway_execute` answer (MIK-7939 D6.RELAY.7, the same `wrap_tool_success`
/// envelope); a surfaced tool's answer, whatever its name, is read as delivered.
#[test]
fn only_a_gateway_invoke_answer_is_wrapped() {
    for tool in ["gateway_invoke", "gateway_execute"] {
        assert_eq!(AnswerShape::of(tool), AnswerShape::InvokeWrapped, "{tool}");
    }
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
    // In the chain member, which delivery strips, and in a scope delivery
    // clamps to `private`.
    for undelivered in [
        json!({
            "contents": [{"uri": "res://orchard", "text": PROSE}],
            "_meta": {CHAIN_META: {"link": pii}},
        }),
        json!({
            "contents": [{"uri": "res://orchard", "text": PROSE}],
            "cacheScope": pii,
        }),
    ] {
        let recorded =
            meta.recorded_prompt(("alpha", "resources/read"), None, "catalogue", &undelivered);
        assert!(recorded.get("_context_integrity").is_none(), "{recorded}");
    }
    let delivered = json!({
        "contents": [{"uri": "res://orchard", "text": format!("{PROSE} {pii}")}],
    });
    let recorded = meta.recorded_prompt(("alpha", "resources/read"), None, "catalogue", &delivered);
    assert!(
        recorded.get("_context_integrity").is_some(),
        "control: {recorded}"
    );
}

/// [`receipt_after_rebuild`] for an answer of `shape` (a legacy route).
async fn receipt_after_rebuild_as(
    meta: &Arc<MetaMcp>,
    staged: &Value,
    delivered: &Value,
    shape: AnswerShape,
) {
    let ((), receipts) = meta
        .collecting_staged(async {
            meta.stage_relay_receipt(RelayKey::new("alice", true), ("alpha", "send"), staged);
            meta.rebuild_receipt_from_final(Some(delivered), GatewayStamps::Legacy, shape);
        })
        .await;
    receipts.commit(true);
}

/// [`PROSE`] as lines shorter than a fingerprint: every window crosses a
/// newline, which a wrapper escapes.
fn short_lines() -> String {
    PROSE
        .split(' ')
        .collect::<Vec<_>>()
        .chunks(4)
        .map(|words| words.join(" "))
        .collect::<Vec<_>>()
        .join("\n")
}

/// MIK-7939 D6.RELAY.7: a single-tool `gateway_execute` answer is the
/// backend value wrapped as pretty-printed JSON text, read decoded, so the
/// lines the caller read keep their receipt.
#[tokio::test]
async fn a_wrapped_gateway_execute_answer_is_read_decoded() {
    let (meta, firewall) = relay_meta();
    let value = json!({ "text": short_lines() });
    let delivered =
        crate::gateway::meta_mcp_helpers::wrap_tool_success(RequestId::Number(1), &value, false)
            .result
            .expect("a wrapped result");
    let shape = AnswerShape::of("gateway_execute");
    receipt_after_rebuild_as(&meta, &value, &delivered, shape).await;
    assert!(relayed_by_bob(&firewall, &short_lines()), "{delivered}");
}

/// MIK-7939 D6.RELAY.12: a `gateway_invoke` value that is not an object (an
/// array of lines) is wrapped the same way and read decoded too.
#[tokio::test]
async fn a_wrapped_array_value_is_read_decoded() {
    let (meta, firewall) = relay_meta();
    let value = json!([short_lines()]);
    let delivered =
        crate::gateway::meta_mcp_helpers::wrap_tool_success(RequestId::Number(1), &value, false)
            .result
            .expect("a wrapped result");
    receipt_after_rebuild_as(&meta, &value, &delivered, AnswerShape::InvokeWrapped).await;
    assert!(relayed_by_bob(&firewall, &short_lines()), "{delivered}");
}

/// MIK-7939 D6.RELAY.3/.9: a `tasks/get` answer is the gateway's task
/// envelope around the stored result. Only the delivered slot is the
/// backend's text: the envelope's `statusMessage` is not receipted.
#[tokio::test]
async fn a_task_envelope_receipts_only_its_delivered_slot() {
    let (meta, firewall) = relay_meta();
    let stored = text_result(PROSE);
    let delivered = json!({
        "taskId": "t-1",
        "status": "completed",
        "statusMessage": OTHER_PROSE,
        "result": stored,
    });
    let shape = AnswerShape::of("tasks/get");
    receipt_after_rebuild_as(&meta, &stored, &delivered, shape).await;
    assert!(
        relayed_by_bob(&firewall, PROSE),
        "the slot lost its receipt"
    );
    assert!(
        !relayed_by_bob(&firewall, OTHER_PROSE),
        "envelope text was receipted"
    );
}

/// MIK-7939 (B04b-1 design, task envelope): an envelope with no delivered
/// slot keeps the receipt staged from the stored slot, also when a final
/// check rewrote the envelope in place (as the rebuild does).
#[tokio::test]
async fn a_rewritten_slotless_envelope_keeps_the_stored_receipt() {
    let (meta, firewall) = relay_meta();
    let stored = text_result(PROSE);
    let before = json!({"taskId": "t-1", "status": "working", "statusMessage": OTHER_PROSE});
    let after = json!({"taskId": "t-1", "status": "working", "statusMessage": "[redacted]"});
    let ((), staged) = meta
        .collecting_staged(async {
            meta.stage_relay_receipt(RelayKey::new("alice", true), ("alpha", "send"), &stored);
            let snapshot = meta.relay_snapshot(&before);
            meta.restage_if_changed(snapshot, Some(&after), AnswerShape::of("tasks/get"));
        })
        .await;
    staged.commit(true);
    assert!(
        relayed_by_bob(&firewall, PROSE),
        "the stored slot lost its receipt"
    );
}

/// Rebuild from `delivered`, built inside the same delivery scope by `build`
/// (the gateway's write sites run there), as a `gateway_invoke` answer.
async fn receipt_after_invoke(
    meta: &Arc<MetaMcp>,
    staged: &Value,
    build: impl FnOnce() -> Value,
) -> Value {
    let (delivered, receipts) = meta
        .collecting_staged(async {
            meta.stage_relay_receipt(RelayKey::new("alice", true), ("alpha", "send"), staged);
            let value = build();
            let delivered = crate::gateway::meta_mcp_helpers::wrap_tool_success(
                RequestId::Number(1),
                &value,
                false,
            )
            .result
            .expect("a wrapped result");
            meta.rebuild_receipt_from_final(
                Some(&delivered),
                GatewayStamps::Legacy,
                AnswerShape::InvokeWrapped,
            );
            value
        })
        .await;
    receipts.commit(true);
    delivered
}

/// MIK-7939 D6.RELAY.6: members the gateway adds to a `gateway_invoke`
/// result (`predicted_next`, `trace_id`) are not the backend's text.
#[tokio::test]
async fn gateway_augmentations_are_not_receipted() {
    use crate::gateway::meta_mcp::support::{augment_with_predictions, augment_with_trace};
    let (meta, firewall) = relay_meta();
    let backend = json!({ "text": PROSE });
    receipt_after_invoke(&meta, &backend, || {
        let v = augment_with_predictions(backend.clone(), vec![json!(OTHER_PROSE)]);
        augment_with_trace(v, "4bf92f3577b34da6a3ce929d0e0e4736")
    })
    .await;
    assert!(
        relayed_by_bob(&firewall, PROSE),
        "backend text lost its receipt"
    );
    assert!(
        !relayed_by_bob(&firewall, OTHER_PROSE),
        "gateway predictions were receipted"
    );
}

/// MIK-7939 pin (green before and after): a member the gateway did not
/// write stays backend text whatever its name, so naming relayed text
/// `predicted_next` or `recovery` cannot hide it.
#[tokio::test]
async fn a_backend_member_named_like_a_gateway_one_is_receipted() {
    let (meta, firewall) = relay_meta();
    let backend = json!({ "text": "ok", "predicted_next": PROSE, "recovery": OTHER_PROSE });
    receipt_after_invoke(&meta, &backend, || backend.clone()).await;
    assert!(relayed_by_bob(&firewall, PROSE));
    assert!(relayed_by_bob(&firewall, OTHER_PROSE));
}

/// MIK-7991.LIVE.1: the recovery hint the gateway attaches to a backend's
/// `isError` result is not the backend's text.
#[tokio::test]
async fn a_gateway_recovery_hint_is_not_receipted() {
    use crate::gateway::meta_mcp::invoke::post_dispatch::attach_tool_error_recovery;
    let (meta, firewall) = relay_meta();
    let failed = crate::gateway::meta_mcp::invoke::receipt_test_support::backend_failure(PROSE);
    let backend = json!({ "isError": true, "content": [{ "type": "text", "text": failed }] });
    let delivered = receipt_after_invoke(&meta, &backend, || {
        attach_tool_error_recovery(
            backend.clone(),
            "send",
            "alpha",
            crate::gateway::recovery::MetaSurface::Standard(
                crate::gateway::recovery::Revive::Offered,
            ),
        )
    })
    .await;
    let own = hint_own_text(&delivered);
    assert!(
        relayed_by_bob(&firewall, PROSE),
        "backend text lost its receipt"
    );
    assert!(
        !relayed_by_bob(&firewall, &own),
        "the hint was receipted: {own}"
    );
}

/// The delivered hint's own text (not [`PROSE`]).
fn hint_own_text(delivered: &Value) -> String {
    crate::gateway::meta_mcp::invoke::receipt_test_support::own_hint_text(delivered, PROSE)
}

/// MIK-7939 (impl review): a failed dispatch answers with the gateway's own
/// recovery hint (`dispatch_error_result`, the first dispatch and a bridged
/// continuation alike); the hint is not the backend's text.
#[tokio::test]
async fn a_dispatch_failure_hint_is_not_receipted() {
    use crate::gateway::meta_mcp::invoke::errors::dispatch_error_result;
    let (meta, firewall) = relay_meta();
    let backend = text_result(PROSE);
    let delivered = receipt_after_invoke(&meta, &backend, || {
        dispatch_error_result(
            &crate::Error::BackendUnavailable(PROSE.to_owned()),
            "send",
            "alpha",
            crate::gateway::recovery::MetaSurface::Standard(
                crate::gateway::recovery::Revive::Offered,
            ),
        )
    })
    .await;
    let own = hint_own_text(&delivered);
    assert!(
        relayed_by_bob(&firewall, PROSE),
        "the failure text lost its receipt"
    );
    assert!(
        !relayed_by_bob(&firewall, &own),
        "the hint was receipted: {own}"
    );
}

/// MIK-7939 D6.RELAY.3 (impl review): a task-augmented `gateway_invoke`
/// replay answers with the task envelope the gateway built
/// (`BeginOutcome::into_response`), read as one whatever the method's shape:
/// its `statusMessage` is not receipted, the stored result is. A backend
/// answer shaped like an envelope is read whole.
#[tokio::test]
async fn a_built_task_envelope_is_read_as_one() {
    use crate::gateway::task_service::CommittedTask;
    use crate::gateway::task_service::execution::BeginOutcome;
    use crate::protocol::tasks::{Task, TaskTransition};
    let (meta, firewall) = relay_meta();
    let stored = text_result(PROSE);
    let mut task = Task::create("gateway_invoke");
    task.transition(
        TaskTransition::StatusMessage(Some(OTHER_PROSE.to_owned())),
        chrono::Utc::now(),
    )
    .expect("a status message");
    task.complete(stored.clone());
    let replay = CommittedTask {
        task,
        revision: 1,
        targets: Vec::new(),
        targets_recorded: true,
        output_free: false,
        error_author: None,
        owner_digest: String::new(),
        gateway_writes: crate::gateway::gateway_writes::WriteRecord::default(),
    };
    let ((), receipts) = meta
        .collecting_staged(async {
            meta.stage_relay_receipt(RelayKey::new("alice", true), ("alpha", "send"), &stored);
            // No sealed question here, so no holds to carry.
            let replay = crate::gateway::meta_mcp::sealed_hold::Held::new(
                replay,
                crate::gateway::meta_mcp::sealed_hold::CarriedHolds::none(),
            );
            let answer = BeginOutcome::Existing(replay).into_response(RequestId::Number(1));
            meta.rebuild_receipt_from_final(
                answer.result.as_ref(),
                GatewayStamps::Legacy,
                AnswerShape::of("gateway_invoke"),
            );
        })
        .await;
    receipts.commit(true);
    assert!(
        relayed_by_bob(&firewall, PROSE),
        "the stored result lost its receipt"
    );
    assert!(
        !relayed_by_bob(&firewall, OTHER_PROSE),
        "envelope text was receipted"
    );

    // Control: the same members from a backend, with no envelope built.
    let (meta, firewall) = relay_meta();
    let lookalike = json!({
        "taskId": "t-1",
        "status": "completed",
        "statusMessage": OTHER_PROSE,
        "result": text_result(PROSE),
    });
    receipt_after_rebuild_as(&meta, &lookalike, &lookalike, AnswerShape::Literal).await;
    assert!(
        relayed_by_bob(&firewall, OTHER_PROSE),
        "a backend's envelope-shaped answer was narrowed"
    );
}

/// Backend text a test places where the gateway also writes, with bytes
/// other than the gateway's.
const BACKEND_ADVICE: &str = "Field notes from the upland survey: the stone wall along the east \
    boundary needs resetting, the spring by the shepherd's hut runs clear again, and the gate \
    hinge on the lower track was replaced with a galvanised one before the first snow.";

/// `MIK-7993.STORE.1`/`.2`: a `tasks/get` read restores the row's write
/// record before staging. The advice the gateway wrote into the stored
/// result is not receipted; the backend's text is; and a backend member of
/// the same name holding other bytes stays receipted.
#[tokio::test]
async fn a_stored_result_receipts_only_what_the_backend_wrote() {
    use crate::gateway::meta_mcp::invoke::gateway_writes;
    let written = json!({
        "content": [{"type": "text", "text": PROSE}],
        "_cost_warnings": [OTHER_PROSE],
    });
    // The record the worker stored: the gateway wrote `_cost_warnings`.
    let record = gateway_writes::scope(async {
        gateway_writes::note(gateway_writes::Layer::Value, &["_cost_warnings"], &written);
        gateway_writes::recorded()
    })
    .await;
    assert!(!record.is_empty(), "premise: the note was taken");

    let (meta, firewall) = relay_meta();
    let mut stored = stored_task(|task| task.complete(written.clone()));
    stored.gateway_writes = record.clone();
    let ((), staged) = meta
        .collecting_staged(async {
            meta.stage_stored_receipt(RelayKey::new("alice", true), None, &stored);
        })
        .await;
    staged.commit(true);
    assert!(
        relayed_by_bob(&firewall, PROSE),
        "the backend's text lost its receipt"
    );
    assert!(
        !relayed_by_bob(&firewall, OTHER_PROSE),
        "the gateway's own advice was receipted as backend text"
    );

    // STORE.2: the same record over a backend member of that name with
    // other bytes exempts nothing.
    let (meta, firewall) = relay_meta();
    let backend = json!({
        "content": [{"type": "text", "text": PROSE}],
        "_cost_warnings": [BACKEND_ADVICE],
    });
    let mut stored = stored_task(|task| task.complete(backend));
    stored.gateway_writes = record;
    let ((), staged) = meta
        .collecting_staged(async {
            meta.stage_stored_receipt(RelayKey::new("alice", true), None, &stored);
        })
        .await;
    staged.commit(true);
    assert!(
        relayed_by_bob(&firewall, BACKEND_ADVICE),
        "a backend member the gateway did not write lost its receipt"
    );
}

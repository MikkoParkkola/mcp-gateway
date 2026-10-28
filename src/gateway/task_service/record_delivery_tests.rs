// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A stored task is delivered without any `Noted`
//! gateway-only member its row does not record as the gateway's own write.
//! The ingress strip removes a backend's copy before store, so a member at
//! a noted `(layer, dest)` is the gateway's, even sealed or redacted after its
//! note; a row stored before the rename notes the plain dest, so a `_` member
//! planted in it matches nothing and is removed. `Outside` members are left
//! as stored.

use serde_json::{Value, json};

use super::CommittedTask;
use crate::gateway::gateway_writes::WriteRecord;
use crate::protocol::JsonRpcError;
use crate::protocol::mrtr::InputRequired;
use crate::protocol::tasks::{Task, TaskTransition};

const DIGEST: &str = "636810988c0638ebda7b64c4fcac77cae55b300084dd6c553983f9c1aaf350db";

/// A note as a row stores it.
fn note(layer: &str, dest: &[&str], kind: &[&str], within: &[&str]) -> Value {
    json!({"layer": layer, "dest": dest, "kind": kind, "within": within, "digest": DIGEST})
}

fn row(task: Task, notes: Vec<Value>) -> CommittedTask {
    CommittedTask {
        task,
        revision: 1,
        targets: Vec::new(),
        targets_recorded: true,
        output_free: false,
        error_author: None,
        owner_digest: String::new(),
        gateway_writes: serde_json::from_value::<WriteRecord>(Value::Array(notes))
            .expect("a record always decodes"),
        bindings: Vec::new(),
        // M2: only a bindings-recorded row is served at all.
        bindings_recorded: true,
    }
}

fn completed(result: &Value, notes: Vec<Value>) -> CommittedTask {
    let mut task = Task::create("gateway_invoke").expect("the clock reads after 1970");
    task.complete(result).expect("a live task completes");
    row(task, notes)
}

fn planted() -> Value {
    json!({
        "_recovery": {"hint": "FORGED-recovery"},
        "_trace_id": "FORGED-trace",
        "_predicted_next": ["FORGED-next"],
    })
}

fn assert_unforged(what: &str, delivered: &Value) {
    let text = delivered.to_string();
    assert!(
        !text.contains("FORGED-"),
        "{what}: a planted member was served: {text}"
    );
}

/// A completed row stored since the rename keeps the gateway's own noted
/// `_recovery`, its sealed provenance (sealed after the note, so its digest
/// moved), its signature under an answer-layer note, and the `Outside`
/// members it stored.
#[test]
fn a_post_rename_row_keeps_every_gateway_write() {
    let result = json!({
        "content": [{"type": "text", "text": "ok"}],
        "_recovery": {"hint": "the gateway's"},
        "_trace_id": "gw-1",
        "_context_integrity": {"policy": {"decision": "allow"}},
        "_signature": {"sig": "the gateway's"},
        "_meta": {
            "provenance": {"receipt": {"r": 1}, "public_signature": {"sig": "sealed"}},
            "io.mcp-gateway/executionOutcome": "executed",
            "io.mcp-gateway/reason": "the gateway's",
        },
    });
    let stored = completed(
        &result,
        vec![
            note("value", &["_recovery"], &["_recovery"], &[]),
            note("value", &["_trace_id"], &["_trace_id"], &[]),
            // An answer-layer note claims an envelope member.
            note("answer", &["_signature"], &["_signature"], &[]),
            note(
                "value",
                &["_meta", "provenance"],
                &["_meta", "provenance"],
                &[],
            ),
        ],
    );
    let delivered = stored.delivered_wire();
    assert_eq!(delivered["result"], result, "{delivered}");
}

/// A row stored before the rename: its notes name the plain members, so the
/// planted `_` members match nothing and are removed, the plain members
/// (the gateway's then, backend data now) stay, and the seal that covered
/// the planted members is dropped while its receipt stays (R3.6).
#[test]
fn a_pre_rename_row_loses_its_planted_members_and_their_seal() {
    let mut result = planted();
    result["content"] = json!([{"type": "text", "text": "ok"}]);
    result["recovery"] = json!({"hint": "old gateway hint"});
    result["trace_id"] = json!("gw-old");
    result["_meta"] = json!({
        "provenance": {"receipt": {"r": 1}, "public_signature": {"sig": "sealed-over-plants"}},
    });
    let stored = completed(
        &result,
        vec![
            note("value", &["recovery"], &["recovery"], &[]),
            note("value", &["trace_id"], &["trace_id"], &[]),
            note(
                "value",
                &["_meta", "provenance"],
                &["_meta", "provenance"],
                &[],
            ),
        ],
    );
    let delivered = stored.delivered_wire();
    assert_unforged("pre-rename result", &delivered);
    let served = &delivered["result"];
    assert_eq!(served["recovery"]["hint"], "old gateway hint", "{served}");
    assert_eq!(served["trace_id"], "gw-old", "{served}");
    let provenance = &served["_meta"]["provenance"];
    assert_eq!(provenance["receipt"], json!({"r": 1}), "{served}");
    assert!(
        provenance.get("public_signature").is_none(),
        "a seal over removed members was served: {served}"
    );
}

/// A clean row stored before the rename keeps its seal: nothing it covers
/// was removed.
#[test]
fn a_clean_pre_rename_row_keeps_its_seal() {
    let result = json!({
        "content": [{"type": "text", "text": "ok"}],
        "_meta": {"provenance": {"receipt": {"r": 1}, "public_signature": {"sig": "s"}}},
    });
    let stored = completed(
        &result,
        vec![note(
            "value",
            &["_meta", "provenance"],
            &["_meta", "provenance"],
            &[],
        )],
    );
    assert_eq!(stored.delivered_wire()["result"], result);
}

/// A note at the right dest on the wrong layer, or for only part of the
/// member (`within`), or rebased under a composite's step, keeps nothing at
/// the top level.
#[test]
fn only_a_whole_top_level_value_note_keeps_a_member() {
    for (what, notes) in [
        (
            "answer layer",
            vec![note("answer", &["_recovery"], &["_recovery"], &[])],
        ),
        (
            "partial",
            vec![note("value", &["_recovery"], &["_recovery"], &["hint"])],
        ),
        (
            "rebased",
            vec![note(
                "value",
                &["results", "0", "result", "_recovery"],
                &["_recovery"],
                &[],
            )],
        ),
    ] {
        let stored = completed(&json!({"_recovery": {"hint": "FORGED-recovery"}}), notes);
        assert_unforged(what, &stored.delivered_wire());
    }
}

/// A Failed row's stored `error.data` keeps no `Noted` member: its record
/// is always empty, and the gateway never writes one there.
#[test]
fn a_failed_rows_error_data_loses_planted_members() {
    let mut task = Task::create("gateway_invoke").expect("the clock reads after 1970");
    let mut data = planted();
    data["detail"] = json!("the backend's");
    task.fail(&JsonRpcError {
        code: -32000,
        message: "failed".to_owned(),
        data: Some(data),
    })
    .expect("a live task fails");
    let delivered = row(task, Vec::new()).delivered_wire();
    assert_unforged("error.data", &delivered);
    assert_eq!(
        delivered["error"]["data"]["detail"], "the backend's",
        "{delivered}"
    );
}

/// A parked round's stored `input_requests` lose planted members too.
#[test]
fn parked_input_requests_lose_planted_members() {
    let mut task = Task::create("gateway_invoke").expect("the clock reads after 1970");
    let mut request = planted();
    request["method"] = json!("elicitation/create");
    task.transition(
        TaskTransition::RequireInput(InputRequired {
            requests: vec![("k-1".to_owned(), request)],
            request_state: None,
        }),
        chrono::DateTime::UNIX_EPOCH,
    )
    .expect("a live task parks");
    let delivered = row(task, Vec::new()).delivered_wire();
    assert_unforged("input_requests", &delivered);
    assert_eq!(
        delivered["inputRequests"]["k-1"]["method"], "elicitation/create",
        "{delivered}"
    );
}

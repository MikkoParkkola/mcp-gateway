// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8428 Case E: a chain resumed after its pending step's caller verdict
//! met a mint-time custody `Busy`. The verdict carried that sealed error to
//! the dispatch; the resume fingerprint must answer it rather than resolve
//! (mint, read custody, audit) a second time in the same request.

use serde_json::{Value, json};

use super::{BACKEND, Fx, TOOL, fixture, refusals, send};

/// The chain: `read` asks a question and stops; a second `read` follows.
fn chain() -> Value {
    let step = json!({"tool": format!("{BACKEND}:{TOOL}"), "arguments": {"folder": "inbox"}});
    json!([step.clone(), step])
}

/// Declares elicitation, so a step that asks stops the chain with a handle.
fn eliciting_meta() -> Value {
    json!({
        "io.modelcontextprotocol/protocolVersion": "2026-07-28",
        "io.modelcontextprotocol/clientCapabilities": {"elicitation": {"form": {}}},
    })
}

/// The first `requestState` anywhere in `value`, a text block's JSON included.
fn request_state_in(value: &Value) -> Option<String> {
    match value {
        Value::Object(map) => match map.get("requestState") {
            Some(Value::String(state)) => Some(state.clone()),
            _ => map.values().find_map(request_state_in),
        },
        Value::Array(items) => items.iter().find_map(request_state_in),
        Value::String(text) => serde_json::from_str::<Value>(text)
            .ok()
            .as_ref()
            .and_then(request_state_in),
        _ => None,
    }
}

async fn execute(fx: &Fx, resume: Option<&str>) -> Value {
    let mut params = json!({"name": "gateway_execute",
        "arguments": {"chain": chain()}, "_meta": eliciting_meta()});
    if let Some(handle) = resume {
        params["requestState"] = json!(handle);
        params["inputResponses"] = json!({"q1": {"action": "accept", "content": {"pick": "b"}}});
    }
    send(fx, "tools/call", "gateway_execute", params).await
}

/// SETTLE.10. Primary: the resume reads custody twice (the verdict's view
/// and its busy mint) and writes one `idp_refuse`. A fingerprint that
/// resolves again makes it three and two.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_resume_after_a_mint_busy_resolves_its_pending_step_once() {
    let fx = fixture().await;
    fx.gateway.answer_next(json!({
        "resultType": "input_required",
        "inputRequests": {"q1": {"method": "elicitation/create", "params": {"message": "which?"}}},
        "requestState": "backend-state-1"
    }));
    let stop = execute(&fx, None).await;
    let handle = request_state_in(&stop)
        .unwrap_or_else(|| panic!("premise: the chain stops with a resume handle: {stop}"));

    fx.gateway.fail_custody_after_for_test(1);
    let reads = fx.gateway.resolves();
    let before = refusals(&fx);
    let resumed = execute(&fx, Some(&handle)).await;
    assert_eq!(
        (fx.gateway.resolves() - reads, refusals(&fx) - before),
        (2, 1),
        "SETTLE.10: (custody reads, idp_refuse) for the resumed step: {resumed}"
    );
}

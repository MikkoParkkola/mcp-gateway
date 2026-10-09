// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The saturation gate the stdio read loop consults (moved from `server/mod.rs`, MIK-8144).

use super::super::*;

#[test]
fn a_saturated_gate_refuses_instead_of_making_the_reader_wait() {
    let inflight = std::sync::Arc::new(tokio::sync::Semaphore::new(2));
    let first = admit_stdio_request(&inflight).expect("an empty gate admits");
    let _second = admit_stdio_request(&inflight).expect("the gate admits up to its cap");
    assert!(
        admit_stdio_request(&inflight).is_none(),
        "over the cap the gate must refuse: awaiting here parks the only reader that can \
         deliver the replies the already-accepted work is waiting for"
    );
    drop(first);
    assert!(
        admit_stdio_request(&inflight).is_some(),
        "a finished dispatch must return its slot to the gate"
    );
}

#[test]
fn a_refusal_answers_the_id_it_refused() {
    let refusal = stdio_busy_response(&serde_json::json!({
        "jsonrpc": "2.0", "id": 7, "method": "tools/call"
    }))
    .expect("a request carrying an id must be answered");
    assert_eq!(refusal["id"], serde_json::json!(7));
    assert_eq!(refusal["error"]["code"], serde_json::json!(-32000));
}

#[test]
fn a_notification_is_refused_in_silence() {
    assert!(
        stdio_busy_response(&serde_json::json!({
            "jsonrpc": "2.0", "method": "notifications/initialized"
        }))
        .is_none(),
        "a frame with no id has nothing to answer; replying to one is a protocol violation"
    );
    assert!(
        stdio_busy_response(&serde_json::json!({
            "jsonrpc": "2.0", "id": null, "method": "notifications/initialized"
        }))
        .is_none(),
        "an explicit null id is the same notification, spelled out"
    );
}

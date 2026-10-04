// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Admission and refusal for the stdio read loop, none of which may wait:
//! the reader that calls them is the only thing that reads EOF and cancels.

use std::sync::Arc;

/// Take a slot for one accepted stdio request, or refuse.
///
/// Deliberately not `async`. The read loop is the only thing that can deliver
/// a bridged reply, so a wait here is woken only by work that is itself
/// waiting on this loop — the deadlock the concurrent-dispatch package exists
/// to remove, relocated from the first request to the cap-plus-first. A
/// synchronous signature makes "the reader never parks on admission" a
/// property of the type rather than of review.
pub(super) fn admit_stdio_request(
    inflight: &Arc<tokio::sync::Semaphore>,
) -> Option<tokio::sync::OwnedSemaphorePermit> {
    Arc::clone(inflight).try_acquire_owned().ok()
}

/// The refusal a saturated gateway owes the client, or `None` when the frame
/// is a notification: no id means nothing to answer, and answering anyway is a
/// protocol violation the client cannot correlate.
pub(super) fn stdio_busy_response(request: &serde_json::Value) -> Option<serde_json::Value> {
    let id = request.get("id").filter(|id| !id.is_null())?.clone();
    Some(serde_json::json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": {
            "code": -32000,
            "message": "server busy: too many stdio requests in flight, retry this request"
        }
    }))
}

/// The refusal a saturated gateway owes a batch (JSON-RPC 2.0 §6), or `None`
/// when no element can be answered. An empty batch is one invalid-request
/// error; an element with an id is refused busy; a well-formed notification
/// gets nothing; any other element is an invalid request.
pub(super) fn stdio_busy_batch_response(batch: &serde_json::Value) -> Option<serde_json::Value> {
    let invalid = || {
        serde_json::json!({
            "jsonrpc": "2.0",
            "id": null,
            "error": {"code": -32600, "message": "Invalid Request"}
        })
    };
    let items = batch.as_array()?;
    if items.is_empty() {
        return Some(invalid());
    }
    let answers: Vec<serde_json::Value> = items
        .iter()
        .filter_map(|item| {
            if !item.is_object() {
                return Some(invalid());
            }
            if let Some(busy) = stdio_busy_response(item) {
                return Some(busy);
            }
            // No id: a well-formed notification is not answered; anything
            // else is an invalid request, and the client is owed that.
            let notification = item.get("jsonrpc").and_then(serde_json::Value::as_str)
                == Some("2.0")
                && item.get("method").is_some_and(serde_json::Value::is_string);
            (!notification).then(invalid)
        })
        .collect();
    (!answers.is_empty()).then_some(serde_json::Value::Array(answers))
}

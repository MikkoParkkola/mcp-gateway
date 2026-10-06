// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Dispatch-result classification, HTTP-status stripping, interrupted payloads.

use serde_json::{Value, json};

use crate::gateway::authz::HTTP_STATUS_DATA_KEY;
use crate::protocol::mrtr::InputRequired;
use crate::protocol::{JsonRpcError, JsonRpcResponse};

pub(super) enum DispatchSettlement {
    Complete(Value),
    Fail(JsonRpcError),
    /// The backend stopped to ask, in a shape `from_result` accepts. Its
    /// `requestState` is the gateway-sealed continuation, never the backend's.
    Input(InputRequired),
    /// A claimed round whose shape is rejected: settled on the gateway's
    /// own abandoned result, so the backend's text in it is never delivered.
    Abandoned,
}

pub(super) fn classify_dispatch(response: JsonRpcResponse) -> DispatchSettlement {
    if let Some(error) = response.error {
        return DispatchSettlement::Fail(strip_http_status(error));
    }
    let result = response.result.unwrap_or(Value::Null);
    if InputRequired::claims_input_required(&result) {
        // A claimed round whose shape is rejected keeps the abandoned result.
        return InputRequired::from_result(&result)
            .map_or_else(|| DispatchSettlement::Abandoned, DispatchSettlement::Input);
    }
    DispatchSettlement::Complete(stored_result(result))
}

pub(super) fn interrupted_before_dispatch() -> Value {
    interrupted_result(
        "not_executed",
        "gateway_interrupted_before_dispatch",
        "The gateway interrupted this task before the backend was called.",
    )
}

pub(super) fn abandoned_input_round() -> Value {
    interrupted_result(
        "unknown",
        "input_round_unavailable",
        "The backend asked for input that cannot be continued.",
    )
}

pub(super) fn interrupted_result(outcome: &str, reason: &str, text: &str) -> Value {
    json!({
        "content": [{"type": "text", "text": text}],
        "isError": true,
        "_meta": {
            (super::super::record::EXECUTION_OUTCOME_KEY): outcome,
            "io.mcp-gateway/reason": reason,
        }
    })
}

/// A backend's result without the `_meta` key that marks the gateway's own
/// sentences, so a backend cannot pass its output for one.
pub(super) fn backend_output(mut result: Value) -> Value {
    if let Some(meta) = result.get_mut("_meta").and_then(Value::as_object_mut) {
        meta.remove(super::super::record::EXECUTION_OUTCOME_KEY);
    }
    result
}

/// A backend's result as a task stores it: the gateway's marker removed, a
/// non-object wrapped as one text block. The settled receipt is taken from
/// this same value, so it holds the text a read delivers (MIK-7939).
pub(super) fn stored_result(result: Value) -> Value {
    as_result_object(backend_output(result))
}

fn as_result_object(result: Value) -> Value {
    if result.is_object() {
        result
    } else {
        json!({
            "content": [{"type": "text", "text": result.to_string()}],
            "isError": false,
        })
    }
}

pub(super) fn strip_http_status(mut error: JsonRpcError) -> JsonRpcError {
    if let Some(Value::Object(data)) = error.data.as_mut() {
        data.remove(HTTP_STATUS_DATA_KEY);
        if data.is_empty() {
            error.data = None;
        }
    }
    error
}

#[cfg(test)]
mod tests;

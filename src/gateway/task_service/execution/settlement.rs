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
}

pub(super) fn classify_dispatch(response: JsonRpcResponse) -> DispatchSettlement {
    if let Some(error) = response.error {
        return DispatchSettlement::Fail(strip_http_status(error));
    }
    let result = response.result.unwrap_or(Value::Null);
    if InputRequired::claims_input_required(&result) {
        return DispatchSettlement::Complete(abandoned_input_round());
    }
    DispatchSettlement::Complete(as_result_object(result))
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

fn interrupted_result(outcome: &str, reason: &str, text: &str) -> Value {
    json!({
        "content": [{"type": "text", "text": text}],
        "isError": true,
        "_meta": {
            "io.mcp-gateway/executionOutcome": outcome,
            "io.mcp-gateway/reason": reason,
        }
    })
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
    let Some(Value::Object(mut data)) = error.data.take() else {
        return error;
    };
    data.remove(HTTP_STATUS_DATA_KEY);
    error.data = (!data.is_empty()).then_some(Value::Object(data));
    error
}

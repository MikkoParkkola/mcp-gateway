// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! What the scripted backend answers with, by [`Answer`]: the question an
//! `Ask*` answer opens with, a `tools/call` answer, and a `tools/list` page.
//! Moved out of the shared fixture to keep it under the file-size ceiling.

use serde_json::{Value, json};

use super::egress::error_answer;
use super::{Answer, Fx};
use crate::protocol::{JsonRpcResponse, RequestId};

/// The question an `Ask*` answer opens with.
pub(super) fn question(answer: Answer) -> Value {
    let mut asked = json!({
        "resultType": "input_required",
        "inputRequests": {
            "k1": {
                "method": "elicitation/create",
                "params": {"message": "Which account?", "requestedSchema": {"type": "object"}}
            }
        },
        "requestState": "backend-state-1"
    });
    if matches!(answer, Answer::AskNoState) {
        asked.as_object_mut().unwrap().remove("requestState");
    }
    if matches!(answer, Answer::AskMalformed) {
        asked["inputRequests"] = json!("surprise");
    }
    if matches!(answer, Answer::AskBig) {
        asked["requestState"] = json!("s".repeat(16 * 1024));
    }
    if matches!(answer, Answer::AskBadMeta) {
        asked["_meta"] = json!(5);
    }
    if let Answer::AskWith(text) = answer {
        asked["inputRequests"]["k1"]["params"]["message"] = json!(text);
        asked["content"] = json!([{"type": "text", "text": text}]);
    }
    if let Answer::AskEdited(edit) = answer {
        edit(&mut asked);
    }
    asked
}

/// What the backend answers a `tools/call` with, past the question rounds.
pub(super) fn call_answer(answer: Answer, id: RequestId) -> crate::Result<JsonRpcResponse> {
    match answer {
        Answer::DoneWithState => Ok(JsonRpcResponse::success(
            id,
            json!({"content": [{"type": "text", "text": "ok"}], "isError": false,
                   "requestState": "backend-state-1"}),
        )),
        Answer::Ok
        | Answer::WithNote
        | Answer::Paged(..)
        | Answer::Unreadable(_)
        | Answer::NonNumeric(_) => Ok(JsonRpcResponse::success(
            id,
            json!({"content": [{"type": "text", "text": "ok"}], "isError": false}),
        )),
        Answer::ModernList => Ok(JsonRpcResponse::success(
            id,
            json!({"content": [{"type": "text", "text": "ok"}], "isError": false, "ttlMs": 3000}),
        )),
        Answer::PublicScope => Ok(JsonRpcResponse::success(
            id,
            json!({"content": [{"type": "text", "text": "ok"}], "isError": false,
                   "cacheScope": "public"}),
        )),
        Answer::IsError => Ok(JsonRpcResponse::success(
            id,
            json!({"content": [{"type": "text", "text": "backend says no"}], "isError": true}),
        )),
        Answer::RpcError(code) => Ok(JsonRpcResponse::error(Some(id), code, "backend says no")),
        Answer::RateLimited => Ok(JsonRpcResponse::error(
            Some(id),
            -32000,
            "rate limit exceeded",
        )),
        Answer::Transport => Err(crate::Error::Transport("connection refused".to_string())),
        Answer::RpcErrorText(_)
        | Answer::RpcErrorData(_)
        | Answer::FailedWith(_)
        | Answer::ForgedAccount(_) => error_answer(answer, id),
        Answer::Unreachable => Err(crate::Error::TransportConnect("no route".to_string())),
        Answer::AskOnce
        | Answer::AskNoState
        | Answer::AskMalformed
        | Answer::AskBig
        | Answer::AskWith(_)
        | Answer::AskBadMeta
        | Answer::AskAndError
        | Answer::AskSecond
        | Answer::AskEdited(_)
        | Answer::StateOnlyRounds(..)
        | Answer::AskThenEcho
        | Answer::AskThenStore => {
            unreachable!("answered above")
        }
        Answer::Text(text) => Ok(JsonRpcResponse::success(
            id,
            json!({"content": [{"type": "text", "text": text}], "isError": false}),
        )),
    }
}

/// The `tools/list` page `answer` scripts for the request carrying `params`.
pub(super) fn listing(answer: Answer, params: Option<&Value>) -> Value {
    let mut result = json!({"tools": [{"name": "read", "inputSchema": {
        "type": "object",
        "properties": {"cmd": {"type": "string"}}
    }}]});
    match answer {
        Answer::WithNote => {
            result["tools"] = json!([
                {"name": "read", "inputSchema": {"type": "object"}},
                {"name": "note", "inputSchema": {"type": "object"}}
            ]);
        }
        Answer::ModernList => {
            result["resultType"] = json!("complete");
            result["ttlMs"] = json!(5000);
            result["cacheScope"] = json!("private");
        }
        Answer::Paged(first, second) => {
            let later = params.and_then(|p| p.get("cursor")).is_some();
            let hint = if later { second } else { first };
            if later {
                result["tools"] = json!([]);
            } else {
                result["nextCursor"] = json!("page-2");
            }
            if let Some(hint) = hint {
                result["ttlMs"] = json!(hint);
            }
        }
        Answer::NonNumeric(hint) => {
            if params.and_then(|p| p.get("cursor")).is_some() {
                result["tools"] = json!([{"name": "later", "inputSchema": {"type": "object"}}]);
                result["ttlMs"] = json!("soon");
            } else {
                result["nextCursor"] = json!("page-2");
                result["ttlMs"] = json!(hint);
            }
        }
        Answer::Unreadable(hint) => {
            if params.and_then(|p| p.get("cursor")).is_some() {
                result["tools"] = json!("not a list");
            } else {
                result["nextCursor"] = json!("page-2");
                if let Some(hint) = hint {
                    result["ttlMs"] = json!(hint);
                }
            }
        }
        _ => {}
    }
    result
}

/// The first string in `value`, or in a JSON document a string carries (a
/// playbook answer is JSON text in `content`), that opens under `fx`'s
/// continuation keyring: the one "find the envelope" oracle the envelope rows
/// share (MIK-8176 cache guards, MIK-8323).
pub(crate) fn envelope_in(fx: &Fx, value: &Value) -> Option<String> {
    match value {
        Value::String(text) => {
            let continuation = fx.state.meta_mcp.continuation();
            if continuation.keyring().open_now(text).is_ok() {
                return Some(text.clone());
            }
            serde_json::from_str::<Value>(text)
                .ok()
                .filter(|inner| !inner.is_string())
                .and_then(|inner| envelope_in(fx, &inner))
        }
        Value::Array(items) => items.iter().find_map(|item| envelope_in(fx, item)),
        Value::Object(fields) => fields.values().find_map(|field| envelope_in(fx, field)),
        _ => None,
    }
}

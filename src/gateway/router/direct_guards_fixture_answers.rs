// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! What the scripted backend answers with, by [`Answer`]: the question an
//! `Ask*` answer opens with, a `tools/call` answer, and a `tools/list` page.
//! Moved out of the shared fixture to keep it under the file-size ceiling.

use serde_json::{Value, json};

use super::Answer;
use super::egress::error_answer;
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
        | Answer::AskAlways
        | Answer::AskEdited(_)
        | Answer::StateOnlyRounds(..)
        | Answer::AskThenEcho => {
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

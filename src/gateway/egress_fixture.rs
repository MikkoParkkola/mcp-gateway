// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A backend for the egress matrix (design `2026-10-08-one-egress-scan.md`,
//! MIK-8139 family): it answers every method in that method's own shape and
//! plants a credential in exactly one frame part of one method's answer, so
//! a table test can walk method x route x part and ask one question of each
//! cell: does the credential reach the client?

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use serde_json::{Value, json};

use crate::protocol::{JsonRpcError, JsonRpcNotification, JsonRpcResponse, RequestId};

/// The planted credential, a token shape the detector blocks by
/// default. Built at run time so no token-shaped literal sits in the source.
pub(crate) fn secret() -> String {
    format!("ghp_{}", "abcdefghijklmnopqrstuvwxyz1234567890")
}

/// The one tool, prompt and resource the backend serves.
pub(crate) const NAME: &str = "read";
/// The resource's URI.
pub(crate) const URI: &str = "mem://read";

/// Where in its answer the backend plants the credential.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Part {
    /// The method's own text: a tool result, a prompt message, a resource
    /// body, a list entry's description.
    ResultText,
    /// A result member no content walker names (`extra.note`).
    ResultLeaf,
    /// A JSON-RPC error's message.
    ErrorMessage,
    /// A JSON-RPC error's `data`.
    ErrorData,
    /// A frame carrying a clean result and an error with the credential.
    MixedError,
    /// A frame carrying an error and a result with the credential.
    MixedResult,
    /// An interim answer whose question carries the credential.
    InterimQuestion,
    /// An interim answer whose `requestState` is the credential.
    InterimState,
    /// A `notifications/progress` streamed before the answer, its `message`
    /// the credential.
    Progress,
    /// A backend-defined notification streamed before the answer.
    CustomNote,
    /// An interim answer whose question carries the credential and whose
    /// `requestState` is the planted text (an envelope stolen from another
    /// exchange). Not in [`Part::ALL`].
    InterimStolenState,
    /// A state-only interim round (`requestState`, no questions) whose
    /// `extra.note` is the planted text (MIK-8177). Not in [`Part::ALL`].
    /// A harmless `notifications/progress` streamed first, then an interim
    /// answer whose question carries the planted text: the answer leaves on
    /// a stream's streaming arm (MIK-8176). Not in [`Part::ALL`].
    ProgressThenQuestion,
    InterimStateOnly,
    /// A parameter name in the tool's input schema: a call with an undeclared
    /// key is refused with a text listing the declared names. Not in
    /// [`Part::ALL`]: the call never reaches the backend.
    SchemaKey,
}

impl Part {
    /// Every part, for a table to iterate.
    pub(crate) const ALL: [Self; 10] = [
        Self::ResultText,
        Self::ResultLeaf,
        Self::ErrorMessage,
        Self::ErrorData,
        Self::MixedError,
        Self::MixedResult,
        Self::InterimQuestion,
        Self::InterimState,
        Self::Progress,
        Self::CustomNote,
    ];

    /// An interim answer exists only for `tools/call`.
    pub(crate) fn applies_to(self, method: &str) -> bool {
        !matches!(self, Self::InterimQuestion | Self::InterimState) || method == "tools/call"
    }

    /// A part streamed as a notification rather than carried in the answer.
    pub(crate) fn is_notification(self) -> bool {
        matches!(self, Self::Progress | Self::CustomNote)
    }
}

/// The methods whose answer is a backend's: the method axis of the matrix.
/// The completeness row checks every dispatcher arm is here or gateway-own.
pub(crate) const BACKEND_METHODS: [&str; 7] = [
    "tools/call",
    "tools/list",
    "prompts/get",
    "prompts/list",
    "resources/read",
    "resources/list",
    "resources/templates/list",
];

/// `method`'s answer in its own shape, carrying `text` where the method
/// carries text.
pub(crate) fn shaped(method: &str, text: &str) -> Value {
    match method {
        "tools/list" => json!({"tools": [{
            "name": NAME,
            "description": text,
            "inputSchema": {"type": "object", "properties": {"cmd": {"type": "string"}}},
            "annotations": {"readOnlyHint": true}
        }]}),
        "prompts/list" => json!({"prompts": [{"name": NAME, "description": text}]}),
        "prompts/get" => json!({"messages": [
            {"role": "user", "content": {"type": "text", "text": text}}
        ]}),
        "resources/list" => json!({"resources": [
            {"uri": URI, "name": NAME, "description": text}
        ]}),
        "resources/templates/list" => json!({"resourceTemplates": [
            {"uriTemplate": "mem://{id}", "name": NAME, "description": text}
        ]}),
        "resources/read" => json!({"contents": [
            {"uri": URI, "mimeType": "text/plain", "text": text}
        ]}),
        _ => json!({"content": [{"type": "text", "text": text}], "isError": false}),
    }
}

fn interim(question: &str, state: &str) -> Value {
    json!({
        "resultType": "input_required",
        "inputRequests": {"k1": {
            "method": "elicitation/create",
            "params": {"message": question, "requestedSchema": {"type": "object"}}
        }},
        "requestState": state
    })
}

fn notification(method: &str, params: Value) -> JsonRpcNotification {
    JsonRpcNotification {
        jsonrpc: "2.0".to_string(),
        method: method.to_string(),
        params: Some(params),
    }
}

/// The backend: `text` planted at `part` in `method`'s answer, every other
/// method answered clean in its own shape. `calls` counts dispatches of
/// `method`.
pub(crate) struct Planted {
    pub(crate) method: &'static str,
    pub(crate) part: Part,
    /// Settable after construction: a cell can plant what only the built
    /// gateway can make (an envelope from its keyring).
    pub(crate) text: std::sync::Mutex<String>,
    pub(crate) calls: Arc<AtomicUsize>,
}

impl Planted {
    /// The credential planted at `part`.
    pub(crate) fn new(method: &'static str, part: Part) -> Self {
        Self::with_text(method, part, secret())
    }

    /// `text` planted at `part`: a harmless text makes a control cell.
    pub(crate) fn with_text(method: &'static str, part: Part, text: String) -> Self {
        Self {
            method,
            part,
            text: std::sync::Mutex::new(text),
            calls: Arc::new(AtomicUsize::new(0)),
        }
    }

    /// The planted text.
    pub(crate) fn text(&self) -> String {
        self.text.lock().expect("planted text").clone()
    }

    /// Plant `text` instead, from now on.
    pub(crate) fn set_text(&self, text: String) {
        *self.text.lock().expect("planted text") = text;
    }

    fn answer(&self, params: Option<&Value>) -> JsonRpcResponse {
        let (id, method, s) = (RequestId::Number(1), self.method, self.text());
        let clean = || shaped(method, "ok");
        let backend_error = |message: &str, data: Option<Value>| JsonRpcError {
            code: -32001,
            message: message.to_string(),
            data,
        };
        match self.part {
            Part::ResultText => JsonRpcResponse::success(id, shaped(method, &s)),
            Part::ResultLeaf => {
                let mut result = clean();
                result["extra"] = json!({"note": s});
                JsonRpcResponse::success(id, result)
            }
            Part::ErrorMessage => JsonRpcResponse::error(Some(id), -32001, s),
            Part::ErrorData => JsonRpcResponse::error_with_data(
                Some(id),
                -32001,
                "backend says no",
                json!({"detail": s}),
            ),
            Part::MixedError => {
                let mut frame = JsonRpcResponse::success(id, clean());
                frame.error = Some(backend_error(&s, None));
                frame
            }
            Part::MixedResult => {
                let mut frame = JsonRpcResponse::error(Some(id), -32001, "backend says no");
                frame.result = Some(shaped(method, &s));
                frame
            }
            Part::InterimQuestion => JsonRpcResponse::success(id, interim(&s, "state-1")),
            Part::InterimState => JsonRpcResponse::success(id, interim("Which account?", &s)),
            Part::Progress => {
                // The gateway's minted token, so the sink maps it back.
                let token = params
                    .and_then(|p| p.pointer("/_meta/progressToken"))
                    .cloned()
                    .unwrap_or_else(|| json!("p1"));
                crate::transport::notification_sink::publish(vec![notification(
                    "notifications/progress",
                    json!({"progressToken": token, "progress": 1, "message": s}),
                )]);
                JsonRpcResponse::success(id, clean())
            }
            Part::ProgressThenQuestion => {
                let token = params
                    .and_then(|p| p.pointer("/_meta/progressToken"))
                    .cloned()
                    .unwrap_or_else(|| json!("p1"));
                crate::transport::notification_sink::publish(vec![notification(
                    "notifications/progress",
                    json!({"progressToken": token, "progress": 1, "message": "working"}),
                )]);
                JsonRpcResponse::success(id, interim(&s, "state-1"))
            }
            Part::SchemaKey => JsonRpcResponse::success(id, clean()),
            Part::InterimStolenState => JsonRpcResponse::success(id, interim(&secret(), &s)),
            Part::InterimStateOnly => JsonRpcResponse::success(
                id,
                json!({"resultType": "input_required", "requestState": "state-1",
                       "extra": {"note": s}}),
            ),
            Part::CustomNote => {
                crate::transport::notification_sink::publish(vec![notification(
                    "notifications/backend_note",
                    json!({"data": s}),
                )]);
                JsonRpcResponse::success(id, clean())
            }
        }
    }
}

#[async_trait::async_trait]
impl crate::transport::Transport for Planted {
    async fn request(&self, method: &str, params: Option<Value>) -> crate::Result<JsonRpcResponse> {
        if self.part == Part::SchemaKey && method == "tools/list" {
            let mut list = shaped(method, "ok");
            list["tools"][0]["inputSchema"]["properties"][self.text().as_str()] =
                json!({"type": "string"});
            return Ok(JsonRpcResponse::success(RequestId::Number(1), list));
        }
        if method != self.method {
            return Ok(JsonRpcResponse::success(
                RequestId::Number(1),
                shaped(method, "ok"),
            ));
        }
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(self.answer(params.as_ref()))
    }

    async fn notify(&self, _method: &str, _params: Option<Value>) -> crate::Result<()> {
        Ok(())
    }

    fn is_connected(&self) -> bool {
        true
    }

    async fn close(&self) -> crate::Result<()> {
        Ok(())
    }
}

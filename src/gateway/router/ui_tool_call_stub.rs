// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The fake backend behind the Try-a-tool rows: a fixed tool list, and a scripted reply for each tool.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use serde_json::{Value, json};

use crate::protocol::{JsonRpcResponse, RequestId};
use crate::transport::Transport;

/// The longest `slow` holds its answer for a gate that never opens. Kept here,
/// not beside the rows, because this file compiles in every test part.
pub(super) const SLOW_GATE_BOUND: Duration = Duration::from_secs(5);

/// A backend whose `tools/list` declares `read`, `fail` and `iserr`
/// read-only and leaves `write` and `get_x` undeclared, counting every call.
pub(super) struct Stub {
    pub(super) calls: Arc<AtomicUsize>,
    /// Declare `read` read-only (false: a replacement that does not).
    pub(super) declares_read: bool,
    /// `tools/list` waits for this, when set: a cold catalogue is filled
    /// before the gate, so a test holds a call there for as long as it likes.
    pub(super) list_gate: Option<Arc<tokio::sync::Notify>>,
    /// Signalled (one stored permit) as `tools/list` starts waiting on
    /// `list_gate`, so a row can time a stall from inside the call.
    pub(super) list_entered: Option<Arc<tokio::sync::Notify>>,
    /// When set, `slow` answers only once this is signalled (or after
    /// [`SLOW_GATE_BOUND`]); unset, it answers after 400 ms.
    pub(super) slow_gate: Option<Arc<tokio::sync::Notify>>,
}

#[async_trait::async_trait]
impl Transport for Stub {
    async fn request(&self, method: &str, params: Option<Value>) -> crate::Result<JsonRpcResponse> {
        let id = RequestId::Number(1);
        if method == "tools/list" {
            if let Some(gate) = &self.list_gate {
                if let Some(entered) = &self.list_entered {
                    entered.notify_one();
                }
                gate.notified().await;
            }
            let ro = json!({"readOnlyHint": true});
            let read = if self.declares_read {
                ro.clone()
            } else {
                json!({})
            };
            let tool = |name: &str, annotations: &Value| json!({"name": name, "inputSchema": {"type": "object"}, "annotations": annotations});
            return Ok(JsonRpcResponse::success(
                id,
                json!({"tools": [
                    tool("read", &read),
                    tool("fail", &ro),
                    tool("iserr", &ro),
                    tool("slow", &ro),
                    tool("ask", &ro),
                    tool("flaky", &ro),
                    tool("write", &json!({})),
                    tool("get_x", &json!({})),
                ]}),
            ));
        }
        self.calls.fetch_add(1, Ordering::SeqCst);
        let name = params
            .as_ref()
            .and_then(|p| p["name"].as_str())
            .unwrap_or_default()
            .to_owned();
        match name.as_str() {
            // A tool that stops to ask the user a question (elicitation).
            "ask" => Ok(JsonRpcResponse::success(
                id,
                json!({
                    "resultType": "input_required",
                    "inputRequests": {"k1": {
                        "method": "elicitation/create",
                        "params": {"message": "Which account?", "requestedSchema": {"type": "object"}},
                    }},
                    "requestState": "backend-state-1",
                }),
            )),
            "slow" => {
                match &self.slow_gate {
                    // Bounded, so a row whose deadline never fires gets its
                    // answer (and fails its 504 check) instead of hanging.
                    Some(gate) => {
                        let _ = tokio::time::timeout(SLOW_GATE_BOUND, gate.notified()).await;
                    }
                    None => {
                        tokio::time::sleep(Duration::from_millis(400)).await;
                    }
                }
                Ok(JsonRpcResponse::success(
                    id,
                    json!({"content": [{"type": "text", "text": "late"}], "isError": false}),
                ))
            }
            // Times out once (the request may have reached it), then cannot be
            // reached: a retry that ends in a connect failure.
            "flaky" if self.calls.load(Ordering::SeqCst) == 1 => {
                Err(crate::Error::BackendTimeout("stub timed out".into()))
            }
            "flaky" => Err(crate::Error::TransportConnect("stub unreachable".into())),
            "fail" => Err(crate::Error::BackendTimeout("stub timed out".into())),
            "iserr" => Ok(JsonRpcResponse::success(
                id,
                json!({"content": [{"type": "text", "text": "no"}], "isError": true}),
            )),
            _ => Ok(JsonRpcResponse::success(
                id,
                json!({"content": [{"type": "text", "text": "done"}], "isError": false}),
            )),
        }
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

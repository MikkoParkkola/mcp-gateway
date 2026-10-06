// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! What a backend receives as `_meta.prompt_cache_key` from `gateway_invoke`
//! (MIK-7652, MIK-7639): a key is derived only from a real session id, and a
//! caller's own key is forwarded as it was sent.

use std::sync::Arc;

use serde_json::{Value, json};

use crate::gateway::authz::AllowAll;
use crate::gateway::meta_mcp::MetaMcp;
use crate::gateway::meta_mcp::authz_tests::ctx;
use crate::protocol::{JsonRpcResponse, RequestId};

/// A backend keeping every `tools/call` params it received.
struct Seen(Arc<parking_lot::Mutex<Vec<Value>>>);

#[async_trait::async_trait]
impl crate::transport::Transport for Seen {
    async fn request(&self, method: &str, params: Option<Value>) -> crate::Result<JsonRpcResponse> {
        let id = RequestId::Number(1);
        if method == "tools/list" {
            let tool = json!({"name": "ask", "inputSchema": {"type": "object"}});
            return Ok(JsonRpcResponse::success(id, json!({"tools": [tool]})));
        }
        self.0.lock().push(params.unwrap_or(Value::Null));
        let answer = json!({"content": [{"type": "text", "text": "ok"}], "isError": false});
        Ok(JsonRpcResponse::success(id, answer))
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

/// The `_meta.prompt_cache_key` the backend received for one `gateway_invoke`
/// with `call` as its arguments and `session_id` as the caller's session.
async fn forwarded_key(call: Value, session_id: Option<&str>) -> Option<Value> {
    let registry = Arc::new(crate::backend::BackendRegistry::new());
    let backend = Arc::new(crate::backend::Backend::new(
        "llm",
        crate::config::BackendConfig::default(),
        &crate::config::FailsafeConfig::default(),
        std::time::Duration::from_secs(60),
    ));
    let seen = Arc::new(parking_lot::Mutex::new(Vec::new()));
    backend.set_transport_for_test(Arc::new(Seen(Arc::clone(&seen))));
    assert!(registry.register(backend));
    let meta = MetaMcp::new(registry);
    meta.invoke_tool(&call, session_id, &ctx(&AllowAll))
        .await
        .expect("the call reaches the backend");
    let seen = seen.lock().clone();
    assert_eq!(seen.len(), 1, "{seen:?}");
    seen[0].pointer("/_meta/prompt_cache_key").cloned()
}

fn plain_call() -> Value {
    json!({"server": "llm", "tool": "ask", "arguments": {"q": "hi"}})
}

/// A session-less call (no session id, or the empty one a 2026-07-28 caller
/// has) forwards no derived key. A real session does, so the capture is shown
/// to see one when it is there.
#[tokio::test]
async fn a_sessionless_call_forwards_no_derived_prompt_cache_key() {
    for session in [None, Some("")] {
        assert_eq!(
            forwarded_key(plain_call(), session).await,
            None,
            "session {session:?}"
        );
    }
    assert!(
        forwarded_key(plain_call(), Some("session-1"))
            .await
            .is_some_and(|key| key.is_string()),
        "control: a real session derives a key"
    );
}

/// A caller's own `_meta.prompt_cache_key` is forwarded as sent (within the
/// 64-character limit `CacheKeyDeriver::from_header` truncates to), with or
/// without a session.
#[tokio::test]
async fn an_explicit_prompt_cache_key_is_forwarded() {
    let call = json!({
        "server": "llm",
        "tool": "ask",
        "arguments": {"q": "hi"},
        "_meta": {"prompt_cache_key": "caller-chosen-key"}
    });
    for session in [None, Some("session-1")] {
        assert_eq!(
            forwarded_key(call.clone(), session).await,
            Some(json!("caller-chosen-key")),
            "session {session:?}"
        );
    }
}

// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8392 STORED.1 review findings F1, F2 (shared) and F5 on the shared
//! catalogue: a removed backend, a stale shared catalogue past its TTL, and
//! a cleared cache.

use super::*;

/// F1 (MIK-8392): the backend is removed after the task ran. The live call
/// answers a tool result with isError ("Backend not found: ..."); a task read
/// cannot carry a tool result, so it answers BackendNotFound (-32001) with the
/// live call's own text, and never the stored output (lead ruling 2026-10-12).
/// Red without the fix: the read judged only policy and served the output.
#[tokio::test]
async fn f1_a_removed_backend_answers_the_live_refusal_as_an_error() {
    let mock = MockBackend::answering(Answer::ok());
    let (state, _store) = state_with(&mock).await;
    let id = finished(&state, "s1-f1").await;
    assert!(state.backends.remove(BACKEND), "premise: removed");
    let live = post(&state, "key-a", sync_invoke(9, json!({ "q": 1 }))).await;
    // The live gateway_invoke answers a tool result with isError; a task read
    // cannot carry a tool result, so it answers the same refusal as the
    // JSON-RPC error BackendNotFound (-32001) carrying the live call's own
    // text (lead ruling 2026-10-12).
    std::assert_eq!(
        live.pointer("/result/isError"),
        Some(&json!(true)),
        "premise: the live call is refused: {live}"
    );
    let envelope: Value = live
        .pointer("/result/content/0/text")
        .and_then(Value::as_str)
        .and_then(|text| serde_json::from_str(text).ok())
        .unwrap_or_else(|| panic!("premise: the live refusal carries its envelope: {live}"));
    let live_text = envelope
        .pointer("/content/0/text")
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("premise: the live refusal carries its text: {live}"))
        .to_owned();
    let stored = get_task(&state, "key-a", &id).await;
    std::assert_eq!(
        stored.pointer("/error/code"),
        Some(&json!(-32001)),
        "F1: the stored read answers BackendNotFound: {stored}"
    );
    std::assert_eq!(
        stored.pointer("/error/message").and_then(Value::as_str),
        Some(live_text.as_str()),
        "F1: the stored read carries the live call's own text: {stored}"
    );
    assert!(
        stored.pointer("/result").is_none()
            && !stored.to_string().contains("mock-backend-answered"),
        "F1: no stored output: {stored}"
    );
}

/// F5 (MIK-8392): a cleared shared cache (no cached value, ever populated)
/// reads as retryable — never complete-and-empty (-32601) and never served
/// — until a fill stores again. Red without the fix: the read answers
/// -32601 permanently.
#[tokio::test]
async fn f5_a_cleared_catalogue_answers_retryable_until_refilled() {
    let mock = MockBackend::answering(Answer::ok());
    let (state, _store) = state_with(&mock).await;
    let id = finished(&state, "s1-f5").await;
    backend(&state).empty_tool_catalogues_for_test();
    let read = get_task(&state, "key-a", &id).await;
    std::assert_eq!(
        read.pointer("/error/code"),
        Some(&json!(-32603)),
        "F5: retryable, not -32601: {read}"
    );
    std::assert_eq!(
        read.pointer("/error/data/retryable"),
        Some(&json!(true)),
        "F5: {read}"
    );
    assert!(
        !read.to_string().contains("mock-backend-answered"),
        "F5: no output: {read}"
    );
    let tool: crate::protocol::Tool = serde_json::from_value(json!({
        "name": TOOL, "description": "Reads.", "inputSchema": {"type": "object"}
    }))
    .expect("a tool");
    backend(&state).store_shared_tools_for_test(vec![tool]);
    assert_carries_the_backend_result(&get_task(&state, "key-a", &id).await);
}

/// A shared upstream whose `tools/list` the row controls (MIK-8392 F2).
struct Listing {
    tools: std::sync::Mutex<Value>,
    lists: std::sync::atomic::AtomicUsize,
}

impl Listing {
    fn with(tools: Value) -> std::sync::Arc<Self> {
        std::sync::Arc::new(Self {
            tools: std::sync::Mutex::new(tools),
            lists: std::sync::atomic::AtomicUsize::new(0),
        })
    }
}

#[async_trait::async_trait]
impl crate::transport::Transport for Listing {
    async fn request(
        &self,
        method: &str,
        _params: Option<Value>,
    ) -> crate::Result<crate::protocol::JsonRpcResponse> {
        match method {
            "initialize" => Ok(crate::protocol::JsonRpcResponse::success(
                crate::protocol::RequestId::Number(1),
                json!({
                    "protocolVersion": "2025-06-18",
                    "capabilities": { "tools": {} },
                    "serverInfo": { "name": "listing", "version": "0" }
                }),
            )),
            "tools/list" => {
                self.lists.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                let tools = self
                    .tools
                    .lock()
                    .expect("listing is never poisoned")
                    .clone();
                Ok(crate::protocol::JsonRpcResponse::success(
                    crate::protocol::RequestId::Number(1),
                    json!({ "tools": tools }),
                ))
            }
            _ => Ok(crate::protocol::JsonRpcResponse::success(
                crate::protocol::RequestId::Number(1),
                json!({}),
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

/// F2 shared (MIK-8392): within the TTL a withdrawn shared tool still
/// serves (the documented residual); past the TTL the read refreshes from
/// the upstream that withdrew it and answers -32601. Red without the fix:
/// the stale list serves forever.
#[tokio::test]
async fn f2_a_stale_shared_catalogue_refreshes_past_its_ttl() {
    let mock = MockBackend::answering(Answer::ok());
    let (state, _store) = state_with(&mock).await;
    let id = finished(&state, "s1-f2s").await;
    assert!(
        backend(&state).get_cached_tool_for(None, TOOL).is_some(),
        "premise: the shared slot holds the tool"
    );
    // The tool is withdrawn upstream; the fresh cache still serves it, and
    // no refresh lists the upstream.
    let upstream = Listing::with(json!([]));
    backend(&state).set_transport_for_test(
        std::sync::Arc::clone(&upstream) as std::sync::Arc<dyn crate::transport::Transport>
    );
    assert_carries_the_backend_result(&get_task(&state, "key-a", &id).await);
    std::assert_eq!(
        upstream.lists.load(std::sync::atomic::Ordering::SeqCst),
        0,
        "F2: within the TTL no refresh lists the upstream"
    );
    // Past the TTL the read refreshes and the withdrawn tool is absent.
    backend(&state).age_tools_cache_for_test(None, 400);
    let read = get_task(&state, "key-a", &id).await;
    std::assert_eq!(
        read.pointer("/error/code"),
        Some(&json!(-32601)),
        "F2: refreshed, the withdrawn tool is absent: {read}"
    );
    assert!(
        !read.to_string().contains("mock-backend-answered"),
        "F2: no output: {read}"
    );
    assert!(
        upstream.lists.load(std::sync::atomic::Ordering::SeqCst) >= 1,
        "F2: the refresh listed the upstream"
    );
}

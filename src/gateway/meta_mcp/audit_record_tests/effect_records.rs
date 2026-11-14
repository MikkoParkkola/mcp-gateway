// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A dispatched call's record carries the effect the tool declared, read
//! from the slot a real `tools/list` filled, never inferred from the name.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use serde_json::{Value, json};

use super::{api_key_caller, context, meta, ok_result, records};
use crate::gateway::authz::AllowAll;
use crate::gateway::meta_mcp::MetaMcp;
use crate::protocol::{JsonRpcResponse, RequestId};

/// A backend listing one tool `read` whose `readOnlyHint` is `hint`, and
/// answering every call; `calls` counts the calls that reached it.
struct Listing {
    hint: Option<bool>,
    calls: Arc<AtomicUsize>,
}

#[async_trait::async_trait]
impl crate::transport::Transport for Listing {
    async fn request(
        &self,
        method: &str,
        _params: Option<Value>,
    ) -> crate::Result<JsonRpcResponse> {
        let result = if method == "tools/list" {
            let mut tool = json!({"name": "read", "inputSchema": {"type": "object"}});
            if let Some(hint) = self.hint {
                tool["annotations"] = json!({"readOnlyHint": hint});
            }
            json!({"tools": [tool]})
        } else {
            self.calls.fetch_add(1, Ordering::SeqCst);
            ok_result()
        };
        Ok(JsonRpcResponse::success_serialized(
            RequestId::Number(1),
            result,
        ))
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

/// `meta` whose backend `alpha` lists `read` with `hint`, from a cold slot.
pub(super) fn listing(hint: Option<bool>, dir: &tempfile::TempDir) -> (MetaMcp, Arc<AtomicUsize>) {
    let meta = meta(Ok(ok_result()), dir);
    let calls = Arc::new(AtomicUsize::new(0));
    let alpha = meta.backends.for_test().get("alpha").expect("alpha");
    alpha.set_transport_for_test(Arc::new(Listing {
        hint,
        calls: Arc::clone(&calls),
    }));
    (meta, calls)
}

async fn call(meta: &MetaMcp, retry: &crate::protocol::mrtr::RetryFields) {
    let who = api_key_caller();
    let caller = crate::gateway::meta_mcp::MetaMcpCallerContext {
        retry,
        ..context(&AllowAll, &who)
    };
    let args = json!({"server": "alpha", "tool": "read", "arguments": {}});
    let _ = meta.invoke_tool(&args, None, &caller).await;
}

/// The decision of the one record a call to `read` writes.
async fn decision_after(hint: Option<bool>) -> Value {
    let dir = crate::test_dir_keep::kept_tempdir();
    let (meta, _) = listing(hint, &dir);
    call(&meta, &crate::protocol::mrtr::NO_RETRY).await;
    let all = records(&dir);
    assert_eq!(all.len(), 1, "{all:?}");
    all[0]["decision"].clone()
}

#[tokio::test]
async fn a_declared_read_only_tool_records_read_only_from_the_tool() {
    let d = decision_after(Some(true)).await;
    assert_eq!(d["declared_effect"], "read_only", "{d}");
    assert_eq!(d["declared_effect_source"], "tool_annotation", "{d}");
}

#[tokio::test]
async fn a_tool_declaring_read_only_false_records_may_write() {
    let d = decision_after(Some(false)).await;
    assert_eq!(d["declared_effect"], "may_write", "{d}");
    assert_eq!(d["declared_effect_source"], "tool_annotation", "{d}");
}

#[tokio::test]
async fn a_tool_with_no_hint_records_undeclared() {
    let d = decision_after(None).await;
    assert_eq!(d["declared_effect"], "undeclared", "{d}");
}

#[tokio::test]
async fn a_response_cache_hit_records_its_admissions_effect() {
    let dir = crate::test_dir_keep::kept_tempdir();
    let (mut meta, calls) = listing(Some(true), &dir);
    meta.cache = Some(Arc::new(crate::cache::ResponseCache::new()));
    meta.default_cache_ttl = Duration::from_secs(300);
    for _ in 0..2 {
        call(&meta, &crate::protocol::mrtr::NO_RETRY).await;
    }
    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "the second call was not a hit"
    );
    let all = records(&dir);
    assert_eq!(all.len(), 2, "{all:?}");
    let hit = &all[1]["decision"];
    assert_eq!(hit["decided"], "cache_hit_not_redecided", "{hit}");
    assert_eq!(hit["declared_effect"], "read_only", "{hit}");
    assert_eq!(hit["declared_effect_source"], "tool_annotation", "{hit}");
}

/// A replay can stand in for a stored write, so it records what the slot
/// declares now: read-only once relisted so, nothing once the list is gone.
#[tokio::test]
async fn an_idempotency_replay_takes_the_live_lookup() {
    let dir = crate::test_dir_keep::kept_tempdir();
    let (mut meta, calls) = listing(Some(false), &dir);
    meta.enable_idempotency(
        Arc::new(crate::idempotency::IdempotencyCache::new()),
        Duration::from_secs(300),
    );
    let retry = crate::protocol::mrtr::RetryFields {
        input_responses: None,
        request_state: None,
        idempotency_key: Some("live-lookup".to_string()),
        malformed: Vec::new(),
        attestation: None,
    };
    let alpha = meta.backends.for_test().get("alpha").expect("alpha");
    call(&meta, &retry).await;
    // Relisted read-only, as an accepted fill would store it.
    let read_only: crate::protocol::Tool = serde_json::from_value(json!({
        "name": "read", "inputSchema": {"type": "object"},
        "annotations": {"readOnlyHint": true}
    }))
    .expect("tool");
    alpha.prefill_tools_for_test(vec![read_only]);
    alpha.set_read_only_declared_for_test(&["read"]);
    call(&meta, &retry).await;
    // Then listed no more.
    alpha.prefill_tools_for_test(Vec::new());
    alpha.set_read_only_declared_for_test(&[]);
    call(&meta, &retry).await;
    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "a replay reached the backend"
    );
    let all = records(&dir);
    assert_eq!(all.len(), 3, "{all:?}");
    let effects: Vec<&Value> = all
        .iter()
        .map(|r| &r["decision"]["declared_effect"])
        .collect();
    assert_eq!(
        effects,
        [&json!("may_write"), &json!("read_only"), &Value::Null],
        "{all:?}"
    );
    assert_eq!(all[1]["decision"]["decided"], "replayed", "{all:?}");
}

/// A capability's effect is its definition's `read_only`, and says so.
#[tokio::test]
async fn a_capability_tool_records_its_definitions_effect() {
    for (read_only, effect) in [(true, "read_only"), (false, "may_write")] {
        let dir = crate::test_dir_keep::kept_tempdir();
        let meta = meta(Ok(ok_result()), &dir);
        let definition = crate::capability::parse_capability(&format!(
            "name: lookup\n\
             description: Look one thing up\n\
             metadata:\n\
             \x20 exposure: public\n\
             \x20 read_only: {read_only}\n\
             providers:\n\
             \x20 primary:\n\
             \x20   service: rest\n\
             \x20   config:\n\
             \x20     base_url: http://127.0.0.1:9\n\
             \x20     path: /lookup\n\
             \x20     method: GET\n"
        ))
        .expect("the capability parses");
        let executor = Arc::new(crate::capability::CapabilityExecutor::new());
        let caps = Arc::new(crate::capability::CapabilityBackend::new("caps", executor));
        caps.register_capability(definition).expect("registers");
        meta.set_capabilities(caps);
        let who = api_key_caller();
        let args = json!({"server": "caps", "tool": "lookup", "arguments": {}});
        let _ = meta
            .invoke_tool(&args, None, &context(&AllowAll, &who))
            .await;
        let all = records(&dir);
        assert_eq!(all.len(), 1, "{all:?}");
        let d = &all[0]["decision"];
        assert_eq!(d["declared_effect"], effect, "{d}");
        assert_eq!(d["declared_effect_source"], "capability_definition", "{d}");
    }
}

/// A response-cache hit on a capability keeps its definition's effect and
/// says so, as the backend hit keeps the tool's.
#[tokio::test]
async fn a_capability_cache_hit_records_its_definitions_effect() {
    let hits = Arc::new(AtomicUsize::new(0));
    let counted = Arc::clone(&hits);
    let app = axum::Router::new().route(
        "/lookup",
        axum::routing::get(move || {
            counted.fetch_add(1, Ordering::SeqCst);
            async { axum::Json(json!({"value": "ok"})) }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind the endpoint");
    let port = listener.local_addr().expect("its address").port();
    tokio::spawn(async move { drop(axum::serve(listener, app).await) });
    let base_url = crate::test_fixture_host::fixture_url(port);
    let definition = crate::capability::parse_capability(&format!(
        "name: lookup\n\
         description: Look one thing up\n\
         metadata:\n\
         \x20 exposure: public\n\
         \x20 read_only: true\n\
         providers:\n\
         \x20 primary:\n\
         \x20   service: rest\n\
         \x20   config:\n\
         \x20     base_url: {base_url}\n\
         \x20     path: /lookup\n\
         \x20     method: GET\n"
    ))
    .expect("the capability parses");
    let client = crate::test_fixture_host::fixture_client(Duration::from_secs(5));
    let executor =
        Arc::new(crate::capability::CapabilityExecutor::new().with_test_http_client(client));
    let caps = Arc::new(crate::capability::CapabilityBackend::new("caps", executor));
    caps.register_capability(definition).expect("registers");
    let dir = crate::test_dir_keep::kept_tempdir();
    let mut meta = meta(Ok(ok_result()), &dir);
    meta.set_capabilities(caps);
    meta.cache = Some(Arc::new(crate::cache::ResponseCache::new()));
    meta.default_cache_ttl = Duration::from_secs(300);
    let who = api_key_caller();
    let args = json!({"server": "caps", "tool": "lookup", "arguments": {}});
    for _ in 0..2 {
        let _ = meta
            .invoke_tool(&args, None, &context(&AllowAll, &who))
            .await;
    }
    assert_eq!(
        hits.load(Ordering::SeqCst),
        1,
        "premise: the second call was a hit"
    );
    let all = records(&dir);
    assert_eq!(all.len(), 2, "{all:?}");
    let hit = &all[1]["decision"];
    assert_eq!(hit["decided"], "cache_hit_not_redecided", "{hit}");
    assert_eq!(hit["declared_effect"], "read_only", "{hit}");
    assert_eq!(
        hit["declared_effect_source"], "capability_definition",
        "{hit}"
    );
}

/// A completed-execution replay that carries no named target and no stored
/// slot records `replayed` and no declared effect, even where the slot holds
/// evidence: recording nothing beats reading a slot it did not run under.
/// The replays that carry both are pinned in `replay_effects`.
#[tokio::test]
async fn a_replay_with_no_stored_facts_records_no_declared_effect() {
    let dir = crate::test_dir_keep::kept_tempdir();
    let (meta, _) = listing(Some(true), &dir);
    call(&meta, &crate::protocol::mrtr::NO_RETRY).await;
    let alpha = meta.backends.for_test().get("alpha").expect("alpha");
    assert_eq!(
        alpha.declared_effect_for(None, "read"),
        Some(crate::security::decision_record::Effect::ReadOnly),
        "premise: the slot holds evidence"
    );
    let who = api_key_caller();
    let replay = JsonRpcResponse::success(RequestId::Number(7), ok_result());
    let _ = meta
        .audit_replay(
            "gateway_invoke",
            &json!({"server": "alpha", "tool": "read", "arguments": {}}),
            None,
            &context(&AllowAll, &who),
            replay,
            crate::gateway::meta_mcp::admission::ReplayFacts::default(),
        )
        .await;
    let all = records(&dir);
    assert_eq!(all.len(), 2, "{all:?}");
    let d = &all[1]["decision"];
    assert_eq!(d["decided"], "replayed", "{d}");
    assert!(d.get("declared_effect").is_none(), "{d}");
    assert!(d.get("declared_effect_source").is_none(), "{d}");
}

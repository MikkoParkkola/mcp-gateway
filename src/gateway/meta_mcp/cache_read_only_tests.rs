// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8393 (from #3773, terafin): the response cache may stand in for a call
//! only where the backend declared the tool read-only.
//!
//! Serving a cached result skips the call. Where the call has an effect, the
//! caller is told it happened and it did not — email left unread behind a
//! "Successfully marked as read". So the gate is the backend's own
//! `readOnlyHint`, and an undeclared tool is never cached.
//!
//! Every case counts backend calls, and the read-only case is the control:
//! without it, "the second call reached the backend" is also satisfied by a
//! cache that stores nothing at all.

use std::sync::atomic::{AtomicUsize, Ordering};

use super::*;

/// Answers `tools/list` from `tools` (swappable, so a case can relist), and
/// counts `tools/call` — the only evidence a cache hit did not reach the backend.
struct AnnotatedToolsTransport {
    tools: Arc<parking_lot::Mutex<serde_json::Value>>,
    calls: Arc<AtomicUsize>,
}

#[async_trait::async_trait]
impl crate::transport::Transport for AnnotatedToolsTransport {
    async fn request(
        &self,
        method: &str,
        _params: Option<serde_json::Value>,
    ) -> crate::Result<crate::protocol::JsonRpcResponse> {
        match method {
            "tools/list" => Ok(crate::protocol::JsonRpcResponse::success_serialized(
                RequestId::Number(1),
                json!({ "tools": self.tools.lock().clone() }),
            )),
            "tools/call" => {
                self.calls.fetch_add(1, Ordering::SeqCst);
                Ok(crate::protocol::JsonRpcResponse::success_serialized(
                    RequestId::Number(1),
                    json!({"content": [{"type": "text", "text": "ok"}], "isError": false}),
                ))
            }
            other => panic!("unexpected method {other}"),
        }
    }

    async fn notify(&self, _method: &str, _params: Option<serde_json::Value>) -> crate::Result<()> {
        Ok(())
    }

    fn is_connected(&self) -> bool {
        true
    }

    async fn close(&self) -> crate::Result<()> {
        Ok(())
    }
}

struct Fixture {
    registry: Arc<crate::backend::BackendRegistry>,
    backend: Arc<crate::backend::Backend>,
    tools: Arc<parking_lot::Mutex<serde_json::Value>>,
    calls: Arc<AtomicUsize>,
}

fn listing(tool: &str, annotations: &serde_json::Value) -> serde_json::Value {
    json!([{
        "name": tool,
        "description": "the tool under test",
        "inputSchema": {"type": "object"},
        "annotations": annotations,
    }])
}

/// A backend serving one tool named `tool`, carrying `annotations`. With
/// `discover`, its `tools/list` has been read, as it is ahead of every call in
/// production: that read is what records the declaration.
async fn backend(
    server: &str,
    tool: &str,
    annotations: serde_json::Value,
    discover: bool,
) -> Fixture {
    use crate::backend::Backend;
    use crate::config::{BackendConfig, FailsafeConfig, InputSchemaEnforcement};

    let registry = Arc::new(crate::backend::BackendRegistry::new());
    let calls = Arc::new(AtomicUsize::new(0));
    let tools = Arc::new(parking_lot::Mutex::new(listing(tool, &annotations)));
    // Enforcement off: nothing lists a cold slot ahead of the cache gate, so
    // an undiscovered backend stays undiscovered (F13 would fill it otherwise).
    let config = BackendConfig {
        input_schema_enforcement: InputSchemaEnforcement::Off,
        ..BackendConfig::default()
    };
    let backend = Arc::new(Backend::new(
        server,
        config,
        &FailsafeConfig::default(),
        Duration::from_secs(300),
    ));
    let transport: Arc<dyn crate::transport::Transport> = Arc::new(AnnotatedToolsTransport {
        tools: Arc::clone(&tools),
        calls: Arc::clone(&calls),
    });
    backend.set_transport_for_test(transport);
    let _ = registry.register(Arc::clone(&backend));
    if discover {
        backend
            .get_tools_shared()
            .await
            .expect("tools/list must answer");
    }
    Fixture {
        registry,
        backend,
        tools,
        calls,
    }
}

impl Fixture {
    fn meta(&self) -> MetaMcp {
        MetaMcp::with_features(
            Arc::clone(&self.registry),
            Some(Arc::new(crate::cache::ResponseCache::new())),
            None,
            None,
            Duration::from_secs(300),
        )
    }

    /// The backend relists the tool with new annotations, and the gateway
    /// re-reads the list through the production invalidation path.
    async fn relist(&self, tool: &str, annotations: serde_json::Value) {
        *self.tools.lock() = listing(tool, &annotations);
        self.backend.invalidate_tools();
        self.backend.get_tools_shared().await.expect("relist");
    }

    fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }
}

async fn invoke(meta: &MetaMcp, server: &str, tool: &str) {
    let _ = meta
        .invoke_tool(
            &json!({"server": server, "tool": tool, "arguments": {}}),
            Some("session-1"),
            &allow_all_ctx_named(Some("alice"), None),
        )
        .await;
}

const READ_ONLY: &str =
    r#"{"readOnlyHint": true, "idempotentHint": true, "destructiveHint": false}"#;
const IDEMPOTENT_WRITE: &str =
    r#"{"readOnlyHint": false, "idempotentHint": true, "destructiveHint": false}"#;

fn ann(text: &str) -> serde_json::Value {
    serde_json::from_str(text).expect("fixture json")
}

/// R1, the control: a declared read-only tool's second call is a hit. Driven
/// by a real `tools/list` fill, so a fill that never records the declaration
/// fails here.
#[tokio::test]
async fn a_declared_read_only_tool_is_served_from_cache() {
    let fx = backend("docs", "search", ann(READ_ONLY), true).await;
    let meta = fx.meta();
    invoke(&meta, "docs", "search").await;
    invoke(&meta, "docs", "search").await;
    assert_eq!(
        fx.calls(),
        1,
        "a declared read-only tool may be served from cache"
    );
}

/// R2, the reported bug: `mark_emails_as_read` declares `idempotentHint: true`
/// with `readOnlyHint: false`. A cache hit is not a retry — the call does not
/// run at all — so retry permission must not be enough to cache it.
#[tokio::test]
async fn an_idempotent_write_is_never_served_from_cache() {
    let fx = backend("mail", "mark_emails_as_read", ann(IDEMPOTENT_WRITE), true).await;
    let meta = fx.meta();
    invoke(&meta, "mail", "mark_emails_as_read").await;
    invoke(&meta, "mail", "mark_emails_as_read").await;
    assert_eq!(
        fx.calls(),
        2,
        "an idempotent write must reach the backend on every call"
    );
}

/// R3: undeclared denies, and the declaration decides, not the name:
/// `get_status` is read-only by inference, and the backend never said so.
#[tokio::test]
async fn an_untagged_tool_is_not_cached_even_when_its_name_reads_as_a_getter() {
    let fx = backend("unlabelled", "get_status", json!(null), true).await;
    let meta = fx.meta();
    invoke(&meta, "unlabelled", "get_status").await;
    invoke(&meta, "unlabelled", "get_status").await;
    assert_eq!(fx.calls(), 2, "a name inference is not a declaration");
}

/// R4: an undiscovered backend declares nothing, so nothing it serves is
/// cached. Enforcement is off, so nothing lists the slot before the gate.
#[tokio::test]
async fn an_undiscovered_backend_caches_nothing() {
    let fx = backend("later", "search", ann(READ_ONLY), false).await;
    let meta = fx.meta();
    invoke(&meta, "later", "search").await;
    invoke(&meta, "later", "search").await;
    assert_eq!(
        fx.calls(),
        2,
        "with no discovery there is no declaration to trust"
    );
}

/// R9, the lookup gate: call 1 stores while the tool is read-only; the
/// backend then relists it as a write. The entry is still in the cache, so
/// only a gated lookup sends call 2 to the backend.
#[tokio::test]
async fn a_tool_relisted_as_a_write_is_not_served_its_cached_answer() {
    let fx = backend("docs", "toggle", ann(READ_ONLY), true).await;
    let meta = fx.meta();
    invoke(&meta, "docs", "toggle").await;
    assert_eq!(
        fx.calls(),
        1,
        "premise: call 1 reached the backend and stored"
    );
    fx.relist("toggle", ann(IDEMPOTENT_WRITE)).await;
    assert!(
        !fx.backend.is_read_only_for(None, "toggle"),
        "premise: the relist revoked"
    );
    invoke(&meta, "docs", "toggle").await;
    assert_eq!(
        fx.calls(),
        2,
        "a cached answer served a tool now declared a write"
    );
}

/// R10, the store gate: call 1 runs while the tool is a write, then the
/// backend relists it read-only. Only an ungated store would have kept call
/// 1's answer for call 2 to hit.
#[tokio::test]
async fn a_write_answer_is_never_stored() {
    let fx = backend("docs", "toggle", ann(IDEMPOTENT_WRITE), true).await;
    let meta = fx.meta();
    invoke(&meta, "docs", "toggle").await;
    assert_eq!(fx.calls(), 1, "premise: call 1 reached the backend");
    fx.relist("toggle", ann(READ_ONLY)).await;
    assert!(
        fx.backend.is_read_only_for(None, "toggle"),
        "premise: the relist re-admitted, so only a stored entry could make call 2 a hit"
    );
    invoke(&meta, "docs", "toggle").await;
    assert_eq!(
        fx.calls(),
        2,
        "a write's answer was stored and later served"
    );
}

// --- The capability route (r3/r5: the capability's own `read_only`) ---------

/// A capability `name` on the capability backend `capabilities`, reached at a
/// counting fixture-host endpoint. No `cache:` block, so the executor's own
/// cache is off and any hit is the outer response cache's (r4, muse H2).
async fn counting_capability(meta: &MetaMcp, name: &str, metadata: &str) -> Arc<AtomicUsize> {
    let hits = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&hits);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let port = listener.local_addr().expect("addr").port();
    tokio::spawn(async move {
        let app = axum::Router::new().route(
            "/probe",
            axum::routing::get(move || {
                let counter = Arc::clone(&counter);
                async move {
                    counter.fetch_add(1, Ordering::SeqCst);
                    axum::Json(json!({"ok": true}))
                }
            }),
        );
        axum::serve(listener, app).await.expect("serve");
    });
    let base_url = crate::test_fixture_host::fixture_url(port);
    let definition = crate::capability::parse_capability(&format!(
        "name: {name}\ndescription: the capability under test\nmetadata:\n{metadata}\
         providers:\n  primary:\n    service: rest\n    config:\n      \
         base_url: {base_url}\n      path: /probe\n      method: GET\n"
    ))
    .expect("fixture capability");
    let client = crate::test_fixture_host::fixture_client(Duration::from_secs(5));
    let executor =
        Arc::new(crate::capability::CapabilityExecutor::new().with_test_http_client(client));
    let capabilities = Arc::new(crate::capability::CapabilityBackend::new(
        "capabilities",
        executor,
    ));
    capabilities
        .register_capability(definition)
        .expect("register");
    meta.set_capabilities(capabilities);
    hits
}

/// R11, the capability control: a capability declared `read_only: true` keeps
/// its outer cache hit.
#[tokio::test]
async fn a_read_only_capability_is_served_from_the_outer_cache() {
    let fx = backend("unrelated", "search", ann(READ_ONLY), false).await;
    let meta = fx.meta();
    let hits = counting_capability(&meta, "lookup", "  read_only: true\n").await;
    invoke(&meta, "capabilities", "lookup").await;
    invoke(&meta, "capabilities", "lookup").await;
    assert_eq!(
        hits.load(Ordering::SeqCst),
        1,
        "a read-only capability may be cached"
    );
}

/// R12: a capability not declared read-only is never served from the outer
/// cache, even when it says it is idempotent (mutant c11 reads that field).
#[tokio::test]
async fn a_capability_not_declared_read_only_is_never_served_from_cache() {
    let fx = backend("unrelated", "search", ann(READ_ONLY), false).await;
    let meta = fx.meta();
    let hits = counting_capability(
        &meta,
        "mark_read",
        "  read_only: false\n  idempotent: true\n",
    )
    .await;
    invoke(&meta, "capabilities", "mark_read").await;
    invoke(&meta, "capabilities", "mark_read").await;
    assert_eq!(
        hits.load(Ordering::SeqCst),
        2,
        "a capability write must reach its endpoint on every call"
    );
}

/// R15: dispatch picks the capability before a registry backend of the same
/// name (dispatch.rs:248), so the gate must too. The backend declares `toggle`
/// read-only; the capability `toggle` does not.
#[tokio::test]
async fn a_capability_shadowing_a_backend_is_judged_by_its_own_declaration() {
    let fx = backend("capabilities", "toggle", ann(READ_ONLY), true).await;
    let meta = fx.meta();
    let hits = counting_capability(&meta, "toggle", "  read_only: false\n").await;
    invoke(&meta, "capabilities", "toggle").await;
    invoke(&meta, "capabilities", "toggle").await;
    assert_eq!(
        hits.load(Ordering::SeqCst),
        2,
        "the backend's declaration admitted the capability"
    );
    assert_eq!(
        fx.calls(),
        0,
        "the capability, not the backend, serves the call"
    );
}

/// R16: with no capability and no backend there is nothing to declare, so
/// nothing is served. The entry is real: the backend stored it while it was
/// registered and read-only, then it was removed. Only a gate whose last arm
/// admits (mutant c12) would answer the call from it.
#[tokio::test]
async fn a_call_to_a_removed_backend_is_never_answered_from_cache() {
    let fx = backend("gone", "search", ann(READ_ONLY), true).await;
    let meta = fx.meta();
    invoke(&meta, "gone", "search").await;
    invoke(&meta, "gone", "search").await;
    assert_eq!(fx.calls(), 1, "premise: the entry exists and serves a hit");
    assert!(
        fx.registry.remove("gone"),
        "premise: the backend was registered"
    );
    let second = meta
        .invoke_tool(
            &json!({"server": "gone", "tool": "search", "arguments": {}}),
            Some("session-1"),
            &allow_all_ctx_named(Some("alice"), None),
        )
        .await;
    // A missing backend is answered with a rendered error result, not a Rust
    // `Err` (post_dispatch.rs); the stored entry would come back as "ok".
    let answer = second.expect("a missing backend is rendered as a result");
    assert_eq!(
        answer["isError"],
        json!(true),
        "a call with nothing behind it was answered from cache: {answer}"
    );
    assert!(answer.to_string().contains("Backend not found"), "{answer}");
}

#[path = "cache_read_only_slot_tests.rs"]
mod slot;

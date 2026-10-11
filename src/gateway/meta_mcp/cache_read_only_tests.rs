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
    fx.relist("toggle", ann(IDEMPOTENT_WRITE)).await;
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
    fx.relist("toggle", ann(READ_ONLY)).await;
    invoke(&meta, "docs", "toggle").await;
    assert_eq!(
        fx.calls(),
        2,
        "a write's answer was stored and later served"
    );
}

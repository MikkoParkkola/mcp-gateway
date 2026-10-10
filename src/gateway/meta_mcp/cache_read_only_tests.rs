// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The response cache may stand in for a call only where the backend declared
//! the tool read-only.
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

/// Answers `tools/list` from `tools`, and counts `tools/call` — the only
/// evidence that a cache hit did not reach the backend.
struct AnnotatedToolsTransport {
    tools: serde_json::Value,
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
                json!({ "tools": self.tools }),
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

/// A backend serving one tool named `tool`, carrying `annotations`, already
/// discovered.
///
/// Discovery is not incidental: it is what reads the declarations, exactly as
/// `tools/list` ahead of every `tools/call` does in production. A backend that
/// has not been discovered declares nothing, and declares nothing means cache
/// nothing.
async fn discovered_backend(
    server: &str,
    tool: &str,
    annotations: serde_json::Value,
) -> (Arc<crate::backend::BackendRegistry>, Arc<AtomicUsize>) {
    use crate::backend::Backend;
    use crate::config::{BackendConfig, FailsafeConfig};

    let registry = Arc::new(crate::backend::BackendRegistry::new());
    let calls = Arc::new(AtomicUsize::new(0));
    let backend = Arc::new(Backend::new(
        server,
        BackendConfig::default(),
        &FailsafeConfig::default(),
        Duration::from_secs(300),
    ));
    let transport: Arc<dyn crate::transport::Transport> = Arc::new(AnnotatedToolsTransport {
        tools: json!([{
            "name": tool,
            "description": "the tool under test",
            "inputSchema": {"type": "object"},
            "annotations": annotations,
        }]),
        calls: Arc::clone(&calls),
    });
    backend.set_transport_for_test(transport);
    let _ = registry.register(Arc::clone(&backend));
    backend
        .get_tools_shared()
        .await
        .expect("tools/list must answer");
    (registry, calls)
}

fn caching_meta(registry: Arc<crate::backend::BackendRegistry>) -> MetaMcp {
    MetaMcp::with_features(
        registry,
        Some(Arc::new(crate::cache::ResponseCache::new())),
        None,
        None,
        Duration::from_secs(300),
    )
}

async fn invoke_twice(meta: &MetaMcp, server: &str, tool: &str) {
    for _ in 0..2 {
        let _ = meta
            .invoke_tool(
                &json!({"server": server, "tool": tool, "arguments": {}}),
                Some("session-1"),
                &allow_all_ctx_named(Some("alice"), Some("agent-1")),
            )
            .await;
    }
}

/// The reported bug, in its live shape: `mark_emails_as_read` declares
/// `idempotentHint: true` with `readOnlyHint: false`, so the retry path admits
/// it. A cache hit is not a retry — the call does not run at all — so retry
/// permission must not be enough to cache it.
#[tokio::test]
async fn an_idempotent_write_is_never_served_from_cache() {
    let (registry, calls) = discovered_backend(
        "mail",
        "mark_emails_as_read",
        json!({"readOnlyHint": false, "idempotentHint": true, "destructiveHint": false}),
    )
    .await;
    let meta = caching_meta(registry);

    invoke_twice(&meta, "mail", "mark_emails_as_read").await;

    assert_eq!(
        calls.load(Ordering::SeqCst),
        2,
        "an idempotent write must reach the backend on every call"
    );
}

/// The control. `search` is both explicitly read-only and a name the gateway's
/// own inference reads as a read, so this passes under either rule — which is
/// the point: it proves the cache is live in this harness.
#[tokio::test]
async fn a_declared_read_only_tool_is_served_from_cache() {
    let (registry, calls) = discovered_backend(
        "docs",
        "search",
        json!({"readOnlyHint": true, "idempotentHint": true, "destructiveHint": false}),
    )
    .await;
    let meta = caching_meta(registry);

    invoke_twice(&meta, "docs", "search").await;

    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "a declared read-only tool may be served from cache"
    );
}

/// Undeclared denies, and it has to be the declaration that decides rather than
/// the name: `get_status` is read-only by inference, and the backend never said
/// so.
#[tokio::test]
async fn an_untagged_tool_is_not_cached_even_when_its_name_reads_as_a_getter() {
    let (registry, calls) = discovered_backend("unlabelled", "get_status", json!(null)).await;
    let meta = caching_meta(registry);

    invoke_twice(&meta, "unlabelled", "get_status").await;

    assert_eq!(
        calls.load(Ordering::SeqCst),
        2,
        "a name inference is not a declaration, so an untagged tool must not be cached"
    );
}

/// An undiscovered backend declares nothing, so nothing it serves is cached.
#[tokio::test]
async fn an_undiscovered_backend_caches_nothing() {
    use crate::backend::Backend;
    use crate::config::{BackendConfig, FailsafeConfig};

    let registry = Arc::new(crate::backend::BackendRegistry::new());
    let calls = Arc::new(AtomicUsize::new(0));
    let backend = Arc::new(Backend::new(
        "later",
        BackendConfig::default(),
        &FailsafeConfig::default(),
        Duration::from_secs(300),
    ));
    let transport: Arc<dyn crate::transport::Transport> = Arc::new(AnnotatedToolsTransport {
        tools: json!([{"name": "search", "description": "r",
                       "inputSchema": {"type": "object"},
                       "annotations": {"readOnlyHint": true}}]),
        calls: Arc::clone(&calls),
    });
    backend.set_transport_for_test(transport);
    let _ = registry.register(backend);
    // Deliberately no `get_tools_shared`.

    let meta = caching_meta(registry);
    invoke_twice(&meta, "later", "search").await;

    assert_eq!(
        calls.load(Ordering::SeqCst),
        2,
        "with no discovery there is no declaration to trust"
    );
}

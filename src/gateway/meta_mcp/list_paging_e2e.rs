// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK 7570 PAGING.1 through the meta route (F3 design §5 cells #2, #3, and
//! the `admitted_counts` halves of #5 and #9).

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;

use serde_json::{Value, json};

use crate::backend::{Backend, BackendRegistry};
use crate::config::{BackendConfig, FailsafeConfig, SurfacedToolConfig};
use crate::gateway::authz::AllowAll;
use crate::gateway::meta_mcp::authz_tests::ctx;
use crate::gateway::meta_mcp::{InvokeScope, MetaMcp};
use crate::gateway::meta_mcp_tool_total::ToolTotal;
use crate::gateway::router::CallerStanding;
use crate::protocol::{JsonRpcResponse, RequestId};
use crate::transport::Transport;

/// Page 0 lists `alpha_tool` with cursor `p1`; page 1 lists `zebra_tool`.
/// `endless` pages forever instead (`page_K`, cursor `p{K+1}`). Answers
/// `tools/call` and counts the calls that reach it.
struct TwoPages {
    endless: AtomicBool,
    /// Page 0 omits the `tools` key and keeps only `nextCursor`.
    keyless_first: bool,
    calls: AtomicUsize,
}

#[async_trait::async_trait]
impl Transport for TwoPages {
    async fn request(&self, method: &str, params: Option<Value>) -> crate::Result<JsonRpcResponse> {
        let id = RequestId::Number(1);
        if method == "tools/call" {
            self.calls.fetch_add(1, Ordering::SeqCst);
            return Ok(JsonRpcResponse::success(
                id,
                json!({ "content": [{ "type": "text", "text": "ok" }] }),
            ));
        }
        assert_eq!(method, "tools/list");
        let page: usize = params
            .as_ref()
            .and_then(|p| p.get("cursor")?.as_str()?.strip_prefix('p')?.parse().ok())
            .unwrap_or(0);
        let tool = |name: String| json!({ "name": name, "inputSchema": { "type": "object" } });
        let result = if self.endless.load(Ordering::SeqCst) {
            json!({ "tools": [tool(format!("page_{page}"))], "nextCursor": format!("p{}", page + 1) })
        } else if page == 0 && self.keyless_first {
            json!({ "nextCursor": "p1" })
        } else if page == 0 {
            json!({ "tools": [tool("alpha_tool".into())], "nextCursor": "p1" })
        } else {
            json!({ "tools": [tool("zebra_tool".into())] })
        };
        Ok(JsonRpcResponse::success(id, result))
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

async fn pager_meta(endless: bool, ttl: Duration) -> (MetaMcp, Arc<Backend>, Arc<TwoPages>) {
    let transport = TwoPages {
        endless: AtomicBool::new(endless),
        keyless_first: false,
        calls: AtomicUsize::new(0),
    };
    meta_over(transport, ttl).await
}

async fn meta_over(transport: TwoPages, ttl: Duration) -> (MetaMcp, Arc<Backend>, Arc<TwoPages>) {
    let transport = Arc::new(transport);
    let backend = Arc::new(Backend::new(
        "pager",
        BackendConfig::default(),
        &FailsafeConfig::default(),
        ttl,
    ));
    backend.set_transport_for_test(Arc::clone(&transport) as Arc<dyn Transport>);
    backend.get_tools_shared().await.expect("fill");
    let registry = Arc::new(BackendRegistry::new());
    let _ = registry.register(Arc::clone(&backend));
    (MetaMcp::new(registry), backend, transport)
}

async fn call(meta: &MetaMcp, tool: &str, args: Value) -> Value {
    let response =
        Box::pin(meta.handle_tools_call(RequestId::Number(1), tool, args, None, ctx(&AllowAll)))
            .await;
    assert!(response.error.is_none(), "{tool}: {:?}", response.error);
    response.result.expect("result")
}

/// #2: listing half is red today; the invoke half is a regression guard
/// (`gateway_invoke` dispatches uncached names, design fact 11).
#[tokio::test]
async fn page_two_tool_is_discoverable_and_invocable_via_meta_route() {
    let (meta, _backend, transport) = pager_meta(false, Duration::from_secs(300)).await;

    let search = call(
        &meta,
        "gateway_search_tools",
        json!({ "query": "zebra_tool" }),
    )
    .await;
    assert!(
        search.to_string().contains("zebra_tool"),
        "search: {search}"
    );
    let listed = call(&meta, "gateway_list_tools", json!({ "server": "pager" })).await;
    assert!(listed.to_string().contains("zebra_tool"), "list: {listed}");

    let invoked = call(
        &meta,
        "gateway_invoke",
        json!({ "server": "pager", "tool": "zebra_tool", "arguments": {} }),
    )
    .await;
    assert!(invoked.to_string().contains("ok"), "invoke: {invoked}");
    assert_eq!(transport.calls.load(Ordering::SeqCst), 1);
}

/// #3: a surfaced tool resolves from the cache; a page-2 miss was omitted.
#[tokio::test]
async fn surfaced_tool_on_page_two_is_listed() {
    let (meta, _backend, _transport) = pager_meta(false, Duration::from_secs(300)).await;
    let meta = meta.with_surfaced_tools(vec![SurfacedToolConfig {
        server: "pager".to_string(),
        tool: "zebra_tool".to_string(),
    }]);

    let listed = meta.handle_tools_list_for_session(
        RequestId::Number(1),
        None,
        InvokeScope::allow_all(CallerStanding::Admin),
    );
    let result = listed.result.expect("tools/list result");
    assert!(result.to_string().contains("zebra_tool"), "{result}");
}

/// #5 and #9, count halves: a truncated drain is `AtLeast`, and the next
/// complete drain restores `Exact`.
#[tokio::test]
async fn truncated_drain_is_a_lower_bound_until_a_complete_fill() {
    let (meta, backend, transport) = pager_meta(true, Duration::ZERO).await;
    let scope = InvokeScope::allow_all(CallerStanding::Admin);
    let (total, _) = meta.admitted_counts(scope, None);
    assert_eq!(total, ToolTotal::AtLeast(crate::backend::LIST_MAX_PAGES));

    transport.endless.store(false, Ordering::SeqCst);
    backend.get_tools_shared().await.expect("complete fill");
    let (total, _) = meta.admitted_counts(InvokeScope::allow_all(CallerStanding::Admin), None);
    assert_eq!(total, ToolTotal::Exact(2));
}

/// Page 1 carries `nextCursor` but no `tools` key: page 2's tool is still
/// listed and invocable through the meta route.
#[tokio::test]
async fn keyless_first_page_still_lists_page_two() {
    let transport = TwoPages {
        endless: AtomicBool::new(false),
        keyless_first: true,
        calls: AtomicUsize::new(0),
    };
    let (meta, _backend, transport) = meta_over(transport, Duration::from_secs(300)).await;

    let listed = call(&meta, "gateway_list_tools", json!({ "server": "pager" })).await;
    assert!(listed.to_string().contains("zebra_tool"), "list: {listed}");
    let invoked = call(
        &meta,
        "gateway_invoke",
        json!({ "server": "pager", "tool": "zebra_tool", "arguments": {} }),
    )
    .await;
    assert!(invoked.to_string().contains("ok"), "invoke: {invoked}");
    assert_eq!(transport.calls.load(Ordering::SeqCst), 1);
}

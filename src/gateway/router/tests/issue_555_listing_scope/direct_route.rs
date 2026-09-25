// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A3 cells for the direct route `POST /mcp/{name}`, the spec-preview
//! methods, and the audit silence of discovery.

use serde_json::{Value, json};
use std::sync::Arc;
use std::time::Duration;

use super::{Auth, Fixture, fixture, post, rpc};
use crate::backend::Backend;
use crate::config::{BackendConfig, FailsafeConfig};
use crate::protocol::{JsonRpcResponse, RequestId};

/// An upstream that pages its `tools/list`. `pages` is served in order and
/// the last page repeats forever when `endless`, so a drain that never stops
/// is visible as a cap overflow rather than a hang.
struct Pager {
    pages: Vec<Value>,
    endless: bool,
}

#[async_trait::async_trait]
impl crate::transport::Transport for Pager {
    async fn request(&self, method: &str, params: Option<Value>) -> crate::Result<JsonRpcResponse> {
        let id = RequestId::Number(1);
        if method == "tools/call" {
            return Ok(JsonRpcResponse::success(
                id,
                json!({ "content": [{ "type": "text", "text": "ok" }] }),
            ));
        }
        if method != "tools/list" {
            return Ok(JsonRpcResponse::success(id, json!({})));
        }
        let cursor = params
            .as_ref()
            .and_then(|p| p.get("cursor"))
            .and_then(Value::as_str);
        let page = cursor
            .and_then(|c| c.rsplit('-').next())
            .and_then(|n| n.parse::<usize>().ok())
            .unwrap_or(0);
        if self.endless {
            return Ok(JsonRpcResponse::success(
                id,
                json!({ "tools": [super::tool_json(&format!("t{page}"))], "nextCursor": format!("alpha_write-{}", page + 1) }),
            ));
        }
        Ok(JsonRpcResponse::success(
            id,
            self.pages[page.min(self.pages.len() - 1)].clone(),
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

/// Two pages. Page 0 carries an admitted tool that does not parse, a denied
/// tool in both forms, a sibling key and a cursor that each name the denied
/// tool. Page 1 carries the parseable admitted tool.
fn two_pages() -> Vec<Value> {
    vec![
        json!({
            "tools": [
                { "name": "alpha_read", "description": 7 },
                { "name": "alpha_write", "description": 7 },
                super::tool_json("alpha_write"),
            ],
            "nextCursor": "alpha_write-1",
            "x-sibling": { "hint": "alpha_write" }
        }),
        json!({ "tools": [super::tool_json("alpha_read")] }),
    ]
}

/// The fixture plus a `pager` backend. The registry is shared, so the router
/// already built over it sees the addition.
async fn with_pager(pager: Pager) -> Fixture {
    let f = fixture(Auth::Keys).await;
    let backend = Arc::new(Backend::new(
        "pager",
        BackendConfig::default(),
        &FailsafeConfig::default(),
        Duration::from_secs(300),
    ));
    backend.set_transport_for_test(Arc::new(pager) as Arc<dyn crate::transport::Transport>);
    assert!(f.state.backends.register(backend), "pager registration");
    f
}

/// T13 (a): the direct-route listing is the direct call predicate's view of
/// the whole upstream catalogue, rebuilt as `{tools}` with no cursor.
#[tokio::test]
async fn direct_route_tools_list_follows_direct_call_predicate() {
    let f = with_pager(Pager {
        pages: two_pages(),
        endless: false,
    })
    .await;
    let (_, body) = post(
        &f.router,
        "/mcp/pager",
        Some("read-key"),
        "tools/list",
        json!({}),
    )
    .await;
    let text = body.to_string();
    assert!(
        !text.contains("alpha_write"),
        "a denied name survived: {body}"
    );
    let tools = body["result"]["tools"]
        .as_array()
        .unwrap_or_else(|| panic!("tools: {body}"));
    assert_eq!(
        tools.len(),
        1,
        "exactly the parsed admitted tool from page 1: {body}"
    );
    assert_eq!(tools[0]["name"], "alpha_read");
    assert!(
        tools[0]["description"].is_string(),
        "an unparsed entry survived: {body}"
    );
    let keys: Vec<&String> = body["result"].as_object().expect("result").keys().collect();
    assert!(
        keys.iter().all(|k| *k == "tools" || *k == "_meta"),
        "result keys: {keys:?}"
    );
    let (_, call) = post(
        &f.router,
        "/mcp/pager",
        Some("read-key"),
        "tools/call",
        json!({ "name": "alpha_read", "arguments": {} }),
    )
    .await;
    assert!(
        call.get("error").is_none(),
        "a listed tool must be callable: {call}"
    );
}

/// T13 (b): a catalogue longer than the page cap is an error, never a
/// partial list, and it is counted.
#[test]
#[cfg(feature = "metrics")]
fn direct_route_tools_list_page_cap_is_an_error() {
    let recorder = metrics_exporter_prometheus::PrometheusBuilder::new().build_recorder();
    let handle = recorder.handle();
    let body = telemetry_metrics::with_local_recorder(&recorder, || {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime")
            .block_on(async {
                let f = with_pager(Pager {
                    pages: Vec::new(),
                    endless: true,
                })
                .await;
                post(
                    &f.router,
                    "/mcp/pager",
                    Some("read-key"),
                    "tools/list",
                    json!({}),
                )
                .await
                .1
            })
    });
    assert_eq!(body["error"]["code"], json!(-32005), "{body}");
    assert_eq!(
        body["error"]["data"]["reason"],
        json!("direct_list_page_cap"),
        "{body}"
    );
    assert!(body.get("result").is_none(), "{body}");
    let rendered = handle.render();
    assert!(
        rendered
            .lines()
            .any(|l| l
                .starts_with("mcp_direct_tools_list_page_cap_exceeded_total{backend=\"pager\"} 1")),
        "counter: {rendered}"
    );
}

/// T15: the spec-preview methods resolve and filter only what the caller
/// could invoke, and a withheld name resolves like an absent one.
#[cfg(feature = "spec-preview")]
#[tokio::test]
async fn tools_resolve_and_query_list_are_scoped() {
    let f = fixture(Auth::Keys).await;
    let key = Some("alpha-only");
    let withheld = rpc(
        &f.router,
        key,
        "tools/resolve",
        json!({ "name": "beta_tool" }),
    )
    .await;
    let absent = rpc(&f.router, key, "tools/resolve", json!({ "name": "nope" })).await;
    assert_eq!(withheld["error"]["code"], json!(-32601), "{withheld}");
    assert_eq!(
        withheld.to_string().replace("beta_tool", "X"),
        absent.to_string().replace("nope", "X"),
        "withheld and absent must read alike"
    );
    let near = rpc(
        &f.router,
        key,
        "tools/resolve",
        json!({ "name": "beta_too" }),
    )
    .await;
    assert!(
        !near.to_string().contains("beta_tool"),
        "hint named a withheld tool: {near}"
    );
    let filtered = rpc(&f.router, key, "tools/list", json!({ "query": "beta" })).await;
    let tools = filtered["result"]["tools"]
        .as_array()
        .unwrap_or_else(|| panic!("{filtered}"));
    assert!(tools.is_empty(), "?query= disclosed beta: {filtered}");
}

/// Everything written to tracing on this thread while the guard lives.
fn capture() -> (
    Arc<parking_lot::Mutex<Vec<u8>>>,
    tracing::subscriber::DefaultGuard,
) {
    #[derive(Clone)]
    struct Sink(Arc<parking_lot::Mutex<Vec<u8>>>);
    impl std::io::Write for Sink {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0.lock().extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    // A global subscriber interested in everything, so a callsite first hit
    // on another thread is not cached as "never interesting" (the pattern
    // `openwebui_adapter::start_route::capture` uses).
    static INTEREST: std::sync::Once = std::sync::Once::new();
    INTEREST.call_once(|| {
        use tracing_subscriber::prelude::*;
        let _ = tracing::subscriber::set_global_default(
            tracing_subscriber::Registry::default()
                .with(tracing::level_filters::LevelFilter::TRACE),
        );
    });
    let buffer = Arc::new(parking_lot::Mutex::new(Vec::new()));
    let sink = Sink(Arc::clone(&buffer));
    let subscriber = tracing_subscriber::fmt()
        .without_time()
        .with_ansi(false)
        .with_max_level(tracing::Level::TRACE)
        .with_writer(move || sink.clone())
        .finish();
    (buffer, tracing::subscriber::set_default(subscriber))
}

fn audit_records(buffer: &parking_lot::Mutex<Vec<u8>>) -> usize {
    String::from_utf8_lossy(&buffer.lock())
        .lines()
        .filter(|line| line.contains("agent_tool_audit"))
        .count()
}

/// An HS256 agent scoped to `alpha`, and a token it presents.
pub(super) fn agent_token(registry: &crate::gateway::oauth::AgentRegistry) -> String {
    let secret = "a3-listing-scope-agent-secret-0123456789";
    registry.register(crate::gateway::oauth::AgentDefinition {
        client_id: "a3-agent".to_string(),
        name: "a3-agent".to_string(),
        hs256_secret: Some(secret.to_string()),
        rs256_public_key: None,
        scopes: vec!["tools:alpha:*".to_string()],
        issuer: None,
        audience: Some("a3".to_string()),
    });
    let now = chrono::Utc::now().timestamp();
    jsonwebtoken::encode(
        &jsonwebtoken::Header::new(jsonwebtoken::Algorithm::HS256),
        &json!({ "sub": "a3-agent", "exp": now + 3600, "iat": now, "aud": "a3" }),
        &jsonwebtoken::EncodingKey::from_secret(secret.as_bytes()),
    )
    .expect("sign agent token")
}

/// T12 (guard): discovery writes no invocation audit record; an allowed call
/// still writes its allow records. The silent half passes today only because
/// discovery checks nothing, and goes red the moment it calls `authorize`.
#[tokio::test]
async fn listing_emits_no_invocation_audit() {
    let Fixture {
        router,
        mut state,
        store: _store,
        caps: _caps,
    } = fixture(Auth::Off).await;
    drop(router);
    let registry = Arc::new(crate::gateway::oauth::AgentRegistry::new());
    let token = agent_token(&registry);
    Arc::get_mut(&mut state).expect("router dropped").agent_auth =
        crate::gateway::oauth::AgentAuthState::new(true, registry);
    let router = super::create_router(state);
    let (buffer, _guard) = capture();
    let listing = rpc(&router, Some(&token), "tools/list", json!({})).await;
    assert!(
        listing.to_string().contains("alpha_read"),
        "listing control: {listing}"
    );
    let _ = super::call_tool(
        &router,
        Some(&token),
        "gateway_search_tools",
        json!({ "query": "alpha" }),
    )
    .await;
    assert_eq!(
        audit_records(&buffer),
        0,
        "discovery wrote invocation audit records"
    );
    let call = super::call_tool(&router, Some(&token), "alpha_read", json!({ "q": "x" })).await;
    assert!(
        call.get("error").is_none(),
        "the call must be allowed: {call}"
    );
    // Three, not one: measured on the base tip (red run 36067080760), where
    // the router pre-check and the dispatch chokepoint each authorize a
    // surfaced call. The invoke path stays byte-identical, so the count holds.
    assert_eq!(
        audit_records(&buffer),
        3,
        "invoke-path allow records changed"
    );
}

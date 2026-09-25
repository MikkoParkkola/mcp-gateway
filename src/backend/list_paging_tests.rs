// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK 7570 PAGING.1: the metadata-cache fill follows `nextCursor`
//! (F3 design §5 cells #1, #4-#11; the meta-route cells live in
//! `meta_mcp/list_paging_e2e.rs`).

use super::{Backend, LIST_MAX_PAGES};
use crate::config::{BackendConfig, FailsafeConfig};
use crate::protocol::{JsonRpcResponse, RequestId};
use async_trait::async_trait;
use parking_lot::Mutex;
use serde_json::{Value, json};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

fn item(key: &str, name: &str, extra: &Value) -> Value {
    let mut v = match key {
        "resourceTemplates" => json!({ "uriTemplate": format!("x://{name}/{{id}}"), "name": name }),
        _ => json!({ "name": name, "inputSchema": { "type": "object" } }),
    };
    if let (Some(m), Some(e)) = (v.as_object_mut(), extra.as_object()) {
        m.extend(e.clone());
    }
    v
}

/// What the upstream answers. Pages are chosen by the cursor received (none
/// is page 0, `cK` is page K), so a second fill after TTL expiry restarts at
/// page 0 exactly as a real backend would.
struct Script {
    /// `(item names, nextCursor)` per page.
    pages: Vec<(Vec<&'static str>, Option<&'static str>)>,
    /// Page K serves `tK` and points at `c{K+1}` forever.
    endless: bool,
    /// Global request index from which every answer is a JSON-RPC error.
    error_from: Option<usize>,
    /// Global request index from which every answer has neither `result`
    /// nor `error`.
    bare_from: Option<usize>,
    /// Page index whose answer omits the list key (keeps `nextCursor`).
    keyless_page: Option<usize>,
    sleep_per_page: Duration,
}

/// A paging `*/list` upstream that counts requests and records every
/// request's params verbatim.
struct Pager {
    method: &'static str,
    key: &'static str,
    extra: Value,
    script: Mutex<Script>,
    requests: AtomicUsize,
    params_seen: Mutex<Vec<Option<Value>>>,
}

impl Pager {
    fn with(method: &'static str, key: &'static str, script: Script) -> Arc<Self> {
        Arc::new(Self {
            method,
            key,
            extra: json!({}),
            script: Mutex::new(script),
            requests: AtomicUsize::new(0),
            params_seen: Mutex::new(Vec::new()),
        })
    }

    fn tools(pages: Vec<(Vec<&'static str>, Option<&'static str>)>) -> Arc<Self> {
        Self::with("tools/list", "tools", finite(pages))
    }

    fn request_count(&self) -> usize {
        self.requests.load(Ordering::SeqCst)
    }

    fn cursors(&self) -> Vec<String> {
        self.params_seen
            .lock()
            .iter()
            .filter_map(|p| p.as_ref()?.get("cursor")?.as_str().map(str::to_owned))
            .collect()
    }
}

fn finite(pages: Vec<(Vec<&'static str>, Option<&'static str>)>) -> Script {
    Script {
        pages,
        endless: false,
        error_from: None,
        bare_from: None,
        keyless_page: None,
        sleep_per_page: Duration::ZERO,
    }
}

fn endless(error_from: Option<usize>, sleep_per_page: Duration) -> Script {
    Script {
        pages: Vec::new(),
        endless: true,
        error_from,
        bare_from: None,
        keyless_page: None,
        sleep_per_page,
    }
}

#[async_trait]
impl crate::transport::Transport for Pager {
    async fn request(&self, method: &str, params: Option<Value>) -> crate::Result<JsonRpcResponse> {
        let id = RequestId::Number(1);
        assert_eq!(method, self.method, "fixture serves one list method");
        let n = self.requests.fetch_add(1, Ordering::SeqCst);
        self.params_seen.lock().push(params.clone());
        let page: usize = params
            .as_ref()
            .and_then(|p| p.get("cursor")?.as_str()?.strip_prefix('c')?.parse().ok())
            .unwrap_or(0);
        let sleep = self.script.lock().sleep_per_page;
        if !sleep.is_zero() {
            tokio::time::sleep(sleep).await;
        }
        let script = self.script.lock();
        if script.error_from.is_some_and(|from| n >= from) {
            return Ok(JsonRpcResponse::error(Some(id), -32603, "upstream failed"));
        }
        if script.bare_from.is_some_and(|from| n >= from) {
            let mut bare = JsonRpcResponse::success(id, json!(null));
            bare.result = None;
            return Ok(bare);
        }
        let (names, next) = if script.endless {
            (vec![format!("t{page}")], Some(format!("c{}", page + 1)))
        } else {
            let (names, next) = &script.pages[page];
            (
                names.iter().map(|s| (*s).to_owned()).collect(),
                next.map(str::to_owned),
            )
        };
        let items: Vec<Value> = names
            .iter()
            .map(|n| item(self.key, n, &self.extra))
            .collect();
        let mut result = json!({});
        if script.keyless_page != Some(page) {
            result[self.key] = json!(items);
        }
        if let Some(next) = next {
            result["nextCursor"] = json!(next);
        }
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

fn backend_with(transport: Arc<Pager>, ttl: Duration) -> Arc<Backend> {
    let backend = Arc::new(Backend::new(
        "pager",
        BackendConfig::default(),
        &FailsafeConfig::default(),
        ttl,
    ));
    backend.set_transport_for_test(transport as Arc<dyn crate::transport::Transport>);
    backend
}

const LONG_TTL: Duration = Duration::from_secs(300);

fn names(backend: &Backend) -> Vec<String> {
    let mut v: Vec<String> = backend
        .get_cached_tools_snapshot()
        .iter()
        .map(|t| t.name.clone())
        .collect();
    v.sort_unstable();
    v
}

fn three_pages() -> Vec<(Vec<&'static str>, Option<&'static str>)> {
    vec![
        (vec!["t0"], Some("c1")),
        (vec!["t1"], Some("c2")),
        (vec!["t2"], None),
    ]
}

/// Runs `fut` under a local Prometheus recorder; returns the rendered text.
#[cfg(feature = "metrics")]
fn counted<T>(paused: bool, fut: impl std::future::Future<Output = T>) -> (T, String) {
    let recorder = metrics_exporter_prometheus::PrometheusBuilder::new().build_recorder();
    let handle = recorder.handle();
    let out = telemetry_metrics::with_local_recorder(&recorder, || {
        let mut rt = tokio::runtime::Builder::new_current_thread();
        rt.enable_all().start_paused(paused);
        rt.build().expect("runtime").block_on(fut)
    });
    (out, handle.render())
}

#[cfg(feature = "metrics")]
fn truncated_count(rendered: &str, reason: &str) -> Option<String> {
    rendered
        .lines()
        .find(|l| {
            l.starts_with("mcp_backend_list_truncated_total{")
                && l.contains(&format!("reason=\"{reason}\""))
        })
        .map(|l| l.rsplit(' ').next().unwrap_or_default().to_owned())
}

/// #1
#[tokio::test]
async fn cache_fill_follows_next_cursor_across_three_pages() {
    let pager = Pager::tools(three_pages());
    let backend = backend_with(Arc::clone(&pager), LONG_TTL);

    backend.get_tools_shared().await.expect("fill");
    assert_eq!(names(&backend), ["t0", "t1", "t2"]);
    assert_eq!(pager.request_count(), 3);
    assert_eq!(pager.cursors(), ["c1", "c2"]);
    assert!(!backend.cached_tools_truncated());
}

/// #4: merge then parse once, so the retry set spans every page.
#[tokio::test]
async fn resend_permission_spans_all_pages() {
    let pager = Arc::new(Pager {
        method: "tools/list",
        key: "tools",
        extra: json!({ "annotations": { "idempotentHint": true } }),
        script: Mutex::new(finite(vec![(vec!["a"], Some("c1")), (vec!["b"], None)])),
        requests: AtomicUsize::new(0),
        params_seen: Mutex::new(Vec::new()),
    });
    let backend = backend_with(Arc::clone(&pager), LONG_TTL);

    backend.get_tools_shared().await.expect("fill");
    let permitted = backend.resend_permitted_snapshot();
    assert!(
        permitted.contains("a") && permitted.contains("b"),
        "{permitted:?}"
    );
}

/// #5
#[test]
#[cfg(feature = "metrics")]
fn page_cap_overflow_keeps_32_pages_and_marks_truncated() {
    let pager = Pager::with(
        "tools/list",
        "tools",
        endless(Some(2 * LIST_MAX_PAGES + 1), Duration::ZERO),
    );
    let backend = backend_with(Arc::clone(&pager), LONG_TTL);

    let (fill, rendered) = counted(false, backend.get_tools_shared());
    assert_eq!(
        fill.expect("fill stores what it drained").len(),
        LIST_MAX_PAGES
    );
    assert_eq!(pager.request_count(), LIST_MAX_PAGES);
    assert!(
        backend.cached_tools_truncated(),
        "cap overflow must mark truncated"
    );
    assert_eq!(
        truncated_count(&rendered, "page_cap").as_deref(),
        Some("1"),
        "{rendered}"
    );
}

/// #6
#[test]
#[cfg(feature = "metrics")]
fn repeated_cursor_stops_drain_at_first_repeat() {
    let pager = Pager::tools(vec![(vec!["t0"], Some("c1")), (vec!["t1"], Some("c1"))]);
    let backend = backend_with(Arc::clone(&pager), LONG_TTL);

    let (fill, rendered) = counted(false, backend.get_tools_shared());
    fill.expect("fill");
    assert_eq!(names(&backend), ["t0", "t1"]);
    assert_eq!(pager.request_count(), 2, "must stop, not run all 32 pages");
    assert!(backend.cached_tools_truncated());
    assert_eq!(
        truncated_count(&rendered, "cursor_repeat").as_deref(),
        Some("1"),
        "{rendered}"
    );
}

/// #7: a transient page error keeps the last complete catalogue.
#[tokio::test]
async fn mid_drain_failure_keeps_previous_catalogue() {
    let pager = Pager::tools(three_pages());
    let backend = backend_with(Arc::clone(&pager), Duration::ZERO);

    backend.get_tools_shared().await.expect("first fill");
    assert_eq!(names(&backend), ["t0", "t1", "t2"], "precondition");
    pager.script.lock().error_from = Some(pager.request_count() + 2);

    assert!(backend.get_tools_shared().await.is_err(), "page 3 errors");
    assert_eq!(names(&backend), ["t0", "t1", "t2"]);
    assert!(!backend.cached_tools_truncated());
}

/// A page answering with neither `result` nor `error` mid-drain is a
/// transient page failure too: the last complete catalogue stays (design E).
#[tokio::test]
async fn mid_drain_empty_answer_keeps_previous_catalogue() {
    let pager = Pager::tools(three_pages());
    let backend = backend_with(Arc::clone(&pager), Duration::ZERO);

    backend.get_tools_shared().await.expect("first fill");
    assert_eq!(names(&backend), ["t0", "t1", "t2"], "precondition");
    pager.script.lock().bare_from = Some(pager.request_count() + 2);

    assert!(
        backend.get_tools_shared().await.is_err(),
        "page 3 has no result"
    );
    assert_eq!(names(&backend), ["t0", "t1", "t2"]);
    assert!(!backend.cached_tools_truncated());
}

/// Page 1 omits the `tools` key but carries `nextCursor`: later pages'
/// tools must still land in the cache.
#[tokio::test]
async fn keyless_first_page_keeps_later_pages() {
    let pager = Pager::tools(vec![(vec![], Some("c1")), (vec!["t1"], None)]);
    pager.script.lock().keyless_page = Some(0);
    let backend = backend_with(Arc::clone(&pager), LONG_TTL);

    backend.get_tools_shared().await.expect("fill");
    assert_eq!(pager.request_count(), 2);
    assert_eq!(names(&backend), ["t1"]);
}

/// #8
#[tokio::test]
async fn single_page_backend_request_is_unchanged() {
    let pager = Pager::tools(vec![(vec!["t0"], None)]);
    let backend = backend_with(Arc::clone(&pager), LONG_TTL);

    backend.get_tools_shared().await.expect("fill");
    assert_eq!(
        pager.request_count(),
        1,
        "byte-identical: still one request"
    );
    assert_eq!(*pager.params_seen.lock(), [None], "page 1 sends no params");
}

/// #9
#[tokio::test]
async fn complete_fill_clears_truncated_flag() {
    let pager = Pager::with("tools/list", "tools", endless(None, Duration::ZERO));
    let backend = backend_with(Arc::clone(&pager), Duration::ZERO);

    backend.get_tools_shared().await.expect("capped fill");
    assert!(backend.cached_tools_truncated(), "precondition");
    *pager.script.lock() = finite(vec![(vec!["t0"], Some("c1")), (vec!["t1"], None)]);

    backend.get_tools_shared().await.expect("complete fill");
    assert!(!backend.cached_tools_truncated());
    assert_eq!(names(&backend), ["t0", "t1"]);
}

/// #10: the one family whose array key differs from its `kind`.
#[tokio::test]
async fn resource_templates_cache_follows_next_cursor() {
    let script = finite(vec![(vec!["a"], Some("c1")), (vec!["b"], None)]);
    let pager = Pager::with("resources/templates/list", "resourceTemplates", script);
    let backend = backend_with(Arc::clone(&pager), LONG_TTL);

    let templates = backend.get_resource_templates_shared().await.expect("fill");
    assert_eq!(templates.len(), 2, "{templates:?}");
}

/// #11 (F3-T11): a slow backend stops at the 120 s drain budget.
#[test]
#[cfg(feature = "metrics")]
fn fill_budget_expiry_keeps_pages_and_marks_truncated() {
    let pager = Pager::with(
        "tools/list",
        "tools",
        endless(None, Duration::from_secs(10)),
    );
    let backend = backend_with(Arc::clone(&pager), LONG_TTL);

    let (fill, rendered) = counted(true, backend.get_tools_shared());
    fill.expect("fill stores what it drained");
    // Pages end at 10 s, 20 s, ... 120 s; the check before page 13 stops it.
    assert_eq!(pager.request_count(), 12, "budget, not the 32-page cap");
    assert!(backend.cached_tools_truncated());
    assert_eq!(
        truncated_count(&rendered, "fill_budget").as_deref(),
        Some("1"),
        "{rendered}"
    );
}

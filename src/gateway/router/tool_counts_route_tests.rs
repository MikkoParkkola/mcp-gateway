// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Per-tool and per-server call counts on the tool list and the server
//! status (U11): every tool, both 24-hour windows, one store read, and
//! `null` (present, never 0) when a count could be low.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::{Value, json};
use tower::ServiceExt;

use super::{http_backend_at, scoped_auth_config, test_router_app_state_with_auth_and_config};
use crate::counters::{Call, CounterStore, Label, Tally};
use crate::gateway::router::{AppState, create_router};

const SECRET: &str = "scoped-key";
const DAY: u64 = 86_400;

/// An app state with `servers` backends of `per_server` cached tools each,
/// named `tool-<n>`, and a counter store when `counted`.
async fn state(
    admin: bool,
    servers: &[&str],
    per_server: usize,
    counted: bool,
) -> (
    Arc<AppState>,
    Option<Arc<CounterStore>>,
    crate::gateway::router::tests::FixtureDir,
) {
    let (state, dir) = test_router_app_state_with_auth_and_config(
        &scoped_auth_config(admin),
        crate::config::Config::default(),
    )
    .await;
    for server in servers {
        let backend = http_backend_at(server, "http://127.0.0.1:9");
        let tools = (0..per_server)
            .map(|n| {
                serde_json::from_value(json!({
                    "name": format!("tool-{n}"),
                    "inputSchema": {"type": "object"},
                }))
                .expect("a tool")
            })
            .collect();
        backend.prefill_tools_for_test(tools);
        assert!(state.backends.register(backend), "fixture registration");
    }
    let store = counted.then(|| {
        let store = Arc::new(CounterStore::new(0));
        state.meta_mcp.set_counters(Arc::clone(&store));
        store
    });
    (state, store, dir)
}

fn record(store: &CounterStore, server: &str, tool: &str, at: u64, times: usize) {
    let call = Call {
        caller: "key:scoped-client",
        server: Label::Known(server),
        tool: Label::Known(tool),
        tally: Tally::default(),
    };
    for _ in 0..times {
        store.record(&call, at, &chrono::Local);
    }
}

async fn get(state: &Arc<AppState>, uri: &str, key: Option<&str>) -> (StatusCode, Value) {
    let mut builder = Request::builder().method("GET").uri(uri);
    if let Some(key) = key {
        builder = builder.header("authorization", format!("Bearer {key}"));
    }
    let response = create_router(Arc::clone(state))
        .oneshot(builder.body(Body::empty()).unwrap())
        .await
        .unwrap();
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

fn now() -> u64 {
    crate::clock::unix_secs().expect("a readable clock")
}

/// The tool-list entry for `server`/`tool`.
fn entry<'a>(body: &'a Value, server: &str, tool: &str) -> &'a Value {
    body["tools"]
        .as_array()
        .expect("tools")
        .iter()
        .find(|t| t["server"] == server && t["name"] == tool)
        .unwrap_or_else(|| panic!("{server}/{tool} listed"))
}

/// T1: 300 tools, all listed, each carrying both windows; recorded calls
/// read exactly, a tool with none reads 0.
#[tokio::test]
async fn t1_every_tool_carries_both_windows() {
    let (state, store, _dir) = state(true, &["alpha", "beta", "gamma"], 100, true).await;
    let store = store.expect("a store");
    let now = now();
    record(&store, "beta", "tool-7", now - 60, 3);
    record(&store, "beta", "tool-7", now - DAY, 2);
    let (status, body) = get(&state, "/ui/api/tools", Some(SECRET)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["total"], 300, "every tool");
    for tool in body["tools"].as_array().expect("tools") {
        let obj = tool.as_object().expect("an entry");
        assert!(obj.contains_key("calls_24h"), "{tool}");
        assert!(obj.contains_key("calls_prev_24h"), "{tool}");
    }
    let counted = entry(&body, "beta", "tool-7");
    assert_eq!(counted["calls_24h"], 3, "{counted}");
    assert_eq!(counted["calls_prev_24h"], 2, "{counted}");
    let quiet = entry(&body, "alpha", "tool-7");
    assert_eq!(quiet["calls_24h"], 0, "{quiet}");
    assert_eq!(quiet["calls_prev_24h"], 0, "{quiet}");
    assert_eq!(body["counts_since"], 0, "the store's coverage start");
}

/// T1b: the same tool name on two servers is two counts.
#[tokio::test]
async fn t1b_a_shared_tool_name_keeps_one_count_per_server() {
    let (state, store, _dir) = state(true, &["alpha", "beta"], 2, true).await;
    let store = store.expect("a store");
    let now = now();
    record(&store, "alpha", "tool-1", now - 60, 5);
    record(&store, "beta", "tool-1", now - 60, 1);
    let (_, body) = get(&state, "/ui/api/tools", Some(SECRET)).await;
    assert_eq!(entry(&body, "alpha", "tool-1")["calls_24h"], 5);
    assert_eq!(entry(&body, "beta", "tool-1")["calls_24h"], 1);
}

/// T4: no counter store: every count present and `null`, the list complete.
#[tokio::test]
async fn t4_without_a_counter_store_counts_are_null_not_zero() {
    let (state, _, _dir) = state(true, &["alpha"], 3, false).await;
    let (status, body) = get(&state, "/ui/api/tools", Some(SECRET)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["total"], 3);
    let tool = entry(&body, "alpha", "tool-0")
        .as_object()
        .expect("an entry");
    assert_eq!(tool.get("calls_24h"), Some(&Value::Null));
    assert_eq!(tool.get("calls_prev_24h"), Some(&Value::Null));
    let root = body.as_object().expect("an object");
    assert_eq!(root.get("counts_since"), Some(&Value::Null));
}

/// T5: each status server carries both windows, and the status names the
/// coverage start.
#[tokio::test]
async fn t5_status_servers_carry_both_windows() {
    let (state, store, _dir) = state(true, &["alpha", "beta"], 1, true).await;
    let store = store.expect("a store");
    let now = now();
    record(&store, "alpha", "tool-0", now - 60, 4);
    record(&store, "alpha", "tool-0", now - DAY, 1);
    let (status, body) = get(&state, "/ui/api/status", Some(SECRET)).await;
    assert_eq!(status, StatusCode::OK);
    let servers = body["servers"].as_array().expect("servers");
    let alpha = servers
        .iter()
        .find(|s| s["name"] == "alpha")
        .expect("alpha");
    assert_eq!(alpha["calls_24h"], 4, "{alpha}");
    assert_eq!(alpha["calls_prev_24h"], 1, "{alpha}");
    let beta = servers.iter().find(|s| s["name"] == "beta").expect("beta");
    assert_eq!(beta["calls_24h"], 0, "{beta}");
    assert_eq!(body["counts_since"], 0);
}

/// T6: the tool list stays admin-only; the status route's non-admin answer
/// stays redacted, with no servers and no counts.
#[tokio::test]
async fn t6_non_admins_get_no_counts() {
    let (state, store, _dir) = state(false, &["alpha"], 1, true).await;
    record(&store.expect("a store"), "alpha", "tool-0", now() - 60, 1);
    let (status, _) = get(&state, "/ui/api/tools", Some(SECRET)).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let (status, body) = get(&state, "/ui/api/status", Some(SECRET)).await;
    assert_eq!(status, StatusCode::OK);
    let root = body.as_object().expect("an object");
    assert!(!root.contains_key("servers"), "{body}");
    assert!(!root.contains_key("counts_since"), "{body}");
    assert!(!body.to_string().contains("calls_24h"), "{body}");
}

/// T7 at the routes: one tool-list request with 300 tools, and one status
/// request, each take the counter store's lock exactly once.
#[tokio::test]
async fn t7_each_route_reads_the_store_once() {
    let (state, store, _dir) = state(true, &["alpha", "beta", "gamma"], 100, true).await;
    let store = store.expect("a store");
    let before = store.reads_for_test();
    let (status, body) = get(&state, "/ui/api/tools", Some(SECRET)).await;
    assert_eq!((status, &body["total"]), (StatusCode::OK, &json!(300)));
    assert_eq!(store.reads_for_test() - before, 1, "tool list");
    let before = store.reads_for_test();
    let (status, _) = get(&state, "/ui/api/status", Some(SECRET)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(store.reads_for_test() - before, 1, "status");
}

/// T4 on the status route: no counter store, every server count present
/// and `null`, `counts_since` `null`, the answer still 200.
#[tokio::test]
async fn t4_status_without_a_counter_store_reads_null() {
    let (state, _, _dir) = state(true, &["alpha"], 1, false).await;
    let (status, body) = get(&state, "/ui/api/status", Some(SECRET)).await;
    assert_eq!(status, StatusCode::OK);
    let alpha = body["servers"][0].as_object().expect("a server");
    assert_eq!(alpha.get("calls_24h"), Some(&Value::Null));
    assert_eq!(alpha.get("calls_prev_24h"), Some(&Value::Null));
    let root = body.as_object().expect("an object");
    assert_eq!(root.get("counts_since"), Some(&Value::Null));
}

/// H8: each tool carries the completed hour, the hour before and a 12-point
/// series in order, aligned to `series_start`. Expectations come from the
/// route's own `series_start`, so a half-hour tick between recording and
/// reading cannot make the row flaky.
#[tokio::test]
async fn h8_tools_carry_the_hour_windows_and_series() {
    const HALF: u64 = 1_800;
    let (state, store, _dir) = state(true, &["alpha"], 2, true).await;
    let store = store.expect("a store");
    let nb = now() / HALF;
    let recorded = [(nb - 1, 3), (nb - 3, 1), (nb - 6, 2)];
    for (bucket, times) in recorded {
        record(&store, "alpha", "tool-1", bucket * HALF + 5, times);
    }
    let (status, body) = get(&state, "/ui/api/tools", Some(SECRET)).await;
    assert_eq!(status, StatusCode::OK);
    let start = body["series_start"].as_i64().expect("a series start");
    let first = u64::try_from(start).expect("after the epoch") / HALF;
    let mut series = [0_usize; 12];
    for (bucket, times) in recorded {
        if let Some(slot) = bucket.checked_sub(first).filter(|i| *i < 12) {
            series[usize::try_from(slot).unwrap()] += times;
        }
    }
    let tool = entry(&body, "alpha", "tool-1");
    assert_eq!(tool["calls_series"], json!(series), "{tool}");
    assert_eq!(tool["calls_1h"], series[9] + series[10], "{tool}");
    assert_eq!(tool["calls_prev_1h"], series[7] + series[8], "{tool}");
    assert_ne!(tool["calls_1h"], tool["calls_prev_1h"], "{tool}");
    assert_ne!(tool["calls_1h"], 0, "{tool}");
    let quiet = entry(&body, "alpha", "tool-0");
    assert_eq!(
        quiet["calls_series"],
        Value::Array(vec![json!(0); 12]),
        "{quiet}"
    );
}

/// H9: no counter store: the hour windows are null, the series is 12 nulls,
/// and `series_start` is null.
#[tokio::test]
async fn h9_without_a_counter_store_the_hour_fields_are_null() {
    let (state, _, _dir) = state(true, &["alpha"], 1, false).await;
    let (_, body) = get(&state, "/ui/api/tools", Some(SECRET)).await;
    let tool = entry(&body, "alpha", "tool-0");
    assert_eq!(tool["calls_1h"], Value::Null, "{tool}");
    assert_eq!(tool["calls_prev_1h"], Value::Null, "{tool}");
    assert_eq!(
        tool["calls_series"],
        Value::Array(vec![Value::Null; 12]),
        "{tool}"
    );
    let root = body.as_object().expect("an object");
    assert_eq!(root.get("series_start"), Some(&Value::Null));
}

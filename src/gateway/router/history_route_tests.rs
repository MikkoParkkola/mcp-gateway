// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! History routes over HTTP (test plan T34 shape, T40-T43): admin
//! only, the series and markers as read, and no secret or caller-chosen name
//! in anything U1 writes or answers.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::Value;
use tower::ServiceExt;

use super::{scoped_auth_config, test_router_app_state_with_auth_and_config};
use crate::counters::{Call, CounterStore, Label, MarkerKind, Tally};
use crate::gateway::router::create_router;

const SECRET: &str = "scoped-key";
const SENTINEL: &str = "sk-live-SENTINEL-8854";

async fn state(
    admin: bool,
) -> (
    Arc<crate::gateway::router::AppState>,
    Arc<CounterStore>,
    crate::gateway::router::tests::FixtureDir,
) {
    let (state, dir) = test_router_app_state_with_auth_and_config(
        &scoped_auth_config(admin),
        crate::config::Config::default(),
    )
    .await;
    let store = Arc::new(CounterStore::new(0));
    state.meta_mcp.set_counters(Arc::clone(&store));
    (state, store, dir)
}

async fn get(
    state: &Arc<crate::gateway::router::AppState>,
    uri: &str,
    key: Option<&str>,
) -> (StatusCode, Value, String) {
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
    let text = String::from_utf8_lossy(&bytes).into_owned();
    (
        status,
        serde_json::from_str(&text).unwrap_or(Value::Null),
        text,
    )
}

fn now() -> u64 {
    crate::clock::unix_secs().expect("a readable clock")
}

/// T41: no credential is 401, a non-admin key 403 with the admin body, an
/// admin key 200, on both routes.
#[tokio::test]
async fn t41_both_routes_are_admin_only() {
    for uri in [
        "/ui/api/metrics/series?metric=calls",
        "/ui/api/metrics/series?metric=latency_p95",
        "/ui/api/markers",
    ] {
        let (user, _, _dir) = state(false).await;
        assert_eq!(
            get(&user, uri, None).await.0,
            StatusCode::UNAUTHORIZED,
            "{uri}"
        );
        let (status, body, _) = get(&user, uri, Some(SECRET)).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{uri}");
        assert_eq!(body["error"], "Admin authentication required", "{uri}");
        let (admin, _, _dir) = state(true).await;
        assert_eq!(
            get(&admin, uri, Some(SECRET)).await.0,
            StatusCode::OK,
            "{uri}"
        );
    }
}

/// T34 over HTTP: the series answers its points and the previous period.
#[tokio::test]
async fn t34_the_series_route_answers_points_and_the_previous_period() {
    let (admin, store, _dir) = state(true).await;
    let call = Call {
        caller: "key:scoped-client",
        server: Label::Known("demo"),
        tool: Label::Known("t"),
        tally: Tally::default(),
    };
    store.record(&call, now(), &chrono::Local);
    let (status, body, _) = get(
        &admin,
        "/ui/api/metrics/series?metric=calls&window=24h&compare=prev",
        Some(SECRET),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(body["points"].is_array(), "the series has points: {body}");
    let points = body["points"].as_array().unwrap();
    assert_eq!(points.len(), 48, "{body}");
    let total: u64 = points.iter().map(|p| p["v"].as_u64().unwrap()).sum();
    assert_eq!(total, 1);
    assert!(body["previous"].is_array(), "{body}");
    assert_eq!(body["bucket_secs"], 1800);
    assert_eq!(body["folded"], false);
    let (status, body, _) = get(
        &admin,
        "/ui/api/metrics/series?window=30d&compare=prev",
        Some(SECRET),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
}

/// T51 over HTTP: a label admitted after its overflow answers the same
/// fields as any series, with `since` moved to its own first count.
#[tokio::test]
async fn t51_a_late_label_answers_the_same_shape_with_a_later_since() {
    const DAY: u64 = 86_400;
    let (admin, store, _dir) = state(true).await;
    let at = |tool: &str, when: u64| {
        let call = Call {
            caller: "key:scoped-client",
            server: Label::Known("demo"),
            tool: Label::Known(tool),
            tally: Tally::default(),
        };
        store.record(&call, when, &chrono::Local);
    };
    let base = now() - 32 * DAY;
    let names: Vec<String> = (0..crate::counters::MAX_LABELS)
        .map(|i| format!("old-{i}"))
        .collect();
    for name in &names {
        at(name, base);
    }
    at("late", base + 5 * DAY);
    at("new-1", now() - 10);
    at("late", now() - 5);
    let uri = "/ui/api/metrics/series?metric=calls&window=30d";
    let (_, global, _) = get(&admin, uri, Some(SECRET)).await;
    let (status, late, _) = get(
        &admin,
        &format!("{uri}&server=demo&tool=late"),
        Some(SECRET),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{late}");
    let keys = |v: &Value| {
        let mut keys: Vec<String> = v.as_object().unwrap().keys().cloned().collect();
        keys.sort();
        keys
    };
    assert_eq!(keys(&late), keys(&global), "the same fields");
    assert_eq!(late["folded"], false);
    assert!(
        late["since"].as_u64().unwrap() > base + 5 * DAY,
        "since starts after the overflowed call: {late}"
    );
    assert_eq!(
        global["since"], 0,
        "the global series keeps the store's since"
    );
}

/// T40: markers at or after `from`, oldest first.
#[tokio::test]
async fn t40_markers_from_a_time_oldest_first() {
    let (admin, store, _dir) = state(true).await;
    store.mark(MarkerKind::Restart, None, 100);
    store.mark(MarkerKind::SwitchOff, Some("demo"), 300);
    store.mark(MarkerKind::ConfigReload, None, 200);
    let (status, body, _) = get(&admin, "/ui/api/markers?from=200", Some(SECRET)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        body,
        serde_json::json!([
            {"t": 200, "kind": "config_reload", "subject": null},
            {"t": 300, "kind": "switch_off", "subject": "demo"},
        ])
    );
}

/// T42: neither the configured key nor a caller-chosen name reaches the
/// routes, the counters file or the log lines its save and restore write.
#[tokio::test]
async fn t42_no_secret_and_no_caller_chosen_name_in_anything_u1_writes() {
    let (admin, store, dir) = state(true).await;
    let call = Call {
        caller: "key:scoped-client",
        server: Label::Untrusted,
        tool: Label::Untrusted,
        tally: Tally::default(),
    };
    store.record(&call, now(), &chrono::Local);
    store.mark(MarkerKind::Pause, Some("demo"), now());
    let mut answered = String::new();
    for uri in [
        "/ui/api/metrics/series?metric=calls&overflow=server".to_owned(),
        "/ui/api/metrics/series?metric=calls&caller=key:scoped-client".to_owned(),
        format!("/ui/api/metrics/series?metric=calls&server={SENTINEL}"),
        "/ui/api/markers".to_owned(),
    ] {
        let (status, _, text) = get(&admin, &uri, Some(SECRET)).await;
        assert_eq!(status, StatusCode::OK, "{uri}");
        answered.push_str(&text);
    }
    let path = dir.path().join("counters.json");
    let logs = crate::test_log_capture::records(|| {
        let restored = crate::counters::persist::CounterFile::restore(
            path.clone(),
            now(),
            "4.0.0",
            &chrono::Local,
        );
        restored.file.save(&store, "4.0.0", now());
        let _ = crate::counters::persist::CounterFile::restore(
            path.clone(),
            now(),
            "4.0.0",
            &chrono::Local,
        );
    });
    let file = std::fs::read_to_string(&path).expect("saved");
    let logged = serde_json::to_string(&logs).unwrap();
    for (what, text) in [
        ("routes", &answered),
        ("counters.json", &file),
        ("logs", &logged),
    ] {
        assert!(!text.contains(SECRET), "the key in {what}");
        assert!(!text.contains(SENTINEL), "a caller-chosen name in {what}");
    }
    assert!(
        file.contains("key:scoped-client"),
        "the file is the real store"
    );
}

/// Without a counter store (a gateway built without the server's start),
/// both routes tell the admin counting is off, never an empty 200 that
/// would read as "no calls". The one place this body is asserted.
#[tokio::test]
async fn t41_without_a_store_both_routes_say_counting_is_off() {
    let (state, _dir) = test_router_app_state_with_auth_and_config(
        &scoped_auth_config(true),
        crate::config::Config::default(),
    )
    .await;
    for uri in ["/ui/api/metrics/series?metric=calls", "/ui/api/markers"] {
        let (status, body, _) = get(&state, uri, Some(SECRET)).await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{uri}");
        assert_eq!(body["error"], "call counters are not running", "{uri}");
    }
}

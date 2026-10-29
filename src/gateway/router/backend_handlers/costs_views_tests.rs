// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! `GET /api/costs` views: one key, one session, and the aggregate, each with
//! its "no data" answer. The admin gate and the selector refusals are pinned
//! in `trace_span_tests`.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::Value;
use tower::ServiceExt;

use crate::gateway::router::create_router;
use crate::gateway::router::tests::{
    scoped_auth_config, test_router_app_state_with_auth_and_config,
};

async fn call(
    state: &Arc<crate::gateway::router::AppState>,
    uri: &str,
    session: Option<&str>,
) -> (StatusCode, Value) {
    let mut request = Request::builder()
        .method("GET")
        .uri(uri)
        .header("authorization", "Bearer scoped-key");
    if let Some(id) = session {
        request = request.header("x-cost-session-id", id);
    }
    let response = create_router(Arc::clone(state))
        .oneshot(request.body(Body::empty()).unwrap())
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

/// The state plus the temp directory backing its stores; keep both alive.
async fn admin_state() -> (
    Arc<crate::gateway::router::AppState>,
    crate::gateway::router::tests::FixtureDir,
) {
    test_router_app_state_with_auth_and_config(
        &scoped_auth_config(true),
        crate::config::Config::default(),
    )
    .await
}

#[tokio::test]
async fn a_key_or_session_with_no_spend_answers_no_data() {
    // MIK-8369.COST.2: "no data" is an error, so it carries 404, not 200.
    let (state, _store) = admin_state().await;
    let (status, body) = call(&state, "/api/costs?key=nobody", None).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
    assert_eq!(body["error"], "No data for key 'nobody'");

    let (status, body) = call(&state, "/api/costs", Some("no-such-session")).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
    assert_eq!(body["error"], "No data for session 'no-such-session'");

    // A bare `?key` decodes to the empty name, which has no spend either.
    let (status, body) = call(&state, "/api/costs?key", None).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
    assert_eq!(body["error"], "No data for key ''");
}

/// The aggregate names the zone daily budgets count days in:
/// the host's IANA zone, UTC on a UTC host. Mutant: the field is dropped.
#[tokio::test]
async fn the_aggregate_names_the_zone_days_are_counted_in() {
    let (state, _store) = admin_state().await;
    let (status, all) = call(&state, "/api/costs", None).await;
    assert_eq!(status, StatusCode::OK, "{all}");
    assert_eq!(all["day_zone"], "UTC", "{all}");
    let _zone = crate::local_day::test_zone(chrono_tz::Europe::Amsterdam);
    let (_, all) = call(&state, "/api/costs", None).await;
    assert_eq!(all["day_zone"], "Europe/Amsterdam", "{all}");
    #[cfg(feature = "cost-governance")]
    {
        let (status, ui) = call(&state, "/ui/api/costs", None).await;
        assert_eq!(status, StatusCode::OK, "{ui}");
        assert_eq!(ui["day_zone"], "Europe/Amsterdam", "{ui}");
    }
}

#[cfg(feature = "cost-governance")]
#[tokio::test]
async fn a_recorded_key_and_the_aggregate_carry_the_spend() {
    let (state, _store) = admin_state().await;
    state
        .meta_mcp
        .cost_tracker()
        .record("sess-1", Some("ops"), "srv", "tool", 2_000_000, 3.0);

    let (status, by_key) = call(&state, "/api/costs?key=ops", None).await;
    assert_eq!(status, StatusCode::OK, "{by_key}");
    assert_eq!(by_key["api_key_name"], "ops", "{by_key}");
    assert_eq!(by_key["window_24h"]["tokens"], 2_000_000, "{by_key}");
    let cost = by_key["window_24h"]["cost_usd"].as_f64().unwrap();
    assert!((cost - 6.0).abs() < 1e-9, "{by_key}");

    let (status, all) = call(&state, "/api/costs", None).await;
    assert_eq!(status, StatusCode::OK, "{all}");
    assert_eq!(all["aggregate"]["total_calls"], 1, "{all}");
    assert_eq!(all["aggregate"]["total_tokens"], 2_000_000, "{all}");
    assert_eq!(all["sessions"].as_array().map(Vec::len), Some(1), "{all}");
    assert_eq!(all["keys"].as_array().map(Vec::len), Some(1), "{all}");
}

/// Records one call's spend under `key`.
#[cfg(feature = "cost-governance")]
fn spend_as(state: &crate::gateway::router::AppState, key: &str) {
    state
        .meta_mcp
        .cost_tracker()
        .record("sess-1", Some(key), "srv", "tool", 1_000, 1.0);
}

/// MIK-8369.COST.1: a key selector is URL-decoded before it is matched, so a
/// key whose name needs escaping is reachable: `%20` and `+` for a space, and
/// escaped reserved characters.
#[cfg(feature = "cost-governance")]
#[tokio::test]
async fn an_encoded_key_selector_selects_its_decoded_key() {
    let (state, _store) = admin_state().await;
    spend_as(&state, "team ops");
    spend_as(&state, "a&b=c");
    for (uri, key) in [
        ("/api/costs?key=team%20ops", "team ops"),
        ("/api/costs?key=team+ops", "team ops"),
        ("/api/costs?key=a%26b%3Dc", "a&b=c"),
    ] {
        let (status, body) = call(&state, uri, None).await;
        assert_eq!(status, StatusCode::OK, "{uri}: {body}");
        assert_eq!(body["api_key_name"], key, "{uri}: {body}");
    }
}

/// A repeated selector keeps its last value, judged on the decoded name, so
/// an escaped spelling of `key` is the same selector.
#[cfg(feature = "cost-governance")]
#[tokio::test]
async fn a_repeated_key_selector_keeps_the_last_decoded_value() {
    let (state, _store) = admin_state().await;
    spend_as(&state, "team ops");
    for uri in [
        "/api/costs?key=nobody&key=team%20ops",
        "/api/costs?key=nobody&k%65y=team%20ops",
    ] {
        let (status, body) = call(&state, uri, None).await;
        assert_eq!(status, StatusCode::OK, "{uri}: {body}");
        assert_eq!(body["api_key_name"], "team ops", "{uri}: {body}");
    }
}

/// MIK-8369.COST.3: the session id never travels in the URI, and an escaped
/// spelling of `session` is refused the same way.
#[tokio::test]
async fn an_escaped_session_parameter_is_refused_like_the_plain_one() {
    let (state, _store) = admin_state().await;
    for uri in ["/api/costs?session=s-1", "/api/costs?sess%69on=s-1"] {
        let (status, body) = call(&state, uri, None).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{uri}: {body}");
        assert_eq!(
            body["error"], "Pass the session id in the X-Cost-Session-Id header, not ?session=",
            "{uri}"
        );
    }
}

/// A key's report keeps its shape: the same fields, with no limit and an
/// "Ok" status, since nothing enforces a per-key rolling limit. Scripts and
/// the dashboard read these fields, so removing the dead limit code must not
/// change them.
#[cfg(feature = "cost-governance")]
#[tokio::test]
async fn a_key_report_keeps_its_fields_with_no_limit_and_an_ok_status() {
    let (state, _store) = admin_state().await;
    state
        .meta_mcp
        .cost_tracker()
        .record("sess-1", Some("ops"), "srv", "tool", 1_000, 3.0);

    let (status, by_key) = call(&state, "/api/costs?key=ops", None).await;
    assert_eq!(status, StatusCode::OK, "{by_key}");
    let (status, all) = call(&state, "/api/costs", None).await;
    assert_eq!(status, StatusCode::OK, "{all}");

    for report in [&by_key, &all["keys"][0]] {
        let mut fields: Vec<&str> = report
            .as_object()
            .expect("a key report is an object")
            .keys()
            .map(String::as_str)
            .collect();
        fields.sort_unstable();
        assert_eq!(
            fields,
            [
                "api_key_name",
                "budget_status",
                "by_tool",
                "hard_limit_usd",
                "window_24h",
                "window_30d",
                "window_7d"
            ],
            "{report}"
        );
        assert_eq!(report["hard_limit_usd"], Value::Null, "{report}");
        assert_eq!(report["budget_status"], "Ok", "{report}");
    }
}

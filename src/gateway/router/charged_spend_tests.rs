// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The cost tracker behind the costs views records the USD the budget
//! enforcer charges for each answered call, so a view and the limits read
//! one figure. Every row dispatches through the real `gateway_invoke` route.

use serde_json::{Value, json};

use super::direct_guards_fixture::{
    Answer, WITH_ADMIN, fixture_built, initialize, post_meta_invoke,
};
use super::live_budget_tests::{KEY, fixture, governance, reload};

/// One answered `gateway_invoke` of `tool` on `alpha` as [`KEY`].
async fn invoke(fx: &super::live_budget_tests::Fx, tool: &str, session: Option<&str>) {
    let (status, body) = post_meta_invoke(fx, KEY, "alpha", tool, json!({}), None, session).await;
    // A refused tool comes back as a result flagged isError, not a JSON-RPC
    // error, so both shapes count as not answered.
    let flagged = body.pointer("/result/isError") == Some(&json!(true));
    assert!(
        status.is_success() && body.get("error").is_none() && !flagged,
        "{tool} was not answered: {status} {body}"
    );
}

/// [`KEY`]'s 24-hour USD as the costs views report it.
fn key_window_usd(fx: &super::live_budget_tests::Fx) -> f64 {
    let tracker = fx.state.meta_mcp.cost_tracker();
    let report = tracker.key_snapshot(KEY).expect("the key has a report");
    report.window_24h.cost_usd.expect("a dated window")
}

/// [`KEY`]'s USD today as the budget enforcer counts it.
fn enforcer_usd(fx: &super::live_budget_tests::Fx) -> f64 {
    super::live_budget_tests::spent(fx)
}

fn close(got: f64, want: f64, what: &str) {
    assert!((got - want).abs() < 1e-9, "{what}: {got}, want {want}");
}

/// `uri` read as the fixture's admin key: the operator's HTTP costs view.
async fn admin_get(fx: &super::live_budget_tests::Fx, uri: &str) -> Value {
    use tower::ServiceExt;
    let request = axum::http::Request::builder()
        .method("GET")
        .uri(uri)
        .header("authorization", "Bearer k-admin")
        .body(axum::body::Body::empty())
        .expect("request");
    let response = fx.router.clone().oneshot(request).await.expect("response");
    assert!(
        response.status().is_success(),
        "{uri}: {}",
        response.status()
    );
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body");
    serde_json::from_slice(&bytes).expect("JSON")
}

/// Two calls in a session and one without, each priced 0.25: the key, the
/// session and the aggregate report the charged figure, through the tracker
/// and the operator's HTTP view, and tokens stay 0. Over `/mcp` a request with
/// no session header still runs under a session of its own, so the third
/// call is in the aggregate but never in a session-less caller breakdown.
#[tokio::test]
async fn a_priced_call_shows_the_charged_usd_in_every_costs_view() {
    crate::test_day::same_utc_day_async(|| async {
        let mut cfg = governance(|_| {});
        cfg.tool_costs.insert("read".to_owned(), 0.25);
        // With the admin key `k-admin`, which the HTTP costs view needs.
        WITH_ADMIN.with(|s| s.set(true));
        let fx = fixture(&cfg).await;
        WITH_ADMIN.with(|s| s.set(false));
        let session = initialize(&fx, KEY).await;
        invoke(&fx, "read", Some(&session)).await;
        invoke(&fx, "read", Some(&session)).await;
        invoke(&fx, "read", None).await;

        close(key_window_usd(&fx), 0.75, "key window");
        close(enforcer_usd(&fx), 0.75, "enforcer key total");
        let tracker = fx.state.meta_mcp.cost_tracker();
        let report = tracker.key_snapshot(KEY).expect("key report");
        assert_eq!(report.window_24h.tokens, Some(0), "no tokens are invented");

        let held = tracker.session_snapshot(&session).expect("session report");
        assert_eq!(held.call_count, 2);
        close(held.total_cost_usd, 0.50, "session");
        // The aggregate is both sessions: the shared one and the third call's.
        let all = tracker.aggregate();
        assert_eq!(all.total_calls, 3);
        assert_eq!(all.total_tokens, 0);
        close(all.total_cost_usd, 0.75, "aggregate");

        // The operator's HTTP view reports the same key total, for this key:
        // 0.75 is also the gateway total here, so the name is checked too.
        let by_key = admin_get(&fx, &format!("/api/costs?key={KEY}")).await;
        assert_eq!(by_key["api_key_name"], KEY, "{by_key}");
        let usd = by_key["window_24h"]["cost_usd"].as_f64();
        let usd = usd.unwrap_or_else(|| panic!("no USD: {by_key}"));
        close(usd, 0.75, "/api/costs key window");
    })
    .await;
}

/// With no enforcer there is no price: a call is counted at 0 USD.
#[tokio::test]
async fn with_governance_off_at_start_a_call_records_no_usd() {
    let fx = fixture_built(Answer::Ok, |meta| meta).await;
    invoke(&fx, "read", None).await;
    close(key_window_usd(&fx), 0.0, "key window");
    assert_eq!(fx.state.meta_mcp.cost_tracker().aggregate().total_calls, 1);
}

/// A reload that turns governance off leaves the enforcer charging; the
/// tracker records what it charges, not what the reloaded flag says.
#[tokio::test]
async fn governance_turned_off_by_reload_still_records_the_charge() {
    crate::test_day::same_utc_day_async(|| async {
        let mut cfg = governance(|_| {});
        cfg.tool_costs.insert("read".to_owned(), 0.25);
        let fx = fixture(&cfg).await;
        reload(&fx, |c| c.enabled = false);
        invoke(&fx, "read", None).await;
        close(enforcer_usd(&fx), 0.25, "enforcer key total");
        close(key_window_usd(&fx), 0.25, "key window");
    })
    .await;
}

/// A tool with no listed cost is charged the default in both places.
#[tokio::test]
async fn an_unlisted_tool_records_the_default_cost() {
    crate::test_day::same_utc_day_async(|| async {
        // `read` is the fixture's answered tool; without its listed cost it
        // is an unlisted tool and takes the default.
        let mut cfg = governance(|c| c.tool_costs.clear());
        cfg.default_cost = 0.10;
        let fx = fixture(&cfg).await;
        invoke(&fx, "read", None).await;
        close(enforcer_usd(&fx), 0.10, "enforcer key total");
        close(key_window_usd(&fx), 0.10, "key window");
    })
    .await;
}

/// A price below one micro-USD's resolution lands as the same whole
/// micro-USD on both sides, and the view reports it.
#[tokio::test]
async fn a_fractional_price_records_the_same_micro_usd_on_both_sides() {
    crate::test_day::same_utc_day_async(|| async {
        let mut cfg = governance(|_| {});
        cfg.tool_costs.insert("read".to_owned(), 0.000_001_5);
        let fx = fixture(&cfg).await;
        invoke(&fx, "read", None).await;
        close(enforcer_usd(&fx), 0.000_002, "enforcer key total");
        close(key_window_usd(&fx), 0.000_002, "key window");
    })
    .await;
}

/// S1 (r7b carry): what a real priced call was charged comes back from the
/// spend history: saved, then restored into a new tracker, the key's window
/// still reads 0.25.
#[tokio::test]
async fn a_priced_calls_charge_comes_back_from_the_spend_history() {
    use crate::cost_accounting::{CostTracker, spend_history};
    let priced = governance(|c| {
        c.tool_costs.insert("read".to_owned(), 0.25);
    });
    let run = || async {
        let fx = fixture(&priced).await;
        invoke(&fx, "read", None).await;
        let dir = crate::test_dir_keep::kept_tempdir();
        let now = crate::clock::unix_secs().expect("a clock");
        let live = fx.state.meta_mcp.cost_tracker();
        assert!(spend_history::save(&live, dir.path(), now), "saved");
        let back = CostTracker::new();
        spend_history::restore(&back, dir.path(), &[KEY.to_owned()], Some(now));
        let report = back.key_snapshot(KEY).expect("the key came back");
        let usd = report.window_24h.cost_usd.expect("a dated window");
        close(usd, 0.25, "restored key window");
    };
    crate::test_day::same_utc_day_async(run).await;
}

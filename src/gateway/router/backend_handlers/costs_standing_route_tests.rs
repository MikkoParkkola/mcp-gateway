// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! `GET /ui/api/costs`: each key row carries where it stands against its own
//! daily limit, and the body says when limits next reset.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::{Value, json};
use tower::ServiceExt;

use crate::clock::test_clock;
use crate::cost_accounting::config::{AlertAction, AlertRule, BudgetLimits, CostGovernanceConfig};
use crate::cost_accounting::enforcer::BudgetEnforcer;
use crate::cost_accounting::registry::CostRegistry;
use crate::gateway::router::create_router;
use crate::gateway::router::tests::{
    FixtureDir, full_admin_auth_config, test_router_app_state_with_auth_and_config,
};

type State = Arc<crate::gateway::router::AppState>;

/// 2026-03-29 10:00 UTC; tests count days in UTC.
const NOW: u64 = 1_774_778_400;
/// The next UTC midnight.
const RESETS_AT: u64 = 1_774_828_800;

fn rule(at_percent: u32, action: AlertAction) -> AlertRule {
    AlertRule { at_percent, action }
}

fn governance(limits: &[(&str, f64)], alerts: Vec<AlertRule>) -> CostGovernanceConfig {
    let mut config = CostGovernanceConfig {
        enabled: true,
        alerts,
        budgets: BudgetLimits {
            per_key: limits.iter().map(|(k, v)| ((*k).to_string(), *v)).collect(),
            ..BudgetLimits::default()
        },
        ..CostGovernanceConfig::default()
    };
    config.tool_costs.insert("cheap".to_string(), 0.01);
    config.tool_costs.insert("dear".to_string(), 3.0);
    config
}

fn default_rules() -> Vec<AlertRule> {
    CostGovernanceConfig::default().alerts
}

/// An admin state governed by `governance`, with its enforcer installed as
/// the gateway builds it.
async fn governed(governance: CostGovernanceConfig) -> (State, FixtureDir, Arc<BudgetEnforcer>) {
    let config = crate::config::Config {
        cost_governance: governance.clone(),
        ..crate::config::Config::default()
    };
    let (mut state, dir) =
        test_router_app_state_with_auth_and_config(&full_admin_auth_config(), config).await;
    let registry = Arc::new(CostRegistry::new(&governance));
    let enforcer = Arc::new(BudgetEnforcer::new(governance, Arc::clone(&registry)));
    let meta = Arc::get_mut(&mut Arc::get_mut(&mut state).expect("state is unique").meta_mcp)
        .expect("meta is unique");
    meta.budget_enforcer = Some(Arc::clone(&enforcer));
    meta.cost_registry = Some(registry);
    (state, dir, enforcer)
}

/// Publish `governance` as a reload would.
fn reload(state: &State, governance: CostGovernanceConfig) {
    let mut config = (*state.live_config.get()).clone();
    config.cost_governance = governance;
    state.live_config.set(config);
}

/// `key` spent `usd` today, in the enforcer and in the per-key series.
fn spent(state: &State, enforcer: &BudgetEnforcer, key: &str, usd: f64) {
    enforcer.record_spend("dear", Some(key), usd);
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    let tokens = (usd * 1_000_000.0).round() as u64;
    state
        .meta_mcp
        .cost_tracker()
        .record("sess-1", Some(key), "srv", "dear", tokens, 1.0);
}

async fn costs(state: &State) -> Value {
    admin_get(state, "/ui/api/costs").await
}

async fn admin_get(state: &State, uri: &str) -> Value {
    let response = create_router(Arc::clone(state))
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(uri)
                .header("authorization", "Bearer scoped-key")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

fn row<'a>(body: &'a Value, key: &str) -> &'a Value {
    body["by_key"]
        .as_array()
        .and_then(|rows| rows.iter().find(|row| row["api_key_name"] == key))
        .unwrap_or_else(|| panic!("no row for {key}: {body}"))
}

/// The four members, the two figures, the reset time; nothing that was there
/// before is gone.
#[tokio::test]
async fn s10_the_ui_costs_rows_carry_the_four_members_and_the_body_resets_at() {
    let _clock = test_clock::at_secs(NOW);
    let limits = [("blocked", 25.0), ("near", 25.0)];
    let (state, _dir, enforcer) = governed(governance(&limits, default_rules())).await;
    spent(&state, &enforcer, "blocked", 24.99);
    spent(&state, &enforcer, "near", 21.0);
    spent(&state, &enforcer, "free", 3.5);
    assert!(!enforcer.check("cheap", Some("blocked")).allowed, "premise");

    let body = costs(&state).await;
    assert_eq!(body["resets_at"], json!(RESETS_AT), "{body}");
    assert!(body.get("alert_rules").is_none(), "ordered rules: {body}");
    for member in ["aggregate", "by_key", "by_session", "day_zone"] {
        assert!(body.get(member).is_some(), "{member} gone: {body}");
    }
    let blocked = row(&body, "blocked");
    assert_eq!(blocked["at_limit"], "block", "{blocked}");
    assert_eq!(blocked["blocking"], true, "{blocked}");
    assert_eq!(blocked["blocked_since"], json!(NOW), "{blocked}");
    assert_eq!(blocked["daily_limit_usd"], json!(25.0), "{blocked}");
    assert!(blocked["rate_3h_usd_per_hour"].is_number(), "{blocked}");
    let near = row(&body, "near");
    assert_eq!(near["at_limit"], "block", "{near}");
    assert_eq!(near["blocking"], false, "{near}");
    assert_eq!(near["blocked_since"], Value::Null, "{near}");
    let free = row(&body, "free");
    assert_eq!(free["at_limit"], Value::Null, "{free}");
    assert_eq!(free["blocking"], false, "{free}");
    assert_eq!(free["daily_limit_usd"], Value::Null, "{free}");
    for row in [blocked, near, free] {
        for member in ["window_24h", "window_7d", "window_30d"] {
            assert!(row.get(member).is_some(), "{member} gone: {row}");
        }
    }
}

/// Each row's rate is its own key's spend over the three complete hours
/// before now, over three; the current hour does not count.
#[tokio::test]
async fn s10b_each_row_carries_its_own_keys_three_hour_rate() {
    let (state, _dir, enforcer) = {
        let _clock = test_clock::at_secs(NOW);
        governed(governance(&[("ci", 25.0)], default_rules())).await
    };
    for (at, key, usd) in [
        (NOW - 7200 + 60, "ci", 0.6),
        (NOW - 3600 + 60, "ci", 0.9),
        (NOW - 3600 + 60, "other", 3.0),
        (NOW + 60, "ci", 5.0),
    ] {
        let _clock = test_clock::at_secs(at);
        spent(&state, &enforcer, key, usd);
    }
    let _clock = test_clock::at_secs(NOW + 120);
    let body = costs(&state).await;
    assert_eq!(
        row(&body, "ci")["rate_3h_usd_per_hour"],
        json!(0.5),
        "{body}"
    );
    assert_eq!(
        row(&body, "other")["rate_3h_usd_per_hour"],
        json!(1.0),
        "{body}"
    );
}

/// A rule change by reload changes `at_limit` with no restart.
#[tokio::test]
async fn s11_a_rule_change_by_reload_changes_at_limit_without_a_restart() {
    let _clock = test_clock::at_secs(NOW);
    let limits = [("ci", 25.0)];
    let (state, _dir, enforcer) = governed(governance(&limits, default_rules())).await;
    spent(&state, &enforcer, "ci", 1.0);
    assert_eq!(row(&costs(&state).await, "ci")["at_limit"], "block");
    reload(
        &state,
        governance(&limits, vec![rule(80, AlertAction::Notify)]),
    );
    assert_eq!(row(&costs(&state).await, "ci")["at_limit"], "notify");
}

/// A clock before 1970: no rate and no reset time, never zero.
#[tokio::test]
async fn s9_a_dark_clock_reads_null_never_zero() {
    let (state, _dir, enforcer) = {
        let _clock = test_clock::at_secs(NOW);
        governed(governance(&[("ci", 25.0)], default_rules())).await
    };
    {
        let _clock = test_clock::at_secs(NOW);
        spent(&state, &enforcer, "ci", 1.0);
    }
    let _dark = test_clock::before_epoch();
    let body = costs(&state).await;
    assert_eq!(body["resets_at"], Value::Null, "{body}");
    let ci = row(&body, "ci");
    assert_eq!(ci["rate_3h_usd_per_hour"], Value::Null, "{ci}");
    assert_eq!(ci["blocking"], false, "{ci}");
    assert_eq!(ci["blocked_since"], Value::Null, "{ci}");
}

/// Today's judged spend and the key's own limit, from the request's
/// generation: a reload that changes the limit changes the answer.
#[tokio::test]
async fn s13_each_row_carries_todays_spend_and_the_limit() {
    let _clock = test_clock::at_secs(NOW);
    let (state, _dir, enforcer) = governed(governance(&[("ci", 25.0)], default_rules())).await;
    spent(&state, &enforcer, "ci", 3.5);
    spent(&state, &enforcer, "free", 2.0);
    let body = costs(&state).await;
    assert_eq!(row(&body, "ci")["today_usd"], json!(3.5), "{body}");
    assert_eq!(row(&body, "ci")["daily_limit_usd"], json!(25.0), "{body}");
    assert_eq!(row(&body, "free")["today_usd"], json!(2.0), "{body}");
    assert_eq!(row(&body, "free")["daily_limit_usd"], Value::Null, "{body}");
    reload(&state, governance(&[("ci", 40.0)], default_rules()));
    assert_eq!(
        row(&costs(&state).await, "ci")["daily_limit_usd"],
        json!(40.0)
    );
}

/// The route half of s2f: rules that are not ordered by severity are said in
/// the answer; ordered ones say nothing.
#[tokio::test]
async fn s2f_unordered_rules_are_said_in_the_route_answer() {
    let _clock = test_clock::at_secs(NOW);
    let unordered = vec![rule(80, AlertAction::Block), rule(100, AlertAction::Notify)];
    let (state, _dir, _enforcer) = governed(governance(&[("ci", 25.0)], unordered)).await;
    assert_eq!(costs(&state).await["alert_rules"], "unordered");
    reload(&state, governance(&[("ci", 25.0)], default_rules()));
    assert!(costs(&state).await.get("alert_rules").is_none());
}

/// The keys the overview's needs-you list warns about at its limit.
async fn overview_warned(state: &State) -> Vec<String> {
    let body = admin_get(state, "/ui/api/overview").await;
    body["needs_you"]["rows"]
        .as_array()
        .unwrap_or_else(|| panic!("no needs-you rows: {body}"))
        .iter()
        .filter(|row| row["kind"] == "limit_80")
        .filter_map(|row| row["subject"].as_str().map(str::to_owned))
        .collect()
}

/// The Costs list warns at the overview's own threshold.
/// The answer's `warn_at_percent` is the lowest Notify rule's percent, 80
/// with no Notify rule, and null with no enforcer; the overview warns at the
/// same percent from the same rules.
#[tokio::test]
async fn s14_warn_at_percent_is_the_overviews_threshold() {
    let _clock = test_clock::at_secs(NOW);
    let limits = [("near", 10.0), ("low", 10.0), ("high", 10.0)];
    let at_70 = vec![rule(70, AlertAction::Notify), rule(100, AlertAction::Block)];
    let (state, _dir, enforcer) = governed(governance(&limits, at_70)).await;
    spent(&state, &enforcer, "near", 7.2);
    spent(&state, &enforcer, "low", 6.9);
    spent(&state, &enforcer, "high", 8.5);
    assert_eq!(costs(&state).await["warn_at_percent"], json!(70.0));
    assert_eq!(overview_warned(&state).await, ["key:high", "key:near"]);

    reload(
        &state,
        governance(&limits, vec![rule(100, AlertAction::Block)]),
    );
    assert_eq!(costs(&state).await["warn_at_percent"], json!(80.0));
    assert_eq!(overview_warned(&state).await, ["key:high"]);

    let config = crate::config::Config {
        cost_governance: governance(&limits, default_rules()),
        ..crate::config::Config::default()
    };
    let (bare, _bare_dir) =
        test_router_app_state_with_auth_and_config(&full_admin_auth_config(), config).await;
    assert!(
        bare.meta_mcp.budget_enforcer.is_none(),
        "premise: no enforcer"
    );
    let body = costs(&bare).await;
    assert!(
        body.get("warn_at_percent").is_some(),
        "the member is sent: {body}"
    );
    assert_eq!(body["warn_at_percent"], Value::Null, "{body}");
}

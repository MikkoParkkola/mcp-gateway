// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! `GET /ui/api/overview` rows O1-O6: admin only, one round trip for the
//! first screen, a body bounded whatever the server count, the 80% budget
//! row, the newest admin actions, and the rule that a section with no source
//! is absent, never a zero. Every request goes through `create_router`, so
//! the real auth middleware runs.

use std::sync::Arc;
use std::time::Duration;

use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode, header};
use serde_json::{Map, Value, json};
use tower::ServiceExt;

use super::tests::test_router_app_state_with_auth_and_key_server;
use super::{AppState, create_router};
use crate::backend::Backend;
use crate::config::{ApiKeyConfig, AuthConfig, BackendConfig, FailsafeConfig};
use crate::security::TransparencyLogger;
use crate::security::audit::{AuditEnvelope, AuditWho};
use crate::security::transparency_log::TransparencyLogConfig;

const OVERVIEW: &str = "/ui/api/overview";
const ADMIN_KEY: &str = "overview-admin-key";
const STANDARD_KEY: &str = "overview-standard-key";
/// The handler's caps (`ui/overview.rs`), repeated so a changed cap is a
/// deliberate edit in both places.
const SERVER_ROWS: usize = 24;
const NEEDS_YOU_ROWS: usize = 20;
const ACTION_ROWS: usize = 5;

fn api_key(key: &str, admin: bool) -> ApiKeyConfig {
    ApiKeyConfig {
        key: None,
        key_sha256: Some(crate::config::api_key_digest_spec(key.as_bytes())),
        expires_at: None,
        name: key.to_string(),
        rate_limit: 0,
        backends: vec!["*".to_string()],
        allowed_tools: None,
        denied_tools: None,
        admin,
        kind: crate::config::ApiKeyKind::Shared,
    }
}

/// Auth on, one admin and one standard key, and `servers` registered
/// backends named `name-NNN` (`long` pads each name to 200 characters).
async fn fixture(servers: usize, long: bool) -> (Arc<AppState>, tempfile::TempDir) {
    let auth = AuthConfig {
        enabled: true,
        api_keys: vec![api_key(ADMIN_KEY, true), api_key(STANDARD_KEY, false)],
        ..AuthConfig::default()
    };
    let (state, dir) = test_router_app_state_with_auth_and_key_server(&auth, None).await;
    for i in 0..servers {
        let mut name = format!("name-{i:03}");
        if long {
            name.push_str(&"x".repeat(200 - name.len()));
        }
        let backend = Arc::new(Backend::new(
            &name,
            BackendConfig::default(),
            &FailsafeConfig::default(),
            Duration::from_secs(300),
        ));
        assert!(state.backends.register(backend), "register {name}");
    }
    (state, dir)
}

async fn get(state: &Arc<AppState>, bearer: Option<&str>) -> (StatusCode, String) {
    let mut builder = Request::builder().method("GET").uri(OVERVIEW);
    if let Some(credential) = bearer {
        builder = builder.header(header::AUTHORIZATION, format!("Bearer {credential}"));
    }
    let request = builder.body(Body::empty()).expect("request builds");
    let response = tokio::time::timeout(
        Duration::from_secs(30),
        create_router(Arc::clone(state)).oneshot(request),
    )
    .await
    .expect("the request finished")
    .expect("the router is infallible");
    let status = response.status();
    let body = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body reads");
    (status, String::from_utf8_lossy(&body).into_owned())
}

async fn overview(state: &Arc<AppState>) -> Value {
    let (status, body) = get(state, Some(ADMIN_KEY)).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    serde_json::from_str(&body).expect("a JSON body")
}

/// O1: auth on, an unauthenticated caller is stopped by the middleware (401),
/// an authenticated non-admin gets 403, and neither refusal carries data.
#[tokio::test]
async fn o1_only_an_admin_reads_the_overview() {
    let (state, _dir) = fixture(2, false).await;
    let (anonymous, body) = get(&state, None).await;
    assert_eq!(anonymous, StatusCode::UNAUTHORIZED, "{body}");
    assert!(!body.contains("name-000"), "{body}");
    let (standard, body) = get(&state, Some(STANDARD_KEY)).await;
    assert_eq!(standard, StatusCode::FORBIDDEN, "{body}");
    assert!(
        !body.contains("name-000") && !body.contains("kpi"),
        "{body}"
    );
    let (admin, body) = get(&state, Some(ADMIN_KEY)).await;
    assert_eq!(admin, StatusCode::OK, "{body}");
}

/// O2 (API16.1, the sections that have a source on this line): one call
/// carries the KPI strip, the servers, needs-you and the checklist; the KPI
/// counts match the registry.
#[tokio::test]
async fn o2_one_call_carries_the_first_screen() {
    let (state, _dir) = fixture(3, false).await;
    let body = overview(&state).await;
    assert!(body["generated_at"].is_string(), "{body}");
    let kpi = &body["kpi"];
    assert_eq!(kpi["servers_total"], 3, "{body}");
    assert_eq!(kpi["servers_up"], 0, "registered but never started: {body}");
    assert_eq!(kpi["tools_total"], 0, "{body}");
    assert!(kpi["uptime_secs"].is_u64(), "{body}");
    assert_eq!(kpi["version"], env!("CARGO_PKG_VERSION"), "{body}");
    let names: Vec<&str> = body["servers"]["rows"]
        .as_array()
        .expect("server rows")
        .iter()
        .map(|row| row["name"].as_str().expect("a name"))
        .collect();
    assert_eq!(names, ["name-000", "name-001", "name-002"], "name order");
    assert_eq!(body["servers"]["more"]["count"], 0, "{body}");
    assert!(body["needs_you"]["rows"].is_array(), "{body}");
    assert_eq!(body["checklist"]["has_key"], true, "{body}");
}

/// O3 (API16.2): 140 servers with 200-character names. The server rows stop
/// at the cap, the rest are counted in `more`, and the body stays under a
/// ceiling computed from the caps, not from the server count.
#[tokio::test]
async fn o3_a_140_server_gateway_returns_a_bounded_body() {
    let (state, _dir) = fixture(140, true).await;
    let (status, raw) = get(&state, Some(ADMIN_KEY)).await;
    assert_eq!(status, StatusCode::OK, "{raw}");
    let body: Value = serde_json::from_str(&raw).expect("a JSON body");
    assert_eq!(
        body["servers"]["rows"].as_array().map(Vec::len),
        Some(SERVER_ROWS),
        "{raw}"
    );
    assert_eq!(body["servers"]["more"]["count"], 140 - SERVER_ROWS, "{raw}");
    assert_eq!(body["kpi"]["servers_total"], 140, "{raw}");
    // Per server row: a 200-byte name plus at most ~64 bytes of fields.
    // Fixed sections: well under 4 KiB without U1/U4 data.
    let ceiling = SERVER_ROWS * 264 + NEEDS_YOU_ROWS * 512 + ACTION_ROWS * 512 + 4096;
    assert!(
        raw.len() <= ceiling,
        "{} bytes over the {ceiling}-byte ceiling",
        raw.len()
    );
}

/// O6: a section with no source on this line is absent, never a zero or an
/// empty list, and no `degraded` list appears when nothing failed.
#[tokio::test]
async fn o6_a_section_without_a_source_is_absent_not_zero() {
    let (state, _dir) = fixture(1, false).await;
    let body = overview(&state).await;
    for absent in ["edges", "markers", "last_actions", "degraded"] {
        assert!(body.get(absent).is_none(), "{absent} present: {body}");
    }
    for absent in ["calls_24h", "blocks_24h", "errors_24h"] {
        assert!(body["kpi"].get(absent).is_none(), "kpi.{absent}: {body}");
    }
    for absent in ["tool_tried", "client_connected"] {
        assert!(
            body["checklist"].get(absent).is_none(),
            "checklist.{absent}: {body}"
        );
    }
    let kinds: Vec<&Value> = body["needs_you"]["rows"]
        .as_array()
        .expect("needs-you rows")
        .iter()
        .map(|row| &row["kind"])
        .collect();
    for absent in ["sign_in", "decisions"] {
        assert!(!kinds.iter().any(|k| *k == absent), "{absent}: {body}");
    }
}

/// A transparency log at `dir`, shared with the state as the server wires it.
fn with_log(state: &mut Arc<AppState>, dir: &tempfile::TempDir) -> Arc<TransparencyLogger> {
    let log = Arc::new(
        TransparencyLogger::open(Arc::new(TransparencyLogConfig {
            enabled: true,
            path: dir
                .path()
                .join("overview-audit.jsonl")
                .to_string_lossy()
                .into_owned(),
            key_id: "overview".to_string(),
            ..TransparencyLogConfig::default()
        }))
        .expect("open log"),
    );
    Arc::get_mut(state)
        .expect("state is unique")
        .transparency_log = Some(Arc::clone(&log));
    log
}

fn admin_action(log: &TransparencyLogger, route: &str) {
    let mut fields = Map::new();
    fields.insert("route".into(), route.into());
    fields.insert("method".into(), "POST".into());
    let envelope = AuditEnvelope::ok(AuditWho::from_actor_id("operator"));
    log.append_admin_action("admin_ui", fields, &envelope)
        .expect("admin action appended");
}

/// O5: no log configured, `last_actions` is absent and not degraded. With a
/// log, seven admin actions and invocation records after them: the five
/// newest actions, newest first. A log that cannot be read: absent, and
/// `degraded` names it.
#[tokio::test]
async fn o5_last_actions_are_the_newest_admin_actions() {
    let (mut state, _dir) = fixture(1, false).await;
    let body = overview(&state).await;
    assert!(body.get("last_actions").is_none(), "no log: {body}");

    let logs = tempfile::tempdir().expect("log dir");
    let log = with_log(&mut state, &logs);
    for i in 0..7 {
        admin_action(&log, &format!("/ui/api/route-{i}"));
    }
    for _ in 0..50 {
        let mut fields = Map::new();
        fields.insert("event".into(), "invocation_note".into());
        let envelope = AuditEnvelope::ok(AuditWho::from_actor_id("caller"));
        log.append_event(fields, &envelope)
            .expect("invocation appended");
    }
    let body = overview(&state).await;
    let routes: Vec<&str> = body["last_actions"]["rows"]
        .as_array()
        .expect("action rows")
        .iter()
        .map(|row| row["route"].as_str().expect("a route"))
        .collect();
    assert_eq!(
        routes,
        [
            "/ui/api/route-6",
            "/ui/api/route-5",
            "/ui/api/route-4",
            "/ui/api/route-3",
            "/ui/api/route-2"
        ],
        "{body}"
    );
    assert_eq!(body["last_actions"]["complete"], true, "{body}");
    assert!(body.get("degraded").is_none(), "{body}");

    let path = log.path();
    std::fs::remove_file(&path).expect("remove the log file");
    std::fs::create_dir(&path).expect("a directory where the log was");
    let body = overview(&state).await;
    assert!(body.get("last_actions").is_none(), "unreadable log: {body}");
    assert_eq!(body["degraded"], json!(["last_actions"]), "{body}");
}

/// O4 (API16.3, the D6 half): with the default Notify rule at 80, spend at
/// exactly 80% of the daily limit is a row (inclusive), 85% is a row with its
/// percent, 79% is none. Governance off: no limit rows at all.
#[cfg(feature = "cost-governance")]
#[tokio::test]
async fn o4_a_budget_at_its_notify_percent_needs_you() {
    use crate::cost_accounting::config::CostGovernanceConfig;
    use crate::cost_accounting::enforcer::BudgetEnforcer;
    use crate::cost_accounting::registry::CostRegistry;

    async fn limit_rows(spent: f64) -> Vec<Value> {
        let (mut state, _dir) = fixture(1, false).await;
        let mut cfg = CostGovernanceConfig {
            enabled: true,
            ..Default::default()
        };
        cfg.budgets.daily = Some(1.0);
        let enforcer = Arc::new(BudgetEnforcer::new(
            cfg.clone(),
            Arc::new(CostRegistry::new(&cfg)),
        ));
        enforcer.record_spend("search", None, spent);
        let inner = Arc::get_mut(&mut state).expect("state is unique");
        let mut meta = crate::gateway::meta_mcp::MetaMcp::new(Arc::clone(&inner.backends));
        meta.budget_enforcer = Some(enforcer);
        inner.meta_mcp = Arc::new(meta);
        let body = overview(&state).await;
        body["needs_you"]["rows"]
            .as_array()
            .expect("needs-you rows")
            .iter()
            .filter(|row| row["kind"] == "limit_80")
            .cloned()
            .collect()
    }

    let at_80 = limit_rows(0.80).await;
    assert_eq!(at_80.len(), 1, "inclusive at 80: {at_80:?}");
    let at_85 = limit_rows(0.85).await;
    assert_eq!(at_85.len(), 1, "{at_85:?}");
    assert_eq!(at_85[0]["subject"], "global", "{at_85:?}");
    let percent = at_85[0]["detail"]["percent"].as_f64().expect("a percent");
    assert!((percent - 85.0).abs() < 1e-6, "{at_85:?}");
    assert!(limit_rows(0.79).await.is_empty(), "79% is not a row");

    let (state, _dir) = fixture(1, false).await;
    let body = overview(&state).await;
    assert!(
        !body["needs_you"]["rows"]
            .as_array()
            .expect("needs-you rows")
            .iter()
            .any(|row| row["kind"] == "limit_80"),
        "governance off: {body}"
    );
}

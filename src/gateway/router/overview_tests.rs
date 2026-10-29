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
pub(super) const ADMIN_KEY: &str = "overview-admin-key";
const STANDARD_KEY: &str = "overview-standard-key";
/// The handler's caps (`ui/overview.rs`), repeated so a changed cap is a
/// deliberate edit in both places.
pub(super) const SERVER_ROWS: usize = 24;
pub(super) const NEEDS_YOU_ROWS: usize = 20;
pub(super) const ACTION_ROWS: usize = 5;
/// The longest a clipped text field serializes to: 256 bytes, each a control
/// character JSON writes as a six-byte `\u00XX` escape, plus its quotes.
pub(super) const FIELD: usize = 2 + 6 * 256;
/// The body's byte ceiling from the caps alone. Each row is its clipped text
/// fields at [`FIELD`] plus a margin for keys and numbers: a server row has one
/// text field, a needs-you row two (subject, name), an action row seven (at,
/// route, method, outcome, authority, subject, account). The rest of the body
/// (KPIs, `more`, `complete`, `degraded`) fits in 4 KiB.
pub(super) const WORST_BODY: usize = SERVER_ROWS * (FIELD + 64)
    + NEEDS_YOU_ROWS * (2 * FIELD + 256)
    + ACTION_ROWS * (7 * FIELD + 256)
    + 4096;
/// A fixed instant for the budget tests: the enforcer's day must not roll
/// over between recording spend and reading the overview.
#[cfg(feature = "cost-governance")]
pub(super) const BUDGET_NOW: u64 = 1_800_000_000;

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
        ..ApiKeyConfig::default()
    }
}

/// Auth on, one admin and one standard key, and `servers` registered
/// backends named `name-NNN` (`long` pads each name to 200 characters).
pub(super) async fn fixture(
    servers: usize,
    long: bool,
) -> (Arc<AppState>, crate::gateway::router::tests::FixtureDir) {
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

pub(super) async fn get(state: &Arc<AppState>, bearer: Option<&str>) -> (StatusCode, String) {
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

pub(super) async fn overview(state: &Arc<AppState>) -> Value {
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
    assert_eq!(body["servers"]["more"]["up"], 0, "{raw}");
    assert_eq!(body["servers"]["more"]["down"], 140 - SERVER_ROWS, "{raw}");
    assert_eq!(body["kpi"]["servers_total"], 140, "{raw}");
    assert!(
        raw.len() <= WORST_BODY,
        "{} bytes over the {WORST_BODY}-byte ceiling",
        raw.len()
    );
}

/// O3b: a name longer than the field cap is cut to 256 bytes, so one long
/// name cannot grow the body past the computed ceiling.
#[tokio::test]
async fn o3b_a_long_server_name_is_clipped() {
    let (state, _dir) = fixture(0, false).await;
    let name = "n".repeat(1000);
    let backend = Arc::new(Backend::new(
        &name,
        BackendConfig::default(),
        &FailsafeConfig::default(),
        Duration::from_secs(300),
    ));
    assert!(state.backends.register(backend), "register the long name");
    let body = overview(&state).await;
    let shown = body["servers"]["rows"][0]["name"].as_str().expect("a name");
    assert_eq!(shown.len(), 256, "{body}");
}

/// O3c: the cut lands on a character boundary. A two-byte character that
/// straddles byte 256 is dropped whole: the name comes back as the 255 bytes
/// before it, valid UTF-8, and the request does not panic.
#[tokio::test]
async fn o3c_the_cut_never_splits_a_character() {
    let (state, _dir) = fixture(0, false).await;
    let name = format!("{}é{}", "a".repeat(255), "b".repeat(10));
    let backend = Arc::new(Backend::new(
        &name,
        BackendConfig::default(),
        &FailsafeConfig::default(),
        Duration::from_secs(300),
    ));
    assert!(state.backends.register(backend), "register the name");
    let body = overview(&state).await;
    assert_eq!(
        body["servers"]["rows"][0]["name"],
        "a".repeat(255),
        "{body}"
    );
}

/// A transport that only reports itself connected, so a backend reads as up.
struct Connected;

#[async_trait::async_trait]
impl crate::transport::Transport for Connected {
    async fn request(
        &self,
        _method: &str,
        _params: Option<Value>,
    ) -> crate::Result<crate::protocol::JsonRpcResponse> {
        Ok(crate::protocol::JsonRpcResponse::success(
            crate::protocol::RequestId::Number(1),
            json!({}),
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

/// O3d: rows are chosen on the full name, not the clipped one. Thirty names
/// share their first 256 bytes, so every shown name is the same clip; server
/// `i` carries `i` tools, which identifies its row. The shown rows must be
/// servers 0-23 in order, and the six folded ones (all up) must be 24-29. A
/// sort on the clipped name ties all thirty and keeps the registry's hash
/// order, which matches only by chance (about 3 in 10^30).
#[tokio::test]
async fn o3d_the_fold_sorts_on_the_full_name() {
    const SERVERS: usize = 30;
    let (state, _dir) = fixture(0, false).await;
    for i in 0..SERVERS {
        let name = format!("{}{i:02}", "s".repeat(256));
        let backend = Arc::new(Backend::new(
            &name,
            BackendConfig::default(),
            &FailsafeConfig::default(),
            Duration::from_secs(300),
        ));
        let tools = (0..i)
            .map(|t| {
                serde_json::from_value(
                    json!({"name": format!("t{t}"), "inputSchema": {"type": "object"}}),
                )
                .expect("a tool")
            })
            .collect();
        backend.store_shared_tools_for_test(tools);
        if i >= SERVER_ROWS {
            backend.set_transport_for_test(Arc::new(Connected));
        }
        assert!(state.backends.register(backend), "register {i}");
    }
    let body = overview(&state).await;
    let shown: Vec<Value> = body["servers"]["rows"]
        .as_array()
        .expect("server rows")
        .iter()
        .map(|row| json!({ "tools": row["tools"], "up": row["up"] }))
        .collect();
    let want: Vec<Value> = (0..SERVER_ROWS)
        .map(|i| json!({ "tools": i, "up": false }))
        .collect();
    assert_eq!(shown, want, "{body}");
    assert_eq!(body["kpi"]["servers_up"], SERVERS - SERVER_ROWS, "{body}");
    assert_eq!(
        body["servers"]["more"]["count"],
        SERVERS - SERVER_ROWS,
        "{body}"
    );
    assert_eq!(
        body["servers"]["more"]["up"],
        SERVERS - SERVER_ROWS,
        "{body}"
    );
    assert_eq!(body["servers"]["more"]["down"], 0, "{body}");
}

/// The O3e fixture: every list at its cap with escape-heavy text. The clock
/// stays pinned at [`BUDGET_NOW`] while the returned guard lives.
#[cfg(feature = "cost-governance")]
pub(super) async fn worst_case() -> (
    Arc<AppState>,
    crate::gateway::router::tests::FixtureDir,
    crate::clock::test_clock::Forced,
) {
    use crate::cost_accounting::config::CostGovernanceConfig;
    use crate::cost_accounting::enforcer::BudgetEnforcer;
    use crate::cost_accounting::registry::CostRegistry;

    let heavy = "\u{1}".repeat(300);
    let (mut state, dir) = fixture(0, false).await;
    for i in 0..SERVER_ROWS + 6 {
        let backend = Arc::new(Backend::new(
            &format!("{i:02}{heavy}"),
            BackendConfig::default(),
            &FailsafeConfig::default(),
            Duration::from_secs(300),
        ));
        assert!(state.backends.register(backend), "register {i}");
    }
    let log = with_log(&mut state, &dir);
    let actor = format!("oidc:{}:{heavy}:{}:{heavy}", heavy.len(), heavy.len());
    for _ in 0..ACTION_ROWS + 2 {
        let mut fields = Map::new();
        fields.insert("route".into(), heavy.clone().into());
        fields.insert("method".into(), heavy.clone().into());
        let envelope = AuditEnvelope::ok(AuditWho::from_actor_id(&actor));
        log.append_admin_action("admin_ui", fields, &envelope)
            .expect("admin action appended");
    }
    let mut cfg = CostGovernanceConfig {
        enabled: true,
        ..Default::default()
    };
    let tools: Vec<String> = (0..NEEDS_YOU_ROWS + 2)
        .map(|i| format!("{i:02}{heavy}"))
        .collect();
    for tool in &tools {
        cfg.budgets.per_tool.insert(tool.clone(), 1.0);
    }
    let clock = crate::clock::test_clock::at_secs(BUDGET_NOW);
    let enforcer = Arc::new(BudgetEnforcer::new(
        cfg.clone(),
        Arc::new(CostRegistry::new(&cfg)),
    ));
    for tool in &tools {
        enforcer.record_spend(tool, None, 0.9);
    }
    let inner = Arc::get_mut(&mut state).expect("state is unique");
    let mut meta = crate::gateway::meta_mcp::MetaMcp::new(Arc::clone(&inner.backends));
    meta.budget_enforcer = Some(enforcer);
    inner.meta_mcp = Arc::new(meta);
    (state, dir, clock)
}

/// O3e (API16.2, worst case): every capped list full and every text field at
/// its clip, written as control characters so JSON escapes each byte six-fold.
/// The body stays under [`WORST_BODY`], and over three quarters of it, so the
/// fixture really is the worst case the ceiling is computed for.
#[cfg(feature = "cost-governance")]
#[tokio::test]
async fn o3e_a_worst_case_body_stays_under_the_ceiling() {
    let (state, _dir, _clock) = worst_case().await;
    let (status, raw) = get(&state, Some(ADMIN_KEY)).await;
    assert_eq!(status, StatusCode::OK, "{raw}");
    let body: Value = serde_json::from_str(&raw).expect("a JSON body");
    let rows = |path: [&str; 2]| body[path[0]][path[1]].as_array().map(Vec::len);
    assert_eq!(rows(["servers", "rows"]), Some(SERVER_ROWS), "{raw}");
    assert_eq!(rows(["needs_you", "rows"]), Some(NEEDS_YOU_ROWS), "{raw}");
    assert_eq!(rows(["last_actions", "rows"]), Some(ACTION_ROWS), "{raw}");
    assert!(raw.contains("\\u0001"), "the text is escape-heavy");
    assert!(
        raw.len() <= WORST_BODY,
        "{} bytes over the {WORST_BODY}-byte ceiling",
        raw.len()
    );
    assert!(
        raw.len() > WORST_BODY / 4 * 3,
        "{} bytes is not near the {WORST_BODY}-byte worst case",
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
        let _clock = crate::clock::test_clock::at_secs(BUDGET_NOW);
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

/// O4b: several budgets at or past their percent come highest first, so the
/// fold drops the least urgent: a global budget at 90% before a key at 80%.
#[cfg(feature = "cost-governance")]
#[tokio::test]
async fn o4b_limit_rows_come_highest_percent_first() {
    use crate::cost_accounting::config::CostGovernanceConfig;
    use crate::cost_accounting::enforcer::BudgetEnforcer;
    use crate::cost_accounting::registry::CostRegistry;

    let (mut state, _dir) = fixture(1, false).await;
    let mut cfg = CostGovernanceConfig {
        enabled: true,
        ..Default::default()
    };
    cfg.budgets.daily = Some(1.0);
    cfg.budgets.per_key.insert("ops".to_string(), 1.125);
    let _clock = crate::clock::test_clock::at_secs(BUDGET_NOW);
    let enforcer = Arc::new(BudgetEnforcer::new(
        cfg.clone(),
        Arc::new(CostRegistry::new(&cfg)),
    ));
    enforcer.record_spend("search", Some("ops"), 0.9);
    let inner = Arc::get_mut(&mut state).expect("state is unique");
    let mut meta = crate::gateway::meta_mcp::MetaMcp::new(Arc::clone(&inner.backends));
    meta.budget_enforcer = Some(enforcer);
    inner.meta_mcp = Arc::new(meta);
    let body = overview(&state).await;
    let subjects: Vec<&str> = body["needs_you"]["rows"]
        .as_array()
        .expect("needs-you rows")
        .iter()
        .filter(|row| row["kind"] == "limit_80")
        .map(|row| row["subject"].as_str().expect("a subject"))
        .collect();
    assert_eq!(subjects, ["global", "key:ops"], "{body}");
}

/// The overview of a one-server fixture under `cfg`, after `spend` (tool,
/// USD) is recorded.
#[cfg(feature = "cost-governance")]
async fn governed(
    cfg: crate::cost_accounting::config::CostGovernanceConfig,
    spend: &[(&str, f64)],
) -> Value {
    use crate::cost_accounting::enforcer::BudgetEnforcer;
    use crate::cost_accounting::registry::CostRegistry;

    let (mut state, _dir) = fixture(1, false).await;
    let _clock = crate::clock::test_clock::at_secs(BUDGET_NOW);
    let enforcer = Arc::new(BudgetEnforcer::new(
        cfg.clone(),
        Arc::new(CostRegistry::new(&cfg)),
    ));
    for (tool, usd) in spend {
        enforcer.record_spend(tool, None, *usd);
    }
    let inner = Arc::get_mut(&mut state).expect("state is unique");
    let mut meta = crate::gateway::meta_mcp::MetaMcp::new(Arc::clone(&inner.backends));
    meta.budget_enforcer = Some(enforcer);
    inner.meta_mcp = Arc::new(meta);
    overview(&state).await
}

/// O4c: the threshold is the lowest configured Notify percent, not a fixed 80.
#[cfg(feature = "cost-governance")]
#[tokio::test]
async fn o4c_the_threshold_is_the_configured_notify_percent() {
    use crate::cost_accounting::config::{AlertAction, AlertRule, CostGovernanceConfig};

    let mut cfg = CostGovernanceConfig {
        enabled: true,
        ..Default::default()
    };
    cfg.budgets.daily = Some(1.0);
    // The lowest Notify percent counts: not the higher Notify, and not the
    // Log rule below both.
    cfg.alerts = vec![
        AlertRule {
            at_percent: 50,
            action: AlertAction::Log,
        },
        AlertRule {
            at_percent: 60,
            action: AlertAction::Notify,
        },
        AlertRule {
            at_percent: 70,
            action: AlertAction::Notify,
        },
    ];
    let rows = |body: &Value| {
        body["needs_you"]["rows"]
            .as_array()
            .expect("needs-you rows")
            .iter()
            .filter(|row| row["kind"] == "limit_80")
            .count()
    };
    let at_60 = governed(cfg.clone(), &[("search", 0.60)]).await;
    assert_eq!(rows(&at_60), 1, "inclusive at 60: {at_60}");
    let at_59 = governed(cfg, &[("search", 0.59)]).await;
    assert_eq!(rows(&at_59), 0, "59% is under a 60% Notify: {at_59}");
}

/// O4d: more needs-you rows than the cap keeps the most urgent ones, highest
/// percent first, and counts the rest.
#[cfg(feature = "cost-governance")]
#[tokio::test]
async fn o4d_needs_you_folds_past_its_cap() {
    use crate::cost_accounting::config::CostGovernanceConfig;

    let mut cfg = CostGovernanceConfig {
        enabled: true,
        ..Default::default()
    };
    let tools: Vec<String> = (0..NEEDS_YOU_ROWS + 2)
        .map(|i| format!("tool-{i:02}"))
        .collect();
    for tool in &tools {
        cfg.budgets.per_tool.insert(tool.clone(), 1.0);
    }
    // Tool i spends 80% + i/2 %, so the two least urgent are tool-00 and
    // tool-01, and they are the ones folded.
    let spend: Vec<(&str, f64)> = tools
        .iter()
        .zip(0u32..)
        .map(|(tool, i)| (tool.as_str(), 0.80 + f64::from(i) * 0.005))
        .collect();
    let body = governed(cfg, &spend).await;
    let shown: Vec<&str> = body["needs_you"]["rows"]
        .as_array()
        .expect("needs-you rows")
        .iter()
        .map(|row| row["subject"].as_str().expect("a subject"))
        .collect();
    let want: Vec<String> = (2..NEEDS_YOU_ROWS + 2)
        .rev()
        .map(|i| format!("tool:tool-{i:02}"))
        .collect();
    assert_eq!(shown, want, "{body}");
    assert_eq!(body["needs_you"]["more"]["count"], 2, "{body}");
}

#[path = "overview_actions_tests.rs"]
mod actions_tests;

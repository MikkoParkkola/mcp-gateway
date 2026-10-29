// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! `GET /ui/api/overview` rows S1-S12: the call totals, server ranking, top
//! flows, chart markers, server state and the invalid-config and refused
//! rows. Every counter row pins the clock to 2026-06-15T12:00:00Z (a date
//! with no daylight-saving change) and records calls relative to it. The
//! clock seam is per thread, so each row runs on a current-thread runtime.

use std::sync::Arc;
use std::time::Duration;

use serde_json::Value;

use super::AppState;
use super::overview_tests::{ADMIN_KEY, fixture, get, overview};
use crate::backend::Backend;
use crate::clock::test_clock;
use crate::config::{BackendConfig, FailsafeConfig};
use crate::counters::{Call, CounterStore, Label, MarkerKind, Tally};

/// 2026-06-15T12:00:00Z.
pub(super) const NOW: u64 = 1_781_524_800;
const HOUR: u64 = 3600;

/// A state with a counter store whose coverage began at `since`.
fn with_store(state: &Arc<AppState>, since: u64) -> Arc<CounterStore> {
    let store = Arc::new(CounterStore::new(since));
    state.meta_mcp.set_counters(Arc::clone(&store));
    store
}

fn record(store: &CounterStore, caller: &str, server: &str, at: u64, tally: Tally) {
    let call = Call {
        caller,
        server: Label::Known(server),
        tool: Label::Untrusted,
        tally,
    };
    store.record(&call, at, &crate::local_day::host_zone());
}

/// `count` plain calls to `server` just before the pinned instant.
fn calls(store: &CounterStore, server: &str, count: u64) {
    for _ in 0..count {
        record(store, "key:a", server, NOW - 600, Tally::default());
    }
}

/// S1 (API16.1): the KPI strip carries the 24-hour totals.
#[tokio::test]
async fn s1_the_kpi_strip_carries_the_24_hour_totals() {
    let _clock = test_clock::at_secs(NOW);
    let (state, _dir) = fixture(1, false).await;
    let store = with_store(&state, 0);
    calls(&store, "name-000", 4);
    let blocked = Tally {
        blocked: true,
        ..Tally::default()
    };
    let failed = Tally {
        error: true,
        ..Tally::default()
    };
    record(&store, "key:a", "name-000", NOW - 600, blocked);
    record(&store, "key:a", "name-000", NOW - 600, blocked);
    record(&store, "key:a", "name-000", NOW - 600, failed);

    let body = overview(&state).await;

    let kpi = &body["kpi"];
    assert_eq!(kpi["calls_24h"], 7, "{body}");
    assert_eq!(kpi["blocks_24h"], 2, "{body}");
    assert_eq!(kpi["errors_24h"], 1, "{body}");
    assert_eq!(kpi["counting_since"], 0, "{body}");
}

/// S1b: the previous 24 hours is present only when the store covers all of it.
#[tokio::test]
async fn s1b_the_previous_period_needs_full_coverage() {
    let _clock = test_clock::at_secs(NOW);
    let (state, _dir) = fixture(1, false).await;
    let store = with_store(&state, 0);
    record(&store, "key:a", "name-000", NOW - 600, Tally::default());
    for _ in 0..4 {
        record(
            &store,
            "key:a",
            "name-000",
            NOW - 25 * HOUR,
            Tally::default(),
        );
    }
    let full = overview(&state).await;
    assert_eq!(full["kpi"]["calls_prev_24h"], 4, "{full}");

    let (partial_state, _dir) = fixture(1, false).await;
    let partial_store = with_store(&partial_state, NOW - HOUR);
    record(
        &partial_store,
        "key:a",
        "name-000",
        NOW - 600,
        Tally::default(),
    );
    let partial = overview(&partial_state).await;

    assert_eq!(partial["kpi"]["calls_24h"], 1, "{partial}");
    assert!(partial["kpi"].get("calls_prev_24h").is_none(), "{partial}");
}

/// S2 (D1): thirty servers whose call counts disagree with name order; the
/// rows are the top 24 by calls, ties by name, and the rest fold into `more`.
#[tokio::test]
async fn s2_servers_rank_by_calls_then_name() {
    let _clock = test_clock::at_secs(NOW);
    let (state, _dir) = fixture(30, false).await;
    let store = with_store(&state, 0);
    let mut model: Vec<(String, u64)> = (0..30)
        .map(|i| {
            let count = if i >= 28 { 30 } else { (i * 11) % 28 + 2 };
            (format!("name-{i:03}"), count)
        })
        .collect();
    for (name, count) in &model {
        calls(&store, name, *count);
    }
    model.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));

    let body = overview(&state).await;

    let rows = body["servers"]["rows"].as_array().expect("server rows");
    let shown: Vec<(&str, u64)> = rows
        .iter()
        .map(|r| {
            (
                r["name"].as_str().unwrap_or(""),
                r["calls_24h"].as_u64().unwrap_or(u64::MAX),
            )
        })
        .collect();
    let want: Vec<(&str, u64)> = model
        .iter()
        .take(24)
        .map(|(n, c)| (n.as_str(), *c))
        .collect();
    assert_eq!(shown, want, "{body}");
    assert_eq!(body["servers"]["more"]["count"], 6, "{body}");
    assert_eq!(body["servers"]["more"]["down"], 6, "{body}");
}

/// S3 (D2): sixty caller x server pairs; the rows are the top 48 by calls
/// (ties by caller, then server) with their blocks, and `more` counts the 12
/// left and their calls. A pair whose only calls are 25 hours old is neither
/// listed nor counted.
#[tokio::test]
async fn s3_edges_list_the_top_48_pairs() {
    let _clock = test_clock::at_secs(NOW);
    let (state, _dir) = fixture(0, false).await;
    let store = with_store(&state, 0);
    let mut model: Vec<(String, String, u64, u64)> = Vec::new();
    for idx in 0..60u64 {
        let (caller, server) = (format!("key:c{}", idx / 20), format!("srv-{}", idx % 20));
        let count = if idx >= 58 { 60 } else { idx + 1 };
        let blocks = (idx % 3).min(count);
        for n in 0..count {
            let tally = Tally {
                blocked: n < blocks,
                ..Tally::default()
            };
            record(&store, &caller, &server, NOW - 600, tally);
        }
        model.push((caller, server, count, blocks));
    }
    record(
        &store,
        "key:old",
        "srv-0",
        NOW - 25 * HOUR,
        Tally::default(),
    );
    model.sort_by(|a, b| b.2.cmp(&a.2).then_with(|| (&a.0, &a.1).cmp(&(&b.0, &b.1))));

    let body = overview(&state).await;

    assert!(body["edges"]["rows"].is_array(), "edges absent: {body}");
    let rows = body["edges"]["rows"].as_array().expect("edge rows");
    let shown: Vec<(String, String, u64, u64)> = rows
        .iter()
        .map(|r| {
            let text = |k: &str| r[k].as_str().unwrap_or("").to_owned();
            (
                text("caller"),
                text("server"),
                r["calls"].as_u64().unwrap_or(0),
                r["blocks"].as_u64().unwrap_or(0),
            )
        })
        .collect();
    assert_eq!(shown, model[..48], "{body}");
    let rest: u64 = model[48..].iter().map(|row| row.2).sum();
    assert_eq!(body["edges"]["more"]["count"], 12, "{body}");
    assert_eq!(body["edges"]["more"]["calls"], rest, "{body}");
    assert_eq!(body["edges"]["more"]["overflow_calls"], 0, "{body}");
}

/// S4 (API16.1, D4): sixty markers in the last 24 hours and five older ones;
/// fifty rows come back newest first, `more` counts ten, no older marker
/// appears, and a long subject is shown as the store normalized it.
#[tokio::test]
async fn s4_markers_are_the_newest_fifty_of_the_last_day() {
    let _clock = test_clock::at_secs(NOW);
    let (state, _dir) = fixture(0, false).await;
    let store = with_store(&state, 0);
    for i in 0..5 {
        store.mark(MarkerKind::Restart, Some("old"), NOW - 30 * HOUR - i);
    }
    for i in 0..60 {
        store.mark(
            MarkerKind::ConfigReload,
            Some(&format!("m{i:02}")),
            NOW - 3000 + i,
        );
    }
    store.mark(MarkerKind::Upgrade, Some(&"v".repeat(400)), NOW - 10);
    let want = crate::counters::normalize(&"v".repeat(400));

    let body = overview(&state).await;

    assert!(body["markers"]["rows"].is_array(), "markers absent: {body}");
    let rows = body["markers"]["rows"].as_array().expect("marker rows");
    assert_eq!(rows.len(), 50, "{body}");
    assert_eq!(rows[0]["subject"], want.as_str(), "{body}");
    assert_eq!(rows[0]["kind"], "upgrade", "{body}");
    assert_eq!(rows[1]["subject"], "m59", "{body}");
    assert_eq!(rows[49]["subject"], "m11", "{body}");
    assert_eq!(body["markers"]["more"]["count"], 11, "{body}");
    assert!(!body.to_string().contains("\"old\""), "{body}");
}

/// `count` backends named `name-NNN`, kept so a row can read their counters.
fn register(state: &Arc<AppState>, count: usize) -> Vec<Arc<Backend>> {
    (0..count)
        .map(|i| {
            let backend = Arc::new(Backend::new(
                &format!("name-{i:03}"),
                BackendConfig::default(),
                &FailsafeConfig::default(),
                Duration::from_secs(300),
            ));
            assert!(
                state.backends.register(Arc::clone(&backend)),
                "register {i}"
            );
            backend
        })
        .collect()
}

/// S5 (D5): `tool_tried` is true when the last 30 local days hold a call;
/// `client_connected` is never sent.
#[tokio::test]
async fn s5_tool_tried_looks_back_thirty_days() {
    let _clock = test_clock::at_secs(NOW);
    for (age_days, want) in [(None, false), (Some(10), true), (Some(31), false)] {
        let (state, _dir) = fixture(0, false).await;
        let store = with_store(&state, 0);
        if let Some(days) = age_days {
            record(
                &store,
                "key:a",
                "srv",
                NOW - days * 24 * HOUR,
                Tally::default(),
            );
        }
        let body = overview(&state).await;
        assert_eq!(
            body["checklist"]["tool_tried"], want,
            "{age_days:?}: {body}"
        );
        assert!(
            body["checklist"].get("client_connected").is_none(),
            "{body}"
        );
    }
}

/// S6 (D6): thirty idle servers; each of the 24 rows carries a state and a
/// reason, and the state is worked out for those 24 only.
#[tokio::test]
async fn s6_state_is_read_for_the_rows_shown_only() {
    let (state, _dir) = fixture(0, false).await;
    let backends = register(&state, 30);

    let body = overview(&state).await;

    let rows = body["servers"]["rows"].as_array().expect("server rows");
    for row in rows {
        assert_eq!(row["state"], "dormant", "{body}");
        assert!(
            row["reason"].as_str().is_some_and(|r| !r.is_empty()),
            "{body}"
        );
    }
    let evaluations: usize = backends
        .iter()
        .map(|b| b.server_state_evaluations_for_test())
        .sum();
    assert_eq!(evaluations, 24);
}

/// Asserts that every field the counter store feeds is absent from `body`.
fn assert_no_counter_fields(body: &Value) {
    for absent in [
        "calls_24h",
        "calls_prev_24h",
        "blocks_24h",
        "blocks_prev_24h",
        "errors_24h",
        "errors_prev_24h",
        "counting_since",
    ] {
        assert!(body["kpi"].get(absent).is_none(), "kpi.{absent}: {body}");
    }
    for row in body["servers"]["rows"].as_array().expect("server rows") {
        assert!(row.get("calls_24h").is_none(), "servers.rows: {body}");
    }
    assert!(body.get("edges").is_none(), "edges: {body}");
    assert!(body.get("markers").is_none(), "markers: {body}");
    assert!(body["checklist"].get("tool_tried").is_none(), "{body}");
}

/// S8: no counter store, so the counter fields are absent and nothing is
/// degraded. Green at the base: regression coverage.
#[tokio::test]
async fn s8_no_store_leaves_the_counter_fields_out() {
    let (state, _dir) = fixture(1, false).await;

    let body = overview(&state).await;

    assert_no_counter_fields(&body);
    assert!(body.get("degraded").is_none(), "{body}");
    assert_eq!(body["checklist"]["has_key"], true, "{body}");
}

/// S8b: a store but a clock that cannot be read; the counter fields are
/// absent and `degraded` names exactly them.
#[tokio::test]
async fn s8b_an_unreadable_clock_degrades_the_counter_fields() {
    let (state, _dir) = fixture(1, false).await;
    let store = with_store(&state, 0);
    calls(&store, "name-000", 1);
    let _clock = test_clock::before_epoch();

    let (_, raw) = get(&state, Some(ADMIN_KEY)).await;

    let body: Value = serde_json::from_str(&raw).expect("a JSON body");
    assert_no_counter_fields(&body);
    let mut degraded: Vec<&str> = body["degraded"]
        .as_array()
        .expect("a degraded list")
        .iter()
        .filter_map(Value::as_str)
        .collect();
    degraded.sort_unstable();
    let mut want = [
        "kpi.calls_24h",
        "kpi.blocks_24h",
        "kpi.errors_24h",
        "servers.calls_24h",
        "edges",
        "markers",
        "checklist.tool_tried",
    ];
    want.sort_unstable();
    assert_eq!(degraded, want, "{body}");
}

const BAD_CONFIG: &str = "backends: [SENTINEL-BAD-VALUE\n";

/// A reload context over a valid, empty `gateway.yaml` in `dir`, shared with
/// the state. Returns it and the file's path.
fn with_reload(
    state: &Arc<AppState>,
    dir: &tempfile::TempDir,
) -> (Arc<crate::config_reload::ReloadContext>, std::path::PathBuf) {
    use crate::config::Config;
    use crate::config_reload::{LiveConfig, ReloadContext};
    let path = dir.path().join("gateway.yaml");
    crate::gateway::test_helpers::write_owner_only(&path, "backends: {}\n").expect("config");
    let running = Config::load(Some(&path)).expect("config loads");
    let context = Arc::new(
        ReloadContext::new(
            path.clone(),
            Arc::new(LiveConfig::new(running)),
            Arc::new(crate::backend::BackendRegistry::new()),
            FailsafeConfig::default(),
            Duration::from_secs(60),
        )
        .expect("the registry pairs with the config"),
    );
    state.meta_mcp.set_reload_context(Arc::clone(&context));
    (context, path)
}

fn needs_you_kinds(body: &Value) -> Vec<&str> {
    body["needs_you"]["rows"]
        .as_array()
        .expect("needs-you rows")
        .iter()
        .filter_map(|row| row["kind"].as_str())
        .collect()
}

/// S7 (API16.3, D7): an invalid `gateway.yaml` refused by the reload is one
/// `invalid_config` row with the ledger's fixed cause, never the bad value;
/// a later valid reload clears it.
#[tokio::test]
async fn s7_an_invalid_reload_is_one_invalid_config_row() {
    let (state, dir) = fixture(0, false).await;
    let (context, path) = with_reload(&state, &dir);
    crate::gateway::test_helpers::write_owner_only(&path, BAD_CONFIG).expect("bad config");
    context.reload().await.expect_err("the reload refuses it");
    let cause = context.refusals().list()[0].cause.clone();

    let body = overview(&state).await;

    let row = &body["needs_you"]["rows"][0];
    assert_eq!(row["kind"], "invalid_config", "{body}");
    assert_eq!(row["subject"], "config", "{body}");
    assert_eq!(row["detail"]["cause"], cause.as_str(), "{body}");
    assert!(
        row["detail"]["fix"].is_string() && row["detail"]["repeats"] == 1,
        "{body}"
    );
    assert!(!body.to_string().contains("SENTINEL-BAD-VALUE"), "{body}");

    crate::gateway::test_helpers::write_owner_only(&path, "backends: {}\n").expect("config");
    context.reload().await.expect("a valid file reloads");
    let cleared = overview(&state).await;
    assert!(
        !needs_you_kinds(&cleared).contains(&"invalid_config"),
        "{cleared}"
    );
}

/// S12 (F8): two reload refusals, an older one and a newer, give exactly one
/// `invalid_config` row (the newer) and no `refused` row for either.
#[tokio::test]
async fn s12_only_the_newest_invalid_config_is_shown() {
    use crate::config_reload::refusals::RefusalKind;
    let (state, dir) = fixture(0, false).await;
    let (context, _path) = with_reload(&state, &dir);
    let ledger = context.refusals();
    ledger.record(RefusalKind::Reload, None, "Failed to parse config: one");
    ledger.record(RefusalKind::Reload, None, "Failed to parse config: one");
    ledger.record(
        RefusalKind::Edit,
        Some("edited"),
        "Failed to validate config: two",
    );
    ledger.record(RefusalKind::Reload, None, "Failed to parse config: three");

    let body = overview(&state).await;

    assert_eq!(
        needs_you_kinds(&body),
        ["invalid_config", "refused"],
        "{body}"
    );
    assert_eq!(
        body["needs_you"]["rows"][0]["detail"]["repeats"], 1,
        "{body}"
    );
    assert_eq!(body["needs_you"]["rows"][1]["subject"], "edited", "{body}");
}

/// S10: one read takes the store's lock exactly seven times (three KPI
/// series, the server sums, the pairs, the markers, the 30-day series),
/// whatever the server count.
#[tokio::test]
async fn s10_a_read_takes_the_store_lock_seven_times() {
    let _clock = test_clock::at_secs(NOW);
    for servers in [10, 140] {
        let (state, _dir) = fixture(servers, false).await;
        let store = with_store(&state, 0);
        calls(&store, "name-000", 2);
        let before = store.reads_for_test();

        let _ = overview(&state).await;

        assert_eq!(store.reads_for_test() - before, 7, "{servers} servers");
    }
}

/// A plan the runtime policy denies: it asks to mount the host root.
fn forbidden_mount_plan() -> crate::runtime::RuntimePlan {
    use crate::runtime::{
        RuntimeAvailability, RuntimeIntent, RuntimeMount, RuntimeMountMode, RuntimePlanner,
    };
    let mut intent = RuntimeIntent::named("denied");
    intent.image = Some("ghcr.io/example/filesystem:1".to_owned());
    intent.requested_mounts = vec![RuntimeMount {
        source: "/".to_owned(),
        target: "/host".to_owned(),
        mode: RuntimeMountMode::ReadOnly,
    }];
    let plan = RuntimePlanner::new(RuntimeAvailability::with_docker()).plan(&intent);
    assert!(plan.is_denied(), "the fixture plan is denied");
    plan
}

/// Every reason the runtime policy can give for a denial.
#[cfg(feature = "cost-governance")]
const ALL_DENIALS: [crate::runtime::RuntimeDenyReason; 4] = {
    use crate::runtime::RuntimeDenyReason as R;
    [
        R::RuntimeUnavailable,
        R::MissingContainerImage,
        R::InvalidResourcePolicy,
        R::ForbiddenMount,
    ]
};

/// `count` servers denied for every reason, with escape-heavy names. Each has
/// calls at `at`, so they rank first and show their state.
#[cfg(feature = "cost-governance")]
fn register_denied(state: &Arc<AppState>, store: &CounterStore, count: usize, at: u64) {
    for i in 0..count {
        let name = format!("d{i:02}{}", "\u{1}".repeat(300));
        let mut plan = forbidden_mount_plan();
        plan.denied = ALL_DENIALS
            .iter()
            .map(|&reason| crate::runtime::RuntimeDenial {
                reason,
                detail: String::new(),
            })
            .collect();
        plan.audit.denied_reasons = ALL_DENIALS.to_vec();
        let backend = Backend::new_with_runtime_plan(
            &name,
            BackendConfig::default(),
            &FailsafeConfig::default(),
            Duration::from_secs(300),
            Some(plan),
        );
        assert!(state.backends.register(Arc::new(backend)), "register {i}");
        record(store, "key:a", &name, at, Tally::default());
    }
}

/// S11 (F1): a server the runtime policy denies is a `refused` needs-you row
/// with the same cause `/ui/api/refusals` serves, even when its name sorts
/// last and it is folded out of the 24 server rows.
#[tokio::test]
async fn s11_a_startup_denied_server_is_a_refused_row() {
    use crate::runtime::RuntimeDenyReason;
    let (state, _dir) = fixture(0, false).await;
    let _backends = register(&state, 30);
    let plan = forbidden_mount_plan();
    let denied = Arc::new(Backend::new_with_runtime_plan(
        "tail-denied",
        BackendConfig::default(),
        &FailsafeConfig::default(),
        Duration::from_secs(300),
        Some(plan),
    ));
    assert!(
        state.backends.register(denied),
        "register the denied server"
    );
    let want = crate::config_reload::refusals::startup_refusal(
        "tail-denied",
        &[RuntimeDenyReason::ForbiddenMount],
    );

    let body = overview(&state).await;

    let row = body["needs_you"]["rows"]
        .as_array()
        .expect("needs-you rows")
        .iter()
        .find(|row| row["kind"] == "refused")
        .unwrap_or(&Value::Null);
    assert_eq!(row["subject"], "tail-denied", "{body}");
    assert_eq!(row["detail"]["cause"], want.cause.as_str(), "{body}");
    assert_eq!(row["detail"]["code"], "runtime_denied", "{body}");
}

/// S7b (D9): an invalid reload (the oldest), twenty-five refused edits and a
/// budget at 90%: `invalid_config` first, then nineteen `refused` rows newest
/// first; the budget row and six older refusals fold into `more`.
#[cfg(feature = "cost-governance")]
#[tokio::test]
async fn s7b_needs_you_orders_invalid_config_refused_then_limits() {
    use crate::config_reload::refusals::RefusalKind;
    use crate::cost_accounting::config::CostGovernanceConfig;
    use crate::cost_accounting::enforcer::BudgetEnforcer;
    use crate::cost_accounting::registry::CostRegistry;
    let (mut state, dir) = fixture(0, false).await;
    let _clock = test_clock::at_secs(super::overview_tests::BUDGET_NOW);
    let mut cfg = CostGovernanceConfig {
        enabled: true,
        ..Default::default()
    };
    cfg.budgets.daily = Some(1.0);
    let enforcer = Arc::new(BudgetEnforcer::new(
        cfg.clone(),
        Arc::new(CostRegistry::new(&cfg)),
    ));
    enforcer.record_spend("search", None, 0.9);
    let inner = Arc::get_mut(&mut state).expect("state is unique");
    let mut meta = crate::gateway::meta_mcp::MetaMcp::new(Arc::clone(&inner.backends));
    meta.budget_enforcer = Some(enforcer);
    inner.meta_mcp = Arc::new(meta);
    let (context, _path) = with_reload(&state, &dir);
    let ledger = context.refusals();
    ledger.record(RefusalKind::Reload, None, "Failed to parse config: bad");
    for i in 0..25 {
        ledger.record(
            RefusalKind::Edit,
            Some(&format!("b{i:02}")),
            "Failed to validate config: x",
        );
    }

    let body = overview(&state).await;

    let rows = body["needs_you"]["rows"]
        .as_array()
        .expect("needs-you rows");
    assert_eq!(rows.len(), 20, "{body}");
    assert_eq!(rows[0]["kind"], "invalid_config", "{body}");
    let subjects: Vec<&str> = rows[1..]
        .iter()
        .filter_map(|r| r["subject"].as_str())
        .collect();
    let want: Vec<String> = (6..25).rev().map(|i| format!("b{i:02}")).collect();
    assert_eq!(subjects, want, "{body}");
    assert!(rows[1..].iter().all(|r| r["kind"] == "refused"), "{body}");
    assert_eq!(body["needs_you"]["more"]["count"], 7, "{body}");
}

/// S9 (D11, API16.2): O3e's worst case plus a full store: 48 edges with
/// 128-byte escape-heavy labels, 50 markers, and 24 servers denied for every
/// reason, whose state reason is the longest fixed text and whose startup
/// refusals name an escape-heavy backend. The body stays under the ceiling
/// computed from the caps per field class, and over three quarters of it.
#[cfg(feature = "cost-governance")]
#[tokio::test]
async fn s9_the_full_body_stays_under_the_extended_ceiling() {
    use super::overview_tests::{
        BUDGET_NOW, FIELD, NEEDS_YOU_ROWS, SERVER_ROWS, WORST_BODY, worst_case,
    };
    // Counter labels and marker subjects are at most 128 bytes (the store
    // normalizes them). A state reason and a refusal's fix are fixed text,
    // escape-free: priced at the longest this fixture produces. A startup
    // refusal's cause names the backend, so it is dynamic text (`FIELD`), and
    // `WORST_BODY` already prices a needs-you row at two of those.
    const LABEL: usize = 2 + 6 * 128;
    let codes = ALL_DENIALS.map(|r| serde_json::to_value(r).expect("a code"));
    let codes: Vec<&str> = codes.iter().filter_map(Value::as_str).collect();
    let reason = format!("Refused by the runtime policy: {}.", codes.join(", "));
    let fix = crate::config_reload::refusals::startup_refusal("x", &ALL_DENIALS).fix;
    let ceiling = WORST_BODY
        + SERVER_ROWS * (2 + reason.len() + 64)
        + NEEDS_YOU_ROWS * (2 + fix.len() + 64)
        + 48 * (2 * LABEL + 192)
        + 50 * (LABEL + 192);
    let (state, _dir, _clock) = worst_case().await;
    let store = with_store(&state, 0);
    register_denied(&state, &store, SERVER_ROWS, BUDGET_NOW - 600);
    let heavy = |i: usize| format!("{i:02}{}", "\u{1}".repeat(126));
    for caller in 0..2 {
        for server in 0..30 {
            record(
                &store,
                &heavy(caller),
                &heavy(server),
                BUDGET_NOW - 600,
                Tally::default(),
            );
        }
    }
    for i in 0..55 {
        store.mark(
            MarkerKind::ConfigReload,
            Some(&heavy(i)),
            BUDGET_NOW - 3000 + i as u64,
        );
    }

    let (status, raw) = get(&state, Some(ADMIN_KEY)).await;

    assert_eq!(status, axum::http::StatusCode::OK, "{raw}");
    let body: Value = serde_json::from_str(&raw).expect("a JSON body");
    assert_eq!(
        body["edges"]["rows"].as_array().map(Vec::len),
        Some(48),
        "edges"
    );
    assert_eq!(
        body["markers"]["rows"].as_array().map(Vec::len),
        Some(50),
        "markers"
    );
    assert_eq!(
        body["needs_you"]["rows"].as_array().map(Vec::len),
        Some(NEEDS_YOU_ROWS)
    );
    assert_eq!(body["servers"]["rows"][0]["reason"], reason.as_str());
    let refused = body["needs_you"]["rows"][0]["detail"]["cause"].as_str();
    assert_eq!(refused.map(str::len), Some(256), "{refused:?}");
    const { assert!(FIELD > LABEL, "a dynamic field is the larger class") };
    assert!(
        raw.len() <= ceiling,
        "{} bytes over the {ceiling}-byte ceiling",
        raw.len()
    );
    assert!(
        raw.len() > ceiling / 4 * 3,
        "{} bytes is not near the {ceiling}-byte worst case",
        raw.len()
    );
}

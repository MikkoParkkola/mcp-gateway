// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! `GET /ui/api/overview`'s needs-you list: the invalid-config row, the
//! startup-denied and refused rows, the budget rows behind them, and the full
//! body's size with every list at its cap. Moved unchanged out of
//! overview_sources_tests.rs, which keeps the counter rows and shares its
//! store helpers with this file.

use std::sync::Arc;
use std::time::Duration;

use serde_json::Value;

use super::AppState;
use super::overview_sources_tests::register;
#[cfg(feature = "cost-governance")]
use super::overview_sources_tests::{record, timed, with_store};
#[cfg(feature = "cost-governance")]
use super::overview_tests::{ADMIN_KEY, get};
use super::overview_tests::{fixture, overview};
use crate::backend::Backend;
#[cfg(feature = "cost-governance")]
use crate::clock::test_clock;
use crate::config::{BackendConfig, FailsafeConfig};
#[cfg(feature = "cost-governance")]
use crate::counters::{CounterStore, MarkerKind, Tally};

/// A reload refused with no backend named and no parser line.
fn reload_refused(ledger: &crate::config_reload::refusals::RefusalLedger, text: &str) {
    use crate::config_reload::refusals::RefusalKind;
    ledger.record(RefusalKind::Reload, None, text, None);
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
    reload_refused(ledger, "Failed to parse config: one");
    reload_refused(ledger, "Failed to parse config: one");
    ledger.record(
        RefusalKind::Edit,
        Some("edited"),
        "Failed to validate config: two",
        None,
    );
    reload_refused(ledger, "Failed to parse config: three");

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
    reload_refused(ledger, "Failed to parse config: bad");
    for i in 0..25 {
        ledger.record(
            RefusalKind::Edit,
            Some(&format!("b{i:02}")),
            "Failed to validate config: x",
            None,
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
        + 50 * (LABEL + 192)
        // Latency: a row per server shown plus the slowest, name and numbers.
        + (SERVER_ROWS + 1) * (LABEL + 64)
        + 128;
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
    for server in 0..30 {
        for _ in 0..21 {
            timed(&store, &heavy(server), BUDGET_NOW - 600, 30_000);
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
    assert_eq!(
        body["latency"]["servers"].as_array().map(Vec::len),
        Some(SERVER_ROWS),
        "latency"
    );
    assert!(body["latency"]["slowest"].is_object(), "latency.slowest");
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

// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! `GET /ui/api/overview`'s needs-you list: the invalid-config row, the
//! decisions row, the startup-denied and refused rows, the sign-in rows, the
//! budget rows behind them, what folds, and the full body's size with every
//! list at its cap. overview_sources_tests.rs keeps the counter rows and
//! shares its store helpers with this file.

use std::sync::Arc;
use std::time::Duration;

use chrono::Utc;
use serde_json::{Value, json};

use super::AppState;
#[cfg(feature = "cost-governance")]
use super::overview_sources_tests::timed;
use super::overview_sources_tests::{record, register, with_store};
#[cfg(feature = "cost-governance")]
use super::overview_tests::get;
use super::overview_tests::{ADMIN_KEY, FIELD, fixture, get_at, overview};
use crate::backend::Backend;
use crate::clock::test_clock;
use crate::config::{BackendConfig, FailsafeConfig, OAuthConfig};
use crate::counters::Tally;
#[cfg(feature = "cost-governance")]
use crate::counters::{CounterStore, MarkerKind};
use crate::decisions::{AdoptFind, Health, Shared, Source, UnreadableFile, UnreadableReason};
use crate::discovery::DiscoverySource;
use crate::discovery::shadow::ShadowRiskSeverity;
use crate::oauth::client::sign_in::SignIn;

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
    const DECISIONS_ROW_MAX: &str = r#"{"kind":"decisions","subject":"decisions","detail":{"count":18446744073709551615,"revision":18446744073709551615}}"#;
    const BY_KIND_MAX: &str = r#","by_kind":{"invalid_config":18446744073709551615,"decisions":18446744073709551615,"refused":18446744073709551615,"sign_in":18446744073709551615,"limit_80":18446744073709551615}"#;
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
        + 128
        // The decisions row and `more.by_kind`, priced at 20-digit numbers.
        + DECISIONS_ROW_MAX.len()
        + 1
        + BY_KIND_MAX.len();
    let (state, _dir, _clock) = worst_case().await;
    // After `worst_case`, which replaces `meta_mcp`.
    ready_set(&state, &["s9-a", "s9-b"]);
    for i in 0..3 {
        waiting(&state, &format!("w{i}{}", "\u{1}".repeat(300)));
    }
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
    assert_eq!(body["needs_you"]["rows"][0]["kind"], "decisions");
    let more = json!({"count": 30, "by_kind": {"refused": 5, "sign_in": 3, "limit_80": 22}});
    assert_eq!(body["needs_you"]["more"], more);
    let refused = body["needs_you"]["rows"][1]["detail"]["cause"].as_str();
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

/// Record a sign-in wait on `backend`'s shared slot.
fn wait(backend: &Backend) {
    backend.shared_entry_for_test().auth_wait.set();
}

const IDLE: Duration = Duration::from_secs(300);

/// A backend named `name` with `config`, registered.
fn add(state: &AppState, name: &str, config: BackendConfig) -> Arc<Backend> {
    let backend = Arc::new(Backend::new(name, config, &FailsafeConfig::default(), IDLE));
    assert!(state.backends.register(Arc::clone(&backend)), "{name:?}");
    backend
}

/// A backend named `name` the runtime policy denied at startup, registered.
fn denied(state: &AppState, name: &str) -> Arc<Backend> {
    let (config, failsafe) = (BackendConfig::default(), FailsafeConfig::default());
    let plan = Some(forbidden_mount_plan());
    let backend = Backend::new_with_runtime_plan(name, config, &failsafe, IDLE, plan);
    let backend = Arc::new(backend);
    assert!(state.backends.register(Arc::clone(&backend)), "{name}");
    backend
}

/// A backend named `name` with no OAuth block, registered and waiting.
fn waiting(state: &AppState, name: &str) -> Arc<Backend> {
    let backend = add(state, name, BackendConfig::default());
    wait(&backend);
    backend
}

/// An OAuth-enabled backend at `status`, registered, with no wait.
fn oauth_backend(state: &AppState, name: &str, status: SignIn) -> Arc<Backend> {
    let oauth = Some(OAuthConfig {
        enabled: true,
        ..OAuthConfig::default()
    });
    let backend = add(
        state,
        name,
        BackendConfig {
            oauth,
            ..BackendConfig::default()
        },
    );
    backend.sign_in.status.set(status);
    backend
}

/// An edit refused for `name`, on the reload context's ledger.
fn edited(context: &crate::config_reload::ReloadContext, name: &str) {
    use crate::config_reload::refusals::RefusalKind;
    let cause = "Failed to validate config: x";
    let ledger = context.refusals();
    ledger.record(RefusalKind::Edit, Some(name), cause, None);
}

fn rows(body: &Value) -> &[Value] {
    body["needs_you"]["rows"].as_array().expect("rows")
}

fn pairs(body: &Value) -> Vec<(&str, &str)> {
    rows(body)
        .iter()
        .map(|r| {
            (
                r["kind"].as_str().unwrap_or("?"),
                r["subject"].as_str().unwrap_or("?"),
            )
        })
        .collect()
}

/// An unmanaged client find called `name`.
fn adopt(name: &str) -> AdoptFind {
    AdoptFind {
        find_id: format!("find-{name}"),
        name: name.to_owned(),
        source: DiscoverySource::ClaudeDesktop,
        config_file: Some("client.json".to_owned()),
        transport: "http",
        command: None,
        url: Some(format!("https://{name}.example.invalid/mcp")),
        severity: ShadowRiskSeverity::High,
    }
}

/// A decision set attached to `state`: access, control plane and capability
/// absent, and one adopt item per name in `finds`.
fn ready_set(state: &AppState, finds: &[&str]) -> Arc<Shared> {
    let set = Arc::new(Shared::with_key([9; 32]));
    set.update(|s| {
        for source in [Source::Access, Source::ControlPlane, Source::Capability] {
            s.set_health(source, Health::Absent);
        }
        let finds = finds.iter().map(|n| adopt(n)).collect();
        s.set_discovery(finds, vec![], 1, Utc::now());
    });
    state.meta_mcp.set_decisions(Arc::clone(&set));
    set
}

/// N1 (SIGN.2): a waiting backend is one `sign_in` row; so is one whose
/// predicate needs a person with no wait; nobody waiting adds nothing, and
/// no count of sign-ins is ever sent.
#[tokio::test]
async fn n1_a_backend_waiting_for_sign_in_is_one_needs_you_row() {
    let (state, _dir) = fixture(0, false).await;
    let backends = register(&state, 2);
    wait(&backends[1]);
    assert!(backends[1].needs_sign_in() && !backends[0].needs_sign_in());
    let body = overview(&state).await;
    let want = json!({"kind": "sign_in", "subject": "name-001", "detail": {}});
    assert_eq!(rows(&body), [want], "{body}");
    assert_eq!(body["needs_you"]["more"], json!({"count": 0}), "{body}");
    assert!(!body.to_string().contains("sign_ins"), "{body}");

    // The predicate, not the flag, decides.
    let (state, _dir) = fixture(0, false).await;
    let held = oauth_backend(&state, "oauth-a", SignIn::NeverSignedIn);
    assert!(!held.shared_entry_for_test().auth_wait.get(), "no wait");
    assert!(held.needs_sign_in(), "the predicate needs a person");
    let body = overview(&state).await;
    let want = json!({"kind": "sign_in", "subject": "oauth-a", "detail": {}});
    assert_eq!(rows(&body), [want], "{body}");
    assert!(!body.to_string().contains("sign_ins"), "{body}");

    let (state, _dir) = fixture(0, false).await;
    let _backends = register(&state, 2);
    let body = overview(&state).await;
    assert!(!needs_you_kinds(&body).contains(&"sign_in"), "{body}");
    assert!(!body.to_string().contains("sign_ins"), "{body}");
    assert_eq!(body["needs_you"]["more"], json!({"count": 0}), "{body}");

    // OAuth on and signed in: no row.
    let (state, _dir) = fixture(0, false).await;
    let fine = oauth_backend(&state, "oauth-b", SignIn::SignedIn { expires_at: None });
    assert!(!fine.shared_entry_for_test().auth_wait.get(), "no wait");
    assert!(!fine.needs_sign_in(), "a held sign-in needs nobody");
    let body = overview(&state).await;
    assert!(!needs_you_kinds(&body).contains(&"sign_in"), "{body}");
    assert!(!body.to_string().contains("sign_ins"), "{body}");
}

/// N2: sign-in rows come after every refusal and before the budget rows.
#[cfg(feature = "cost-governance")]
#[tokio::test]
async fn n2_sign_in_rows_sit_after_refusals_and_before_budgets() {
    use crate::cost_accounting::config::CostGovernanceConfig;
    use crate::cost_accounting::enforcer::BudgetEnforcer;
    use crate::cost_accounting::registry::CostRegistry;
    let (mut state, dir) = fixture(0, false).await;
    let _clock = test_clock::at_secs(super::overview_tests::BUDGET_NOW);
    let mut governance = CostGovernanceConfig {
        enabled: true,
        ..Default::default()
    };
    governance.budgets.daily = Some(1.0);
    let registry = Arc::new(CostRegistry::new(&governance));
    let budgets = Arc::new(BudgetEnforcer::new(governance, registry));
    budgets.record_spend("search", None, 0.9);
    let mut meta = crate::gateway::meta_mcp::MetaMcp::new(Arc::clone(&state.backends));
    meta.budget_enforcer = Some(budgets);
    Arc::get_mut(&mut state).expect("unique").meta_mcp = Arc::new(meta);
    denied(&state, "a-denied");
    let (context, _path) = with_reload(&state, &dir);
    edited(&context, "b-edited");
    waiting(&state, "c-wait");

    let body = overview(&state).await;

    let want = [
        ("refused", "a-denied"),
        ("refused", "b-edited"),
        ("sign_in", "c-wait"),
        ("limit_80", "global"),
    ];
    assert_eq!(pairs(&body), want, "{body}");
}

/// N3: folded rows are counted by kind, and the cap stays 20; sign-in rows
/// are shown in name order, not registration order.
#[tokio::test]
async fn n3_folded_sign_ins_are_counted_by_kind() {
    let (state, dir) = fixture(0, false).await;
    let (context, _path) = with_reload(&state, &dir);
    for i in 0..19 {
        edited(&context, &format!("b{i:02}"));
    }
    for i in 0..3 {
        waiting(&state, &format!("w{i}"));
    }
    let body = overview(&state).await;
    let shown = rows(&body);
    assert_eq!(shown.len(), 20, "{body}");
    assert!(shown[..19].iter().all(|r| r["kind"] == "refused"), "{body}");
    let first = json!({"kind": "sign_in", "subject": "w0", "detail": {}});
    assert_eq!(shown[19], first, "{body}");
    let more = json!({"count": 2, "by_kind": {"sign_in": 2}});
    assert_eq!(body["needs_you"]["more"], more, "{body}");

    let (state, _dir) = fixture(0, false).await;
    for i in (0..25).rev() {
        waiting(&state, &format!("w{i:02}"));
    }
    let body = overview(&state).await;
    let subjects: Vec<&str> = pairs(&body).into_iter().map(|(_, s)| s).collect();
    let want: Vec<String> = (0..20).map(|i| format!("w{i:02}")).collect();
    assert_eq!(subjects, want, "{body}");
    let more = json!({"count": 5, "by_kind": {"sign_in": 5}});
    assert_eq!(body["needs_you"]["more"], more, "{body}");
}

/// N4: a name longer than the 256-byte clip is cut on a character boundary
/// and marked `clipped`; one exactly at the clip is not.
#[tokio::test]
async fn n4_a_name_longer_than_the_clip_is_marked() {
    let (state, _dir) = fixture(0, false).await;
    let ctrl = "\u{1}".repeat(256);
    let long_a = format!("{ctrl}a");
    let long_b = format!("{ctrl}b");
    let accented = format!("a{}", "é".repeat(128));
    let at_clip = "c".repeat(256);
    assert_eq!((accented.len(), accented.chars().count()), (257, 129));
    for name in [&at_clip, &accented, &long_b, &long_a] {
        waiting(&state, name);
    }

    let body = overview(&state).await;

    let cut = |subject: String| json!({"kind": "sign_in", "subject": subject, "detail": {"clipped": true}});
    let want = [
        cut(ctrl.clone()),
        cut(ctrl.clone()),
        cut(format!("a{}", "é".repeat(127))),
        json!({"kind": "sign_in", "subject": at_clip, "detail": {}}),
    ];
    assert_eq!(rows(&body), want, "{body}");
    for row in rows(&body) {
        let size = serde_json::to_string(row).expect("a row").len();
        assert!(size <= 2 * FIELD + 256, "{size} bytes: {row}");
    }
}

/// N5: a startup-denied server that also waits for a sign-in is both a
/// `refused` row and a `sign_in` row.
#[tokio::test]
async fn n5_a_refused_server_that_waits_is_both_rows() {
    let (state, _dir) = fixture(0, false).await;
    let both = denied(&state, "x-both");
    wait(&both);
    assert!(both.startup_denial().is_some(), "denied at startup");
    assert!(both.needs_sign_in(), "the denied slot holds the wait");

    let body = overview(&state).await;

    let want = [("refused", "x-both"), ("sign_in", "x-both")];
    assert_eq!(pairs(&body), want, "{body}");
}

/// D1 (DEC.2): open decisions are one row with the set's count and
/// revision, the same pair the count route serves; it follows the set; a
/// count of zero is no row.
#[tokio::test]
async fn d1_open_decisions_are_one_row_with_count_and_revision() {
    let (state, _dir) = fixture(0, false).await;
    let set = ready_set(&state, &["d1-a", "d1-b"]);
    let broken = || UnreadableFile {
        source: DiscoverySource::VsCode,
        file: "user.json".to_owned(),
        path_digest: "d1-u".to_owned(),
        reason: UnreadableReason::DidNotParse,
    };
    let two = || vec![adopt("d1-a"), adopt("d1-b")];
    set.update(|s| s.set_discovery(two(), vec![broken()], 2, Utc::now()));
    let view = set.view().expect("every source readable");
    let kinds: Vec<(&str, &str)> = view
        .decisions
        .iter()
        .map(|d| {
            (
                d["kind"].as_str().unwrap_or("?"),
                d["server"]["name"].as_str().unwrap_or(""),
            )
        })
        .collect();
    assert_eq!(kinds.len(), 3, "{kinds:?}");
    assert!(kinds.contains(&("adopt", "d1-a")) && kinds.contains(&("adopt", "d1-b")));
    assert!(kinds.iter().any(|(k, _)| *k == "client_config_unreadable"));
    let (count, revision) = set.snapshot().expect("readable");
    assert!(count == 3 && count as u64 != revision, "{count} {revision}");

    let body = overview(&state).await;

    let row = json!({"kind": "decisions", "subject": "decisions", "detail": {"count": 3, "revision": revision}});
    assert_eq!(rows(&body), [row], "{body}");
    assert!(body.get("degraded").is_none(), "{body}");
    let uri = "/ui/api/decisions/count";
    let (status, raw) = get_at(&state, uri, Some(ADMIN_KEY)).await;
    assert_eq!(status, axum::http::StatusCode::OK, "{raw}");
    let served: Value = serde_json::from_str(&raw).expect("a JSON body");
    assert_eq!(served, json!({"count": 3, "revision": revision}));

    let mut three = two();
    three.push(adopt("d1-c"));
    set.update(|s| s.set_discovery(three, vec![broken()], 3, Utc::now()));
    let body = overview(&state).await;
    let detail = &rows(&body)[0]["detail"];
    assert_eq!(detail["count"], 4, "{body}");
    assert_ne!(detail["revision"], revision, "{body}");

    let (state, _dir) = fixture(0, false).await;
    let set = ready_set(&state, &[]);
    assert!(matches!(set.snapshot(), Some((0, _))), "an empty set");
    let body = overview(&state).await;
    assert!(!needs_you_kinds(&body).contains(&"decisions"), "{body}");
    assert!(body.get("degraded").is_none(), "{body}");
}

/// D2 (DEC.2): an unreadable decision source is no row and a `degraded`
/// name, never a zero; it extends the other degraded names.
#[tokio::test]
async fn d2_an_unreadable_decision_source_is_degraded_never_zero() {
    let (state, _dir) = fixture(0, false).await;
    let set = ready_set(&state, &["d2-a"]);
    set.update(|s| s.discovery_down());
    assert_eq!(set.snapshot(), None, "unreadable");
    let body = overview(&state).await;
    assert!(!needs_you_kinds(&body).contains(&"decisions"), "{body}");
    assert_eq!(body["degraded"], json!(["needs_you.decisions"]), "{body}");

    // Beside the counter fields an unreadable clock degrades.
    let (state, _dir) = fixture(1, false).await;
    let store = with_store(&state, 0);
    record(&store, "key:d2", "name-000", 1_000, Tally::default());
    let _clock = test_clock::before_epoch();
    ready_set(&state, &["d2-a"]).update(|s| s.discovery_down());
    let body = overview(&state).await;
    let mut names: Vec<&str> = body["degraded"]
        .as_array()
        .map(|a| a.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default();
    names.sort_unstable();
    let mut want = [
        "checklist.tool_tried",
        "edges",
        "kpi.blocks_24h",
        "kpi.calls_24h",
        "kpi.errors_24h",
        "latency",
        "markers",
        "needs_you.decisions",
        "servers.calls_24h",
    ];
    want.sort_unstable();
    assert_eq!(names, want, "{body}");
    assert!(!needs_you_kinds(&body).contains(&"decisions"), "{body}");
}

/// D3: with no decision set the overview adds no row and no degraded name.
#[tokio::test]
async fn d3_no_decision_set_adds_nothing() {
    let (state, _dir) = fixture(0, false).await;
    assert!(state.meta_mcp.decisions().is_none(), "no set");
    let body = overview(&state).await;
    assert!(!needs_you_kinds(&body).contains(&"decisions"), "{body}");
    assert!(body.get("degraded").is_none(), "{body}");
}

/// D6: the decisions row sits right after the invalid config and never
/// folds, however many refusals follow.
#[tokio::test]
async fn d6_the_decisions_row_survives_a_full_list() {
    let (state, dir) = fixture(0, false).await;
    let (context, _path) = with_reload(&state, &dir);
    reload_refused(context.refusals(), "Failed to parse config: bad");
    for i in 0..30 {
        edited(&context, &format!("b{i:02}"));
    }
    let set = ready_set(&state, &["d6-a", "d6-b"]);
    let (_, revision) = set.snapshot().expect("readable");

    let body = overview(&state).await;

    let shown = rows(&body);
    assert_eq!(shown.len(), 20, "{body}");
    assert_eq!(shown[0]["kind"], "invalid_config", "{body}");
    let row = json!({"kind": "decisions", "subject": "decisions", "detail": {"count": 2, "revision": revision}});
    assert_eq!(shown[1], row, "{body}");
    assert!(shown[2..].iter().all(|r| r["kind"] == "refused"), "{body}");
    let subjects: Vec<&str> = pairs(&body)[2..].iter().map(|&(_, s)| s).collect();
    let want: Vec<String> = (12..30).rev().map(|i| format!("b{i:02}")).collect();
    assert_eq!(subjects, want, "{body}");
    let more = json!({"count": 12, "by_kind": {"refused": 12}});
    assert_eq!(body["needs_you"]["more"], more, "{body}");
}

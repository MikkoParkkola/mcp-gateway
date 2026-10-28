// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8857.API4.3: the refusal ledger. Causes are classified and rebuilt,
//! never re-served as given.

use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use super::{REFUSAL_CAP, RefusalCode, RefusalKind, RefusalLedger};
use crate::config::{Config, LiveEnv};
use crate::config_reload::LiveConfig;
use crate::config_reload::reload_context::{STOPPED, load_config_patch};
use crate::gateway::test_helpers::write_owner_only;

const CANARY_HEADER: &str = "refusal-canary-header-7f3a";
const CANARY_QUERY: &str = "refusal-canary-query-91bd";
const CANARY_USER: &str = "refusal-canary-user-c04e";

fn fixed_clock() -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(1_800_000_000)
}

/// The error a real reload gives for `yaml`, through the reload loader.
fn reload_error(yaml: &str) -> String {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("gateway.yaml");
    write_owner_only(&path, "server:\n  port: 39401\n").expect("write config");
    let startup = Config::load_evaluated(Some(&path)).expect("startup loads");
    let live = Arc::new(LiveConfig::new(startup.config.clone()));
    let env = LiveEnv::new(startup.overlay, startup.env_paths);
    write_owner_only(&path, yaml).expect("write the refused config");
    match load_config_patch(&path, &live, &env) {
        Err(reason) => reason,
        Ok(_) => panic!("the reload must be refused"),
    }
}

/// A credential-bearing `http://` backend off this machine, carrying a canary
/// in each place a credential can sit on the wire.
fn cleartext_yaml() -> String {
    format!(
        "server:\n  port: 39401\nbackends:\n  inventory:\n    http_url: \
         \"http://{CANARY_USER}:pw@10.0.4.7/mcp?token={CANARY_QUERY}\"\n    \
         headers:\n      Authorization: \"Bearer {CANARY_HEADER}\"\n"
    )
}

#[test]
fn api4_3_a_cleartext_reload_refusal_is_classified_with_its_fix() {
    let ledger = RefusalLedger::with_clock(fixed_clock);
    ledger.record(RefusalKind::Reload, None, &reload_error(&cleartext_yaml()));

    let list = ledger.list();
    assert_eq!(list.len(), 1, "{list:?}");
    let refusal = &list[0];
    assert_eq!(refusal.kind, RefusalKind::Reload);
    assert_eq!(refusal.code, RefusalCode::CleartextCredentials);
    assert_eq!(refusal.backend.as_deref(), Some("inventory"));
    assert!(refusal.cause.contains("inventory"), "{}", refusal.cause);
    assert!(!refusal.fix.is_empty());
    assert!(refusal.active);
    assert_eq!(
        refusal.at,
        Some(chrono::DateTime::<chrono::Utc>::from(fixed_clock()))
    );
}

#[test]
fn api4_3_no_canary_reaches_the_served_body() {
    let ledger = RefusalLedger::new();
    ledger.record(RefusalKind::Reload, None, &reload_error(&cleartext_yaml()));
    ledger.record(
        RefusalKind::Add,
        Some("inventory"),
        &reload_error(&cleartext_yaml()),
    );
    // An unclassified refusal whose text carries every canary.
    ledger.record(
        RefusalKind::Edit,
        Some("inventory"),
        &format!("Failed to validate config: {CANARY_HEADER} {CANARY_QUERY} {CANARY_USER}"),
    );

    let body = serde_json::to_string(&ledger.list()).expect("serialises");
    for canary in [CANARY_HEADER, CANARY_QUERY, CANARY_USER] {
        assert!(!body.contains(canary), "{canary} leaked: {body}");
    }
}

#[test]
fn api4_3_an_unclassified_cause_is_withheld() {
    let ledger = RefusalLedger::new();
    ledger.record(
        RefusalKind::Reload,
        None,
        "Failed to parse config: sets protocol_version secret-ish-value on a ws_url",
    );
    let list = ledger.list();
    assert_eq!(list.len(), 1);
    assert_eq!(list[0].code, RefusalCode::InvalidConfig);
    assert!(
        !list[0].cause.contains("secret-ish-value"),
        "{}",
        list[0].cause
    );
    assert!(list[0].cause.contains("withheld"), "{}", list[0].cause);
}

#[test]
fn api4_3_a_shutdown_is_not_a_refusal() {
    let ledger = RefusalLedger::new();
    ledger.record(RefusalKind::Reload, None, STOPPED);
    assert!(ledger.list().is_empty());
}

#[test]
fn api4_3_an_applied_reload_resolves_earlier_reload_refusals_only() {
    // One clock instant for every entry: resolution must come from order,
    // not from timestamps.
    let ledger = RefusalLedger::with_clock(fixed_clock);
    ledger.record(RefusalKind::Reload, None, "Failed to parse config: bad");
    ledger.record(
        RefusalKind::Add,
        Some("inventory"),
        "Failed to validate config: bad",
    );
    ledger.reload_applied();
    ledger.record(
        RefusalKind::Reload,
        None,
        "Failed to parse config: bad again",
    );

    let list = ledger.list();
    assert_eq!(list.len(), 3);
    // Newest first.
    assert_eq!(list[0].kind, RefusalKind::Reload);
    assert!(list[0].active, "refused after the applied reload");
    assert_eq!(list[1].kind, RefusalKind::Add);
    assert!(
        list[1].active,
        "an add is resolved by a write, not a reload"
    );
    assert_eq!(list[2].kind, RefusalKind::Reload);
    assert!(!list[2].active, "resolved by the later applied reload");
}

#[test]
fn api4_3_an_applied_write_resolves_that_backend_only() {
    let ledger = RefusalLedger::new();
    ledger.record(RefusalKind::Add, Some("inventory"), "x");
    ledger.record(RefusalKind::Edit, Some("billing"), "x");
    // The pair the admin write handler uses: a place reserved inside the
    // write's lock, stamped once the write committed.
    let ticket = ledger.reserve();
    ledger.write_applied_at("inventory", ticket);

    let list = ledger.list();
    let by = |name: &str| {
        list.iter()
            .find(|r| r.backend.as_deref() == Some(name))
            .unwrap()
    };
    assert!(!by("inventory").active);
    assert!(by("billing").active);
}

#[test]
fn api4_3_the_ledger_is_bounded_newest_first() {
    let ledger = RefusalLedger::new();
    // Distinct backends, so no two in a row merge as repeats.
    for i in 0..(REFUSAL_CAP + 6) {
        ledger.record(
            RefusalKind::Add,
            Some(&format!("b{i}")),
            "Failed to validate config: x",
        );
    }
    let list = ledger.list();
    assert_eq!(list.len(), REFUSAL_CAP);
    assert!(
        list.windows(2).all(|w| w[0].id > w[1].id),
        "ids strictly descending"
    );
    assert_eq!(list[0].id, (REFUSAL_CAP + 6) as u64, "ids start at 1");
}

#[test]
fn api4_3_the_same_refusal_in_a_row_is_one_entry_with_repeats() {
    let ledger = RefusalLedger::new();
    for _ in 0..3 {
        ledger.record(RefusalKind::Reload, None, &reload_error(&cleartext_yaml()));
    }
    let list = ledger.list();
    assert_eq!(list.len(), 1, "{list:?}");
    assert_eq!(list[0].repeats, 3);
}

#[test]
fn api4_3_a_posture_refusal_gets_fixed_text() {
    let ledger = RefusalLedger::new();
    ledger.record(
        RefusalKind::Reload,
        None,
        &format!(
            "{} refusing to serve HTTP on {CANARY_QUERY}:8080 No backend was started or stopped",
            crate::config_reload::POSTURE_REFUSED_PREFIX
        ),
    );
    let list = ledger.list();
    assert_eq!(list[0].code, RefusalCode::Posture);
    assert!(!list[0].cause.contains(CANARY_QUERY), "{}", list[0].cause);
}

#[test]
fn api4_3_an_unreadable_clock_serves_no_time() {
    fn before_epoch() -> SystemTime {
        UNIX_EPOCH - Duration::from_secs(1)
    }
    let ledger = RefusalLedger::with_clock(before_epoch);
    ledger.record(RefusalKind::Reload, None, "Failed to parse config: x");
    assert_eq!(ledger.list()[0].at, None);
}

#[test]
fn api4_3_a_value_that_imitates_the_cleartext_refusal_is_withheld() {
    // A configured value (here a ws protocol_version) quoted inside another
    // validator's message, carrying the cleartext words around a canary.
    let error = format!(
        "Failed to parse config: Configuration validation error: Backend 'ws' sets \
         protocol_version Backend '{CANARY_HEADER}' {} on a ws_url",
        crate::config::CLEARTEXT_REFUSAL
    );
    let ledger = RefusalLedger::new();
    ledger.record(RefusalKind::Reload, None, &error);
    let list = ledger.list();
    assert_eq!(list[0].code, RefusalCode::InvalidConfig);
    assert_eq!(list[0].backend, None);
    let body = serde_json::to_string(&list).unwrap();
    assert!(!body.contains(CANARY_HEADER), "{body}");
}

/// Code review r2: a write's success is stamped at the place it reserved
/// inside its lock, so a refusal recorded after that place stays active even
/// when the older write's success lands later.
#[test]
fn api4_3_an_older_write_success_does_not_resolve_a_newer_refusal() {
    let ledger = RefusalLedger::new();
    // Different kinds, so the two are not merged as repeats.
    ledger.record(RefusalKind::Add, Some("inventory"), "x");
    let older = ledger.reserve();
    ledger.record(RefusalKind::Edit, Some("inventory"), "y");
    ledger.write_applied_at("inventory", older);
    let list = ledger.list();
    assert!(list[0].active, "the newer refusal stays active: {list:?}");
    assert!(!list[1].active, "the older one is resolved: {list:?}");
}

/// A load that refuses, standing in for a reload that rejects the file.
fn refused_load(
    _: &std::path::Path,
    _: &Arc<LiveConfig>,
    _: &LiveEnv,
) -> std::result::Result<crate::config_reload::reload_context::EvaluatedReload, String> {
    Err("the reload refuses this file".to_owned())
}

/// A write whose config is valid but whose reload is refused records the
/// reload's refusal exactly once: one entry, not merged with a second record
/// as a repeat. The written config still lands on disk. (The admin UI records
/// its own entry only for a config that fails validation, before any reload;
/// that path is pinned by the web UI's refused-add test.)
#[tokio::test]
async fn api4_3_a_write_whose_reload_is_refused_is_one_reload_entry() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("gateway.yaml");
    write_owner_only(
        &path,
        "backends:\n  a:\n    http_url: \"http://127.0.0.1:9/mcp\"\n",
    )
    .expect("write config");
    let running = Config::load(Some(&path)).expect("config loads");
    let ctx = crate::config_reload::ReloadContext::new(
        path.clone(),
        Arc::new(LiveConfig::new(running)),
        Arc::new(crate::backend::BackendRegistry::new()),
        crate::config::FailsafeConfig::default(),
        Duration::from_secs(60),
    )
    .expect("the registry pairs with the config")
    .with_load(refused_load);
    let mut edited = Config::load_literal(Some(&path)).expect("loads");
    let backend = edited.backends["a"].clone();
    edited.backends.insert("b".to_owned(), backend);

    let written = ctx.write_and_reload_outcome(&path, &edited).await;

    let failed = written.expect_err("the refused reload fails the write");
    assert!(
        format!("{failed:?}").contains("the reload refuses this file"),
        "failed by the injected refusal, not another: {failed:?}"
    );
    let on_disk = Config::load_literal(Some(&path)).expect("loads");
    assert!(on_disk.backends.contains_key("b"), "the write lands first");
    let list = ctx.refusals().list();
    assert_eq!(list.len(), 1, "one refusal, not zero or two: {list:?}");
    assert_eq!(list[0].kind, RefusalKind::Reload);
    assert_eq!(list[0].repeats, 1, "recorded once, not twice: {list:?}");
}

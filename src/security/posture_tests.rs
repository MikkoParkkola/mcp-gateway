// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! `security.posture`: preset floor, startup refusal, the shared predicate
//! and its startup warning. Configs come from YAML through `Config::load`.

use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use serde_json::json;

use super::*;
use crate::config::ContextIntegrityPresetConfig as Preset;
use crate::context_integrity::ContextIntegrityPolicyMode;

/// The target every posture record carries.
const TARGET: &str = "mcp_gateway::security::posture";

fn write_yaml(dir: &tempfile::TempDir, body: &str) -> PathBuf {
    let path = dir.path().join("gateway.yaml");
    crate::gateway::test_helpers::write_owner_only(&path, body).unwrap();
    path
}

fn load(body: &str) -> Config {
    let dir = tempfile::tempdir().unwrap();
    Config::load(Some(&write_yaml(&dir, body))).expect("fixture loads")
}

fn preset_yaml(posture: &str, preset: &str) -> String {
    format!("security:\n  posture: {posture}\n  context_integrity:\n    preset: {preset}\n")
}

#[test]
fn hardened_raises_monitor_only_to_team_shared() {
    for preset in ["monitor_only", "local_developer", "audit_only"] {
        let config = load(&preset_yaml("hardened", preset));
        let ci = &config.security.context_integrity;
        assert_eq!(ci.preset, Preset::TeamShared, "{preset} is raised");
        assert!(ci.non_bypassable, "{preset}: floor is non-bypassable");
        assert_eq!(
            ci.policy().effective_mode(),
            ContextIntegrityPolicyMode::Enforce
        );
    }
}

#[test]
fn hardened_keeps_enterprise_strict() {
    for (spelled, expected) in [
        ("team_shared", Preset::TeamShared),
        ("enterprise_strict", Preset::EnterpriseStrict),
    ] {
        let config = load(&preset_yaml("hardened", spelled));
        let ci = &config.security.context_integrity;
        assert_eq!(ci.preset, expected, "{spelled} is kept");
        assert!(ci.non_bypassable, "{spelled}: non-bypassable");
    }
}

#[test]
fn literal_load_does_not_apply_floor() {
    let dir = tempfile::tempdir().unwrap();
    let path = write_yaml(&dir, &preset_yaml("hardened", "monitor_only"));
    let config = Config::load_literal(Some(&path)).unwrap();
    assert_eq!(config.security.posture, SecurityPosture::Hardened);
    let ci = &config.security.context_integrity;
    assert_eq!(
        ci.preset,
        Preset::MonitorOnly,
        "a rewrite keeps the file's value"
    );
    assert!(!ci.non_bypassable);
}

#[test]
fn posture_defaults_to_standard_and_round_trips() {
    assert_eq!(load("{}\n").security.posture, SecurityPosture::Standard);
    for (value, text) in [
        (SecurityPosture::Standard, "standard"),
        (SecurityPosture::Hardened, "hardened"),
    ] {
        assert_eq!(serde_yaml::to_string(&value).unwrap().trim(), text);
        assert_eq!(
            serde_yaml::from_str::<SecurityPosture>(text).unwrap(),
            value
        );
    }
}

#[test]
fn standard_posture_applies_no_override() {
    let config = load(&preset_yaml("standard", "monitor_only"));
    let ci = &config.security.context_integrity;
    assert_eq!(ci.preset, Preset::MonitorOnly);
    assert!(!ci.non_bypassable);
    let mut config = config;
    resolve(&mut config, FirewallBuild::Absent).expect("standard never refuses");
}

#[test]
fn hardened_startup_refusals() {
    let dir = tempfile::tempdir().unwrap();
    let path = write_yaml(&dir, &preset_yaml("hardened", "team_shared"));
    let mut config = Config::load_literal(Some(&path)).unwrap();
    let error = resolve(&mut config, FirewallBuild::Absent)
        .expect_err("hardened needs the firewall feature")
        .to_string();
    assert!(error.contains("firewall"), "names the feature: {error}");
    assert!(
        error.contains("security.posture"),
        "names the switch: {error}"
    );
    resolve(&mut config, FirewallBuild::Compiled).expect("control: the default build loads");
}

// ── The unhardened multi-user predicate and its startup warning ──────────────
//
// The same table is in the doctor tests (`doctor_row_matches_unhardened_table`),
// so the warning and the doctor row are held to one expected column.

/// Auth shapes, and whether each is multi-user.
fn auth_shapes() -> Vec<(&'static str, Config, bool)> {
    // A digest-shaped key, so a gateway built from the shape validates.
    let key = |name: &str| {
        serde_json::from_value(
            json!({ "name": name, "key_sha256": format!("sha256:{}", "ab".repeat(32)) }),
        )
        .unwrap()
    };
    let mut shapes = Vec::new();
    // Would be multi-user if auth were on: only `enabled` makes it false.
    let mut disabled = Config::default();
    disabled.auth.api_keys = vec![key("a"), key("b")];
    shapes.push(("auth disabled, two keys", disabled, false));
    let mut one_key = Config::default();
    one_key.auth.enabled = true;
    one_key.auth.api_keys = vec![key("a")];
    shapes.push(("one key", one_key.clone(), true));
    let mut solo = one_key.clone();
    solo.auth.single_user = true;
    shapes.push(("one key, single_user", solo.clone(), false));
    let mut two_keys = solo.clone();
    two_keys.auth.api_keys.push(key("b"));
    shapes.push(("two keys, single_user", two_keys, true));
    let mut oidc = solo;
    oidc.key_server.oidc =
        vec![serde_json::from_value(json!({ "issuer": "https://idp.example" })).unwrap()];
    shapes.push(("one key, single_user, OIDC", oidc, true));
    let mut bearer = Config::default();
    bearer.auth.enabled = true;
    bearer.auth.bearer_token = Some("t".repeat(40));
    shapes.push(("bearer only", bearer, true));
    shapes
}

#[derive(Clone, Default)]
struct Sink(Arc<Mutex<Vec<u8>>>);

impl std::io::Write for Sink {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// The posture records `run` emits, as `(level, message)`.
///
/// Thread-local subscriber over a process-wide TRACE registry (idiom from
/// `agent_identity_audit_tests`), so no callsite is filtered before it.
pub(crate) fn posture_records(run: impl FnOnce()) -> Vec<(String, String)> {
    use tracing_subscriber::prelude::*;
    static INTEREST: std::sync::Once = std::sync::Once::new();
    INTEREST.call_once(|| {
        let _ = tracing::subscriber::set_global_default(
            tracing_subscriber::Registry::default()
                .with(tracing::level_filters::LevelFilter::TRACE),
        );
    });
    let sink = Sink::default();
    let writer = sink.clone();
    let subscriber = tracing_subscriber::fmt()
        .json()
        .without_time()
        .with_ansi(false)
        .with_max_level(tracing::Level::TRACE)
        .with_writer(move || writer.clone())
        .finish();
    tracing::subscriber::with_default(subscriber, run);
    let bytes = sink.0.lock().unwrap().clone();
    String::from_utf8(bytes)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap())
        .filter(|record| record["target"] == TARGET)
        .map(|record| {
            (
                record["level"].as_str().unwrap_or_default().to_string(),
                record["fields"]["message"]
                    .as_str()
                    .unwrap_or_default()
                    .to_string(),
            )
        })
        .collect()
}

#[test]
fn startup_warn_matches_unhardened_table() {
    for (shape, mut config, multi_user) in auth_shapes() {
        for posture in [SecurityPosture::Standard, SecurityPosture::Hardened] {
            config.security.posture = posture;
            // As a load would: the info line reports effective values.
            resolve(&mut config, FirewallBuild::Compiled).unwrap();
            let expected = multi_user && posture == SecurityPosture::Standard;
            let warning = unhardened_multi_user_warning(&config);
            assert_eq!(warning.is_some(), expected, "{shape} under {posture:?}");
            let records = posture_records(|| log_startup(&config));
            if let Some(warning) = warning {
                assert!(records.iter().any(|(_, m)| m == warning), "{records:?}");
            }
            let warns = records.iter().filter(|(level, _)| level == "WARN").count();
            assert_eq!(
                warns,
                usize::from(expected),
                "{shape} under {posture:?}: {records:?}"
            );
            let infos = records.iter().filter(|(level, _)| level == "INFO").count();
            let hardened = posture == SecurityPosture::Hardened;
            assert_eq!(
                infos,
                usize::from(hardened),
                "{shape} under {posture:?}: {records:?}"
            );
            if hardened {
                let line = &records[0].1;
                assert!(line.contains("preset=team_shared"), "{records:?}");
                assert!(line.contains("non_bypassable=true"), "{records:?}");
                assert!(line.contains("anomaly_block_threshold=1"), "{records:?}");
            }
        }
    }
}

/// Gateway construction logs the posture exactly once (every constructor
/// funnels into one body), so the warning cannot go missing or double.
#[test]
fn gateway_startup_logs_posture_once() {
    let (_, mut unhardened, _) = auth_shapes().swap_remove(1);
    // Auth on requires the audit log; give it a writable home.
    let dir = tempfile::tempdir().unwrap();
    unhardened.security.transparency_log.enabled = true;
    unhardened.security.transparency_log.path = dir.path().join("audit.log").display().to_string();
    // The same multi-user shape: only the posture tells the two apart.
    let mut hardened = unhardened.clone();
    // Not resolved here: the constructor must apply the floor itself.
    hardened.security.posture = SecurityPosture::Hardened;
    for (name, config, level) in [
        ("unhardened", unhardened, "WARN"),
        ("hardened", hardened, "INFO"),
    ] {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let records = posture_records(|| {
            runtime.block_on(async {
                let gateway = crate::gateway::Gateway::new(config).await;
                drop(gateway.expect("gateway builds"));
            });
        });
        assert_eq!(records.len(), 1, "{name}: {records:?}");
        assert_eq!(records[0].0, level, "{name}: {records:?}");
        if level == "INFO" {
            assert!(records[0].1.contains("preset=team_shared"), "{records:?}");
            assert!(records[0].1.contains("non_bypassable=true"), "{records:?}");
            assert!(
                records[0].1.contains("anomaly_detection=true"),
                "{records:?}"
            );
            assert!(
                records[0].1.contains("anomaly_block_threshold=1"),
                "{records:?}"
            );
        }
    }
}

/// An in-memory hardened config is forced before it is validated, so a
/// block threshold above 1.0 is refused on the constructor path too.
#[test]
fn gateway_constructor_validates_what_hardened_forces() {
    let mut config = Config::default();
    config.security.posture = SecurityPosture::Hardened;
    config.security.firewall.anomaly_block_threshold = Some(1.5);
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let error = runtime
        .block_on(async { crate::gateway::Gateway::new(config).await.map(drop) })
        .expect_err("a forced detector's range check refuses 1.5");
    assert!(
        error.to_string().contains("anomaly_block_threshold"),
        "{error}"
    );
}

// ── A1: hardened forces anomaly blocking ─────────────────────────────────────

fn firewall_yaml(posture: &str, block: Option<&str>) -> String {
    let block = block.map_or(String::new(), |b| {
        format!("    anomaly_block_threshold: {b}\n")
    });
    format!(
        "security:\n  posture: {posture}\n  firewall:\n    enabled: false\n    \
         anomaly_detection: false\n{block}"
    )
}

fn load_err(body: &str) -> String {
    let dir = tempfile::tempdir().unwrap();
    Config::load(Some(&write_yaml(&dir, body)))
        .expect_err("refused")
        .to_string()
}

#[test]
fn hardened_forces_anomaly_blocking() {
    for (block, expected) in [(None, 1.0), (Some("0.95"), 0.95), (Some("0.9"), 0.9)] {
        let config = load(&firewall_yaml("hardened", block));
        let firewall = &config.security.firewall;
        assert!(firewall.enabled, "{block:?}: firewall forced on");
        assert!(firewall.anomaly_detection, "{block:?}: detection forced on");
        assert_eq!(
            firewall.anomaly_block_threshold,
            Some(expected),
            "{block:?}: block threshold"
        );
    }
}

#[test]
fn standard_posture_leaves_the_firewall_alone() {
    let config = load(&firewall_yaml("standard", None));
    let firewall = &config.security.firewall;
    assert!(!firewall.enabled);
    assert!(!firewall.anomaly_detection);
    assert_eq!(firewall.anomaly_block_threshold, None);
}

#[test]
fn hardened_refuses_a_block_threshold_below_the_floor() {
    let error = load_err(&firewall_yaml("hardened", Some("0.85")));
    assert!(error.contains("anomaly_block_threshold"), "{error}");
    assert!(error.contains("0.9"), "names the floor: {error}");
    // Above 1.0 is refused by the range check the forced detection enables.
    let error = load_err(&firewall_yaml("hardened", Some("1.5")));
    assert!(error.contains("anomaly_block_threshold"), "{error}");
    // Standard keeps its own semantics: detection off, nothing checked.
    load(&firewall_yaml("standard", Some("0.85")));
}

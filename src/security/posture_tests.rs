// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! `security.posture`: preset floor, startup refusal, the shared predicate
//! and its startup warning. Configs come from YAML through `Config::load`.

use std::path::PathBuf;
use std::sync::{Arc, Mutex};

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

pub(crate) fn load(body: &str) -> Config {
    let dir = tempfile::tempdir().unwrap();
    Config::load(Some(&write_yaml(&dir, body))).expect("fixture loads")
}

fn preset_yaml(posture: &str, preset: &str) -> String {
    format!(
        "security:\n  posture: {posture}\n  context_integrity:\n    preset: {preset}\n{SIGNING_YAML}"
    )
}

/// Under `security:`: the signing secret hardened requires (row 6). Inert
/// under standard, where signing stays off.
const SIGNING_YAML: &str =
    "  message_signing:\n    shared_secret: hardened-signing-secret-0123456789abcdef\n";

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
    let config = load(&format!(
        "{}{SSRF_OFF}",
        preset_yaml("standard", "monitor_only")
    ));
    let ci = &config.security.context_integrity;
    assert_eq!(ci.preset, Preset::MonitorOnly);
    assert!(!ci.non_bypassable);
    assert!(
        !config.security.ssrf_protection,
        "standard keeps the file's value"
    );
    assert!(config.security.trust_configured_backends);
    assert!(
        !config.security.message_signing.enabled,
        "standard leaves signing off"
    );
    let mut config = config;
    resolve(&mut config, FirewallBuild::Absent).expect("standard never refuses");
}

/// A 32-byte signing secret for hardened fixtures.
pub(crate) const SIGNING_SECRET: &str = "hardened-signing-secret-0123456789abcdef";

/// Row 6: hardened forces signing before the secret is resolved, so a secret
/// set only in an env file resolves, whatever `enabled` the file says.
#[test]
fn hardened_resolves_env_secret_before_signing_check() {
    for enabled in ["", "    enabled: false\n"] {
        let dir = tempfile::tempdir().unwrap();
        let env = dir.path().join("gateway.env");
        crate::gateway::test_helpers::write_owner_only(
            &env,
            format!("HARDENED_SIGNING_SECRET={SIGNING_SECRET}\n"),
        )
        .unwrap();
        let body = format!(
            "env_files:\n  - '{}'\nsecurity:\n  posture: hardened\n  message_signing:\n{enabled}    \
             shared_secret: \"${{HARDENED_SIGNING_SECRET}}\"\n",
            env.display()
        );
        let config = Config::load(Some(&write_yaml(&dir, &body))).expect("the env secret resolves");
        let signing = &config.security.message_signing;
        assert!(signing.enabled, "hardened forces signing ({enabled:?})");
        assert_eq!(signing.shared_secret, SIGNING_SECRET, "({enabled:?})");
    }
}

/// Row 6: hardened with no signing secret refuses to start.
#[test]
fn hardened_without_signing_secret_refuses() {
    let err = load_err("security:\n  posture: hardened\n");
    assert!(
        err.contains("security.message_signing.shared_secret"),
        "{err}"
    );
}

/// Appended under a `security:` block: the two SSRF switches at their weakest.
const SSRF_OFF: &str = "  ssrf_protection: false\n  trust_configured_backends: true\n";

#[test]
fn hardened_forces_ssrf_flags() {
    let config = load(&format!(
        "{}{SSRF_OFF}",
        preset_yaml("hardened", "team_shared")
    ));
    assert!(
        config.security.ssrf_protection,
        "hardened forces SSRF protection"
    );
    assert!(
        !config.security.trust_configured_backends,
        "hardened re-checks configured backends"
    );
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

    // The refusals a hardened start meets through `Config::load`, each named by
    // the field it fires on. The 31-byte secret sits under `enabled: false`, so
    // it refuses only because the posture forced signing on.
    let short_secret = "  message_signing:\n    enabled: false\n    \
                        shared_secret: \"0123456789abcdef0123456789abcde\"\n";
    let unknown_backend =
        format!("  hardened:\n    private_backends: [no-such-backend]\n{SIGNING_YAML}");
    let low_block =
        firewall_yaml("hardened", Some("0.85")).replacen("security:\n  posture: hardened\n", "", 1);
    for (case, block, field) in [
        (
            "short secret",
            short_secret.to_string(),
            "security.message_signing.shared_secret",
        ),
        (
            "unconfigured private backend",
            unknown_backend,
            "private_backends",
        ),
        (
            "block threshold below the floor",
            low_block,
            "anomaly_block_threshold",
        ),
    ] {
        let error = load_err(&format!("security:\n  posture: hardened\n{block}"));
        assert!(error.contains(field), "{case}: {error}");
    }
    // Control: the same 31-byte secret under standard is dormant and loads.
    load(&format!("security:\n  posture: standard\n{short_secret}"));
}

// ── The unhardened multi-user predicate and its startup warning ──────────────
//
// Row 15: `auth_shapes` is one table, read here and by the doctor test
// (`doctor_row_matches_unhardened_table`), so the warning and the doctor row
// are held to one expected column.

use super::auth_shapes::auth_shapes;

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
    crate::test_log_capture::keep_interest_open();
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
    unhardened.security.transparency_log.enabled = Some(true);
    unhardened.security.transparency_log.path = dir.path().join("audit.log").display().to_string();
    // The same multi-user shape: only the posture tells the two apart.
    let mut hardened = unhardened.clone();
    // Not resolved here: the constructor must apply the floor itself.
    hardened.security.posture = SecurityPosture::Hardened;
    hardened.security.message_signing.shared_secret = SIGNING_SECRET.to_string();
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
#[cfg(feature = "firewall")]
#[test]
fn gateway_constructor_validates_what_hardened_forces() {
    let mut config = Config::default();
    config.security.posture = SecurityPosture::Hardened;
    config.security.firewall.anomaly_block_threshold = Some(1.5);
    config.security.message_signing.shared_secret = SIGNING_SECRET.to_string();
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

pub(crate) fn firewall_yaml(posture: &str, block: Option<&str>) -> String {
    let block = block.map_or(String::new(), |b| {
        format!("    anomaly_block_threshold: {b}\n")
    });
    format!(
        "security:\n  posture: {posture}\n  firewall:\n    enabled: false\n    \
         anomaly_detection: false\n{block}{SIGNING_YAML}"
    )
}

fn load_err(body: &str) -> String {
    let dir = tempfile::tempdir().unwrap();
    Config::load(Some(&write_yaml(&dir, body)))
        .expect_err("refused")
        .to_string()
}

#[cfg(feature = "firewall")]
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

#[cfg(feature = "firewall")]
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

/// Row 12b (#1881): under hardened the egress proxy is refused at load, since
/// it is a route out that the destination policy does not govern.
#[test]
fn hardened_refuses_capability_egress_proxy() {
    let yaml = |posture: &str| {
        format!(
            "security:\n  posture: {posture}\ncapabilities:\n  egress_proxy: \"http://proxy.internal:3128\"\n"
        )
    };
    let error = load_err(&yaml("hardened"));
    assert!(error.contains("capabilities.egress_proxy"), "{error}");
    assert!(error.contains("security.posture=hardened"), "{error}");
    // Standard keeps the proxy.
    let config = load(&yaml("standard"));
    assert!(config.capabilities.egress_proxy.is_some());
}

/// `security:` for `posture` with `private_backends` listing `names`, and two
/// configured stdio backends, `a` and `b`.
fn private_yaml(posture: &str, names: &str) -> String {
    format!(
        "backends:\n  a:\n    command: echo a\n  b:\n    command: echo b\nsecurity:\n  posture: \
         {posture}\n{SIGNING_YAML}  hardened:\n    private_backends: [{names}]\n"
    )
}

/// Row 17: under hardened a listed name that is no configured backend
/// refuses start, naming it.
#[test]
fn hardened_refuses_missing_private_backend() {
    let err = load_err(&private_yaml("hardened", "a, ghost"));
    assert!(err.contains("names 'ghost'"), "{err}");
    let config = load(&private_yaml("hardened", "a"));
    assert_eq!(config.security.hardened.private_backends, ["a"]);
}

/// Row 16: under standard the key is accepted and refuses nothing.
#[test]
fn standard_ignores_private_backends() {
    let config = load(&private_yaml("standard", "ghost"));
    assert_eq!(config.security.hardened.private_backends, ["ghost"]);
}

/// `security.hardened` is restart-only: a reload that changes the list is
/// refused, one that keeps it is not.
#[test]
fn reload_refuses_private_backends_change() {
    let running = load(&private_yaml("hardened", "a"));
    let changed = load(&private_yaml("hardened", "a, b"));
    let same = load(&private_yaml("hardened", "a"));
    let refusal = reload_refusal(&running, &changed).expect("a changed list is refused");
    assert!(refusal.contains("security.hardened"), "{refusal}");
    assert!(reload_refusal(&running, &same).is_none());
}

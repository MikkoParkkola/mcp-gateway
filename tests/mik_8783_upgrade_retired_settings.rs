// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8782 / MIK-8783 (Family settings-automatic-first): `mcp-gateway
//! upgrade` deletes each retired setting, keeps every other byte, and never
//! turns a switch off by deleting the section that is the switch.
//!
//! Driven through the built binary, like surf2: the rewrite, the save and the
//! report are wired in `main`.

#[path = "common/gateway_bin.rs"]
mod gateway_bin;

use std::path::PathBuf;
use std::process::Output;

use mcp_gateway::config::Config;

struct Setup {
    dir: tempfile::TempDir,
    config: PathBuf,
}

fn setup(yaml: &str) -> Setup {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::write(dir.path().join("version.stamp"), env!("CARGO_PKG_VERSION")).expect("stamp");
    let config = dir.path().join("gateway.yaml");
    mcp_gateway::gateway::test_helpers::write_owner_only(&config, yaml).expect("config");
    Setup { dir, config }
}

fn upgrade(s: &Setup) -> Output {
    gateway_bin::command(s.dir.path(), gateway_bin::Inherit::Environment)
        .arg("--config")
        .arg(&s.config)
        .arg("upgrade")
        .arg("--data-dir")
        .arg(s.dir.path())
        .output()
        .expect("the upgrade command runs")
}

fn text(out: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

fn read(s: &Setup) -> String {
    std::fs::read_to_string(&s.config).expect("read config")
}

const SEED: &str = "CQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQk=";

/// T1.5: each retired key, given a sibling, is deleted and nothing else moves.
#[test]
fn upgrade_deletes_each_retired_setting() {
    let rows = [
        (
            "capabilities.stale_check_secs",
            "capabilities:\n  stale_check_secs: 0\n  enabled: true\n",
            "capabilities:\n  enabled: true\n",
        ),
        (
            "cache.enabled",
            "cache:\n  enabled: false\n  max_entries: 10\n",
            "cache:\n  max_entries: 10\n",
        ),
        (
            "failsafe.retry.enabled",
            "failsafe:\n  retry:\n    enabled: false\n    max_attempts: 2\n",
            "failsafe:\n  retry:\n    max_attempts: 2\n",
        ),
        (
            "failsafe.circuit_breaker.enabled",
            "failsafe:\n  circuit_breaker:\n    enabled: false\n    failure_threshold: 4\n",
            "failsafe:\n  circuit_breaker:\n    failure_threshold: 4\n",
        ),
        (
            "auth.client_circuit_breaker.enabled",
            "auth:\n  client_circuit_breaker:\n    enabled: true\n    failure_threshold: 3\n",
            "auth:\n  client_circuit_breaker:\n    failure_threshold: 3\n",
        ),
        (
            "server.protocol_revision_window",
            "server:\n  port: 39400\n  protocol_revision_window: record\n",
            "server:\n  port: 39400\n",
        ),
    ];
    for (key, before, after) in rows {
        let s = setup(before);
        let out = upgrade(&s);
        assert!(out.status.success(), "{key}: {}", text(&out));
        assert_eq!(read(&s), after, "{key}: upgrade of {before:?}");
        Config::load(Some(&s.config))
            .unwrap_or_else(|e| panic!("{key}: upgraded file must load: {e}"));
    }
    let chain = format!(
        "security:\n  signature_chain:\n    signing_key: {SEED}\n    key_id: gw-a\n    max_links: 4\n"
    );
    let s = setup(&chain);
    let out = upgrade(&s);
    assert!(out.status.success(), "max_links: {}", text(&out));
    assert_eq!(
        read(&s),
        format!("security:\n  signature_chain:\n    signing_key: {SEED}\n    key_id: gw-a\n"),
        "max_links"
    );
}

/// T1.8: the report says the key is ignored in 4.0, never that it "never had
/// an effect": each of these settings did something in a pre-release.
#[test]
fn upgrade_reports_a_retired_setting_as_ignored() {
    let s = setup("cache:\n  enabled: false\n  max_entries: 10\n");
    let out = upgrade(&s);
    let report = text(&out);
    assert!(
        report.contains("cache.enabled"),
        "the report names the key: {report}"
    );
    assert!(report.contains("ignored in 4.0"), "{report}");
    assert!(!report.contains("never had an effect"), "{report}");
    assert!(
        report.contains("Seven settings are now the gateway's own choice")
            && report.contains("mcp-gateway/blob/main/docs/UPGRADING-4.0.md"),
        "the report points to the upgrade notes that name the hatch: {report}"
    );
}

/// T1.8b: `meta_mcp.cache_tools` also warns, but never did anything, so its
/// report does not send the operator to the seven-settings notes.
#[test]
fn upgrade_reports_cache_tools_as_never_having_an_effect() {
    let s = setup("meta_mcp:\n  enabled: true\n  cache_tools: false\n");
    let out = upgrade(&s);
    let report = text(&out);
    assert!(out.status.success(), "{report}");
    assert!(report.contains("never had an effect"), "{report}");
    assert!(!report.contains("Seven settings"), "{report}");
}

/// T1.6b: a flow-style client breaker with a tuning key beside `enabled` is
/// left as written, and the advice keeps the sibling: delete only `enabled`.
#[test]
fn upgrade_keeps_a_flow_style_client_breaker_and_its_tuning() {
    let before = "auth:\n  client_circuit_breaker: {enabled: true, failure_threshold: 3}\n";
    let s = setup(before);
    let out = upgrade(&s);
    let report = text(&out);
    assert!(out.status.success(), "{report}");
    assert_eq!(
        read(&s),
        before,
        "a flow-style section is left as written: {report}"
    );
    assert!(report.contains("delete only `enabled`"), "{report}");
    assert!(
        report.contains("if that leaves the section empty"),
        "{report}"
    );
    let edited = setup("auth:\n  client_circuit_breaker: {failure_threshold: 3}\n");
    let config = Config::load(Some(&edited.config)).expect("the advised edit loads");
    let breaker = config
        .auth
        .client_circuit_breaker
        .expect("the client breaker stays on");
    assert_eq!(breaker.failure_threshold, 3, "the sibling tuning survives");
}

/// T1.6: a lone `enabled` under `auth.client_circuit_breaker` stays, because
/// deleting it would empty the section whose presence turns the breaker on.
/// The report gives the exact edit, and that edit loads with the breaker on.
#[test]
fn upgrade_keeps_a_lone_client_breaker_switch_and_says_how_to_keep_it_on() {
    let before = "auth:\n  client_circuit_breaker:\n    enabled: true\n";
    let s = setup(before);
    let out = upgrade(&s);
    let report = text(&out);
    assert_eq!(
        read(&s),
        before,
        "the section must not be emptied: {report}"
    );
    assert!(
        report.contains("auth.client_circuit_breaker.enabled"),
        "{report}"
    );
    assert!(
        report.contains("client_circuit_breaker: {}"),
        "the report gives the edit: {report}"
    );
    // The documented edit keeps the breaker on.
    let edited = setup("auth:\n  client_circuit_breaker: {}\n");
    let config = Config::load(Some(&edited.config)).expect("the documented edit loads");
    assert!(
        config.auth.client_circuit_breaker.is_some(),
        "client breaker must stay on"
    );
}

/// T1.7: a `failsafe:` holding only one retired switch is either rewritten to
/// a file that loads, or left with the key named; never silently untouched.
#[test]
fn upgrade_handles_a_failsafe_section_holding_only_a_retired_switch() {
    for (key, before) in [
        (
            "failsafe.retry.enabled",
            "failsafe:\n  retry:\n    enabled: false\n",
        ),
        (
            "failsafe.circuit_breaker.enabled",
            "failsafe:\n  circuit_breaker:\n    enabled: false\n",
        ),
    ] {
        let s = setup(before);
        let out = upgrade(&s);
        let report = text(&out);
        let after = read(&s);
        if after == before {
            assert!(
                report.contains(key),
                "{key}: left, so the report must name it: {report}"
            );
        } else {
            assert!(
                !after.contains("enabled"),
                "{key}: rewritten but still set: {after:?}"
            );
        }
        Config::load(Some(&s.config)).unwrap_or_else(|e| panic!("{key}: must still load: {e}"));
    }
}

// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! `mcp-gateway upgrade --config` names the grant rows that name no one in the
//! grants file that config names, whatever the version stamp says, fails, and
//! edits nothing; a dry run checks the same way.

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use super::super::run_upgrade_with_config;

const ROW_OK: &str = "- grant_id: g-ok\n  subject:\n    authority: api_key\n    subject: alice\n  agent: any\n  capability: calendar_read\n  scope: execute\n  provenance: p\n  reason: kept\n";
const ROW_EMPTY: &str = "- grant_id: g-empty\n  subject:\n    authority: api_key\n    subject: \"\"\n  agent: any\n  capability: calendar_read\n  scope: execute\n  provenance: p\n  reason: empty\n";

/// A config naming a grants file holding `rows`, and a data dir stamped at
/// this build, so no version migration is due.
fn install(dir: &Path, rows: &str) -> (PathBuf, PathBuf, PathBuf) {
    let grants = dir.join("grants.yaml");
    let body = format!("schema_version: identity_grants.v1\ngrants:\n{rows}");
    mcp_gateway::gateway::test_helpers::write_owner_only(&grants, &body).unwrap();
    let config = dir.join("named.yaml");
    let text = format!(
        "security:\n  identity_grants:\n    enabled: true\n    path: {}\n",
        grants.display()
    );
    mcp_gateway::gateway::test_helpers::write_owner_only(&config, &text).unwrap();
    let data = dir.join("data");
    std::fs::create_dir_all(&data).unwrap();
    super::super::write_stamp(&super::super::stamp_path(&data), env!("CARGO_PKG_VERSION")).unwrap();
    (grants, config, data)
}

#[test]
fn upgrade_fails_on_a_nameless_row_at_a_current_stamp_and_edits_nothing() {
    for dry_run in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let (grants, config, data) = install(dir.path(), &format!("{ROW_OK}{ROW_EMPTY}"));
        let before = std::fs::read(&grants).unwrap();
        let listing = || {
            let mut names: Vec<String> = std::fs::read_dir(dir.path())
                .unwrap()
                .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
                .collect();
            names.sort();
            names
        };
        assert_eq!(
            run_upgrade_with_config(dry_run, true, Some(&data), Some(&config)),
            ExitCode::FAILURE,
            "dry_run={dry_run}"
        );
        assert_eq!(std::fs::read(&grants).unwrap(), before);
        // No grants backup or grant lock. The only new file is the config's
        // own lock sidecar, which the URL-key rewrite takes and which, like
        // every config lock, stays on disk for the next writer; a dry run
        // writes nothing.
        let expected: &[&str] = if dry_run {
            &["data", "grants.yaml", "named.yaml"]
        } else {
            &[".named.yaml.lock", "data", "grants.yaml", "named.yaml"]
        };
        assert_eq!(listing(), expected, "dry_run={dry_run}");
    }
}

#[test]
fn upgrade_passes_a_grants_file_that_loads() {
    let dir = tempfile::tempdir().unwrap();
    let (_, config, data) = install(dir.path(), ROW_OK);
    assert_eq!(
        run_upgrade_with_config(false, true, Some(&data), Some(&config)),
        ExitCode::SUCCESS
    );
}

/// Grants on with no grants file fails the upgrade, as it fails startup.
#[test]
fn upgrade_fails_when_the_grants_file_is_missing() {
    let dir = tempfile::tempdir().unwrap();
    let (grants, config, data) = install(dir.path(), ROW_OK);
    std::fs::remove_file(&grants).unwrap();
    assert_eq!(
        run_upgrade_with_config(false, true, Some(&data), Some(&config)),
        ExitCode::FAILURE
    );
}

/// `install` with `extra` appended to the config.
fn install_with(dir: &Path, rows: &str, extra: &str) -> (PathBuf, PathBuf) {
    let (_, config, data) = install(dir, rows);
    let text = std::fs::read_to_string(&config).unwrap();
    mcp_gateway::gateway::test_helpers::write_owner_only(&config, &format!("{text}{extra}"))
        .unwrap();
    (config, data)
}

/// A removed key the config refuses to load with (`marketplace`), which the
/// rewrite removes: a dry run cannot load the config as it stands, so it
/// defers the grants check, and the run that applies the rewrite checks
/// them. With valid grants that run passes, so its failure is the grants'.
#[test]
fn a_pending_rewrite_defers_the_grants_check_to_the_applying_run() {
    const REFUSING: &str = "marketplace:\n  plugin_dir: /tmp/p\n";
    let dir = tempfile::tempdir().unwrap();
    let (config, data) = install_with(dir.path(), &format!("{ROW_OK}{ROW_EMPTY}"), REFUSING);
    assert_eq!(
        run_upgrade_with_config(true, true, Some(&data), Some(&config)),
        ExitCode::SUCCESS,
        "the dry run reports the rewrite, not a config that cannot load yet"
    );
    assert_eq!(
        run_upgrade_with_config(false, true, Some(&data), Some(&config)),
        ExitCode::FAILURE,
        "the applying run loads the rewritten config and checks its grants"
    );
    let clean = tempfile::tempdir().unwrap();
    let (config, data) = install_with(clean.path(), ROW_OK, REFUSING);
    assert_eq!(
        run_upgrade_with_config(false, true, Some(&data), Some(&config)),
        ExitCode::SUCCESS,
        "with valid grants the applying run passes"
    );
}

/// A removed key that only warns (`meta_mcp.cache_tools`) leaves a config
/// that loads as it stands, so a dry run checks its grants rather than
/// deferring.
#[test]
fn a_dry_run_checks_grants_when_the_config_loads_as_it_stands() {
    let dir = tempfile::tempdir().unwrap();
    let (config, data) = install_with(
        dir.path(),
        &format!("{ROW_OK}{ROW_EMPTY}"),
        "meta_mcp:\n  cache_tools: true\n",
    );
    assert_eq!(
        run_upgrade_with_config(true, true, Some(&data), Some(&config)),
        ExitCode::FAILURE
    );
}

/// A dry run with valid grants on a config that loads passes; a config that
/// does not load for a reason the rewrite does not touch fails the dry run
/// too, since no applying run would make it load.
#[test]
fn a_dry_run_passes_valid_grants_and_fails_a_config_no_rewrite_fixes() {
    let dir = tempfile::tempdir().unwrap();
    let (config, data) = install_with(dir.path(), ROW_OK, "");
    assert_eq!(
        run_upgrade_with_config(true, true, Some(&data), Some(&config)),
        ExitCode::SUCCESS
    );
    let broken = tempfile::tempdir().unwrap();
    let (config, data) = install_with(broken.path(), ROW_OK, "server:\n  port: not-a-port\n");
    assert_eq!(
        run_upgrade_with_config(true, true, Some(&data), Some(&config)),
        ExitCode::FAILURE
    );
}

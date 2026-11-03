// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! `mcp-gateway upgrade --config` removes the nameless grant rows from the
//! grants file that config names, whatever the version stamp says, and
//! `--dry-run` writes nothing.

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

#[tokio::test]
async fn upgrade_cleans_the_grants_the_named_config_names_at_a_current_stamp() {
    let dir = tempfile::tempdir().unwrap();
    let (grants, config, data) = install(dir.path(), &format!("{ROW_OK}{ROW_EMPTY}"));
    assert_eq!(
        run_upgrade_with_config(false, true, Some(&data), Some(&config)),
        ExitCode::SUCCESS
    );
    let read = mcp_gateway::identity_grants::read_identity_grants_file(&grants)
        .await
        .expect("loads after the upgrade");
    let ids: Vec<_> = read.grants.iter().map(|g| g.grant_id.as_str()).collect();
    assert_eq!(ids, ["g-ok"]);
    assert!(dir.path().join("grants.yaml.bak.pre-4.0.0").exists());

    let after = std::fs::read(&grants).unwrap();
    assert_eq!(
        run_upgrade_with_config(false, true, Some(&data), Some(&config)),
        ExitCode::SUCCESS
    );
    assert_eq!(
        std::fs::read(&grants).unwrap(),
        after,
        "a second run changes nothing"
    );
}

#[test]
fn a_dry_run_writes_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let (grants, config, data) = install(dir.path(), &format!("{ROW_OK}{ROW_EMPTY}"));
    let before = std::fs::read(&grants).unwrap();
    let files = std::fs::read_dir(dir.path()).unwrap().count();
    assert_eq!(
        run_upgrade_with_config(true, true, Some(&data), Some(&config)),
        ExitCode::SUCCESS
    );
    assert_eq!(std::fs::read(&grants).unwrap(), before);
    assert_eq!(
        std::fs::read_dir(dir.path()).unwrap().count(),
        files,
        "no backup and no lock file"
    );
}

#[test]
fn a_refused_cleanup_fails_the_upgrade_and_writes_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let shadow = ROW_OK.replace("g-ok", "g-empty");
    let (grants, config, data) = install(dir.path(), &format!("{shadow}{ROW_EMPTY}"));
    let before = std::fs::read(&grants).unwrap();
    assert_eq!(
        run_upgrade_with_config(false, true, Some(&data), Some(&config)),
        ExitCode::FAILURE
    );
    assert_eq!(std::fs::read(&grants).unwrap(), before);
}

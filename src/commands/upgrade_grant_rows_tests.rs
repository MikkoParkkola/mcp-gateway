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
        let files = std::fs::read_dir(dir.path()).unwrap().count();
        assert_eq!(
            run_upgrade_with_config(dry_run, true, Some(&data), Some(&config)),
            ExitCode::FAILURE,
            "dry_run={dry_run}"
        );
        assert_eq!(std::fs::read(&grants).unwrap(), before);
        assert_eq!(
            std::fs::read_dir(dir.path()).unwrap().count(),
            files,
            "no backup, no lock file"
        );
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

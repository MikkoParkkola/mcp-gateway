// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
use std::path::{Path, PathBuf};

use super::{Removed, remove_nameless_rows};

const ROW_OK: &str = "- grant_id: g-ok\n  subject:\n    authority: api_key\n    subject: alice\n  agent: any\n  capability: calendar_read\n  scope: execute\n  provenance: mcp-gateway identity grants grant\n  reason: kept row\n";
const ROW_EMPTY: &str = "- grant_id: g-empty\n  subject:\n    authority: api_key\n    subject: \"\"\n  agent: any\n  capability: calendar_read\n  scope: execute\n  provenance: mcp-gateway identity grants grant\n  reason: private-reason-text\n";

fn legacy(dir: &Path) -> (PathBuf, PathBuf, String) {
    let path = dir.join("identity-grants.yaml");
    let body = format!("schema_version: identity_grants.v1\ngrants:\n{ROW_OK}{ROW_EMPTY}");
    crate::gateway::test_helpers::write_owner_only(&path, &body).unwrap();
    (path, dir.join("identity-grants.yaml.bak.4.0.0"), body)
}

fn atomic(path: &Path, text: &str) -> std::io::Result<()> {
    crate::config_persistence::write_text_atomic(path, text).map_err(std::io::Error::other)
}

#[tokio::test]
async fn a_nameless_row_is_removed_and_the_grants_then_load() {
    let dir = tempfile::tempdir().unwrap();
    let (path, backup, _) = legacy(dir.path());
    let removed = remove_nameless_rows(&path, &backup, atomic).unwrap();
    assert_eq!(
        removed,
        vec![Removed {
            grant_id: "g-empty".into(),
            field: "subject".into()
        }]
    );
    let grants = crate::identity_grants::read_identity_grants_file(&path)
        .await
        .expect("loads after the upgrade");
    let ids: Vec<_> = grants.grants.iter().map(|g| g.grant_id.as_str()).collect();
    assert_eq!(ids, ["g-ok"]);
}

#[test]
fn the_report_names_the_rule_and_field_and_nothing_else_of_the_row() {
    let dir = tempfile::tempdir().unwrap();
    let (path, backup, _) = legacy(dir.path());
    let removed = remove_nameless_rows(&path, &backup, atomic).unwrap();
    let shown = format!("{removed:?}");
    assert!(
        shown.contains("g-empty") && shown.contains("subject"),
        "{shown}"
    );
    assert!(
        !shown.contains("private-reason-text"),
        "no row content: {shown}"
    );
}

#[test]
fn the_backup_is_written_before_the_rewrite_and_a_failed_rewrite_keeps_the_original() {
    let dir = tempfile::tempdir().unwrap();
    let (path, backup, body) = legacy(dir.path());
    let failing = |target: &Path, text: &str| {
        if target == path {
            Err(std::io::Error::other("injected rewrite failure"))
        } else {
            atomic(target, text)
        }
    };
    assert!(remove_nameless_rows(&path, &backup, failing).is_err());
    assert_eq!(
        std::fs::read_to_string(&backup).unwrap(),
        body,
        "backup first"
    );
    assert_eq!(
        std::fs::read_to_string(&path).unwrap(),
        body,
        "original intact"
    );
}

#[test]
fn a_second_run_changes_nothing_and_reports_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let (path, backup, _) = legacy(dir.path());
    assert_eq!(
        remove_nameless_rows(&path, &backup, atomic).unwrap().len(),
        1
    );
    let after_first = std::fs::read(&path).unwrap();
    let second = remove_nameless_rows(&path, &backup, |_: &Path, _: &str| {
        panic!("a second run writes nothing")
    })
    .unwrap();
    assert!(second.is_empty());
    assert_eq!(std::fs::read(&path).unwrap(), after_first);
}

#[test]
fn an_absent_grants_path_is_nothing_to_do() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("absent.yaml");
    let removed = remove_nameless_rows(&path, &dir.path().join("b"), atomic).unwrap();
    assert!(removed.is_empty());
    assert!(!path.exists());
}

#[test]
fn a_blank_subject_row_is_removed_like_an_empty_one() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("identity-grants.yaml");
    let blank = ROW_EMPTY.replace("subject: \"\"", "subject: \"   \"");
    let body = format!("schema_version: identity_grants.v1\ngrants:\n{ROW_OK}{blank}");
    crate::gateway::test_helpers::write_owner_only(&path, &body).unwrap();
    let removed = remove_nameless_rows(&path, &dir.path().join("b"), atomic).unwrap();
    assert_eq!(
        removed,
        vec![Removed {
            grant_id: "g-empty".into(),
            field: "subject".into()
        }]
    );
}

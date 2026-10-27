// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! One candidate list drives both the client-file fingerprint and the reads,
//! so the discovery cache's key and its finds can never drift apart.

use std::path::Path;

use serde_json::json;

use super::*;
use crate::discovery::DiscoverySource;

fn claude(path: &Path) -> Candidate {
    Candidate {
        path: path.to_path_buf(),
        source: DiscoverySource::ClaudeDesktop,
        format: Format::Claude,
    }
}

fn write(path: &Path, value: &serde_json::Value) {
    crate::gateway::test_helpers::write_owner_only(path, &value.to_string()).expect("write");
}

fn entry(env_value: &str) -> serde_json::Value {
    json!({"mcpServers": {"srv": {"command": "npx", "env": {"K": env_value}}}})
}

#[test]
fn the_fingerprint_sees_a_created_a_changed_and_a_deleted_file() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("claude.json");
    let candidates = [claude(&path)];

    let absent = ConfigScanner::fingerprint(&candidates);
    write(&path, &entry("v"));
    let created = ConfigScanner::fingerprint(&candidates);
    assert_ne!(absent, created, "a created file changes it");
    assert_eq!(created, ConfigScanner::fingerprint(&candidates), "stable");

    write(&path, &entry("a longer value"));
    let changed = ConfigScanner::fingerprint(&candidates);
    assert_ne!(created, changed, "a changed file changes it");

    std::fs::remove_file(&path).expect("delete");
    assert_eq!(
        ConfigScanner::fingerprint(&candidates),
        absent,
        "deleted is absent again"
    );
}

#[tokio::test]
async fn an_unreadable_file_is_named_and_the_others_still_scan() {
    let dir = tempfile::tempdir().expect("tempdir");
    let good = dir.path().join("good.json");
    let bad = dir.path().join("settings.json");
    let missing = dir.path().join("missing.json");
    write(&good, &entry("v"));
    crate::gateway::test_helpers::write_owner_only(&bad, "{ not json").expect("write");
    let candidates = [
        claude(&good),
        Candidate {
            path: bad.clone(),
            source: DiscoverySource::VsCode,
            format: Format::VsCode,
        },
        claude(&missing),
    ];

    let scan = ConfigScanner::new().scan_candidates(&candidates).await;

    let names: Vec<&str> = scan.finds.iter().map(|s| s.name.as_str()).collect();
    assert_eq!(names, ["srv"]);
    assert_eq!(
        scan.unreadable,
        vec![(DiscoverySource::VsCode, "settings.json".to_string())]
    );
    assert_eq!(scan.fingerprint, ConfigScanner::fingerprint(&candidates));
}

#[tokio::test]
async fn an_entry_digest_follows_every_value_and_nothing_else() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("claude.json");
    let candidates = [claude(&path)];
    let digest = |scan: &ClientScan| scan.finds[0].entry_digest.clone();

    write(&path, &entry("first"));
    let first = digest(&ConfigScanner::new().scan_candidates(&candidates).await);
    let again = digest(&ConfigScanner::new().scan_candidates(&candidates).await);
    write(&path, &entry("second"));
    let second = digest(&ConfigScanner::new().scan_candidates(&candidates).await);

    assert!(!first.is_empty());
    assert_eq!(first, again, "the same entry gives the same digest");
    assert_ne!(first, second, "a value-only change gives a new digest");
}

#[test]
fn the_candidates_name_no_environment_or_process_source() {
    assert!(ConfigScanner::candidates().iter().all(|c| !matches!(
        c.source,
        DiscoverySource::Environment | DiscoverySource::RunningProcess
    )));
}

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
    crate::gateway::test_helpers::write_owner_only(path, value.to_string()).expect("write");
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
async fn a_huge_file_or_a_directory_never_reaches_a_parser() {
    let dir = tempfile::tempdir().expect("tempdir");
    let huge = dir.path().join("huge.json");
    let folder = dir.path().join("folder.json");
    // Valid JSON, just over the cap.
    let filler = "x".repeat(usize::try_from(MAX_CLIENT_FILE).expect("fits"));
    write(&huge, &entry(&filler));
    std::fs::create_dir(&folder).expect("dir");

    let scan = ConfigScanner::new()
        .scan_candidates(&[claude(&huge), claude(&folder)])
        .await;

    assert!(scan.finds.is_empty(), "{:?}", scan.finds);
    assert_eq!(
        scan.unreadable,
        vec![
            (DiscoverySource::ClaudeDesktop, "huge.json".to_string()),
            (DiscoverySource::ClaudeDesktop, "folder.json".to_string()),
        ]
    );
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

/// The webui scan's debug line names a client file escaped: a file whose name
/// holds a bidi override, a zero-width space and a newline is logged on one
/// line, with each written as its escape.
#[cfg(unix)]
#[test]
fn the_client_scan_debug_line_shows_the_file_name_escaped() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("cl\u{202e}\u{200b}x\nforged.json");
    write(&path, &entry("v"));
    let candidates = [claude(&path)];
    let scanner = ConfigScanner::new();
    let (_, logs) = crate::test_log_capture::capture_at(tracing::Level::DEBUG, || {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime")
            .block_on(scanner.scan_candidates(&candidates))
    });
    let line = logs
        .lines()
        .find(|line| line.contains("Scanning client config at"))
        .unwrap_or_else(|| panic!("the site did not fire: {logs:?}"));
    assert!(
        line.contains("forged.json"),
        "the name was split across lines: {logs:?}"
    );
    for spelled in ["\\u{202e}", "\\u{200b}", "\\u{a}"] {
        assert!(line.contains(spelled), "no {spelled} in {line:?}");
    }
    for raw in ['\u{202e}', '\u{200b}'] {
        assert!(!logs.contains(raw), "{raw:?} reached the log: {logs:?}");
    }
}

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

/// Each unreadable file as its app and file name.
fn unreadable_names(scan: &ClientScan) -> Vec<(DiscoverySource, String)> {
    scan.unreadable
        .iter()
        .map(|file| (file.source.clone(), file.file_name()))
        .collect()
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
        unreadable_names(&scan),
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
        unreadable_names(&scan),
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

/// R13: a client file behind a directory the gateway may not search is not
/// "absent": its stamp differs from a missing file's, and the scan names it
/// unreadable. Skipped under root, where permissions do not bind.
#[cfg(unix)]
#[tokio::test]
async fn a_file_behind_an_unsearchable_directory_is_not_absent() {
    use std::os::unix::fs::PermissionsExt as _;
    if rustix::process::geteuid().is_root() {
        return;
    }
    let dir = tempfile::tempdir().expect("tempdir");
    let sub = dir.path().join("client");
    std::fs::create_dir(&sub).expect("dir");
    let path = sub.join("claude.json");
    let candidates = [claude(&path)];
    let absent = ConfigScanner::fingerprint(&candidates);

    write(&path, &entry("v"));
    std::fs::set_permissions(&sub, std::fs::Permissions::from_mode(0o000)).expect("chmod");
    let premise = std::fs::metadata(&path).map_err(|e| e.kind());
    let denied = ConfigScanner::fingerprint(&candidates);
    let scan = ConfigScanner::new().scan_candidates(&candidates).await;
    std::fs::set_permissions(&sub, std::fs::Permissions::from_mode(0o700)).expect("restore");

    assert_eq!(
        premise.err(),
        Some(std::io::ErrorKind::PermissionDenied),
        "premise: the file's metadata is refused"
    );
    assert_ne!(denied, absent, "an unsearchable file read as absent");
    assert_eq!(
        scan.unreadable.len(),
        1,
        "an unsearchable file was skipped as absent"
    );
}

fn candidate(path: &Path, format: Format) -> Candidate {
    Candidate {
        path: path.to_path_buf(),
        source: DiscoverySource::VsCode,
        format,
    }
}

/// R9: each unreadable file carries the reason class it failed for.
#[tokio::test]
async fn an_unreadable_file_carries_its_reason_class() {
    use crate::decisions::UnreadableReason;
    let dir = tempfile::tempdir().expect("tempdir");
    let huge = dir.path().join("huge.json");
    let size = usize::try_from(MAX_CLIENT_FILE + 1).expect("fits");
    std::fs::write(&huge, vec![b' '; size]).expect("write");
    let broken = dir.path().join("broken.json");
    std::fs::write(&broken, "{ not json").expect("write");
    let candidates = [claude(&huge), claude(&broken)];
    let rows = ConfigScanner::new()
        .scan_candidates(&candidates)
        .await
        .unreadable_rows();
    let reason = |file: &str| {
        rows.iter()
            .find(|(name, _, _)| name == file)
            .map(|(_, reason, _)| *reason)
    };
    assert_eq!(
        reason("huge.json"),
        Some(UnreadableReason::NotAReadableFile)
    );
    assert_eq!(reason("broken.json"), Some(UnreadableReason::DidNotParse));
}

/// R9: a file the gateway may not open reads as `no_permission`, whichever
/// parser it is for. Skipped under root, where permissions do not bind.
#[cfg(unix)]
#[tokio::test]
async fn a_file_that_may_not_be_opened_is_no_permission_for_every_format() {
    use std::os::unix::fs::PermissionsExt as _;
    if rustix::process::geteuid().is_root() {
        return;
    }
    let dir = tempfile::tempdir().expect("tempdir");
    let mut candidates = Vec::new();
    for (name, format) in [
        ("claude.json", Format::Claude),
        ("settings.json", Format::VsCode),
        ("zed.json", Format::Zed),
        ("continue.json", Format::Continue),
    ] {
        let path = dir.path().join(name);
        std::fs::write(&path, "{}").expect("write");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o000)).expect("chmod");
        assert_eq!(
            std::fs::File::open(&path).err().map(|e| e.kind()),
            Some(std::io::ErrorKind::PermissionDenied),
            "premise: {name} may not be opened"
        );
        candidates.push(candidate(&path, format));
    }
    let rows = ConfigScanner::new()
        .scan_candidates(&candidates)
        .await
        .unreadable_rows();
    assert_eq!(rows.len(), 4, "{rows:?}");
    for (file, reason, _) in &rows {
        assert_eq!(
            *reason,
            crate::decisions::UnreadableReason::NoPermission,
            "{file}"
        );
    }
}

/// R9: two unreadable files with one name keep distinct path digests, and
/// a row carries the file name and the digest, never the path.
#[tokio::test]
async fn two_unreadable_files_with_one_name_keep_distinct_digests() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut candidates = Vec::new();
    for app in ["code", "cursor"] {
        let sub = dir.path().join(app);
        std::fs::create_dir(&sub).expect("dir");
        let path = sub.join("settings.json");
        std::fs::write(&path, "{ not json").expect("write");
        candidates.push(candidate(&path, Format::VsCode));
    }
    let rows = ConfigScanner::new()
        .scan_candidates(&candidates)
        .await
        .unreadable_rows();
    assert_eq!(rows.len(), 2, "{rows:?}");
    assert_ne!(rows[0].2, rows[1].2, "the two files share a digest");
    let shown = format!("{rows:?}");
    assert!(
        !shown.contains(&dir.path().display().to_string()),
        "a path reached a row: {shown}"
    );
    for (file, _, digest) in &rows {
        assert_eq!(file, "settings.json");
        assert_eq!(digest.len(), 64, "a keyed digest: {digest}");
    }
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

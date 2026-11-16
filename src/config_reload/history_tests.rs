// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

use super::{Bounds, ConfigHistory, Event, Lookup, Outcome, Snapshot, Source, StoredFile};

fn event(at: u64, outcome: Outcome, revision: Option<&str>, unchanged: bool) -> Event {
    Event {
        at,
        source: Source::File,
        outcome,
        revision: revision.map(str::to_string),
        unchanged,
        still_running: None,
        location: None,
        attempted_diff: None,
    }
}

fn snap(revision: &str, at: u64, bytes: &[u8]) -> Snapshot {
    Snapshot {
        revision: revision.to_string(),
        at,
        files: vec![StoredFile {
            path: "gateway.yaml".to_string(),
            bytes: Some(bytes.to_vec()),
        }],
        pending_restart: Vec::new(),
    }
}

fn record_version(history: &ConfigHistory, revision: &str, at: u64, bytes: &[u8], running: &str) {
    history.record(
        event(at, Outcome::Applied, Some(revision), false),
        Some(snap(revision, at, bytes)),
        running,
        at,
    );
}

fn revision_names(history: &ConfigHistory) -> Vec<String> {
    history
        .snapshots()
        .into_iter()
        .map(|snapshot| snapshot.revision)
        .collect()
}

fn expect(revisions: &[&str]) -> Vec<String> {
    revisions
        .iter()
        .map(|revision| (*revision).to_string())
        .collect()
}

fn gateway<'a>(snapshot: &'a Snapshot) -> &'a [u8] {
    snapshot
        .files
        .iter()
        .find(|file| file.path == "gateway.yaml")
        .and_then(|file| file.bytes.as_deref())
        .unwrap_or(b"")
}

#[test]
fn t1_history_survives_a_restart() {
    let dir = tempfile::tempdir().unwrap();
    let history = ConfigHistory::open(dir.path(), Bounds::default(), 0);
    let versions: [(&str, u64, &[u8]); 3] = [
        ("r1", 1, b"a: 1\n"),
        ("r2", 2, b"a: 2\n"),
        ("r3", 3, b"a: 3\n"),
    ];
    for (revision, at, bytes) in versions {
        record_version(&history, revision, at, bytes, revision);
    }

    let reopened = ConfigHistory::open(dir.path(), Bounds::default(), 4);
    let snaps = reopened.snapshots();
    assert_eq!(revision_names(&reopened), expect(&["r1", "r2", "r3"]));
    for (snapshot, (_, _, bytes)) in snaps.iter().zip(versions.iter()) {
        assert_eq!(gateway(snapshot), *bytes);
    }
}

#[test]
fn t2_the_count_bound_keeps_the_newest_and_the_running() {
    let bounds = Bounds {
        snapshots: 5,
        ..Bounds::default()
    };
    let dir = tempfile::tempdir().unwrap();
    let history = ConfigHistory::open(dir.path(), bounds, 0);
    for i in 1..=6 {
        let revision = format!("r{i}");
        let bytes = format!("v{revision}");
        record_version(&history, &revision, i, bytes.as_bytes(), &revision);
    }
    assert_eq!(
        revision_names(&history),
        expect(&["r2", "r3", "r4", "r5", "r6"])
    );

    let dir = tempfile::tempdir().unwrap();
    let history = ConfigHistory::open(dir.path(), bounds, 0);
    for i in 1..=6 {
        let revision = format!("r{i}");
        let bytes = format!("v{revision}");
        record_version(&history, &revision, i, bytes.as_bytes(), "r1");
    }
    assert_eq!(
        revision_names(&history),
        expect(&["r1", "r3", "r4", "r5", "r6"])
    );
}

#[test]
fn t2p_production_bounds_are_the_design_literals() {
    let bounds = Bounds::default();
    assert_eq!(bounds.snapshots, 50);
    assert_eq!(bounds.snapshot_bytes, 33_554_432);
    assert_eq!(bounds.events, 1_000);
    assert_eq!(bounds.event_bytes, 4_194_304);
    assert_eq!(bounds.max_age_secs, 2_592_000);
}

#[test]
fn t3_byte_bounds_evict_until_under() {
    let bounds = Bounds {
        snapshot_bytes: 100,
        events: 3,
        event_bytes: 1_000_000,
        ..Bounds::default()
    };
    let dir = tempfile::tempdir().unwrap();
    let history = ConfigHistory::open(dir.path(), bounds, 0);
    for i in 1..=4 {
        let revision = format!("r{i}");
        let bytes = vec![b'0' + i as u8; 40];
        record_version(&history, &revision, i, &bytes, &revision);
    }
    assert_eq!(revision_names(&history), expect(&["r3", "r4"]));

    for at in 5..=9 {
        history.record(event(at, Outcome::Applied, None, true), None, "r4", at);
    }
    let events = history.events();
    assert_eq!(events.len(), 3);
    let ats: Vec<u64> = events.iter().map(|event| event.at).collect();
    assert_eq!(ats, vec![7, 8, 9]);
}

#[test]
fn t4_old_versions_age_out_unless_running() {
    let bounds = Bounds {
        max_age_secs: 100,
        ..Bounds::default()
    };
    let dir = tempfile::tempdir().unwrap();
    let history = ConfigHistory::open(dir.path(), bounds, 0);
    record_version(&history, "r1", 0, b"a: 1\n", "r1");
    record_version(&history, "r2", 50, b"a: 2\n", "r2");
    history.record(
        event(200, Outcome::Applied, Some("r2"), true),
        None,
        "r2",
        200,
    );

    assert_eq!(revision_names(&history), expect(&["r2"]));
    assert!(matches!(history.lookup("r1"), Lookup::NoLongerKept));
    assert!(matches!(history.lookup("zz"), Lookup::Unknown));
}

#[cfg(unix)]
#[test]
fn t5_an_unreadable_file_is_moved_aside_by_hard_link() {
    use std::os::unix::fs::MetadataExt;

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join(ConfigHistory::FILE);
    std::fs::write(&path, b"{not json").unwrap();
    let inode = std::fs::metadata(&path).unwrap().ino();

    let history = ConfigHistory::open(dir.path(), Bounds::default(), 1000);
    assert!(history.snapshots().is_empty());
    let aside = dir.path().join("config-history.json.unreadable-1000");
    assert!(aside.exists());
    assert_eq!(std::fs::metadata(&aside).unwrap().ino(), inode);
    assert_eq!(std::fs::read(&aside).unwrap(), b"{not json");

    std::fs::write(&path, b"{not json").unwrap();
    let _ = ConfigHistory::open(dir.path(), Bounds::default(), 1000);
    assert_eq!(std::fs::read(&aside).unwrap(), b"{not json");
    assert_eq!(std::fs::metadata(&aside).unwrap().ino(), inode);
    assert!(
        dir.path()
            .join("config-history.json.unreadable-1000-1")
            .exists()
    );
}

#[cfg(unix)]
#[test]
fn t6_the_file_is_owner_only() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join(ConfigHistory::FILE);
    std::fs::write(&path, br#"{"snapshots":[],"events":[]}"#).unwrap();
    let mut perms = std::fs::metadata(&path).unwrap().permissions();
    perms.set_mode(0o644);
    std::fs::set_permissions(&path, perms).unwrap();

    let history = ConfigHistory::open(dir.path(), Bounds::default(), 1);
    record_version(&history, "r1", 1, b"a: 1\n", "r1");
    let mode = std::fs::metadata(&path).unwrap().permissions().mode();
    assert_eq!(mode & 0o777, 0o600);
}

#[test]
fn t7_ids_are_never_recomputed() {
    let dir = tempfile::tempdir().unwrap();
    let history = ConfigHistory::open(dir.path(), Bounds::default(), 0);
    let bytes = b"same-bytes";
    record_version(&history, "r1", 1, bytes, "r1");
    record_version(&history, "r2", 2, bytes, "r2");

    assert_eq!(revision_names(&history), expect(&["r1", "r2"]));
    assert!(matches!(history.lookup("r1"), Lookup::Kept(_)));
    if let Lookup::Kept(found) = history.lookup("r1") {
        assert_eq!(gateway(&found), bytes);
    }
    let path = dir.path().join(ConfigHistory::FILE);
    assert!(path.exists());
    let text = std::fs::read_to_string(&path).unwrap();
    assert!(!text.contains("\"alias\""));
}

#[test]
fn t8_an_event_written_without_a_diff_field_loads() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join(ConfigHistory::FILE);
    std::fs::write(
        &path,
        r#"{
  "snapshots": [],
  "events": [
    {
      "at": 10,
      "source": "file",
      "outcome": "refused",
      "revision": null,
      "unchanged": false
    }
  ]
}
"#,
    )
    .unwrap();

    let history = ConfigHistory::open(dir.path(), Bounds::default(), 10);
    let events = history.events();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].attempted_diff, None);

    history.record(event(11, Outcome::Applied, None, true), None, "r1", 11);
    let text = std::fs::read_to_string(&path).unwrap();
    assert!(!text.contains("attempted_diff"));
}

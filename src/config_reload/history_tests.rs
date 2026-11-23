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
        source: Source::File,
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

fn gateway(snapshot: &Snapshot) -> &[u8] {
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
        let bytes = vec![b'0' + u8::try_from(i).unwrap(); 40];
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
    assert!(matches!(history.lookup("r1"), Ok(Lookup::NoLongerKept)));
    assert!(matches!(history.lookup("zz"), Ok(Lookup::Unknown)));
}

#[cfg(unix)]
#[test]
fn t5_an_unreadable_file_is_moved_aside_by_hard_link() {
    use std::os::unix::fs::MetadataExt;

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join(ConfigHistory::FILE);
    crate::gateway::test_helpers::write_owner_only(&path, b"{not json").unwrap();
    let inode = std::fs::metadata(&path).unwrap().ino();

    let history = ConfigHistory::open_eagerly(dir.path(), Bounds::default(), 1000);
    assert!(history.snapshots().is_empty());
    let aside = dir.path().join("config-history.json.unreadable-1000");
    assert!(aside.exists());
    assert_eq!(std::fs::metadata(&aside).unwrap().ino(), inode);
    assert_eq!(std::fs::read(&aside).unwrap(), b"{not json");

    crate::gateway::test_helpers::write_owner_only(&path, b"{not json").unwrap();
    let _ = ConfigHistory::open_eagerly(dir.path(), Bounds::default(), 1000);
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
    // No file yet: the store's own write makes it, where a plain write
    // would leave 0644.
    let history = ConfigHistory::open(dir.path(), Bounds::default(), 1);
    record_version(&history, "r1", 1, b"a: 1\n", "r1");
    let mode = std::fs::metadata(&path).unwrap().permissions().mode();
    assert_eq!(mode & 0o777, 0o600);
}

#[test]
fn t7_a_rotated_key_gives_a_new_id_and_keeps_the_old() {
    use std::sync::Arc;

    use crate::config::Config;
    use crate::config_reload::LiveConfig;
    use crate::config_reload::revision::RawInputs;
    use crate::gateway::record_principal::RecordPrincipalKey;

    const V1: &[u8] = b"backends:\n  a:\n    http_url: \"http://127.0.0.1:9/mcp\"\n";
    let dir = tempfile::tempdir().unwrap();
    let raw = RawInputs {
        gateway_yaml: V1.to_vec(),
        ..RawInputs::default()
    };
    let (_live, store) = super::record_tests::hold_at(
        dir.path(),
        raw.clone(),
        "gateway.yaml".to_string(),
        None,
        Config::default(),
        None,
    );
    let k1 = store
        .snapshots()
        .last()
        .map(|snapshot| snapshot.revision.clone());

    let rotated = RecordPrincipalKey::from_text("rotated-test-record-key-0123456789abcdef-two")
        .expect("the rotated key is long enough");
    let second = Arc::new(ConfigHistory::open(dir.path(), Bounds::default(), 1));
    let live = LiveConfig::new(Config::default())
        .with_history(super::HistoryHook {
            store: Arc::clone(&second),
            config_path: "gateway.yaml".to_string(),
        })
        .with_startup_revision(&rotated, Some(raw));
    let k2 = live
        .applied_now()
        .published
        .map(|applied| applied.revision.clone());

    assert_ne!(k1, k2);
    let fresh = ConfigHistory::open(dir.path(), Bounds::default(), 1);
    let names = revision_names(&fresh);
    assert_eq!(names.first().cloned(), k1);
    assert_eq!(names.get(1).cloned(), k2);
    assert_eq!(names.len(), 2);
    let kept = match k1.as_deref().map(|revision| fresh.lookup(revision)) {
        Some(Ok(Lookup::Kept(snapshot))) => Some(gateway(&snapshot).to_vec()),
        _ => None,
    };
    assert_eq!(kept.as_deref(), Some(V1));
    let text = std::fs::read_to_string(dir.path().join(ConfigHistory::FILE)).unwrap();
    assert!(!text.contains("\"alias\""));
}

#[test]
fn t8_an_event_written_without_a_diff_field_loads() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join(ConfigHistory::FILE);
    crate::gateway::test_helpers::write_owner_only(
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

/// A valid stored history holding one version, "r0".
#[cfg(unix)]
const ONE_VERSION: &[u8] =
    br#"{"snapshots":[{"revision":"r0","at":1,"files":[],"pending_restart":[]}],"events":[]}"#;

/// The history file holds env-file bytes, so it is read as a secret file: a
/// loose or linked one is not loaded, and is never saved over. (A file owned
/// by another account takes the same refusal; a row cannot create one
/// without root, and the owner rule is the guarded reader's own.)
#[cfg(unix)]
#[test]
fn t9_a_loose_or_linked_history_file_is_refused_and_left_alone() {
    use std::os::unix::fs::PermissionsExt;

    // The store opens with its first record in hand, as startup and the first
    // reload do, and a refused file sends that record to memory. Each case
    // takes the same steps (open, record r1) and reads back exactly what the
    // store holds.

    // The premise: the same bytes, owner-only, load under the same steps.
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join(ConfigHistory::FILE);
    std::fs::write(&path, ONE_VERSION).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    let history = ConfigHistory::open(dir.path(), Bounds::default(), 5);
    record_version(&history, "r1", 6, b"a: 1\n", "r1");
    assert_eq!(
        revision_names(&history),
        expect(&["r0", "r1"]),
        "owner-only loads"
    );

    // Loose: readable by others.
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join(ConfigHistory::FILE);
    std::fs::write(&path, ONE_VERSION).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
    let history = ConfigHistory::open(dir.path(), Bounds::default(), 5);
    record_version(&history, "r1", 6, b"a: 1\n", "r1");
    assert_eq!(
        revision_names(&history),
        expect(&["r1"]),
        "a loose file is not loaded; history runs in memory"
    );
    assert_eq!(
        std::fs::read(&path).unwrap(),
        ONE_VERSION,
        "left byte-identical"
    );
    let mode = std::fs::metadata(&path).unwrap().permissions().mode();
    assert_eq!(mode & 0o777, 0o644, "its mode is left alone");

    // Linked: a symbolic link to an owner-only file holding a valid store.
    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("elsewhere.json");
    std::fs::write(&target, ONE_VERSION).unwrap();
    std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o600)).unwrap();
    let path = dir.path().join(ConfigHistory::FILE);
    std::os::unix::fs::symlink(&target, &path).unwrap();
    let history = ConfigHistory::open(dir.path(), Bounds::default(), 5);
    record_version(&history, "r1", 6, b"a: 1\n", "r1");
    assert_eq!(
        revision_names(&history),
        expect(&["r1"]),
        "a linked file is not loaded; history runs in memory"
    );
    let link = std::fs::symlink_metadata(&path).unwrap();
    assert!(link.file_type().is_symlink(), "the link is left in place");
    assert_eq!(
        std::fs::read(&target).unwrap(),
        ONE_VERSION,
        "its target is left byte-identical"
    );
}

/// A refused history file is said once, naming the file and why: history
/// that silently stops being kept is a loss nobody would notice.
#[cfg(unix)]
#[test]
fn t10_a_refused_history_file_is_one_warning_naming_it() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join(ConfigHistory::FILE);
    std::fs::write(&path, ONE_VERSION).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();

    let ((), warnings) = crate::test_log_capture::capture_warnings(|| {
        let history = ConfigHistory::open(dir.path(), Bounds::default(), 5);
        record_version(&history, "r1", 6, b"a: 1\n", "r1");
        record_version(&history, "r2", 7, b"a: 2\n", "r2");
    });
    assert_eq!(warnings.lines().count(), 1, "one warning: {warnings}");
    let named = format!("Refusing to load config history file {}", path.display());
    assert!(warnings.contains(&named), "it names the file: {warnings}");
    assert!(
        warnings.contains("mode 0644 lets other users read it"),
        "it says why: {warnings}"
    );
}

/// A second start of the same inputs is an unchanged event and no new version.
#[test]
fn t11_a_restart_of_an_unchanged_config_stores_no_second_version() {
    use crate::config::Config;
    use crate::config_reload::revision::RawInputs;

    const V1: &[u8] = b"backends:\n  a:\n    http_url: \"http://127.0.0.1:9/mcp\"\n";
    let dir = tempfile::tempdir().unwrap();
    let raw = RawInputs {
        gateway_yaml: V1.to_vec(),
        ..RawInputs::default()
    };
    let k = {
        let (_live, store) = super::record_tests::hold_at(
            dir.path(),
            raw.clone(),
            "gateway.yaml".to_string(),
            None,
            Config::default(),
            None,
        );
        store
            .snapshots()
            .last()
            .map(|snapshot| snapshot.revision.clone())
    };
    let _restart = super::record_tests::hold_at(
        dir.path(),
        raw,
        "gateway.yaml".to_string(),
        None,
        Config::default(),
        None,
    );

    let fresh = ConfigHistory::open(dir.path(), Bounds::default(), 1);
    let one: Vec<String> = k.iter().cloned().collect();
    assert_eq!(revision_names(&fresh), one);
    let outcomes: Vec<Outcome> = fresh.events().iter().map(|event| event.outcome).collect();
    assert_eq!(outcomes, vec![Outcome::Applied, Outcome::Applied]);
    let pairs: Vec<(Source, bool)> = fresh
        .events()
        .iter()
        .map(|event| (event.source.clone(), event.unchanged))
        .collect();
    assert_eq!(pairs, vec![(Source::Start, false), (Source::Start, true)]);
}

/// The count bound pins only the newest copy of the running revision.
#[test]
fn t12_only_the_newest_copy_of_the_running_version_is_pinned() {
    let bounds = Bounds {
        snapshots: 2,
        ..Bounds::default()
    };
    let dir = tempfile::tempdir().unwrap();
    let history = ConfigHistory::open(dir.path(), bounds, 0);
    record_version(&history, "r1", 1, b"first-r1\n", "r1");
    record_version(&history, "r2", 2, b"r2\n", "r1");
    record_version(&history, "r1", 3, b"second-r1\n", "r1");
    record_version(&history, "r3", 4, b"r3\n", "r1");

    let kept = history.snapshots();
    assert_eq!(revision_names(&history), expect(&["r1", "r3"]));
    let running = kept.iter().find(|snapshot| snapshot.revision == "r1");
    assert_eq!(running.map(gateway), Some(b"second-r1\n".as_slice()));
}

/// Puts `dir` back to 0o700, including when an assertion fails or the row returns.
#[cfg(unix)]
struct RestoreDirMode(std::path::PathBuf);

#[cfg(unix)]
impl Drop for RestoreDirMode {
    fn drop(&mut self) {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&self.0, std::fs::Permissions::from_mode(0o700));
    }
}

/// A save that cannot create its temp file keeps the new version in memory.
#[cfg(unix)]
#[test]
fn t13_a_failed_save_keeps_the_record_in_memory() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::tempdir().unwrap();
    let history = ConfigHistory::open(dir.path(), Bounds::default(), 0);
    record_version(&history, "r1", 1, b"a: 1\n", "r1");

    let _restore = RestoreDirMode(dir.path().to_path_buf());
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o500)).unwrap();
    // Root ignores the mode, so a probe that lands is not a failed save.
    if std::fs::write(dir.path().join("probe-write"), b"x").is_ok() {
        return;
    }
    record_version(&history, "r2", 2, b"a: 2\n", "r2");
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();

    assert_eq!(revision_names(&history), expect(&["r1", "r2"]));
    let on_disk = ConfigHistory::open(dir.path(), Bounds::default(), 1);
    assert_eq!(revision_names(&on_disk), expect(&["r1"]));
}

/// A history opened inside a kept temp dir (`crate::test_dir_keep`) keeps it
/// until its last handle drops: a save its test left running (a watched
/// reload's record) lands before the dir goes, never mid-removal, where its
/// sidecar open would leave the dir behind holding only the lock.
#[test]
fn t14_a_history_in_a_kept_tempdir_keeps_it_until_its_last_handle() {
    let dir = crate::test_dir_keep::kept_tempdir();
    let root = dir.path().to_path_buf();
    let history = ConfigHistory::open(&root, Bounds::default(), 0);
    drop(dir);
    assert!(
        root.is_dir(),
        "the dir went with the test's share while the history lived in it"
    );
    record_version(&history, "r1", 1, b"a: 1\n", "r1");
    assert!(
        root.join(ConfigHistory::FILE).is_file(),
        "the late save landed"
    );
    drop(history);
    assert!(!root.exists(), "the dir outlived the history's last handle");
}

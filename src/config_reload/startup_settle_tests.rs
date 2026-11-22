// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Probe, lock, v1 recovery, refusal text and drain-error rows for the startup gate.

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use super::StartupState;
use super::*;
use crate::config_persistence::journal::v2::drain::DrainError;
use crate::fs_lock::ExclusiveFileLock;
use crate::gateway::test_helpers::write_owner_only;

const START: &str = "backends:\n  a:\n    http_url: \"http://127.0.0.1:9/mcp\"\n";
const NEXT: &str = concat!(
    "backends:\n  a:\n    http_url: \"http://127.0.0.1:9/mcp\"\n",
    "  b:\n    http_url: \"http://127.0.0.1:9/mcp\"\n",
);

/// The disk a writer killed after its rename leaves: `bytes` in place, the
/// original staged, the journal `staged`.
fn crashed_after_rename(path: &Path, original: &str, bytes: &str) {
    use crate::config_persistence::journal;
    journal::stage_original(path, original.as_bytes()).expect("stage");
    journal::begin(path, crate::hashing::sha256_hex(original.as_bytes())).expect("journal");
    write_owner_only(crate::identity_grants::journal::resolved(path), bytes).expect("rename");
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum Snap {
    Absent,
    File(Vec<u8>),
    Link(OsString),
    Dir,
}

fn snap(path: &Path) -> Snap {
    match std::fs::symlink_metadata(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Snap::Absent,
        Err(error) => panic!("stat {}: {error}", path.display()),
        Ok(meta) if meta.file_type().is_symlink() => Snap::Link(
            std::fs::read_link(path)
                .unwrap_or_else(|e| panic!("readlink {}: {e}", path.display()))
                .into_os_string(),
        ),
        Ok(meta) if meta.is_dir() => Snap::Dir,
        Ok(_) => Snap::File(read_bytes(path)),
    }
}

fn journal_file(dir: &Path) -> PathBuf {
    dir.join(".gateway.yaml.replace-journal")
}

fn fresh_config() -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::tempdir().expect("tempdir");
    let config = dir.path().join("gateway.yaml");
    write_owner_only(&config, START).expect("write");
    (dir, config)
}

fn read_bytes(path: &Path) -> Vec<u8> {
    std::fs::read(path).unwrap_or_else(|error| panic!("read {}: {error}", path.display()))
}

/// Every directory entry, name then bytes, so one equality is the listing and the bytes.
fn tree(dir: &Path) -> Vec<(OsString, Snap)> {
    let mut found = Vec::new();
    let entries = std::fs::read_dir(dir)
        .unwrap_or_else(|error| panic!("read_dir {}: {error}", dir.display()));
    for entry in entries {
        let entry = entry.expect("dir entry");
        found.push((entry.file_name(), snap(&entry.path())));
    }
    found.sort_by(|left, right| left.0.cmp(&right.0));
    found
}

/// A directory this account cannot write, for the unwritable-directory
/// rule; `None` under root, where permissions do not bind.
#[cfg(unix)]
fn unwritable_dir(with_journal: bool) -> Option<(tempfile::TempDir, std::path::PathBuf)> {
    if rustix::process::geteuid().is_root() {
        return None;
    }
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("gateway.yaml");
    write_owner_only(&path, START).expect("write");
    if with_journal {
        crashed_after_rename(&path, START, NEXT);
    }
    set_mode(dir.path(), 0o555);
    Some((dir, path))
}

#[cfg(unix)]
fn writable_again(dir: &tempfile::TempDir) {
    set_mode(dir.path(), 0o755);
}

#[cfg(unix)]
fn set_mode(path: &Path, bits: u32) {
    use std::os::unix::fs::PermissionsExt as _;
    let mode = std::fs::Permissions::from_mode(bits);
    std::fs::set_permissions(path, mode).expect("chmod");
}

/// Restores write permission so the temp directory can be removed.
#[cfg(unix)]
struct Release<'a>(&'a tempfile::TempDir);

#[cfg(unix)]
impl Drop for Release<'_> {
    fn drop(&mut self) {
        let real = self.0.path().join("real");
        if real.is_dir() {
            set_mode(&real, 0o755);
        }
        writable_again(self.0);
    }
}

fn logged(log: &Path) -> String {
    format!(
        "{START}security:\n  transparency_log:\n    enabled: true\n    path: {:?}\n",
        log.display().to_string()
    )
}

fn field<'a>(value: &'a serde_json::Value, key: &str) -> Option<&'a str> {
    match value {
        serde_json::Value::Object(map) => map
            .get(key)
            .and_then(serde_json::Value::as_str)
            .or_else(|| map.values().find_map(|child| field(child, key))),
        serde_json::Value::Array(items) => items.iter().find_map(|child| field(child, key)),
        _ => None,
    }
}

/// Recovery-intent identities `(event, base_revision)` in `log`, in order.
fn recovery_identities(log: &Path) -> Vec<(String, String)> {
    let Ok(text) = std::fs::read_to_string(log) else {
        return Vec::new();
    };
    let mut found = Vec::new();
    for line in text
        .lines()
        .filter(|line| line.contains("config_recovery_intent"))
    {
        let value: serde_json::Value = serde_json::from_str(line).expect("an audit line is JSON");
        let event = field(&value, "event").unwrap_or("");
        let base = field(&value, "base_revision").unwrap_or("");
        if event == "config_recovery_intent" {
            found.push((event.to_string(), base.to_string()));
        }
    }
    found
}

fn want_session(
    row: &str,
    case: &str,
    outcome: Result<StartupSession, StartError>,
    want: StartError,
) {
    match outcome {
        Err(got) if got == want => {}
        Err(got) => panic!("{row} {case}: {want:?}, got {got:?}"),
        Ok(session) => {
            panic!(
                "{row} {case}: {want:?}, got a session on {}",
                session.target().display()
            )
        }
    }
}

fn assert_locked(row: &str, session: &StartupSession) {
    assert!(
        matches!(&session.state, StartupState::Locked(_)),
        "{row}: Locked, got ArtifactFreeUnlocked on {}",
        session.target().display()
    );
}

fn assert_locked_no_journal(row: &str, session: &StartupSession) {
    match &session.state {
        StartupState::Locked(drain) => {
            assert!(drain.journal().is_none(), "{row}: Locked holds no journal");
        }
        StartupState::ArtifactFreeUnlocked { .. } => panic!(
            "{row}: Locked with no journal, got ArtifactFreeUnlocked on {}",
            session.target().display()
        ),
    }
}

async fn assert_lock_free(config: &Path, row: &str) {
    let now = Instant::now();
    let outcome = crate::config_persistence::lock::lock_config_deferred(config, now).await;
    match outcome {
        Ok(locked) => drop(locked),
        Err(error) => panic!("{row}: the lock is free, deferred acquisition returned {error:?}"),
    }
}

fn same_tree(row: &str, case: &str, dir: &Path, before: &[(OsString, Snap)]) {
    let after = tree(dir);
    assert_eq!(
        after, before,
        "{row} {case}: directory listing and artifact bytes unchanged"
    );
}

#[cfg(unix)]
fn plant(dir: &Path, name: &str, dangling: bool) {
    let path = dir.join(name);
    if dangling {
        std::os::unix::fs::symlink("missing", &path).expect("dangling symlink");
    } else {
        write_owner_only(&path, name.as_bytes()).expect("artifact");
    }
}

#[cfg(unix)]
async fn refuse_planted(case: &str, plant_one: impl FnOnce(&Path)) {
    let row = "startup_artifact_probe_refuses";
    let dir = tempfile::tempdir().expect("tempdir");
    let _keep = Release(&dir);
    let config = dir.path().join("gateway.yaml");
    write_owner_only(&config, START).expect("write");
    plant_one(dir.path());
    let before = tree(dir.path());
    set_mode(dir.path(), 0o555);
    let outcome = prepare_start(&config).await;
    want_session(row, case, outcome, StartError::ArtifactCheckFailed);
    same_tree(row, case, dir.path(), &before);
}

#[cfg(unix)]
async fn refuse_abandoned_beside_target() {
    let row = "startup_artifact_probe_refuses";
    let case = "abandoned beside target";
    let dir = tempfile::tempdir().expect("tempdir");
    let _keep = Release(&dir);
    let real = dir.path().join("real");
    std::fs::create_dir(&real).expect("real");
    let target = real.join("gateway.yaml");
    write_owner_only(&target, START).expect("target");
    let abandoned = real.join("gateway.yaml.abandoned");
    write_owner_only(&abandoned, b"beside the resolved target").expect("abandoned");
    let link = dir.path().join("gateway.yaml");
    std::os::unix::fs::symlink("real/gateway.yaml", &link).expect("symlink");
    let real_before = tree(&real);
    let dir_before = tree(dir.path());
    assert!(
        real_before
            .iter()
            .any(|(name, _)| name == "gateway.yaml.abandoned"),
        "{row} {case}: the abandoned file is beside the resolved target"
    );
    assert!(
        dir_before
            .iter()
            .all(|(name, _)| name != "gateway.yaml.abandoned"),
        "{row} {case}: the abandoned file is not beside the link"
    );
    set_mode(&real, 0o555);
    set_mode(dir.path(), 0o555);
    let outcome = prepare_start(&link).await;
    want_session(row, case, outcome, StartError::ArtifactCheckFailed);
    same_tree(row, case, &real, &real_before);
    same_tree(row, case, dir.path(), &dir_before);
}

#[cfg(unix)]
fn opened(row: &str, case: &str, outcome: Result<StartupSession, StartError>) -> StartupSession {
    let session = match outcome {
        Ok(session) => session,
        Err(error) => panic!("{row} {case}: ArtifactFreeUnlocked, got {error:?}"),
    };
    assert!(
        matches!(&session.state, StartupState::ArtifactFreeUnlocked { .. }),
        "{row} {case}: ArtifactFreeUnlocked, got Locked on {}",
        session.target().display()
    );
    session
}

#[cfg(unix)]
async fn accept_when_absent() {
    let row = "startup_artifact_probe_refuses";
    let (dir, config) = unwritable_dir(false).expect("not root");
    let _keep = Release(&dir);
    let before = tree(dir.path());
    let session = opened(row, "control", prepare_start(&config).await);
    let canonical = std::fs::canonicalize(&config).expect("resolved config");
    let StartupState::ArtifactFreeUnlocked { target, .. } = &session.state else {
        unreachable!("{row} control: opened already refused Locked");
    };
    assert_eq!(
        (session.target(), target.as_path()),
        (canonical.as_path(), canonical.as_path()),
        "{row} control: accessor and stored target equal the resolved config"
    );
    same_tree(row, "control", dir.path(), &before);
}

/// GATE.1: an absent artifact set resolves to the config; any one artifact refuses.
#[cfg(unix)]
#[tokio::test]
async fn startup_artifact_probe_refuses() {
    if rustix::process::geteuid().is_root() {
        return;
    }
    let cases = [
        ("journal", ".gateway.yaml.replace-journal", false),
        ("abandoned file", "gateway.yaml.abandoned", false),
        ("retired manifest", "gateway.yaml.abandoned.retired", false),
        (
            "journal dangling symlink",
            ".gateway.yaml.replace-journal",
            true,
        ),
        ("abandoned dangling symlink", "gateway.yaml.abandoned", true),
        (
            "retired dangling symlink",
            "gateway.yaml.abandoned.retired",
            true,
        ),
    ];
    for (case, name, dangling) in cases {
        refuse_planted(case, |dir| plant(dir, name, dangling)).await;
    }
    refuse_planted("sidecar directory", |dir| {
        std::fs::create_dir(dir.join(".gateway.yaml.lock")).expect("sidecar directory");
    })
    .await;
    refuse_abandoned_beside_target().await;
    accept_when_absent().await;
}

/// GATE.1: a writable config with no artifact is locked against a zero-bound acquisition.
#[tokio::test]
async fn prepare_locks_a_writable_config() {
    let row = "prepare_locks_a_writable_config";
    let (_dir, config) = fresh_config();
    let session = match prepare_start(&config).await {
        Ok(session) => session,
        Err(error) => panic!("{row}: Locked, got {error:?}"),
    };
    assert_locked(row, &session);
    let outcome = prepare_start_within(&config, Duration::ZERO).await;
    want_session(
        row,
        "zero bound while the session lives",
        outcome,
        StartError::Busy,
    );
}

/// GATE.1, the writable side: a retired manifest beside a config this start can lock is evidence
/// this build cannot read, so the start refuses it before any recovery. A crashed write waits
/// beside it, so a recovery run first would restore the config and remove the journal: the whole
/// folder must keep its entries and bytes, and the lock is free again.
#[tokio::test]
async fn prepare_refuses_a_retired_manifest_it_can_lock() {
    const LEFT: &[u8] = b"written by an older gateway";
    let row = "prepare_refuses_a_retired_manifest_it_can_lock";
    let (dir, config) = fresh_config();
    let manifest = dir.path().join("gateway.yaml.abandoned.retired");
    write_owner_only(&manifest, LEFT).expect("manifest");
    crashed_after_rename(&config, START, NEXT);
    let sidecar = crate::config_persistence::lock::lock_path(
        &crate::identity_grants::journal::resolved(&config),
    );
    let before = tree_with_sidecar(dir.path(), &sidecar);
    assert!(
        matches!(snap(&journal_file(dir.path())), Snap::File(_)),
        "{row}: premise: a journal waits to be recovered"
    );
    let outcome = prepare_start(&config).await;
    want_session(row, "manifest", outcome, StartError::ManifestUnread);
    same_tree(row, "manifest beside a crashed write", dir.path(), &before);
    assert_lock_free(&config, row).await;
}

/// GATE.4: with nothing pending under the lock, finishing accepts and releases the lock.
#[tokio::test]
async fn finish_accepts_a_clean_start() {
    let row = "finish_accepts_a_clean_start";
    let (dir, config) = fresh_config();
    let before = read_bytes(&config);
    let session = match prepare_start(&config).await {
        Ok(session) => session,
        Err(error) => panic!("{row}: Locked, got {error:?}"),
    };
    assert_locked_no_journal(row, &session);
    assert_eq!(finish_start(session, None).await, Ok(()), "{row}: accepts");
    assert_eq!(
        read_bytes(&config),
        before,
        "{row}: the config is unchanged"
    );
    for name in ["gateway.yaml.abandoned", ".gateway.yaml.replace-journal"] {
        assert_eq!(
            snap(&dir.path().join(name)),
            Snap::Absent,
            "{row}: {name} is not created"
        );
    }
    // Released: a fresh start takes the lock at once.
    let again = match prepare_start_within(&config, Duration::ZERO).await {
        Ok(again) => again,
        Err(error) => panic!("{row}: the lock is free after finishing, got {error:?}"),
    };
    assert_locked(row, &again);
}

/// GATE.2: a held lock past a zero bound is Busy and leaves the files unchanged.
#[tokio::test]
async fn start_busy_past_the_bound() {
    let row = "start_busy_past_the_bound";
    let (dir, config) = fresh_config();
    let resolved = crate::identity_grants::journal::resolved(&config);
    let lock_path = crate::config_persistence::lock::lock_path(&resolved);
    let before = tree_with_sidecar(dir.path(), &lock_path);
    let held = ExclusiveFileLock::try_acquire(&lock_path).expect("the test holds the lock");
    let outcome = prepare_start_within(&config, Duration::ZERO).await;
    want_session(row, "held", outcome, StartError::Busy);
    drop(held);
    same_tree(row, "held", dir.path(), &before);
    match prepare_start_within(&config, Duration::ZERO).await {
        Ok(session) => assert_locked(row, &session),
        Err(error) => panic!("{row} held: a fresh acquisition succeeds, got {error:?}"),
    }
}

/// GATE.7: the lock wait leaves the runtime's only thread free, then returns Locked.
#[cfg(feature = "webui")]
#[tokio::test(flavor = "current_thread")]
async fn lock_wait_keeps_the_runtime_ticking() {
    let row = "lock_wait_keeps_the_runtime_ticking";
    let (_dir, config) = fresh_config();
    let resolved = crate::identity_grants::journal::resolved(&config);
    let lock_path = crate::config_persistence::lock::lock_path(&resolved);
    let held = ExclusiveFileLock::try_acquire(&lock_path).expect("the test holds the lock");
    let config_for_gate = config.clone();
    let gate = tokio::spawn(async move {
        prepare_start_within(&config_for_gate, Duration::from_secs(30)).await
    });
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        if crate::config_persistence::lock::waiters_for_test(&lock_path) == 1 {
            break;
        }
        if Instant::now() >= deadline {
            let seen = crate::config_persistence::lock::waiters_for_test(&lock_path);
            panic!("{row}: the gate did not reach one waiter within 30s, saw {seen}");
        }
        tokio::task::yield_now().await;
    }
    let seen = crate::config_persistence::lock::waiters_for_test(&lock_path);
    assert_eq!(
        seen, 1,
        "{row}: one waiter while the runtime ticks, saw {seen}"
    );
    drop(held);
    let session = gate
        .await
        .expect("the gate task finishes")
        .unwrap_or_else(|error| panic!("{row}: Locked, got {error:?}"));
    assert_locked(row, &session);
    assert_eq!(
        session.target(),
        resolved.as_path(),
        "{row}: the Locked session's target is the resolved config"
    );
}

#[cfg(unix)]
async fn unlocked_plain(case: &str) -> (tempfile::TempDir, StartupSession) {
    let (dir, config) = unwritable_dir(false).expect("not root");
    let session = opened(
        "finish_unlocked_rechecks",
        case,
        prepare_start(&config).await,
    );
    (dir, session)
}

#[cfg(unix)]
fn expect_recheck_refused(case: &str, outcome: Result<(), StartError>) {
    match outcome {
        Err(StartError::ArtifactCheckFailed) => {}
        Err(error) => panic!("finish_unlocked_rechecks {case}: ArtifactCheckFailed, got {error:?}"),
        Ok(()) => panic!("finish_unlocked_rechecks {case}: ArtifactCheckFailed, got Ok"),
    }
}

/// GATE.4: an unlocked finish refuses a planted file, a re-pointed link, or a writable directory.
#[cfg(unix)]
#[tokio::test]
async fn finish_unlocked_rechecks() {
    if rustix::process::geteuid().is_root() {
        return;
    }
    let row = "finish_unlocked_rechecks";
    {
        let (dir, session) = unlocked_plain("control").await;
        let _keep = Release(&dir);
        let before = tree(dir.path());
        let outcome = finish_start(session, None).await;
        assert!(outcome.is_ok(), "{row} control: Ok, got {outcome:?}");
        same_tree(row, "control", dir.path(), &before);
    }
    {
        let (dir, session) = unlocked_plain("planted file").await;
        let _keep = Release(&dir);
        writable_again(&dir);
        let abandoned = dir.path().join("gateway.yaml.abandoned");
        write_owner_only(&abandoned, b"parked evidence").expect("plant");
        set_mode(dir.path(), 0o555);
        let before = tree(dir.path());
        expect_recheck_refused("planted file", finish_start(session, None).await);
        same_tree(row, "planted file", dir.path(), &before);
    }
    {
        let dir = tempfile::tempdir().expect("tempdir");
        let _keep = Release(&dir);
        let file_a = dir.path().join("a.yaml");
        let file_b = dir.path().join("b.yaml");
        write_owner_only(&file_a, START).expect("a");
        write_owner_only(&file_b, NEXT).expect("b");
        let link = dir.path().join("gateway.yaml");
        std::os::unix::fs::symlink("a.yaml", &link).expect("link");
        set_mode(dir.path(), 0o555);
        let session = opened(row, "re-pointed link", prepare_start(&link).await);
        let prepared = std::fs::canonicalize(&file_a).expect("canonical prepared target");
        writable_again(&dir);
        std::fs::remove_file(&link).expect("unlink");
        std::os::unix::fs::symlink("b.yaml", &link).expect("re-point");
        set_mode(dir.path(), 0o555);
        assert_eq!(
            session.target(),
            prepared.as_path(),
            "{row} re-pointed link: target read after the re-point is the prepared target"
        );
        let before = tree(dir.path());
        expect_recheck_refused("re-pointed link", finish_start(session, None).await);
        same_tree(row, "re-pointed link", dir.path(), &before);
    }
    {
        let (dir, session) = unlocked_plain("writable directory").await;
        let _keep = Release(&dir);
        writable_again(&dir);
        let before = tree(dir.path());
        expect_recheck_refused("writable directory", finish_start(session, None).await);
        let after = tree(dir.path());
        let kept: Vec<_> = after
            .iter()
            .filter(|(name, _)| name != ".gateway.yaml.lock")
            .cloned()
            .collect();
        assert_eq!(
            kept, before,
            "{row} writable directory: names and bytes stay; only the lock sidecar may be added"
        );
        let gained = after
            .iter()
            .filter(|(name, _)| name == ".gateway.yaml.lock")
            .count();
        assert_eq!(
            gained, 1,
            "{row} writable directory: one added entry .gateway.yaml.lock, after {after:?}"
        );
    }
}

/// GATE.4: a staged v1 journal with logging off restores the original and holds no journal.
#[tokio::test]
async fn prepare_recovers_a_v1_journal() {
    let row = "prepare_recovers_a_v1_journal";
    let dir = tempfile::tempdir().expect("tempdir");
    let config = dir.path().join("gateway.yaml");
    crashed_after_rename(&config, START, NEXT);
    let journal = journal_file(dir.path());
    let before = snap(&journal);
    assert!(
        matches!(before, Snap::File(_)),
        "{row}: the fixture's journal is a file"
    );
    assert_eq!(
        read_bytes(&config),
        NEXT.as_bytes(),
        "{row}: the candidate is on disk before recovery"
    );
    let session = match prepare_start(&config).await {
        Ok(session) => session,
        Err(error) => panic!("{row}: Locked with the original restored, got {error:?}"),
    };
    assert_locked_no_journal(row, &session);
    assert_eq!(
        read_bytes(&config),
        START.as_bytes(),
        "{row}: the config is the original"
    );
    let after = snap(&journal);
    assert_eq!(after, Snap::Absent, "{row}: the journal is gone");
}

/// GATE.4: a staged v1 journal with logging on records one recovery intent and frees the lease.
#[tokio::test]
async fn prepare_records_a_v1_recovery() {
    let row = "prepare_records_a_v1_recovery";
    // Registered: the gate and this row each open the log in this directory.
    let dir = crate::test_dir_keep::kept_tempdir();
    let config = dir.path().join("gateway.yaml");
    let log = dir.path().join("audit.ndjson");
    let original = logged(&log);
    crashed_after_rename(&config, &original, NEXT);
    let journal = journal_file(dir.path());
    let on_disk = read_bytes(&config);
    let base = crate::config_persistence::commit::FileRevision::of(&on_disk);
    let prior = recovery_identities(&log);
    assert_eq!(
        prior,
        Vec::<(String, String)>::new(),
        "{row}: no recovery record before prepare"
    );
    let session = match prepare_start(&config).await {
        Ok(session) => session,
        Err(error) => panic!("{row}: the recovery is recorded, got {error:?}"),
    };
    assert_locked_no_journal(row, &session);
    let arrived = recovery_identities(&log);
    let expected = vec![(
        "config_recovery_intent".to_string(),
        base.as_str().to_string(),
    )];
    assert_eq!(
        arrived, expected,
        "{row}: one new recovery intent for the on-disk revision"
    );
    assert_eq!(snap(&journal), Snap::Absent, "{row}: the journal is gone");
    assert_eq!(
        read_bytes(&config),
        original.as_bytes(),
        "{row}: the config is the surviving original"
    );
    let loaded = crate::config::Config::load(Some(&config))
        .unwrap_or_else(|error| panic!("{row}: the recovered config loads, got {error}"));
    let Some(audit) = loaded.audit_log() else {
        panic!("{row}: the surviving config names a log");
    };
    let opened = crate::security::transparency_log::TransparencyLogger::open;
    match opened(std::sync::Arc::new(audit)) {
        Ok(logger) => drop(logger),
        Err(error) => panic!("{row}: a second open of the log failed: {error}"),
    }
}

/// GATE.4: a v1 journal whose surviving log cannot open refuses with the bytes unchanged.
#[tokio::test]
async fn prepare_refuses_unrecordable_v1() {
    let row = "prepare_refuses_unrecordable_v1";
    let dir = crate::test_dir_keep::kept_tempdir();
    let config = dir.path().join("gateway.yaml");
    let log = dir.path().join("audit.ndjson");
    std::fs::create_dir(&log).expect("the log path is a directory");
    crashed_after_rename(&config, &logged(&log), NEXT);
    let journal = journal_file(dir.path());
    let journal_before = read_bytes(&journal);
    let config_before = read_bytes(&config);
    assert_eq!(
        config_before,
        NEXT.as_bytes(),
        "{row}: the candidate is on disk before the refusal"
    );
    let outcome = prepare_start(&config).await;
    want_session(row, "unopenable log", outcome, StartError::JournalPending);
    assert_eq!(
        read_bytes(&journal),
        journal_before,
        "{row}: journal bytes unchanged"
    );
    assert_eq!(
        read_bytes(&config),
        config_before,
        "{row}: config bytes unchanged"
    );
    assert_lock_free(&config, row).await;
}

/// GATE.4: an unclassifiable journal refuses, leaving the journal and the config unchanged.
#[tokio::test]
async fn prepare_refuses_unclassifiable_journal() {
    let row = "prepare_refuses_unclassifiable_journal";
    let cases: &[(&str, &[u8])] = &[
        ("torn bytes", b"torn-bytes"),
        ("unknown version", br#"{"version": 9}"#),
    ];
    for (case, body) in cases {
        let (dir, config) = fresh_config();
        let journal = journal_file(dir.path());
        write_owner_only(&journal, body).expect("journal");
        let outcome = prepare_start(&config).await;
        want_session(row, case, outcome, StartError::JournalPending);
        assert_eq!(
            read_bytes(&journal),
            *body,
            "{row} {case}: journal bytes unchanged"
        );
        assert_eq!(
            read_bytes(&config),
            START.as_bytes(),
            "{row} {case}: no config write"
        );
        let label = format!("{row} {case}");
        assert_lock_free(&config, &label).await;
    }
}

/// The tree with the lock sidecar created first, by a lock taken and freed:
/// Windows refuses to read a file this process holds locked.
fn tree_with_sidecar(dir: &Path, lock: &Path) -> Vec<(OsString, Snap)> {
    drop(ExclusiveFileLock::try_acquire(lock).expect("the sidecar exists"));
    tree(dir)
}

#[path = "startup_settle_texts_tests.rs"]
mod texts;

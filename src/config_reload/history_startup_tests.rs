// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Design D-1 startup rows: open and the startup record run on one worker
//! under one real-time deadline (gpt G1, kimi confirm). Startup runs on a
//! thread of its own, so a parked open cannot hold the test's thread, and the
//! deadline is checked from outside it.

use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use super::SAVE_DEADLINE;
use super::record_tests::{ONE_BACKEND, Rig, rig_in};
use super::seams::{self, ParkAt};
use super::{Outcome, Source};
use crate::gateway::test_helpers::write_owner_only;

/// Margin over the deadline a startup may take to hand back.
const MARGIN: Duration = Duration::from_secs(2);

pub(super) fn bytes_of(dir: &Path) -> Vec<u8> {
    std::fs::read(dir.join("config-history.json")).expect("the history file reads")
}

pub(super) fn copies_in(dir: &Path) -> Vec<PathBuf> {
    let mut copies: Vec<PathBuf> = std::fs::read_dir(dir)
        .expect("the dir lists")
        .map(|entry| entry.expect("entry").path())
        .filter(|path| {
            path.file_name().is_some_and(|n| {
                n.to_string_lossy()
                    .starts_with("config-history.json.unreadable-")
            })
        })
        .collect();
    copies.sort();
    copies
}

/// A startup in `dir` on its own thread: the rig, what it logged at WARN and
/// above, and how long it took; `None` when it did not hand back within the
/// deadline and the margin.
pub(super) fn start_bounded(dir: tempfile::TempDir) -> Option<(Rig, String, Duration)> {
    let (sent, started) = mpsc::channel();
    std::thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        let _entered = runtime.enter();
        let begun = Instant::now();
        let (rig, logged) = crate::test_log_capture::capture_warnings(|| rig_in(dir, ONE_BACKEND));
        let _ = sent.send((rig, logged, begun.elapsed()));
    });
    started.recv_timeout(SAVE_DEADLINE + MARGIN).ok()
}

/// Wait, in real time and bounded, for a released gate's guarded step to finish.
fn completed(gate: &seams::Gate) {
    tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()
        .expect("runtime")
        .block_on(async {
            tokio::time::timeout(Duration::from_secs(30), gate.completion())
                .await
                .expect("the released worker finished");
        });
}

/// One warning, not more: the count of the memory-only line in `logged`.
fn warnings_in(logged: &str) -> usize {
    logged.matches("config history kept in memory only").count()
}

/// A first startup, then its directory, for a second startup over its file.
fn first_start() -> tempfile::TempDir {
    let dir = tempfile::tempdir().expect("tempdir");
    let rig = rig_in(dir, ONE_BACKEND);
    rig.dir
}

/// C13a: open parked before its read: startup ends within the deadline,
/// memory-only with the startup record, one warning naming the file; released,
/// the file is byte-identical and nothing was moved aside.
#[test]
fn c13a_an_open_parked_before_its_read_does_not_hold_startup() {
    let dir = first_start();
    let path = dir.path().to_path_buf();
    let before = bytes_of(&path);
    let installed = seams::install(&path);
    let gate = installed.seams.park(ParkAt::OpenBeforeRead);
    let Some((rig, logged, took)) = start_bounded(dir) else {
        panic!("startup did not hand back within {SAVE_DEADLINE:?} and {MARGIN:?}");
    };
    assert!(took < SAVE_DEADLINE + MARGIN, "took {took:?}");
    let events = rig.store.events();
    assert_eq!(
        events.len(),
        1,
        "memory-only with the startup record: {events:?}"
    );
    assert_eq!(events[0].source, Source::Start);
    assert_eq!(events[0].outcome, Outcome::Applied);
    assert!(
        logged.contains(&path.join("config-history.json").display().to_string()),
        "one warning names the file: {logged}"
    );
    assert_eq!(warnings_in(&logged), 1, "exactly one warning: {logged}");
    gate.release();
    completed(&gate);
    assert_eq!(bytes_of(&path), before, "byte-identical");
    assert!(copies_in(&path).is_empty(), "nothing moved aside");
}

/// C13b: an unparseable file, open parked after a passed check before the
/// quarantine's hard link: startup ends memory-only with the file in place;
/// released, the copy holds the unparseable bytes exactly.
#[test]
fn c13b_a_late_quarantine_only_copies_the_unparseable_bytes() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().to_path_buf();
    write_owner_only(&path.join("gateway.yaml"), ONE_BACKEND).expect("config");
    let unparseable = b"{not json at all".to_vec();
    // Owner-only, so the file is refused for not parsing, not for its mode (A5).
    write_owner_only(&path.join("config-history.json"), "{not json at all").expect("plant");
    let installed = seams::install(&path);
    let gate = installed.seams.park(ParkAt::BeforeQuarantineLink);
    let Some((rig, _, took)) = start_bounded(dir) else {
        panic!("startup did not hand back within {SAVE_DEADLINE:?} and {MARGIN:?}");
    };
    assert!(took < SAVE_DEADLINE + MARGIN, "took {took:?}");
    assert_eq!(
        bytes_of(&path),
        unparseable,
        "the unparseable file is left in place"
    );
    assert_eq!(
        rig.store.events().len(),
        1,
        "memory-only with the startup record"
    );
    gate.release();
    completed(&gate);
    let copies = copies_in(&path);
    assert_eq!(copies.len(), 1, "one copy: {copies:?}");
    assert_eq!(std::fs::read(&copies[0]).expect("copy"), unparseable);
    // Nothing else: the late link moved the file aside and no save followed it.
    assert!(
        !path.join("config-history.json").exists(),
        "no history file written after the late quarantine"
    );
}

/// C13c: the startup record's save parked after a passed check: released, the
/// file holds exactly the worker's state; the process stays memory-only.
#[test]
fn c13c_a_late_startup_rename_writes_only_the_workers_state() {
    let dir = first_start();
    let path = dir.path().to_path_buf();
    let installed = seams::install(&path);
    let gate = installed.seams.park(ParkAt::AfterCheck);
    let Some((rig, _, took)) = start_bounded(dir) else {
        panic!("startup did not hand back within {SAVE_DEADLINE:?} and {MARGIN:?}");
    };
    assert!(took < SAVE_DEADLINE + MARGIN, "took {took:?}");
    gate.release();
    completed(&gate);
    let file: serde_json::Value = serde_json::from_slice(&bytes_of(&path)).expect("parses");
    let sources: Vec<&str> = file["events"]
        .as_array()
        .expect("events")
        .iter()
        .map(|event| event["source"].as_str().unwrap_or("?"))
        .collect();
    assert_eq!(
        sources,
        ["start", "start"],
        "the first start and the worker's own"
    );
    let now = bytes_of(&path);
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime");
    write_owner_only(&rig.path, super::record_tests::TWO_BACKENDS).expect("add a backend");
    runtime
        .block_on(rig.ctx.reload_outcome())
        .expect("the reload applies");
    assert_eq!(
        bytes_of(&path),
        now,
        "memory-only: a later record writes nothing"
    );
}

const C9_SCENARIO: &str = "config_reload::history::startup_tests::c9_holder_scenario";
const C9_DIR: &str = "C9_HISTORY_DIR";
const C12_SCENARIO: &str = "config_reload::history::startup_tests::c12_child_scenario";
const C12_DIR: &str = "C12_HISTORY_DIR";

/// Wait, in real time and bounded, until `path` exists.
fn wait_for(path: &Path, bound: Duration) -> bool {
    let begun = Instant::now();
    while !path.exists() {
        if begun.elapsed() > bound {
            return false;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    true
}

/// C9's other process: hold the sidecar until the parent says so.
#[test]
fn c9_holder_scenario() {
    let Some(dir) = std::env::var_os(C9_DIR).map(PathBuf::from) else {
        return;
    };
    let _held =
        crate::fs_lock::ExclusiveFileLock::try_acquire(&dir.join("config-history.json.lock"))
            .expect("hold the sidecar");
    std::fs::write(dir.join("c9-held"), b"").expect("say held");
    assert!(
        wait_for(&dir.join("c9-release"), Duration::from_secs(30)),
        "released"
    );
}

/// C9: startup with the sidecar held by another process ends within the
/// deadline, memory-only, with one warning naming the sidecar.
#[test]
fn c9_startup_with_the_sidecar_held_elsewhere_ends_within_the_deadline() {
    let dir = first_start();
    let path = dir.path().to_path_buf();
    let before = bytes_of(&path);
    let mut holder = std::process::Command::new(std::env::current_exe().expect("test binary"))
        .args(["--exact", C9_SCENARIO, "--nocapture"])
        .env(C9_DIR, &path)
        .stdout(std::process::Stdio::null())
        .spawn()
        .expect("start the holder");
    assert!(
        wait_for(&path.join("c9-held"), Duration::from_secs(20)),
        "the holder holds"
    );
    let started = start_bounded(dir);
    std::fs::write(path.join("c9-release"), b"").expect("release the holder");
    let status = holder.wait().expect("the holder exits");
    let Some((rig, logged, took)) = started else {
        panic!("startup did not hand back within {SAVE_DEADLINE:?} and {MARGIN:?}");
    };
    assert!(took < SAVE_DEADLINE + MARGIN, "took {took:?}");
    assert_eq!(bytes_of(&path), before, "byte-identical");
    assert_eq!(
        rig.store.events().len(),
        1,
        "memory-only with the startup record"
    );
    assert!(
        logged.contains("config-history.json.lock"),
        "names the sidecar: {logged}"
    );
    assert_eq!(warnings_in(&logged), 1, "exactly one warning: {logged}");
    assert!(status.success(), "the holder ran cleanly");
}

/// C12's other process: start over the parent's file while the parent's save
/// holds the sidecar past its check. It must wait to its deadline, keep its
/// record in memory, and leave the file as the parent left it.
#[test]
fn c12_child_scenario() {
    let Some(dir) = std::env::var_os(C12_DIR).map(PathBuf::from) else {
        return;
    };
    let config_path = dir.join("gateway.yaml");
    let before = bytes_of(&dir);
    let started = crate::config::Config::load_evaluated(Some(&config_path)).expect("loads");
    let begun = Instant::now();
    let (_live, store) = super::record_tests::hold_at(
        &dir,
        started.inputs,
        config_path.display().to_string(),
        None,
        started.config,
        None,
    );
    let took = begun.elapsed();
    // The parent holds the sidecar until this process exits, so finishing at
    // all means the deadline cut the wait. The bound is a hang guard: the 5 s
    // deadline plus 10 s for a loaded runner, still short of a doubled deadline.
    assert!(took < Duration::from_secs(15), "took {took:?}");
    // It waited for the held sidecar to its deadline, not gave up at once.
    assert!(
        took + Duration::from_secs(1) >= SAVE_DEADLINE,
        "waited only {took:?}"
    );
    assert_eq!(bytes_of(&dir), before, "the child never wrote");
    assert_eq!(store.events().len(), 1, "the child's record is in memory");
}

/// C12: two stores on one path in two processes. The parent's save parks after
/// a passed check, holding the sidecar; the child waits for it to its deadline
/// and never writes; released, the file holds exactly the parent's state.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn c12_a_save_in_another_process_waits_for_the_sidecar_and_never_writes() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().to_path_buf();
    let installed = seams::install(&path);
    let rig = rig_in(dir, ONE_BACKEND);
    write_owner_only(&rig.path, super::record_tests::TWO_BACKENDS).expect("add a backend");
    let gate = installed.seams.park(ParkAt::AfterCheck);
    let ctx = std::sync::Arc::clone(&rig.ctx);
    let reload = tokio::spawn(async move { ctx.reload_outcome().await });
    tokio::time::timeout(Duration::from_secs(30), gate.arrival())
        .await
        .expect("the save reached its check");
    let mut child = tokio::process::Command::new(std::env::current_exe().expect("test binary"));
    child
        .args(["--exact", C12_SCENARIO, "--nocapture"])
        .env(C12_DIR, &path)
        .kill_on_drop(true);
    let output = tokio::time::timeout(Duration::from_secs(60), child.output())
        .await
        .expect("the child finished")
        .expect("run the child");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success() && stdout.contains("1 passed"),
        "the child: stdout={stdout:?} stderr={stderr:?}"
    );
    gate.release();
    tokio::time::timeout(Duration::from_secs(30), gate.completion())
        .await
        .expect("the parent's save finished");
    tokio::time::timeout(Duration::from_secs(30), reload)
        .await
        .expect("the parent's reload ended")
        .expect("joined")
        .expect("the parent's reload applies");
    let file: serde_json::Value = serde_json::from_slice(&bytes_of(&path)).expect("parses");
    let sources: Vec<&str> = file["events"]
        .as_array()
        .expect("events")
        .iter()
        .map(|event| event["source"].as_str().unwrap_or("?"))
        .collect();
    assert_eq!(sources, ["start", "file"], "exactly the parent's events");
    // And exactly the parent's versions, read back by a store of its own (the
    // parent's store went memory-only at its deadline; the late job wrote the
    // file): the start version, then the reload's bytes under the revision
    // the reload published.
    let persisted = super::ConfigHistory::open(&path, super::Bounds::default(), 1).snapshots();
    let gateway = rig.path.display().to_string();
    let bytes_at = |index: usize| {
        persisted
            .get(index)
            .and_then(|snapshot| snapshot.files.iter().find(|file| file.path == gateway))
            .map(|file| file.bytes.clone())
    };
    assert_eq!(persisted.len(), 2, "two versions: {persisted:?}");
    assert_eq!(
        bytes_at(0),
        Some(Some(ONE_BACKEND.as_bytes().to_vec())),
        "the start version"
    );
    assert_eq!(
        bytes_at(1),
        Some(Some(super::record_tests::TWO_BACKENDS.as_bytes().to_vec())),
        "the reload's version"
    );
    let published = rig
        .ctx
        .live_config
        .applied_now()
        .map(|applied| applied.revision.clone());
    assert_eq!(
        persisted.last().map(|snapshot| snapshot.revision.clone()),
        published,
        "under the revision the reload published"
    );
    drop(installed);
}

/// C14 (code review r2): startup whose worker cannot spawn touches no file,
/// keeps the startup record in memory and says why once.
#[test]
fn c14_startup_without_its_worker_keeps_the_record_in_memory_and_touches_no_file() {
    let dir = first_start();
    let path = dir.path().to_path_buf();
    let before = bytes_of(&path);
    let installed = seams::install(&path);
    installed.seams.fail_startup_spawn();
    let Some((rig, logged, took)) = start_bounded(dir) else {
        panic!("startup did not hand back within {SAVE_DEADLINE:?} and {MARGIN:?}");
    };
    assert!(took < SAVE_DEADLINE + MARGIN, "took {took:?}");
    assert_eq!(bytes_of(&path), before, "no file is touched");
    let events = rig.store.events();
    assert_eq!(
        events.len(),
        1,
        "memory-only with the startup record: {events:?}"
    );
    assert_eq!(events[0].source, Source::Start);
    assert!(
        logged.contains("the startup worker could not start")
            && logged.contains(&path.join("config-history.json").display().to_string()),
        "one warning naming the file and the cause: {logged}"
    );
    drop(installed);
}

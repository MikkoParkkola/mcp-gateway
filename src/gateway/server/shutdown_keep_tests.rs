// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A shutdown save keeps the temp dir a test registered until the save
//! returns, and reports a plain one at spawn (family test-temp-sidecar-leak,
//! rows K1-K3k and K10). Each row asserts on the file system or on the
//! recorded line, never on registry state.

use std::sync::Arc;
use std::time::Duration;

use super::*;
use crate::test_dir_keep::{expect_unkept, kept_tempdir};

/// How long a row waits for a dir to go after the save that kept it returns.
const GONE_BOUND: Duration = Duration::from_secs(10);

fn this_test() -> String {
    std::thread::current()
        .name()
        .expect("a test thread")
        .to_owned()
}

/// Releases a held save when dropped, so a row that fails before its own
/// release never leaves a save thread parked.
struct Release(Option<std::sync::mpsc::Sender<()>>);

impl Release {
    fn now(&mut self) {
        if let Some(release) = self.0.take() {
            let _ = release.send(());
        }
    }
}

impl Drop for Release {
    fn drop(&mut self) {
        self.now();
    }
}

/// A save that waits for its release (at most 30 s), then writes `[]` to
/// `root`, as the transition tracking save does.
fn stalled_save(root: PathBuf) -> (Box<dyn FnOnce() + Send>, Release) {
    let (release, held) = std::sync::mpsc::channel::<()>();
    let save = Box::new(move || {
        let _ = held.recv_timeout(Duration::from_secs(30));
        let _ = std::fs::write(&root, b"[]");
    });
    (save, Release(Some(release)))
}

/// A save that writes `[]` to `root` at once.
fn instant_save(root: PathBuf) -> Box<dyn FnOnce() + Send> {
    Box::new(move || {
        let _ = std::fs::write(&root, b"[]");
    })
}

/// What is left under `dir`, for a failure message.
fn listing(dir: &Path) -> Vec<PathBuf> {
    std::fs::read_dir(dir).map_or_else(
        |_| Vec::new(),
        |entries| entries.filter_map(|e| e.ok().map(|e| e.path())).collect(),
    )
}

/// The dir is there while its save is held, then goes once the save returns,
/// with nothing left behind.
async fn held_then_gone(dir: &Path, release: impl FnOnce()) {
    assert!(
        dir.exists(),
        "the dir was removed while its save was still held"
    );
    release();
    let gone = crate::test_wait::wait_real_time(GONE_BOUND, || !dir.exists()).await;
    assert!(
        gone.is_ok(),
        "the dir stayed after its save returned; left: {:?}",
        listing(dir)
    );
}

/// K1. A save abandoned at the deadline in a kept dir (the transitions.json leak shape: a
/// write still running when the shutdown returns) keeps the dir after the
/// test drops its share, until the save returns.
/// Mutant: the keep removed from `run_shutdown_saves`.
#[tokio::test]
async fn an_abandoned_shutdown_save_keeps_its_dir_until_it_returns() {
    let dir = kept_tempdir();
    let root = dir.path().to_path_buf();
    let (save, mut release) = stalled_save(root.join("transitions.json"));
    // limit-under-test (fires-only): the save is stalled until the test releases it, so this deadline always passes first; a slow runner only delays it.
    let deadline = tokio::time::Instant::now() + Duration::from_millis(50);
    run_shutdown_saves(
        deadline,
        vec![ShutdownSave::new(
            "transition tracking save",
            Some(root.join("transitions.json")),
            save,
        )],
    )
    .await;
    drop(dir);
    held_then_gone(&root, || release.now()).await;
}

/// K2. The keep is taken when the save's thread is spawned, not on the
/// thread: the thread is held at its gate, before the save runs, until after
/// the test dropped its share.
/// Mutant: the keep taken on the save's thread.
#[tokio::test]
async fn a_shutdown_save_takes_its_keep_before_its_thread_runs() {
    let dir = kept_tempdir();
    let root = dir.path().to_path_buf();
    let gate = Arc::new(crate::test_pause::Slot::default());
    let (reached, release) = gate.arm();
    let save = ShutdownSave::new(
        "transition tracking save",
        Some(root.join("transitions.json")),
        instant_save(root.join("transitions.json")),
    )
    .gated(Arc::clone(&gate));
    // limit-under-test (fires-only): the save's thread waits at its gate until after this deadline, so it always passes first; a slow runner only delays it.
    let deadline = tokio::time::Instant::now() + Duration::from_millis(50);
    run_shutdown_saves(deadline, vec![save]).await;
    crate::test_pause::within("the save's thread reached its gate", reached.notified()).await;
    drop(dir);
    held_then_gone(&root, || release.notify_one()).await;
}

/// Run one instant save into `root` and wait for it to return.
async fn run_instant(root: &Path) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    run_shutdown_saves(
        deadline,
        vec![ShutdownSave::new(
            "transition tracking save",
            Some(root.to_path_buf()),
            instant_save(root.to_path_buf()),
        )],
    )
    .await;
}

/// K3. A shutdown save in a plain temp dir is recorded once, with its kind,
/// its root and this test.
/// Mutant: `kept_at_spawn` keeps but does not report.
#[tokio::test]
async fn a_shutdown_save_in_a_plain_temp_dir_is_recorded_with_its_kind() {
    let dir = tempfile::tempdir().expect("a temp dir");
    let root = dir.path().join("transitions.json");
    let unkept = expect_unkept();
    run_instant(&root).await;
    assert_eq!(
        unkept.recorded(),
        vec![("shutdown save", root.clone(), this_test())]
    );
    assert!(root.exists(), "the save did not run");
}

/// K3d. The report fires at spawn on every run, not only when a late write
/// races the removal: twenty saves that finish at once, each in a fresh
/// plain dir, record exactly one line each.
/// Mutant: the report taken on the save's thread, or only after a late write.
#[tokio::test]
async fn every_plain_dir_shutdown_save_is_recorded_exactly_once() {
    let dirs: Vec<_> = (0..20)
        .map(|_| tempfile::tempdir().expect("a temp dir"))
        .collect();
    let unkept = expect_unkept();
    let mut want = Vec::new();
    for dir in &dirs {
        let root = dir.path().join("transitions.json");
        run_instant(&root).await;
        assert!(root.exists(), "the save did not run");
        want.push(("shutdown save", root, this_test()));
    }
    assert_eq!(unkept.recorded(), want);
}

/// K3k (control). The same twenty saves in kept dirs record nothing, and
/// each save ran.
/// Mutant: the report also fires for a kept dir.
#[tokio::test]
async fn a_kept_dir_shutdown_save_records_nothing() {
    let dirs: Vec<_> = (0..20).map(|_| kept_tempdir()).collect();
    let unkept = expect_unkept();
    for dir in &dirs {
        let root = dir.path().join("transitions.json");
        run_instant(&root).await;
        assert!(root.exists(), "the save did not run");
    }
    assert_eq!(unkept.recorded(), vec![]);
}

/// Whether `run_shutdown_saves` started a save named `step` with `root`.
fn started_with(step: &str, root: &Path) -> bool {
    STARTED_ROOTS
        .lock()
        .iter()
        .any(|(s, r)| *s == step && r.as_deref() == Some(root))
}

/// K10. The ranking and transition saves keep the files they write.
#[tokio::test]
async fn the_state_saves_carry_their_file_paths_as_roots() {
    let dir = kept_tempdir();
    let (ranker_path, transition_path) = (
        dir.path().join("ranker.json"),
        dir.path().join("transitions.json"),
    );
    save_state_on_shutdown(
        Arc::new(crate::ranking::SearchRanker::new()),
        ranker_path.clone(),
        Arc::new(crate::transition::TransitionTracker::new()),
        transition_path.clone(),
        None,
        vec![],
        tokio::time::Instant::now() + Duration::from_secs(10),
    )
    .await;
    assert!(started_with("search ranking save", &ranker_path));
    assert!(started_with("transition tracking save", &transition_path));
}

/// K10. The final cost save keeps the data dir it writes costs.json into.
#[cfg(feature = "cost-governance")]
#[tokio::test]
async fn the_final_cost_save_carries_its_data_dir_as_root() {
    let dir = kept_tempdir();
    let cfg = CostGovernanceConfig {
        enabled: true,
        ..CostGovernanceConfig::default()
    };
    let registry = Arc::new(CostRegistry::new(&cfg));
    let enforcer = Arc::new(BudgetEnforcer::new(cfg, registry));
    save_state_on_shutdown(
        Arc::new(crate::ranking::SearchRanker::new()),
        dir.path().join("ranker.json"),
        Arc::new(crate::transition::TransitionTracker::new()),
        dir.path().join("transitions.json"),
        Some((
            enforcer,
            Arc::new(crate::cost_accounting::CostTracker::new()),
            dir.path().to_path_buf(),
        )),
        vec![],
        tokio::time::Instant::now() + Duration::from_secs(10),
    )
    .await;
    assert!(started_with("final cost save (costs.json)", dir.path()));
}

/// K10. The counter save keeps counters.json.
#[tokio::test]
async fn the_counter_save_carries_its_file_as_root() {
    let dir = kept_tempdir();
    let meta =
        crate::gateway::meta_mcp::MetaMcp::new(Arc::new(crate::backend::BackendRegistry::new()));
    let (stop, _) = tokio::sync::broadcast::channel(1);
    let (counters, saver) =
        super::super::counter_wiring::start(dir.path(), &meta, stop.subscribe());
    let root = counters.shutdown_save().root().map(Path::to_path_buf);
    let _ = stop.send(());
    let _ = saver.await;
    assert_eq!(root, Some(dir.path().join("counters.json")));
}

/// K10. The health save keeps health.json when saves are on, and carries no
/// root when they are off (it then writes nothing).
#[tokio::test]
async fn the_health_save_carries_its_optional_path_as_root() {
    let dir = kept_tempdir();
    let (stop, _) = tokio::sync::broadcast::channel(1);
    let (mut health, saver) = super::super::health_wiring::start_history(
        dir.path(),
        crate::clock::unix_secs().expect("a clock"),
        crate::health_history::Restores::Counted(0),
        stop.subscribe(),
    );
    let on = health.shutdown_save().root().map(Path::to_path_buf);
    health.path = None;
    let off = health.shutdown_save().root().map(Path::to_path_buf);
    let _ = stop.send(());
    let _ = saver.await;
    assert_eq!(on, Some(dir.path().join("health.json")));
    assert_eq!(off, None);
}

/// K10. The protocol-revision window seal keeps the data dir.
#[tokio::test]
async fn the_window_seal_carries_its_data_dir_as_root() {
    use super::super::window_saver::{SaverSettings, global_counts, start_window_saver};
    let dir = kept_tempdir();
    let (stop, _) = tokio::sync::broadcast::channel(1);
    let settings = SaverSettings {
        every: Duration::from_secs(3600),
        ..SaverSettings::production()
    };
    let saver = start_window_saver(
        crate::config::ProtocolRevisionWindow::Record,
        dir.path().to_path_buf(),
        "127.0.0.1:39402".parse().expect("address"),
        global_counts(Arc::default()),
        stop.subscribe(),
        settings,
    )
    .await
    .expect("a recording saver");
    let _ = stop.send(());
    let _ = saver.await;
    assert!(started_with("protocol-revision window seal", dir.path()));
}

/// K10. Every production construction of a shutdown save is one the rows
/// above read: a new site fails here until it gets its own row.
#[test]
fn every_shutdown_save_construction_has_a_root_row() {
    const READ_BY_A_ROW: [&str; 7] = [
        "search ranking save",
        "transition tracking save",
        "final cost save (costs.json)",
        "counter save (counters.json)",
        "health save (health.json)",
        "protocol-revision window seal",
        "stop checkpoint last pass (each class's root)",
    ];
    let found = production_matches(&source_files(), "ShutdownSave::new(");
    assert_eq!(
        found.len(),
        READ_BY_A_ROW.len(),
        "constructions found: {found:?}"
    );
}

/// One stop checkpoint class named `name` writing `root`, whose checkpoint
/// runs `checkpoint` and whose last pass writes nothing.
fn checkpoint_class(
    name: &'static str,
    root: PathBuf,
    checkpoint: impl Fn() -> bool + Send + Sync + 'static,
) -> super::super::stop_checkpoints::Class {
    super::super::stop_checkpoints::Class {
        name,
        root: Some(root),
        checkpoint: Arc::new(checkpoint),
        last: Arc::new(|| true),
    }
}

/// K10. The stop's last pass keeps each class's file.
#[tokio::test]
async fn the_stop_last_pass_carries_each_class_root() {
    use super::super::stop_checkpoints::Checkpoints;
    let dir = kept_tempdir();
    let file = dir.path().join("usage.json");
    let checkpoints = Checkpoints::new(vec![checkpoint_class("usage", file.clone(), || true)]);
    checkpoints
        .finish(tokio::time::Instant::now() + Duration::from_secs(10))
        .await;
    assert!(started_with("usage", &file));
}

/// K11. A stop checkpoint pass's write in a kept dir keeps the dir after the
/// test drops its share, until the write returns (the transitions.json leak
/// shape, on the stop's once-a-second passes).
/// Mutant: the keep removed from the checkpoint passes.
#[tokio::test]
async fn a_checkpoint_pass_write_keeps_its_dir_until_it_returns() {
    use super::super::stop_checkpoints::Checkpoints;
    let dir = kept_tempdir();
    let root = dir.path().to_path_buf();
    let (entered, reached) = std::sync::mpsc::channel::<()>();
    let (release, held) = std::sync::mpsc::channel::<()>();
    let mut release = Release(Some(release));
    // Only the first pass's write stalls; later passes return at once.
    let (entered, held) = (
        parking_lot::Mutex::new(Some(entered)),
        parking_lot::Mutex::new(held),
    );
    let checkpoints = Checkpoints::new(vec![checkpoint_class(
        "transitions",
        root.join("transitions.json"),
        move || {
            if let Some(entered) = entered.lock().take() {
                let _ = entered.send(());
                let _ = held.lock().recv_timeout(Duration::from_secs(30));
            }
            true
        },
    )]);
    checkpoints.start();
    let started = tokio::task::spawn_blocking(move || reached.recv_timeout(GONE_BOUND))
        .await
        .expect("the waiter ran");
    assert!(started.is_ok(), "the first pass never started its write");
    // Stops the passes; the last pass writes nothing and returns before this does.
    checkpoints
        .finish(tokio::time::Instant::now() + Duration::from_secs(10))
        .await;
    drop(dir);
    held_then_gone(&root, || release.now()).await;
}

/// K12. A stop checkpoint pass in a plain temp dir is recorded at spawn,
/// with its kind, its root and this test, before the last pass runs.
/// Mutant: the passes take the keep without the report.
#[tokio::test]
async fn a_checkpoint_pass_in_a_plain_temp_dir_is_recorded_with_its_kind() {
    use super::super::stop_checkpoints::Checkpoints;
    let dir = tempfile::tempdir().expect("a temp dir");
    let root = dir.path().join("transitions.json");
    let unkept = expect_unkept();
    let (wrote, landed) = std::sync::mpsc::channel::<()>();
    let wrote = parking_lot::Mutex::new(wrote);
    let file = root.clone();
    let checkpoints = Checkpoints::new(vec![checkpoint_class(
        "transitions",
        root.clone(),
        move || {
            let done = std::fs::write(&file, b"[]").is_ok();
            let _ = wrote.lock().send(());
            done
        },
    )]);
    checkpoints.start();
    let landed = tokio::task::spawn_blocking(move || landed.recv_timeout(GONE_BOUND))
        .await
        .expect("the waiter ran");
    assert!(landed.is_ok(), "the first pass never wrote");
    let recorded = unkept.recorded();
    checkpoints
        .finish(tokio::time::Instant::now() + Duration::from_secs(10))
        .await;
    let want = ("stop checkpoint", root, this_test());
    assert!(
        !recorded.is_empty() && recorded.iter().all(|line| *line == want),
        "recorded: {recorded:?}"
    );
}

/// Every non-test `.rs` file under `src/`, as (path, text). Files named
/// `*tests.rs` are test modules; test items inside other files are blanked
/// by the shared reader.
pub(super) fn source_files() -> Vec<(String, String)> {
    fn walk(dir: &Path, files: &mut Vec<(String, String)>) {
        for entry in std::fs::read_dir(dir).expect("a source dir").flatten() {
            let path = entry.path();
            let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
            if path.is_dir() {
                walk(&path, files);
            } else if path.extension().is_some_and(|ext| ext == "rs") && !name.ends_with("tests.rs")
            {
                let text = std::fs::read_to_string(&path).expect("a source file");
                files.push((path.display().to_string(), text));
            }
        }
    }
    let mut files = Vec::new();
    walk(
        &Path::new(env!("CARGO_MANIFEST_DIR")).join("src"),
        &mut files,
    );
    files
}

/// One entry per occurrence of `needle` in the production code of `files`
/// (comments, strings and test-only items removed), naming its file.
pub(super) fn production_matches(files: &[(String, String)], needle: &str) -> Vec<String> {
    files
        .iter()
        .flat_map(|(path, text)| {
            let code =
                crate::test_source_text::sanitize(&crate::test_source_text::production_text(text));
            vec![path.clone(); code.matches(needle).count()]
        })
        .collect()
}

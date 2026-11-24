// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The skills regen loop keeps the temp dirs a test registered until each
//! install write returns, even after its task is gone, and reports a plain
//! one at spawn (family test-temp-sidecar-leak, rows K4-K5k).

use super::*;
use crate::skills::installer::Seams;
use crate::test_dir_keep::{expect_unkept, held_then_gone, kept_tempdir};
use crate::test_pause::{Release, within};

fn this_test() -> String {
    std::thread::current()
        .name()
        .expect("a test thread")
        .to_owned()
}

/// The bundle every row's capability regenerates into.
fn bundle_dir(out: &Path) -> PathBuf {
    out.join("mcp-gateway-keep")
}

/// Start a regen loop writing to `out` with one change queued: a capability
/// in `yaml_dir` whose bundle is `bundle_dir(out)`. The shutdown sender is
/// returned for the caller to hold; dropping it would end the loop.
fn spawn_pass(
    out: &Path,
    yaml_dir: &Path,
    agents: Vec<PathBuf>,
    seams: Option<Arc<Seams>>,
) -> (
    tokio::task::JoinHandle<()>,
    tokio::sync::broadcast::Sender<()>,
) {
    let yaml = yaml_dir.join("keep.yaml");
    std::fs::write(
        &yaml,
        super::burst_tests::cap_yaml("keep_cap", "keep", "keep row"),
    )
    .expect("write capability");
    let (changes, mut source) = change_set();
    source.seams = seams;
    changes.push(yaml);
    let (stop, stopped) = tokio::sync::broadcast::channel(1);
    let task = SkillsWatcher::spawn_regen_task(source, stopped, out.to_path_buf(), agents);
    (task, stop)
}

/// Abort the regen task and await it, asserting it was cancelled: its own
/// keep is gone once this returns.
async fn abort_and_await(task: tokio::task::JoinHandle<()>) {
    task.abort();
    let ended = task.await;
    assert!(
        ended
            .as_ref()
            .is_err_and(tokio::task::JoinError::is_cancelled),
        "the regen task was not cancelled: {ended:?}"
    );
}

/// K4. The crust.json write, held between SKILL.md and itself, keeps the
/// dir after the test drops its share and the regen task is aborted and
/// awaited: at its second seam crust.json has landed in the original dir,
/// which goes only once that write's closure returns.
/// Mutants: the keep held by the task only; a write made without
/// `kept_blocking`, or a helper that does not move its keep into the closure.
#[tokio::test]
async fn a_crust_write_keeps_its_dir_after_the_regen_task_is_gone() {
    let dir = kept_tempdir();
    let root = dir.path().to_path_buf();
    let out = root.join("skills");
    let seams = Arc::new(Seams::default());
    let (before_reached, before) = seams.crust_before.arm();
    let (after_reached, after) = seams.crust_after.arm();
    let (before, after) = (Release(before), Release(after));
    let (task, _stop) = spawn_pass(&out, &root, vec![], Some(Arc::clone(&seams)));
    within(
        "the crust write reached its first seam",
        before_reached.notified(),
    )
    .await;
    let crust = bundle_dir(&out).join("crust.json");
    assert!(
        bundle_dir(&out).join("SKILL.md").exists(),
        "premise: SKILL.md landed"
    );
    assert!(!crust.exists(), "premise: crust.json not yet written");
    drop(dir);
    abort_and_await(task).await;
    before.now();
    within(
        "the crust write reached its second seam",
        after_reached.notified(),
    )
    .await;
    assert!(crust.exists(), "crust.json did not land in the kept dir");
    held_then_gone(&root, || after.now()).await;
}

/// K5. A regen loop on a plain temp dir is recorded once, at spawn, with its
/// kind, its output dir and this test. No pass runs, so nothing is written.
/// Mutant: `kept_at_spawn` keeps but does not report.
#[tokio::test]
async fn a_regen_loop_on_a_plain_temp_dir_is_recorded_with_its_kind() {
    let dir = tempfile::tempdir().expect("a temp dir");
    let out = dir.path().join("skills");
    let unkept = expect_unkept();
    let (_changes, source) = change_set();
    let (_stop, stopped) = tokio::sync::broadcast::channel(1);
    let task = SkillsWatcher::spawn_regen_task(source, stopped, out.clone(), vec![]);
    assert_eq!(unkept.recorded(), vec![("skill bundle", out, this_test())]);
    abort_and_await(task).await;
}

/// K5d. The report fires at spawn on every run: twenty loops, each on a
/// fresh plain dir, record exactly one line each.
/// Mutant: the report taken inside the task, or only on a late write.
#[tokio::test]
async fn every_plain_dir_regen_loop_is_recorded_exactly_once() {
    let dirs: Vec<_> = (0..20)
        .map(|_| tempfile::tempdir().expect("a temp dir"))
        .collect();
    let unkept = expect_unkept();
    let (stop, _) = tokio::sync::broadcast::channel::<()>(1);
    let mut want = Vec::new();
    for dir in &dirs {
        let out = dir.path().join("skills");
        let (_changes, source) = change_set();
        let task = SkillsWatcher::spawn_regen_task(source, stop.subscribe(), out.clone(), vec![]);
        abort_and_await(task).await;
        want.push(("skill bundle", out, this_test()));
    }
    assert_eq!(unkept.recorded(), want);
}

/// K5k (control). Twenty loops on kept dirs record nothing, and each one's
/// pass ran (its crust.json landed).
/// Mutant: the report also fires for a kept dir.
#[tokio::test]
async fn a_kept_dir_regen_loop_records_nothing() {
    let dirs: Vec<_> = (0..20).map(|_| kept_tempdir()).collect();
    let unkept = expect_unkept();
    let mut running = Vec::new();
    for dir in &dirs {
        let out = dir.path().join("skills");
        running.push((spawn_pass(&out, dir.path(), vec![], None), out));
    }
    for ((task, _stop), out) in running {
        let crust = bundle_dir(&out).join("crust.json");
        let ran =
            crate::test_wait::wait_real_time(std::time::Duration::from_secs(30), || crust.exists())
                .await;
        assert!(ran.is_ok(), "the pass into {} did not run", out.display());
        abort_and_await(task).await;
    }
    assert_eq!(unkept.recorded(), vec![]);
}

/// Wait up to 30 s of real time, with no runtime, for `dir` to be gone.
fn gone_within(dir: &Path) -> bool {
    let start = std::time::Instant::now();
    while dir.exists() {
        if start.elapsed() > std::time::Duration::from_secs(30) {
            return false;
        }
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
    true
}

/// K4b. Runtime teardown with the crust.json write in flight: the runtime
/// (current-thread, on its own plain thread) is dropped, the regen task's
/// future is gone, and the test drops its share; the dir survives on the
/// write's own keep, crust.json lands, and the dir goes only after that.
/// Mutant: the keep held by the task only, writes back on `tokio::fs`.
#[test]
fn a_crust_write_keeps_its_dir_through_runtime_teardown() {
    let dir = kept_tempdir();
    let root = dir.path().to_path_buf();
    let out = root.join("skills");
    let seams = Arc::new(Seams::default());
    let (before_reached, before) = seams.crust_before.arm();
    let (after_reached, after) = seams.crust_after.arm();
    let (before, after) = (Release(before), Release(after));
    let (task_gone, gone) = std::sync::mpsc::channel();
    let (drop_runtime, drop_requested) = std::sync::mpsc::channel::<()>();
    let runtime_thread = {
        let (out, root, seams) = (out.clone(), root.clone(), Arc::clone(&seams));
        std::thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("a runtime");
            let stop = runtime.block_on(async {
                let yaml = root.join("keep.yaml");
                std::fs::write(
                    &yaml,
                    super::burst_tests::cap_yaml("keep_cap", "keep", "keep row"),
                )
                .expect("write capability");
                let (changes, mut source) = change_set();
                source.seams = Some(seams);
                source.on_drop = Some(DropSignal(task_gone));
                changes.push(yaml);
                let (stop, stopped) = tokio::sync::broadcast::channel(1);
                let _task = SkillsWatcher::spawn_regen_task(source, stopped, out, vec![]);
                stop
            });
            // Drive the regen task until the test asks for the teardown.
            runtime.block_on(async {
                // Ends on the request, or when a failed row drops the sender.
                while matches!(
                    drop_requested.try_recv(),
                    Err(std::sync::mpsc::TryRecvError::Empty)
                ) {
                    tokio::time::sleep(std::time::Duration::from_millis(5)).await;
                }
            });
            drop(runtime);
            drop(stop);
        })
    };
    crate::test_pause::reached_blocking("the crust write's first seam", &before_reached);
    let crust = bundle_dir(&out).join("crust.json");
    assert!(
        bundle_dir(&out).join("SKILL.md").exists(),
        "premise: SKILL.md landed"
    );
    assert!(!crust.exists(), "premise: crust.json not yet written");
    drop_runtime.send(()).expect("the runtime thread listens");
    assert!(
        gone.recv_timeout(std::time::Duration::from_secs(30))
            .is_ok(),
        "the regen task's future was not dropped with its runtime"
    );
    drop(dir);
    assert!(
        root.exists(),
        "the dir was removed with the task gone and the write still held"
    );
    before.now();
    crate::test_pause::reached_blocking("the crust write's second seam", &after_reached);
    assert!(crust.exists(), "crust.json did not land in the kept dir");
    after.now();
    runtime_thread
        .join()
        .expect("the runtime thread ended cleanly");
    assert!(
        gone_within(&root),
        "the dir stayed after the write returned; left: {:?}",
        crate::test_dir_keep::listing(&root)
    );
}

/// K4c. The agent-root link, held at its first seam, keeps the agent root's
/// own kept dir (a second one) after the test drops both shares and the
/// regen task is aborted and awaited: at its second seam the link points at
/// the bundle, and both dirs go once that write returns.
/// Mutant: the agent roots left out of the loop's keep.
#[cfg(unix)]
#[tokio::test]
async fn an_agent_link_keeps_its_dir_after_the_regen_task_is_gone() {
    let (dir, agents) = (kept_tempdir(), kept_tempdir());
    let (root, agents_dir) = (dir.path().to_path_buf(), agents.path().to_path_buf());
    let (out, agent_root) = (root.join("skills"), agents_dir.join("skills"));
    let seams = Arc::new(Seams::default());
    let (before_reached, before) = seams.link_before.arm();
    let (after_reached, after) = seams.link_after.arm();
    let (before, after) = (Release(before), Release(after));
    let (task, _stop) = spawn_pass(&out, &root, vec![agent_root.clone()], Some(seams));
    within(
        "the link write reached its first seam",
        before_reached.notified(),
    )
    .await;
    drop((dir, agents));
    abort_and_await(task).await;
    before.now();
    within(
        "the link write reached its second seam",
        after_reached.notified(),
    )
    .await;
    assert_eq!(
        std::fs::read_link(agent_root.join("mcp-gateway-keep")).ok(),
        Some(bundle_dir(&out)),
        "the link did not land pointing at the bundle"
    );
    held_then_gone(&agents_dir, || after.now()).await;
    let out_gone =
        crate::test_wait::wait_real_time(std::time::Duration::from_secs(30), || !root.exists())
            .await;
    assert!(
        out_gone.is_ok(),
        "the output dir stayed after the link returned"
    );
}

/// Every file under `dir`, relative to it, with its contents.
#[cfg(not(unix))]
fn tree(dir: &Path) -> Vec<(PathBuf, Vec<u8>)> {
    fn walk(base: &Path, dir: &Path, files: &mut Vec<(PathBuf, Vec<u8>)>) {
        for entry in std::fs::read_dir(dir).expect("a tree dir").flatten() {
            let path = entry.path();
            if path.is_dir() {
                walk(base, &path, files);
            } else {
                let rel = path.strip_prefix(base).expect("under base").to_path_buf();
                files.push((rel, std::fs::read(&path).expect("a tree file")));
            }
        }
    }
    let mut files = Vec::new();
    walk(dir, dir, &mut files);
    files.sort();
    files
}

/// K4w (Windows: the copy fallback, Decision 4). The agent-root copy, held
/// after its first file, keeps both dirs after the test drops both shares
/// and the regen task is aborted and awaited: at its completion seam the
/// copy equals the bundle file for file, and both dirs go once it returns.
/// Mutant: the copy split into per-file blocking steps without the keep.
#[cfg(not(unix))]
#[tokio::test]
async fn an_agent_copy_finishes_whole_in_its_kept_dirs() {
    let (dir, agents) = (kept_tempdir(), kept_tempdir());
    let (root, agents_dir) = (dir.path().to_path_buf(), agents.path().to_path_buf());
    let (out, agent_root) = (root.join("skills"), agents_dir.join("skills"));
    let seams = Arc::new(Seams::default());
    let (mid_reached, mid) = seams.copy_mid.arm();
    let (done_reached, done) = seams.copy_done.arm();
    let (mid, done) = (Release(mid), Release(done));
    let (task, _stop) = spawn_pass(&out, &root, vec![agent_root.clone()], Some(seams));
    within("the copy reached its first file", mid_reached.notified()).await;
    drop((dir, agents));
    abort_and_await(task).await;
    mid.now();
    within(
        "the copy reached its completion seam",
        done_reached.notified(),
    )
    .await;
    let copy = agent_root.join("mcp-gateway-keep");
    let source = tree(&bundle_dir(&out));
    assert!(!source.is_empty(), "premise: the bundle has files");
    assert_eq!(
        tree(&copy),
        source,
        "the copy is not the bundle, file for file"
    );
    held_then_gone(&agents_dir, || done.now()).await;
    let out_gone =
        crate::test_wait::wait_real_time(std::time::Duration::from_secs(30), || !root.exists())
            .await;
    assert!(
        out_gone.is_ok(),
        "the output dir stayed after the copy returned"
    );
}

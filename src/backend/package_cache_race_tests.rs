// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Two starts of one backend racing to repair one cache (split from
//! `package_cache_retry_tests.rs` for the file-size ceiling).

use super::*;

/// Two repairs of one cache, each taking the lock the registry hands out.
///
/// Covers `repair_lock`'s registry: one path yields one lock, and two holders of
/// it are never inside the section at once. It does not cover the repair path's
/// own use of that lock — this test takes it directly, so it holds whether or not
/// the repair does. Covering that use means forcing the window between the latch
/// check and the removal, which no test here does.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn two_repairs_of_one_cache_never_enter_the_guarded_section_together() {
    use std::sync::atomic::{AtomicUsize, Ordering};

    let workspace = tempfile::tempdir().expect("workspace");
    let cache = seed_cache(workspace.path());
    let path = cache.root.clone();

    let live = Arc::new(AtomicUsize::new(0));
    let peak = Arc::new(AtomicUsize::new(0));

    let mut repairs = Vec::new();
    for _ in 0..2 {
        let path = path.clone();
        let live = Arc::clone(&live);
        let peak = Arc::clone(&peak);
        repairs.push(tokio::spawn(async move {
            struct Inside(Arc<AtomicUsize>);
            impl Drop for Inside {
                fn drop(&mut self) {
                    self.0.fetch_sub(1, Ordering::SeqCst);
                }
            }

            let lock = repair_lock(&path);
            let _repairing = lock.lock().await;
            let now = live.fetch_add(1, Ordering::SeqCst) + 1;
            peak.fetch_max(now, Ordering::SeqCst);
            let _inside = Inside(Arc::clone(&live));
            tokio::time::sleep(Duration::from_millis(150)).await;
        }));
    }

    for repairing in repairs {
        repairing.await.expect("the repair task does not panic");
    }

    assert_eq!(
        peak.load(Ordering::SeqCst),
        1,
        "two repairs of one cache must never be inside the section together"
    );
}

/// Two attempts of one backend: exactly one clears, the other finds its mark.
///
/// Released together, both attempts fail the same way and both reach the
/// repair. The latch is a single mark per cache, so the outcome they report has
/// to be one `Cleared` and one `AlreadyRepaired`.
///
/// This does not cover the lock: the two attempts never overlap inside the
/// guarded section here, so the assertion holds whether the lock is taken or not.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn two_attempts_of_one_backend_leave_one_repair_to_clear_the_cache() {
    let workspace = tempfile::tempdir().expect("workspace");
    write_stub(workspace.path(), STUB);
    let cache = seed_cache(workspace.path());
    let log = workspace.path().join("spawns.log");
    let path = cache.root.clone();

    let barrier = Arc::new(tokio::sync::Barrier::new(2));
    let mut attempts = Vec::new();
    for _ in 0..2 {
        let started = transport(
            workspace.path(),
            env_with_cache(&log, "always-fail", CACHE_SHAPED, &path),
            Duration::from_secs(5),
            Some(&path),
        );
        let barrier = Arc::clone(&barrier);
        attempts.push(tokio::spawn(async move {
            barrier.wait().await;
            start_reporting(&started).await.1
        }));
    }

    let mut outcomes = Vec::new();
    for attempt in attempts {
        outcomes.push(attempt.await.expect("the attempt task does not panic"));
    }
    outcomes.sort_by_key(|outcome| match outcome {
        Repair::Cleared => 0,
        Repair::AlreadyRepaired => 1,
        Repair::NotRepaired => 2,
    });

    assert_eq!(
        outcomes,
        vec![Repair::Cleared, Repair::AlreadyRepaired],
        "one attempt clears, and the other finds the mark it left: {:#?}",
        spawns(&log)
    );
}

/// A start of a backend waits for its cache's lock before it spawns anything.
///
/// A start that is not repairing still installs into the cache, so a repair of
/// the same cache must not run underneath it, and the reverse.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_start_waits_for_its_caches_lock_before_spawning() {
    let workspace = tempfile::tempdir().expect("workspace");
    write_stub(workspace.path(), STUB);
    let cache = seed_cache(workspace.path());
    let log = workspace.path().join("spawns.log");
    let env = env_with_cache(&log, "succeed", CACHE_SHAPED, &cache.root);
    let transport = transport(
        workspace.path(),
        env,
        Duration::from_secs(5),
        Some(&cache.root),
    );

    let lock = repair_lock(&cache.root);
    let held = lock.lock().await;
    let attempt = tokio::spawn({
        let transport = Arc::clone(&transport);
        async move { start_reporting(&transport).await }
    });
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert!(
        spawns(&log).is_empty(),
        "nothing spawns while another start or repair holds the cache"
    );
    drop(held);

    let (result, repair) = attempt.await.expect("the start task completes");
    assert!(result.is_ok(), "{result:?}");
    assert_eq!(repair, Repair::NotRepaired);
    assert_eq!(spawns(&log).len(), 1);
}

/// A start cancelled while its rename runs keeps the cache locked until the
/// rename ends.
///
/// Tokio cannot abort a started blocking task, so the rename outlives the
/// cancelled start. If the lock were released with the start, another start of
/// the backend could install into the tree the rename is still moving.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_cancelled_rename_keeps_the_cache_locked_until_it_ends() {
    let workspace = tempfile::tempdir().expect("workspace");
    let dir = temp_root(workspace.path()).join(unique_leaf());
    let lock = repair_lock(&dir);
    let held = Arc::clone(&lock).lock_owned().await;

    let (started_tx, started_rx) = std::sync::mpsc::channel::<()>();
    let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
    let rename = tokio::spawn({
        let dir = dir.clone();
        async move {
            retire_cache_dir(
                &dir,
                held,
                move |_| {
                    started_tx.send(()).expect("the test is listening");
                    release_rx.recv().expect("the test releases the rename");
                    Retired::AlreadyGone
                },
                |_| {},
            )
            .await
        }
    });
    tokio::task::spawn_blocking(move || started_rx.recv())
        .await
        .expect("the wait does not panic")
        .expect("the rename starts");

    rename.abort();
    let _ = rename.await;
    assert!(
        lock.try_lock().is_err(),
        "the start that held the lock is gone, but its rename is still running"
    );

    release_tx.send(()).expect("the rename is waiting");
    drop(
        tokio::time::timeout(Duration::from_secs(5), lock.lock())
            .await
            .expect("the lock is released once the rename ends"),
    );
}

/// A start that cannot get its cache's lock within one full repair
/// (`lock_hold_bound`) fails as unavailable instead of queueing behind it
/// forever, and it does not give up any sooner.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_start_gives_up_waiting_for_a_held_cache() {
    let workspace = tempfile::tempdir().expect("workspace");
    write_stub(workspace.path(), STUB);
    let cache = seed_cache(workspace.path());
    let log = workspace.path().join("spawns.log");
    let env = env_with_cache(&log, "succeed", CACHE_SHAPED, &cache.root);
    let transport = transport(
        workspace.path(),
        env,
        Duration::from_millis(100),
        Some(&cache.root),
    );

    let lock = repair_lock(&cache.root);
    let _held = lock.lock().await;
    let began = std::time::Instant::now();
    let (result, repair) =
        tokio::time::timeout(Duration::from_secs(15), start_reporting(&transport))
            .await
            .expect("the wait is bounded by one full repair");
    let waited = began.elapsed();

    assert!(
        matches!(result, Err(Error::BackendUnavailable(_))),
        "{result:?}"
    );
    let bound = super::super::lock_hold_bound(Duration::from_millis(100));
    assert!(
        waited >= bound,
        "gave up after {waited:?}, before {bound:?}"
    );
    assert_eq!(repair, Repair::NotRepaired);
    assert!(spawns(&log).is_empty(), "nothing spawned without the lock");
}

/// A rename that does not finish in time is given up on, and the cache stays
/// locked until the orphaned rename really ends.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_rename_past_its_limit_is_abandoned_but_keeps_the_lock() {
    let workspace = tempfile::tempdir().expect("workspace");
    let dir = temp_root(workspace.path()).join(unique_leaf());
    let lock = repair_lock(&dir);
    let held = Arc::clone(&lock).lock_owned().await;

    let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
    let outcome = retire_within(
        &dir,
        held,
        move |_| {
            release_rx.recv().expect("the test releases the rename");
            Retired::AlreadyGone
        },
        |_| {},
        Duration::from_millis(200),
    )
    .await;

    assert!(outcome.is_err(), "the rename is given up on at its limit");
    assert!(
        lock.try_lock().is_err(),
        "the orphaned rename still holds the cache"
    );
    release_tx.send(()).expect("the rename is waiting");
    drop(
        tokio::time::timeout(Duration::from_secs(5), lock.lock())
            .await
            .expect("the lock is released once the rename ends"),
    );
}

/// Where `park_discard` left the last tombstone it was handed.
static PARKED: std::sync::Mutex<Option<PathBuf>> = std::sync::Mutex::new(None);

/// A tombstone deletion that never runs on its own: the test finishes it.
fn park_discard(tombstone: PathBuf) {
    *PARKED.lock().expect("parked lock") = Some(tombstone);
}

/// A start right after a repair proceeds while the moved-aside tree is still
/// waiting to be deleted: deleting it holds no lock.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_start_after_a_repair_does_not_wait_for_the_old_tree_to_go() {
    let workspace = tempfile::tempdir().expect("workspace");
    write_stub(workspace.path(), STUB);
    let cache = seed_cache(workspace.path());
    let log = workspace.path().join("spawns.log");
    let repairing = transport(
        workspace.path(),
        env_with_cache(&log, "fail-once", CACHE_SHAPED, &cache.root),
        Duration::from_secs(5),
        Some(&cache.root),
    );

    let (result, repair) = start_reporting_with(&repairing, park_discard).await;
    assert!(result.is_ok(), "{result:?}");
    assert_eq!(repair, Repair::Cleared);
    let tombstone = PARKED
        .lock()
        .expect("parked lock")
        .take()
        .expect("the repair moved the cache aside");
    assert!(
        !cache.root.exists(),
        "the cache path is free for a fresh install"
    );
    assert!(tombstone.exists(), "and the old tree waits, undeleted");

    let next = transport(
        workspace.path(),
        env_with_cache(&log, "succeed", CACHE_SHAPED, &cache.root),
        Duration::from_secs(5),
        Some(&cache.root),
    );
    let (result, _) = tokio::time::timeout(Duration::from_secs(5), start_reporting(&next))
        .await
        .expect("nothing waits on the old tree's deletion");
    assert!(result.is_ok(), "{result:?}");
    assert!(
        tombstone.exists(),
        "the old tree was still there throughout"
    );
    assert!(
        remove_now(&tombstone),
        "the parked deletion can still finish"
    );
}

/// Where `record_orphan_discard` left the tombstone an orphaned rename handed on.
static ORPHAN_DISCARDED: std::sync::Mutex<Option<PathBuf>> = std::sync::Mutex::new(None);

fn record_orphan_discard(tombstone: PathBuf) {
    *ORPHAN_DISCARDED.lock().expect("orphan lock") = Some(tombstone);
}

/// Runs `retire` as a rename that outlives its caller's limit, then waits for
/// the orphaned task to finish and let go of the cache.
async fn orphaned_rename(dir: &Path, retire: Retired) {
    let lock = repair_lock(dir);
    let held = Arc::clone(&lock).lock_owned().await;
    let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
    let outcome = retire_within(
        dir,
        held,
        move |_| {
            release_rx.recv().expect("the test releases the rename");
            retire
        },
        record_orphan_discard,
        Duration::from_millis(100),
    )
    .await;
    assert!(outcome.is_err(), "the caller gave up on the rename");
    release_tx.send(()).expect("the rename is waiting");
    drop(
        tokio::time::timeout(Duration::from_secs(5), lock.lock())
            .await
            .expect("the orphaned rename ends"),
    );
}

/// A refused rename nobody waited for still re-arms the repair, so the backend
/// is not left marked as repaired with nothing cleared.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_orphaned_refused_rename_re_arms_the_repair() {
    let workspace = tempfile::tempdir().expect("workspace");
    let dir = temp_root(workspace.path()).join(unique_leaf());
    assert!(
        mark_repaired(&dir),
        "the repair is taken, as a failed start does"
    );

    orphaned_rename(&dir, Retired::Refused).await;

    assert!(
        mark_repaired(&dir),
        "the refused rename re-armed the latch, so a later start can repair"
    );
}

/// A moved tree nobody waited for is still handed on for deletion.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_orphaned_moved_rename_still_discards_its_tombstone() {
    let workspace = tempfile::tempdir().expect("workspace");
    let dir = temp_root(workspace.path()).join(unique_leaf());
    let tombstone = temp_root(workspace.path()).join(format!("{}.tombstone-x", unique_leaf()));

    orphaned_rename(&dir, Retired::Moved(tombstone.clone())).await;

    assert_eq!(
        ORPHAN_DISCARDED.lock().expect("orphan lock").take(),
        Some(tombstone),
        "the tombstone was handed on although the caller had gone"
    );
}

/// Where `record_cancelled_discard` left the tombstone a cancelled rename handed on.
static CANCELLED_DISCARDED: std::sync::Mutex<Option<PathBuf>> = std::sync::Mutex::new(None);

fn record_cancelled_discard(tombstone: PathBuf) {
    *CANCELLED_DISCARDED.lock().expect("cancelled lock") = Some(tombstone);
}

/// Runs `retire` as a rename whose caller is aborted mid-rename, then waits for
/// the rename to finish and let go of the cache.
async fn cancelled_rename(dir: &Path, retire: Retired) {
    let lock = repair_lock(dir);
    let held = Arc::clone(&lock).lock_owned().await;
    let (started_tx, started_rx) = std::sync::mpsc::channel::<()>();
    let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
    let caller = tokio::spawn({
        let dir = dir.to_path_buf();
        async move {
            retire_cache_dir(
                &dir,
                held,
                move |_| {
                    started_tx.send(()).expect("the test is listening");
                    release_rx.recv().expect("the test releases the rename");
                    retire
                },
                record_cancelled_discard,
            )
            .await
        }
    });
    tokio::task::spawn_blocking(move || started_rx.recv())
        .await
        .expect("the wait does not panic")
        .expect("the rename starts");
    caller.abort();
    let _ = caller.await;
    release_tx.send(()).expect("the rename is waiting");
    drop(
        tokio::time::timeout(Duration::from_secs(5), lock.lock())
            .await
            .expect("the cancelled rename ends"),
    );
}

/// A refused rename whose caller was cancelled still re-arms the repair.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_cancelled_refused_rename_re_arms_the_repair() {
    let workspace = tempfile::tempdir().expect("workspace");
    let dir = temp_root(workspace.path()).join(unique_leaf());
    assert!(
        mark_repaired(&dir),
        "the repair is taken, as a failed start does"
    );

    cancelled_rename(&dir, Retired::Refused).await;

    assert!(
        mark_repaired(&dir),
        "the refused rename re-armed the latch although its caller was cancelled"
    );
}

/// A moved tree whose caller was cancelled is still handed on for deletion.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_cancelled_moved_rename_still_discards_its_tombstone() {
    let workspace = tempfile::tempdir().expect("workspace");
    let dir = temp_root(workspace.path()).join(unique_leaf());
    let tombstone = temp_root(workspace.path()).join(format!("{}.tombstone-y", unique_leaf()));

    cancelled_rename(&dir, Retired::Moved(tombstone.clone())).await;

    assert_eq!(
        CANCELLED_DISCARDED.lock().expect("cancelled lock").take(),
        Some(tombstone),
        "the tombstone was handed on although the caller was cancelled"
    );
}

/// A start that arrives while another start of the backend is repairing waits
/// the repair out and succeeds, instead of failing because the repair outlasted
/// one request timeout.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_start_arriving_mid_repair_succeeds_after_it() {
    let workspace = tempfile::tempdir().expect("workspace");
    write_stub(workspace.path(), STUB);
    let cache = seed_cache(workspace.path());
    let request_timeout = Duration::from_secs(1);

    // The repairing start's retry answers after 0.7 s. With the first
    // attempt's 0.5 s settle and the 0.25 s initialized pause, the repair holds
    // the cache for at least 1.45 s, longer than one request timeout, while each
    // request still answers inside it.
    let first_log = workspace.path().join("first.log");
    let mut env = env_with_cache(&first_log, "fail-once", CACHE_SHAPED, &cache.root);
    env.insert(
        "MCP_GATEWAY_TEST_RETRY_DELAY".to_string(),
        "0.7".to_string(),
    );
    let repairing = transport(workspace.path(), env, request_timeout, Some(&cache.root));
    let first = tokio::spawn({
        let repairing = Arc::clone(&repairing);
        async move { start_reporting(&repairing).await }
    });
    // The lock is taken before the first spawn, so once it has spawned the
    // second start below has to wait for the whole repair.
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    while spawns(&first_log).is_empty() {
        assert!(
            std::time::Instant::now() < deadline,
            "the repair never started"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    let second_log = workspace.path().join("second.log");
    let arriving = transport(
        workspace.path(),
        env_with_cache(&second_log, "succeed", CACHE_SHAPED, &cache.root),
        request_timeout,
        Some(&cache.root),
    );
    let arrived = std::time::Instant::now();
    let (result, repair) =
        tokio::time::timeout(Duration::from_secs(15), start_reporting(&arriving))
            .await
            .expect("the wait is bounded");
    assert!(
        result.is_ok(),
        "the start arriving mid-repair succeeds: {result:?}"
    );
    assert_eq!(repair, Repair::NotRepaired);
    assert!(
        arrived.elapsed() > request_timeout,
        "it waited longer than one request timeout, which a T-bounded wait would have refused"
    );

    let (result, repair) = first.await.expect("the repair task completes");
    assert!(result.is_ok(), "{result:?}");
    assert_eq!(repair, Repair::Cleared);
}

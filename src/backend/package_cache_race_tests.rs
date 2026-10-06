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

/// A start whose failure predates another start's successful repair retries on
/// that install instead of clearing it.
///
/// The test holds the cache's lock, lets one start fail on the old tree, then
/// records a successful repair in its place before letting go. The waiting start
/// must see that its failure describes a tree that no longer exists.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_failure_older_than_a_successful_repair_does_not_clear_it_again() {
    let workspace = tempfile::tempdir().expect("workspace");
    write_stub(workspace.path(), STUB);
    let cache = seed_cache(workspace.path());
    let log = workspace.path().join("spawns.log");
    let env = env_with_cache(&log, "always-fail", CACHE_SHAPED, &cache.root);
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
    // A spawn is logged after the start read the repair count.
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    while spawns(&log).is_empty() {
        assert!(
            std::time::Instant::now() < deadline,
            "the start never spawned"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    bump_repair_generation(&cache.root);
    drop(held);

    let (result, repair) = attempt.await.expect("the start task completes");
    assert_eq!(repair, Repair::Superseded, "{result:?}");
    assert_eq!(
        spawns(&log).len(),
        2,
        "it retries once on the other start's install"
    );
    assert_eq!(
        std::fs::read_to_string(&cache.sentinel).expect("the repaired tree is left in place"),
        SEEDED
    );
}

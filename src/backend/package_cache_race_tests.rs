// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Two starts of one backend racing to repair one cache (split from
//! `package_cache_retry_tests.rs` for the file-size ceiling).

use super::*;

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

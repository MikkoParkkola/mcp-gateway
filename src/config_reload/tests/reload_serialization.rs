// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Reload serialization (#397): concurrent writes and reloads take turns.

use super::*;

// -------------------------------------------------------------------------
// Reload serialization (#397)
// -------------------------------------------------------------------------

/// Two config reloads must not overlap, and the lock has to cover the config
/// read as well as the patch.
///
/// A reload compares the file on disk against the live config, then applies the
/// difference. Registration replaces by name and does not stop what it
/// displaces, so two reloads that both compare against the same live config
/// both decide to add the same backend: the second registration discards the
/// first, and if traffic started that first instance in the gap its child
/// process is orphaned (#397).
///
/// This test drives the stale-comparison case directly. It holds the reload
/// lock, starts two reloads against a config file that adds one backend, then
/// releases. Serialized correctly, the first reload adds the backend and
/// publishes, so the second one compares against the published config and finds
/// nothing to do. If the lock is taken any later than the config read - inside
/// `apply_patch`, say - both reloads decide "backend added" before they queue
/// and both register, which this test sees as a second reload reporting a
/// change instead of reporting none.
#[tokio::test]
async fn concurrent_reloads_do_not_both_add_the_same_backend() {
    // GIVEN: a live config with no backends, and a file on disk that adds one
    let dir = tempfile::tempdir().unwrap();
    let config_path = dir.path().join("gateway.yaml");
    write_owner_only(
        &config_path,
        "backends:\n  svc:\n    http_url: \"http://127.0.0.1:9/mcp\"\n",
    )
    .unwrap();

    let ctx = Arc::new(
        ReloadContext::new(
            config_path,
            Arc::new(LiveConfig::new(Config::default())),
            Arc::new(crate::backend::BackendRegistry::new()),
            crate::config::FailsafeConfig::default(),
            Duration::from_secs(60),
        )
        .expect("the registry pairs with the config"),
    );

    // WHEN: two reloads start while the reload lock is held, so both are queued
    // before either can read the config.
    //
    // The barrier is what makes that claim checkable. Spawning alone proves
    // nothing: a task that the runtime has not scheduled yet has also not read
    // the config, so releasing the guard before it starts would let this test
    // pass even with the lock in the wrong place. Waiting on a barrier that only
    // opens once all three parties have arrived proves both tasks are running
    // and inside the closure. The sleep that follows covers the remaining few
    // instructions between the barrier and the lock, which is a window no
    // synchronisation primitive can close from outside the function under test.
    let started = Arc::new(tokio::sync::Barrier::new(3));
    let guard = ctx.registry.lock_reload().await;
    let first = tokio::spawn({
        let ctx = Arc::clone(&ctx);
        let started = Arc::clone(&started);
        async move {
            started.wait().await;
            ctx.reload_outcome().await
        }
    });
    let second = tokio::spawn({
        let ctx = Arc::clone(&ctx);
        let started = Arc::clone(&started);
        async move {
            started.wait().await;
            ctx.reload_outcome().await
        }
    });
    started.wait().await;
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(
        ctx.registry.get("svc").is_none(),
        "a reload applied while the reload lock was held"
    );
    drop(guard);

    let first = tokio::time::timeout(Duration::from_secs(5), first)
        .await
        .expect("first reload did not finish")
        .expect("first reload task panicked")
        .expect("first reload failed");
    let second = tokio::time::timeout(Duration::from_secs(5), second)
        .await
        .expect("second reload did not finish")
        .expect("second reload task panicked")
        .expect("second reload failed");

    // THEN: exactly one of them added the backend; the other saw an up-to-date
    // config and did nothing
    let added = [first.changes.as_str(), second.changes.as_str()]
        .into_iter()
        .filter(|c| c.contains("svc"))
        .count();
    assert_eq!(
        added, 1,
        "both reloads registered the same backend, so one instance was \
         displaced without being stopped (#397); outcomes were {:?} and {:?}",
        first.changes, second.changes
    );
    assert!(
        ctx.registry.get("svc").is_some(),
        "the backend should be registered after the reloads"
    );
}

/// The config write must happen inside the reload lock, not before it.
///
/// This is the assertion that pins the fix. If the write runs first and the
/// lock is taken afterwards, two admin UI edits interleave: both write, then
/// both reload, and each is told its own edit was applied while the file on
/// disk holds only the last writer's bytes. Holding the guard here proves the
/// write is inside the critical section, because a write that were outside it
/// would land on disk while this test still owns the lock.
#[tokio::test]
async fn a_config_write_waits_for_the_reload_lock() {
    // GIVEN: a context whose config file does not exist yet, so the file
    // appearing is unambiguous evidence that the write ran.
    let dir = tempfile::tempdir().unwrap();
    let config_path = dir.path().join("gateway.yaml");

    let ctx = Arc::new(
        ReloadContext::new(
            config_path.clone(),
            Arc::new(LiveConfig::new(Config::default())),
            Arc::new(crate::backend::BackendRegistry::new()),
            crate::config::FailsafeConfig::default(),
            Duration::from_secs(60),
        )
        .expect("the registry pairs with the config"),
    );

    // WHEN: a write starts while the reload lock is held
    let started = Arc::new(tokio::sync::Barrier::new(2));
    let guard = ctx.registry.lock_reload().await;
    let writer = tokio::spawn({
        let ctx = Arc::clone(&ctx);
        let started = Arc::clone(&started);
        let path = config_path.clone();
        async move {
            started.wait().await;
            ctx.write_and_reload_outcome(&path, &Config::default())
                .await
        }
    });
    started.wait().await;
    tokio::time::sleep(Duration::from_millis(100)).await;

    // THEN: nothing has been written - the writer is queued behind the lock
    assert!(
        !config_path.exists(),
        "the config was written while the reload lock was held, so the write \
         is outside the critical section and two edits can still interleave"
    );

    // AND: releasing the lock lets it finish
    drop(guard);
    let outcome = tokio::time::timeout(Duration::from_secs(5), writer)
        .await
        .expect("write did not finish after the lock was released")
        .unwrap();
    assert!(outcome.is_ok(), "write failed: {outcome:?}");
    assert!(config_path.exists(), "config was never written");
}

/// An edit must not erase a change that landed while it was queued. Reading the
/// config outside the lock is what loses one: the queued edit starts from the
/// copy it read before waiting, so its write drops whatever landed in the
/// meantime while still reporting success.
#[tokio::test]
async fn a_queued_edit_does_not_erase_the_edit_it_waited_for() {
    // GIVEN: a config file with no backends in it
    let dir = tempfile::tempdir().unwrap();
    let config_path = dir.path().join("gateway.yaml");
    crate::gateway::test_helpers::write_config_fixture(&config_path, &Config::default()).unwrap();

    let ctx = Arc::new(
        ReloadContext::new(
            config_path.clone(),
            Arc::new(LiveConfig::new(Config::default())),
            Arc::new(crate::backend::BackendRegistry::new()),
            crate::config::FailsafeConfig::default(),
            Duration::from_secs(60),
        )
        .expect("the registry pairs with the config"),
    );

    // WHEN: an edit adding "beta" is queued behind the reload lock
    let started = Arc::new(tokio::sync::Barrier::new(2));
    let guard = ctx.registry.lock_reload().await;
    let queued_edit = tokio::spawn({
        let ctx = Arc::clone(&ctx);
        let started = Arc::clone(&started);
        let path = config_path.clone();
        async move {
            started.wait().await;
            ctx.mutate_and_reload_outcome(&path, |config: &mut Config| {
                config.backends.insert("beta".to_string(), test_backend());
                Ok::<(), ()>(())
            })
            .await
        }
    });
    started.wait().await;
    tokio::time::sleep(Duration::from_millis(100)).await;

    // AND: the edit that holds the lock adds "alpha" and finishes first
    let mut won_the_lock = Config::default();
    won_the_lock
        .backends
        .insert("alpha".to_string(), test_backend());
    crate::gateway::test_helpers::write_config_fixture(&config_path, &won_the_lock).unwrap();
    drop(guard);

    let result = tokio::time::timeout(Duration::from_secs(5), queued_edit)
        .await
        .expect("the queued edit never finished")
        .unwrap();
    assert!(result.is_ok(), "the queued edit failed: {:?}", result.err());

    // THEN: the saved config has both, not just the queued edit's own change
    let saved = Config::load(Some(&config_path)).unwrap();
    let mut names: Vec<&String> = saved.backends.keys().collect();
    names.sort();
    assert_eq!(
        names,
        vec!["alpha", "beta"],
        "the queued edit erased the change it was waiting behind"
    );
}

/// A backend config that passes validation, for tests that only care about the
/// name.
#[cfg(test)]
fn test_backend() -> crate::config::BackendConfig {
    crate::config::BackendConfig {
        transport: crate::config::TransportConfig::Http {
            http_url: "http://127.0.0.1:9/mcp".to_string(),
            streamable_http: Some(false),
            protocol_version: None,
        },
        ..crate::config::BackendConfig::default()
    }
}

/// Without a live gateway there is nothing to reload, so the write still has
/// to land on disk and report no reload outcome rather than failing.
#[allow(deprecated)] // tests the deprecated snapshot writer itself
#[tokio::test]
async fn write_config_and_reload_without_context_persists_yaml() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("gateway.yaml");
    let config = Config::default();

    write_config_and_reload(&path, &config, None).await.unwrap();

    assert!(path.exists());
    let loaded = Config::load(Some(&path)).unwrap();
    assert_eq!(loaded.backends.len(), config.backends.len());
}

#[allow(deprecated)] // tests the deprecated snapshot writer itself
#[tokio::test]
async fn write_config_and_reload_outcome_without_context_returns_none() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("gateway.yaml");
    let config = Config::default();

    let outcome = write_config_and_reload_outcome(&path, &config, None)
        .await
        .unwrap();

    assert!(outcome.is_none());
}

/// `config_persistence` must not reach back into `config_reload`.
///
/// The two modules used to import each other: persistence called the reload
/// context, and the reload context called persistence. A cycle like that has no
/// build order to reason about, so a change to either module can only be
/// reviewed by reading both. The dependency now points one way — reload knows
/// about persistence, never the reverse — and this test is what keeps it that
/// way, because nothing else in the build will complain if someone adds the
/// import back.
#[test]
fn config_persistence_does_not_depend_on_config_reload() {
    let source = include_str!("../../config_persistence.rs");

    let offenders: Vec<_> = source
        .lines()
        .filter(|line| line.contains("config_reload"))
        .collect();

    assert!(
        offenders.is_empty(),
        "config_persistence reaches back into config_reload, restoring the cycle: {offenders:?}"
    );
}

/// A config write must not queue behind a stuck reload forever.
///
/// The reload lock is held across a full reload: stop backends, re-register
/// them, republish. A backend that is slow to shut down holds it for as long as
/// it takes. Every admin UI backend edit waits on that same lock with no bound,
/// so the HTTP handler blocks, the request times out somewhere the operator
/// cannot see, and the retry queues behind the first one. Reporting "busy" lets
/// the caller decide, and lets the UI answer 503 instead of hanging.
#[tokio::test]
async fn a_config_write_reports_busy_instead_of_waiting_forever() {
    let dir = tempfile::tempdir().unwrap();
    let config_path = dir.path().join("gateway.yaml");
    let ctx = test_reload_context(&config_path);

    let guard = ctx.registry.lock_reload().await;

    let result = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        ctx.mutate_and_reload_outcome_within(
            &config_path,
            std::time::Duration::from_millis(50),
            |config: &mut Config| -> std::result::Result<(), ()> {
                config
                    .backends
                    .insert("blocked".to_string(), test_backend());
                Ok(())
            },
        ),
    )
    .await
    .expect("the write hung on the reload lock instead of reporting busy");

    drop(guard);

    assert!(
        matches!(result, Err(ConfigWriteError::Busy)),
        "a write blocked behind a held reload lock did not report busy"
    );
    assert!(
        !config_path.exists(),
        "a write that reported busy still touched the config file"
    );
}

/// The same bound applies to the whole-config write path, not just the
/// read-modify-write one.
#[tokio::test]
async fn a_whole_config_write_reports_busy_instead_of_waiting_forever() {
    let dir = tempfile::tempdir().unwrap();
    let config_path = dir.path().join("gateway.yaml");
    let ctx = test_reload_context(&config_path);

    let guard = ctx.registry.lock_reload().await;

    let result = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        ctx.write_and_reload_outcome_within(
            &config_path,
            std::time::Duration::from_millis(50),
            &Config::default(),
        ),
    )
    .await
    .expect("the write hung on the reload lock instead of reporting busy");

    drop(guard);

    assert!(
        matches!(result, Err(ConfigWriteError::Busy)),
        "a whole-config write blocked behind a held reload lock did not report busy"
    );
}

/// A write that waits and then gets the lock must still succeed. The bound is
/// there to stop unbounded queueing, not to fail edits that arrive during a
/// normal reload.
#[tokio::test]
async fn a_write_that_gets_the_lock_within_its_bound_still_succeeds() {
    let dir = tempfile::tempdir().unwrap();
    let config_path = dir.path().join("gateway.yaml");
    let ctx = std::sync::Arc::new(test_reload_context(&config_path));

    let guard = ctx.registry.lock_reload().await;

    let writer = tokio::spawn({
        let ctx = std::sync::Arc::clone(&ctx);
        let config_path = config_path.clone();
        async move {
            ctx.mutate_and_reload_outcome_within(
                &config_path,
                std::time::Duration::from_secs(5),
                |config: &mut Config| -> std::result::Result<(), ()> {
                    config
                        .backends
                        .insert("patient".to_string(), test_backend());
                    Ok(())
                },
            )
            .await
        }
    });

    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    drop(guard);

    let result = tokio::time::timeout(std::time::Duration::from_secs(5), writer)
        .await
        .expect("the write never completed after the lock was released")
        .expect("the write task panicked");

    assert!(
        matches!(result, Ok(ConfigMutation::Applied((), _))),
        "a write that waited out a normal reload was refused as busy"
    );
}

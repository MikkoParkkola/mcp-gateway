// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Reload serialization (#397): concurrent writes and reloads take turns.

use super::*;

/// The hang guard: past this a queued call that never finishes fails its row
/// instead of wedging the shard. It is the only time bound in the queued rows
/// below, above every budget they wait on (the reload-lock wait and the
/// config-file lock's deadline, 5 s each), and not derived from either: a
/// margin over a budget can be outrun on a loaded host.
const HANG_GUARD: Duration = Duration::from_secs(30);

/// Polls `call` once while the test holds the reload lock. Its first await is
/// the reload-lock wait, so a call that is still pending after one poll is
/// parked in that lock's queue: queued, with no sleep to hope it got there.
async fn poll_into_the_queue<F: std::future::Future>(call: std::pin::Pin<&mut F>, what: &str) {
    assert!(
        futures::poll!(call).is_pending(),
        "{what} finished while the reload lock was held"
    );
}

/// Right after the test drops its guard: the reload lock cannot be taken,
/// because tokio hands a released permit straight to the first queued waiter
/// and returns only leftovers to the count `try_lock` reads. So the lock went
/// to the queued call, which holds it before it reads anything.
fn handed_to_the_queued_call(ctx: &ReloadContext, what: &str) {
    assert!(
        ctx.registry.reload_lock_handle().try_lock().is_err(),
        "the released reload lock went to no queued call: {what} was not waiting on it"
    );
}

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
    // Starting them proves nothing on its own: a reload that has not reached the
    // lock has also not read the config, so releasing the guard before it gets
    // there would let this test pass even with the lock in the wrong place. One
    // poll each runs a reload to its first await, the reload-lock wait (no
    // grants sink here, so the grants step returns at once), and the handover
    // check after the release proves the first of them was waiting on the lock.
    let guard = ctx.registry.lock_reload().await;
    let mut first = std::pin::pin!(ctx.reload_outcome());
    let mut second = std::pin::pin!(ctx.reload_outcome());
    poll_into_the_queue(first.as_mut(), "the first reload").await;
    poll_into_the_queue(second.as_mut(), "the second reload").await;
    assert!(
        ctx.registry.get("svc").is_none(),
        "a reload applied while the reload lock was held"
    );
    drop(guard);
    handed_to_the_queued_call(&ctx, "the first reload");

    // Both run on from here, polled together as two callers would be. The
    // second stays queued behind the lock the first now holds; the checks
    // below show it read the config the first published, not the old one.
    let (first, second) = tokio::time::timeout(HANG_GUARD, async { tokio::join!(first, second) })
        .await
        .expect("hang guard: the reloads never finished");
    let first = first.expect("first reload failed");
    let second = second.expect("second reload failed");

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

    // WHEN: a write starts while the reload lock is held, and is polled into the
    // lock's queue
    let guard = ctx.registry.lock_reload().await;
    let empty = Config::default();
    let mut writer = std::pin::pin!(ctx.write_and_reload_outcome(&config_path, &empty));
    poll_into_the_queue(writer.as_mut(), "the write").await;

    // THEN: nothing has been written - the writer is queued behind the lock
    assert!(
        !config_path.exists(),
        "the config was written while the reload lock was held, so the write \
         is outside the critical section and two edits can still interleave"
    );

    // AND: releasing the lock hands it to the writer, which then finishes
    drop(guard);
    handed_to_the_queued_call(&ctx, "the write");
    let outcome = tokio::time::timeout(HANG_GUARD, writer)
        .await
        .expect("hang guard: the write never finished after the lock was released");
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

    // WHEN: an edit adding "beta" is polled into the reload lock's queue
    let guard = ctx.registry.lock_reload().await;
    let mut queued_edit = std::pin::pin!(ctx.mutate_and_reload_outcome(
        &config_path,
        |config: &mut Config| {
            config.backends.insert("beta".to_string(), test_backend());
            Ok::<(), ()>(())
        }
    ));
    poll_into_the_queue(queued_edit.as_mut(), "the queued edit").await;

    // AND: the edit that holds the lock adds "alpha" and finishes first
    let mut won_the_lock = Config::default();
    won_the_lock
        .backends
        .insert("alpha".to_string(), test_backend());
    crate::gateway::test_helpers::write_config_fixture(&config_path, &won_the_lock).unwrap();
    drop(guard);
    handed_to_the_queued_call(&ctx, "the queued edit");

    let result = tokio::time::timeout(HANG_GUARD, queued_edit)
        .await
        .expect("hang guard: the queued edit never finished");
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
    let source = concat!(
        include_str!("../../config_persistence.rs"),
        include_str!("../../config_persistence_scratch.rs")
    );

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
        HANG_GUARD,
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
        HANG_GUARD,
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

    let mut writer = std::pin::pin!(ctx.mutate_and_reload_outcome_within(
        &config_path,
        std::time::Duration::from_secs(5),
        |config: &mut Config| -> std::result::Result<(), ()> {
            config
                .backends
                .insert("patient".to_string(), test_backend());
            Ok(())
        },
    ));
    poll_into_the_queue(writer.as_mut(), "the write").await;
    drop(guard);
    handed_to_the_queued_call(&ctx, "the write");

    let result = tokio::time::timeout(HANG_GUARD, writer)
        .await
        .expect("hang guard: the write never completed after the lock was released");

    assert!(
        matches!(result, Ok(ConfigMutation::Applied((), _))),
        "a write that waited out a normal reload was refused as busy"
    );
}

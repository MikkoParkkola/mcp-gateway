// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The shared byte writer: gateway.yaml's exact bytes under the config lock
//! pair, then one reload, and the old file back whenever that reload refuses.

use std::{path::Path, sync::Arc, time::Duration};

#[cfg(unix)] // only the symlink tests read it
use std::path::PathBuf;

use super::reload_context::replace::{
    Expected, FileRevision, Replace, ReplaceError, Replaced, replace_detached,
};
#[cfg(unix)]
use super::replace_test_support::context;
use super::replace_test_support::{NEXT, START, WAIT, names, read, running_has_b, setup, to};
use super::*;
use crate::config::Config;
use crate::fs_lock::ExclusiveFileLock;
use crate::gateway::test_helpers::write_owner_only;

/// T1: the file holds exactly the given bytes, comments included, and the
/// running config is reloaded from them; nothing is left beside it.
#[tokio::test]
async fn replaced_bytes_land_exactly_and_are_reloaded() {
    let (dir, path, ctx) = setup();
    let expected = Expected::Revision(FileRevision::of(START.as_bytes()));

    let outcome = replace_detached(
        Arc::clone(&ctx),
        to(expected, NEXT, Replaced::Discard),
        WAIT,
    )
    .await
    .expect("the replace applies");

    assert_eq!(read(&path), NEXT);
    assert!(running_has_b(&ctx), "the reload must publish the new bytes");
    assert_eq!(outcome.revision, Some(FileRevision::of(NEXT.as_bytes())));
    assert_eq!(names(dir.path()), [".gateway.yaml.lock", "gateway.yaml"]);
}

/// T2: a diff made from an earlier version is refused with the current
/// revision; nothing is written or reloaded.
#[tokio::test]
async fn a_stale_revision_is_refused_with_the_current_one() {
    let (_dir, path, ctx) = setup();
    let earlier = Expected::Revision(FileRevision::of(b"backends: {}\n"));

    let failure = replace_detached(Arc::clone(&ctx), to(earlier, NEXT, Replaced::Discard), WAIT)
        .await
        .expect_err("a stale diff must not apply");

    match failure {
        ReplaceError::Stale { current } => assert_eq!(current, FileRevision::of(START.as_bytes())),
        other => panic!("expected Stale, got {other:?}"),
    }
    assert_eq!(read(&path), START);
    assert!(!running_has_b(&ctx));
}

/// T3: a compute refusal writes nothing and stages nothing.
#[tokio::test]
async fn a_refused_compute_writes_and_stages_nothing() {
    let (dir, path, ctx) = setup();
    let refuse = Replace {
        compute: Box::new(|_| Err("the splice cannot be proven".to_string())),
        ..to(Expected::Any, START, Replaced::KeepBeside)
    };

    let failure = replace_detached(ctx, refuse, WAIT)
        .await
        .expect_err("a refusal must not apply");

    assert!(matches!(failure, ReplaceError::Refused(_)));
    assert_eq!(read(&path), START);
    assert_eq!(names(dir.path()), [".gateway.yaml.lock", "gateway.yaml"]);
}

/// T3b: gateway.yaml bytes that are not UTF-8 are refused.
#[tokio::test]
async fn non_utf8_config_bytes_are_refused() {
    let (_dir, path, ctx) = setup();
    let bad = Replace {
        compute: Box::new(|_| {
            Ok(crate::config_persistence::keyedit::Template::plain(vec![
                0xff, 0xfe, b'\n',
            ]))
        }),
        ..to(Expected::Any, START, Replaced::Discard)
    };

    let failure = replace_detached(ctx, bad, WAIT)
        .await
        .expect_err("not UTF-8");

    assert!(matches!(failure, ReplaceError::Refused(_)));
    assert_eq!(read(&path), START);
}

/// T5 (first copy; the clash suffix needs the clock seam): a kept-beside
/// replacement leaves one owner-only `.rejected` copy of the replaced bytes.
#[tokio::test]
async fn kept_beside_leaves_the_replaced_bytes() {
    let (dir, _path, ctx) = setup();

    let outcome = replace_detached(ctx, to(Expected::Any, NEXT, Replaced::KeepBeside), WAIT)
        .await
        .expect("applies");

    let copy = outcome.kept_beside.expect("a kept copy");
    assert_eq!(
        copy.parent(),
        Some(dir.path().canonicalize().expect("dir").as_path())
    );
    assert!(
        copy.to_string_lossy().ends_with(".rejected"),
        "{}",
        copy.display()
    );
    assert_eq!(read(&copy), START);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mode = std::fs::metadata(&copy).expect("stat").permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "the copy can hold secrets");
    }
}

/// T8b: a reload refused by the posture check rolls the file back byte for
/// byte; the running config never changed and no journal is left.
#[tokio::test]
async fn a_refused_reload_rolls_the_file_back() {
    // A public URL over open tools: the posture check refuses the reload
    // (as in `tests/posture_refusal.rs`).
    const EXPOSED: &str = "server:\n  public_url: \"https://gw.example.com\"\nbackends:\n  a:\n    http_url: \"http://127.0.0.1:9/mcp\"\n  b:\n    http_url: \"http://127.0.0.1:9/mcp\"\n";
    let (dir, path, ctx) = setup();

    let failure = replace_detached(
        Arc::clone(&ctx),
        to(Expected::Any, EXPOSED, Replaced::Discard),
        WAIT,
    )
    .await
    .expect_err("the posture refuses the reload");

    assert!(
        matches!(failure, ReplaceError::ReloadRefused(_)),
        "{failure:?}"
    );
    assert_eq!(read(&path), START, "refused bytes never stay on disk");
    assert!(!running_has_b(&ctx));
    assert_eq!(names(dir.path()), [".gateway.yaml.lock", "gateway.yaml"]);
}

/// T11: with the sidecar lock held past the wait, the call is Busy and
/// nothing is written.
#[tokio::test]
async fn a_held_lock_reports_busy() {
    let (_dir, path, ctx) = setup();
    let lock = crate::config_persistence::lock::lock_path(
        &crate::identity_grants::journal::resolved(&path),
    );
    let held = ExclusiveFileLock::try_acquire(&lock).expect("the test holds the lock");

    let failure = replace_detached(
        ctx,
        to(Expected::Any, NEXT, Replaced::Discard),
        Duration::from_millis(300),
    )
    .await
    .expect_err("the lock is held");

    assert!(matches!(failure, ReplaceError::Busy));
    assert_eq!(read(&path), START);
    drop(held);
}

/// T6f (first half): a symlinked gateway.yaml naming the file loaded at
/// start is written through, the link stays, and a second save through it
/// succeeds too (the trusted identity advanced).
#[cfg(unix)]
#[tokio::test]
async fn a_symlinked_config_is_written_through_twice() {
    let dir = tempfile::tempdir().expect("tempdir");
    let real = dir.path().join("real.yaml");
    write_owner_only(&real, START).expect("write config");
    let link = dir.path().join("gateway.yaml");
    std::os::unix::fs::symlink(&real, &link).expect("symlink");
    let ctx = context(&link);

    replace_detached(
        Arc::clone(&ctx),
        to(Expected::Any, NEXT, Replaced::Discard),
        WAIT,
    )
    .await
    .expect("applies through the link");
    replace_detached(ctx, to(Expected::Any, START, Replaced::Discard), WAIT)
        .await
        .expect("a second save through the link applies");

    assert!(
        std::fs::symlink_metadata(&link)
            .expect("lstat")
            .file_type()
            .is_symlink()
    );
    assert_eq!(read(&real), START);
}

/// T6f (second half): a link re-pointed outside the config directory after
/// start is refused, and nothing is written where it points.
#[cfg(unix)]
#[tokio::test]
async fn a_repointed_link_is_refused() {
    let dir = tempfile::tempdir().expect("tempdir");
    let real = dir.path().join("real.yaml");
    write_owner_only(&real, START).expect("write config");
    let link = dir.path().join("gateway.yaml");
    std::os::unix::fs::symlink(&real, &link).expect("symlink");
    let ctx = context(&link);
    let outside = tempfile::tempdir().expect("outside");
    let victim = outside.path().join("victim.yaml");
    write_owner_only(&victim, START).expect("write victim");
    std::fs::remove_file(&link).expect("unlink");
    std::os::unix::fs::symlink(&victim, &link).expect("re-point");

    let failure = replace_detached(ctx, to(Expected::Any, NEXT, Replaced::Discard), WAIT)
        .await
        .expect_err("a re-pointed link is refused");

    assert!(
        matches!(failure, ReplaceError::Unsupported(_)),
        "{failure:?}"
    );
    assert_eq!(read(&victim), START);
}

/// T13: a compute returning the current bytes writes nothing and still
/// reloads once.
#[tokio::test]
async fn unchanged_bytes_write_nothing_and_still_reload() {
    let (_dir, path, ctx) = setup();
    let before = std::fs::metadata(&path)
        .expect("stat")
        .modified()
        .expect("mtime");

    let outcome = replace_detached(ctx, to(Expected::Any, START, Replaced::KeepBeside), WAIT)
        .await
        .expect("an unchanged file still applies");

    assert_eq!(read(&path), START);
    assert_eq!(
        std::fs::metadata(&path)
            .expect("stat")
            .modified()
            .expect("mtime"),
        before
    );
    assert_eq!(outcome.revision, None);
    assert_eq!(outcome.kept_beside, None);
}

/// The disk a writer killed after its rename leaves: `bytes` in place, the
/// original staged, the journal `staged`.
fn crashed_after_rename(path: &Path, bytes: &str) {
    use crate::config_persistence::journal;
    journal::stage_original(path, START.as_bytes()).expect("stage");
    journal::begin(path, FileRevision::of(START.as_bytes()).as_str().to_owned()).expect("journal");
    write_owner_only(crate::identity_grants::journal::resolved(path), bytes).expect("rename");
}

async fn lock_now(
    path: &Path,
) -> Result<ExclusiveFileLock, crate::config_persistence::lock::NotLocked> {
    crate::config_persistence::lock::lock_config(path, std::time::Instant::now() + WAIT)
        .await
        .map(|locked| locked.held)
}

/// T7: a `staged` journal is rolled back by the next holder of the config
/// lock, byte for byte, and leaves nothing beside the file.
#[tokio::test]
async fn the_next_lock_holder_rolls_a_staged_journal_back() {
    let (dir, path, _ctx) = setup();
    crashed_after_rename(&path, NEXT);

    drop(
        lock_now(&path)
            .await
            .expect("the lock recovers the journal"),
    );

    assert_eq!(read(&path), START);
    assert_eq!(names(dir.path()), [".gateway.yaml.lock", "gateway.yaml"]);
}

/// T8: an `all_renamed` journal keeps the new bytes; recovery only cleans up.
#[tokio::test]
async fn an_all_renamed_journal_keeps_the_new_bytes() {
    let (dir, path, _ctx) = setup();
    crashed_after_rename(&path, NEXT);
    crate::config_persistence::journal::mark_all_renamed(&path).expect("mark");

    drop(
        lock_now(&path)
            .await
            .expect("the lock recovers the journal"),
    );

    assert_eq!(read(&path), NEXT);
    assert_eq!(names(dir.path()), [".gateway.yaml.lock", "gateway.yaml"]);
}

/// T9: a `staged` journal whose original is gone cannot be acted on: the
/// lock is refused with the manual step, and no file changes.
#[tokio::test]
async fn a_journal_without_its_original_refuses_the_lock() {
    let (_dir, path, _ctx) = setup();
    crashed_after_rename(&path, NEXT);
    std::fs::remove_file(crate::config_persistence::journal::original_path(&path)).expect("rm");

    match lock_now(&path).await {
        Err(crate::config_persistence::lock::NotLocked::Failed(message)) => {
            assert!(message.contains("copy the staged original"), "{message}");
        }
        Err(other) => panic!("expected a refusal, got {other:?}"),
        Ok(_) => panic!("an unusable journal must refuse the lock"),
    }
    assert_eq!(read(&path), NEXT);
    assert!(crate::config_persistence::journal::exists(&path));
}

/// T6g: a stranded candidate that does not even parse never blocks an
/// ordinary edit: `mutate_locked` skips its preflight while a journal is
/// pending, the lock restores the original and a reload follows, and the
/// edit lands on the restored file.
#[tokio::test]
async fn an_edit_recovers_a_stranded_unparseable_file_first() {
    let (_dir, path, ctx) = setup();
    crashed_after_rename(&path, "backends: [this is: not: yaml\n");

    let result = ctx
        .mutate_and_reload_outcome_within(&path, WAIT, |config: &mut Config| {
            let backend = config.backends["a"].clone();
            config.backends.insert("b".to_string(), backend);
            Ok::<(), String>(())
        })
        .await;

    assert!(
        matches!(result, Ok(ConfigMutation::Applied(..))),
        "the edit must apply after recovery"
    );
    let on_disk = Config::load(Some(&path)).expect("the restored, edited file loads");
    assert!(on_disk.backends.contains_key("a") && on_disk.backends.contains_key("b"));
    assert!(running_has_b(&ctx));
    assert!(!crate::config_persistence::journal::exists(&path));
}

/// T9b: a staged original that does not match its journal's digest is never
/// written back: the lock is refused and the file is left as it is.
#[tokio::test]
async fn a_tampered_original_is_never_written_back() {
    let (_dir, path, _ctx) = setup();
    crashed_after_rename(&path, NEXT);
    std::fs::write(
        crate::config_persistence::journal::original_path(&path),
        "backends: {}\n",
    )
    .expect("tamper");

    match lock_now(&path).await {
        Err(crate::config_persistence::lock::NotLocked::Failed(message)) => {
            assert!(message.contains("does not match the digest"), "{message}");
        }
        Err(other) => panic!("expected a refusal, got {other:?}"),
        Ok(_) => panic!("a tampered original must refuse the lock"),
    }
    assert_eq!(read(&path), NEXT);
}

/// A rollback whose journal cannot be removed refuses the lock, so no save
/// can land while a `staged` journal still waits to undo it; a later lock
/// recovers again, harmlessly, and a save after that is never undone.
#[tokio::test]
async fn a_journal_that_cannot_be_removed_blocks_writes_until_it_is() {
    within_hang_bound(
        "a_journal_that_cannot_be_removed_blocks_writes_until_it_is",
        async {
            use crate::config_persistence::journal::{self, fault};
            let (_dir, path, _ctx) = setup();
            crashed_after_rename(&path, NEXT);
            let armed = fault::set(&path, fault::Fault::FailJournalRemove);

            let refused = lock_now(&path).await;
            drop(armed);

            match refused {
                Err(crate::config_persistence::lock::NotLocked::Failed(message)) => {
                    assert!(message.contains("could not be removed"), "{message}");
                }
                Err(other) => panic!("expected a refusal, got {other:?}"),
                Ok(_) => panic!("a journal left staged must refuse the lock"),
            }
            assert_eq!(read(&path), START, "the original is already back");
            assert!(journal::exists(&path), "the journal stays until removed");

            drop(lock_now(&path).await.expect("a later lock recovers it"));
            assert!(!journal::exists(&path));
            let target = crate::identity_grants::journal::resolved(&path);
            {
                let _held = lock_now(&path).await.expect("lock for a save");
                write_owner_only(&target, NEXT).expect("a save");
            }
            drop(lock_now(&path).await.expect("the next lock"));
            assert_eq!(read(&path), NEXT, "a save after recovery is never undone");
        },
    )
    .await;
}

/// A caller cancelled while its lock recovers a journal never lets a second
/// holder in: the lock travels with the recovery and is released only when
/// recovery ends.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_cancelled_lock_stays_held_until_its_recovery_ends() {
    within_hang_bound(
        "a_cancelled_lock_stays_held_until_its_recovery_ends",
        async {
            use crate::config_persistence::journal::{self, fault};
            let (_dir, path, _ctx) = setup();
            crashed_after_rename(&path, NEXT);
            let pause = Arc::new(fault::Pause::default());
            let armed = fault::set(&path, fault::Fault::Pause(Arc::clone(&pause)));
            let locking = path.clone();
            let task = tokio::spawn(async move {
                crate::config_persistence::lock::lock_config(
                    &locking,
                    std::time::Instant::now() + WAIT,
                )
                .await
                .map(drop)
            });
            let entered = Arc::clone(&pause);
            tokio::task::spawn_blocking(move || entered.wait_entered())
                .await
                .expect("recovery reached the gate");

            task.abort();
            let _ = task.await;
            let lock = crate::config_persistence::lock::lock_path(
                &crate::identity_grants::journal::resolved(&path),
            );
            assert!(
                ExclusiveFileLock::try_acquire(&lock).is_err(),
                "no second holder while recovery runs"
            );

            drop(armed);
            let mut freed = false;
            for _ in 0..400 {
                if let Ok(held) = ExclusiveFileLock::try_acquire(&lock) {
                    drop(held);
                    freed = true;
                    break;
                }
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
            assert!(freed, "the lock is released once recovery ends");
            assert_eq!(read(&path), START);
            assert!(!journal::exists(&path));
        },
    )
    .await;
}

/// A hang in these crash-path tests fails in seconds, by name, instead of
/// holding a CI shard until its own timeout.
async fn within_hang_bound(test: &str, body: impl std::future::Future<Output = ()>) {
    tokio::time::timeout(Duration::from_secs(30), body)
        .await
        .unwrap_or_else(|_| panic!("{test} hung past 30 s"));
}

/// Paths the recording loader below was asked to load.
#[cfg(unix)] // only the symlink tests read it
static LOADED: std::sync::Mutex<Vec<PathBuf>> = std::sync::Mutex::new(Vec::new());

#[cfg(unix)]
fn recording_load(
    path: &Path,
    live: &Arc<LiveConfig>,
    env: &crate::config::LiveEnv,
) -> Result<super::reload_context::EvaluatedReload, String> {
    LOADED.lock().expect("loaded").push(path.to_path_buf());
    super::reload_context::load_config_patch(path, live, env)
}

/// The write's reload loads the target the writer resolved and checked, not
/// the symlink spelling: a link moved A→B→A during the reload can never make
/// the writer report success on bytes the runtime did not load.
#[cfg(unix)]
#[tokio::test]
async fn the_writes_reload_reads_the_pinned_target_not_the_link() {
    let dir = tempfile::tempdir().expect("tempdir");
    let real = dir.path().join("real.yaml");
    write_owner_only(&real, START).expect("write config");
    let link = dir.path().join("gateway.yaml");
    std::os::unix::fs::symlink(&real, &link).expect("symlink");
    let running = Config::load(Some(&link)).expect("config loads");
    let mut ctx = ReloadContext::new(
        link.clone(),
        Arc::new(LiveConfig::new(running)),
        Arc::new(crate::backend::BackendRegistry::new()),
        crate::config::FailsafeConfig::default(),
        Duration::from_secs(60),
    )
    .expect("context");
    ctx.load = recording_load;

    replace_detached(
        Arc::new(ctx),
        to(Expected::Any, NEXT, Replaced::Discard),
        WAIT,
    )
    .await
    .expect("applies");

    let target = crate::identity_grants::journal::resolved(&link);
    let mine: Vec<PathBuf> = LOADED
        .lock()
        .expect("loaded")
        .iter()
        .filter(|p| p.starts_with(dir.path()) || p.starts_with(target.parent().expect("dir")))
        .cloned()
        .collect();
    assert!(
        mine.contains(&target),
        "the reload read the pinned target: {mine:?}"
    );
    assert!(!mine.contains(&link), "never the link spelling: {mine:?}");
}

/// A restore whose journal then cannot be removed refuses the lock, and the
/// context still owes the reload that brings the runtime to the restored
/// bytes.
#[tokio::test]
async fn a_restore_whose_journal_stays_still_owes_a_reload() {
    use crate::config_persistence::journal::fault;
    let (_dir, path, ctx) = setup();
    crashed_after_rename(&path, NEXT);
    let armed = fault::set(&path, fault::Fault::FailJournalRemove);

    let refused = ctx
        .mutate_and_reload_outcome_within(&path, WAIT, |_: &mut Config| Ok::<(), String>(()))
        .await;
    drop(armed);

    assert!(
        refused.is_err(),
        "the lock is refused while the journal stays"
    );
    assert_eq!(read(&path), START, "the original is back on disk");
    assert!(
        ctx.reload_owed.load(std::sync::atomic::Ordering::SeqCst),
        "the runtime still owes the reload to the restored bytes"
    );
}

/// A reload not started by a write (the watcher's) resolves the config once
/// and loads that same target it locked, never the symlink spelling.
#[cfg(unix)]
#[tokio::test]
async fn a_watcher_reload_loads_the_target_it_locked() {
    let dir = tempfile::tempdir().expect("tempdir");
    let real = dir.path().join("real.yaml");
    write_owner_only(&real, START).expect("write config");
    let link = dir.path().join("gateway.yaml");
    std::os::unix::fs::symlink(&real, &link).expect("symlink");
    let running = Config::load(Some(&link)).expect("config loads");
    let mut ctx = ReloadContext::new(
        link.clone(),
        Arc::new(LiveConfig::new(running)),
        Arc::new(crate::backend::BackendRegistry::new()),
        crate::config::FailsafeConfig::default(),
        Duration::from_secs(60),
    )
    .expect("context");
    ctx.load = recording_load;

    ctx.reload_outcome().await.expect("the reload loads");

    let target = crate::identity_grants::journal::resolved(&link);
    let loaded = LOADED.lock().expect("loaded");
    assert!(
        loaded.contains(&target),
        "the reload read its locked target: {loaded:?}"
    );
    assert!(
        !loaded.contains(&link),
        "never the link spelling: {loaded:?}"
    );
}

/// A gateway on `gateway.yaml`, a symlink to `real.yaml`, with a second
/// config beside it to re-point the link at, and every load recorded.
#[cfg(unix)]
fn linked_context() -> (tempfile::TempDir, PathBuf, PathBuf, Arc<ReloadContext>) {
    let dir = tempfile::tempdir().expect("tempdir");
    let real = dir.path().join("real.yaml");
    write_owner_only(&real, START).expect("write config");
    write_owner_only(dir.path().join("other.yaml"), START).expect("write other");
    let link = dir.path().join("gateway.yaml");
    std::os::unix::fs::symlink(&real, &link).expect("symlink");
    let running = Config::load(Some(&link)).expect("config loads");
    let mut ctx = ReloadContext::new(
        link.clone(),
        Arc::new(LiveConfig::new(running)),
        Arc::new(crate::backend::BackendRegistry::new()),
        crate::config::FailsafeConfig::default(),
        Duration::from_secs(60),
    )
    .expect("context");
    ctx.load = recording_load;
    (dir, real, link, Arc::new(ctx))
}

/// Run `reload` until it has taken its locks, re-point `link` at
/// `other.yaml`, let it finish, check it `applies`, return the paths loaded.
#[cfg(unix)]
async fn repointed_mid_reload(
    dir: &Path,
    link: &Path,
    reload: impl std::future::Future<Output = bool> + Send + 'static,
    applies: bool,
) -> Vec<PathBuf> {
    const BOUND: Duration = Duration::from_secs(30); // fail, never hang
    let pause = super::reload_pause::arm(link);
    let reload = tokio::spawn(reload);
    tokio::time::timeout(BOUND, pause.reached.notified())
        .await
        .expect("the reload reaches its pause");
    std::fs::remove_file(link).expect("unlink");
    std::os::unix::fs::symlink(dir.join("other.yaml"), link).expect("re-point");
    pause.release.notify_one();
    let outcome = tokio::time::timeout(BOUND, reload).await.expect("ends");
    assert_eq!(outcome.expect("reload task"), applies, "applies");
    let dir = crate::identity_grants::journal::resolved(dir);
    LOADED
        .lock()
        .expect("loaded")
        .iter()
        .filter(|p| p.starts_with(&dir) || p.as_path() == link)
        .cloned()
        .collect()
}

/// Every load this test saw read `real`, the target its lock resolved:
/// never the link spelling, nor what the link names after it moved.
#[cfg(unix)]
fn only_the_locked_target(loaded: &[PathBuf], real: &Path) {
    let real = crate::identity_grants::journal::resolved(real);
    assert!(
        !loaded.is_empty() && loaded.iter().all(|p| *p == real),
        "only the locked target {} is loaded: {loaded:?}",
        real.display()
    );
}

/// H1 for writers: the lock, the write and the reload are one config. A link
/// re-pointed while the reload is under way does not move it elsewhere.
#[cfg(unix)]
#[tokio::test]
async fn a_write_reloads_what_it_locked_when_the_link_moves() {
    let (dir, real, link, ctx) = linked_context();
    let at = link.clone();
    let write = async move {
        ctx.mutate_and_reload_outcome_within(&at, WAIT, |_: &mut Config| Ok::<(), String>(()))
            .await
            .is_ok()
    };
    let loaded = repointed_mid_reload(dir.path(), &link, write, true).await;
    only_the_locked_target(&loaded, &real);
}

/// H1 for readers, under the same race: the watcher's reload stays on the
/// target its lock resolved.
#[cfg(unix)]
#[tokio::test]
async fn a_watcher_reload_stays_put_when_the_link_moves() {
    let (dir, real, link, ctx) = linked_context();
    let reload = async move { ctx.reload_outcome().await.is_ok() };
    let loaded = repointed_mid_reload(dir.path(), &link, reload, true).await;
    only_the_locked_target(&loaded, &real);
}

/// H1 for the whole-config writer, under the same race.
#[cfg(unix)]
#[tokio::test]
async fn a_whole_config_write_reloads_what_it_locked_when_the_link_moves() {
    let (dir, real, link, ctx) = linked_context();
    let config = Config::load(Some(&real)).expect("config loads");
    let at = link.clone();
    let write = async move {
        ctx.write_and_reload_outcome_within(&at, WAIT, &config)
            .await
            .is_ok()
    };
    let loaded = repointed_mid_reload(dir.path(), &link, write, true).await;
    only_the_locked_target(&loaded, &real);
}

/// H1 for the reload a lock recovery left owed: paid before the writer's
/// own work, it loads the target the writer locked, not the link.
#[cfg(unix)]
#[tokio::test]
async fn an_owed_reload_loads_what_the_writer_locked_when_the_link_moves() {
    let (dir, real, link, ctx) = linked_context();
    ctx.reload_owed
        .store(true, std::sync::atomic::Ordering::SeqCst);
    let at = link.clone();
    let write = async move {
        ctx.mutate_and_reload_outcome_within(&at, WAIT, |_: &mut Config| Ok::<(), String>(()))
            .await
            .is_ok()
    };
    // Moved before the write: the write refuses after the owed reload.
    let loaded = repointed_mid_reload(dir.path(), &link, write, false).await;
    assert_eq!(loaded.len(), 1, "only the owed reload: {loaded:?}");
    only_the_locked_target(&loaded, &real);
}

/// H1 for a replace that changes nothing: its reload still loads the
/// target the lock resolved.
#[cfg(unix)]
#[tokio::test]
async fn an_unchanged_replace_reloads_what_it_locked_when_the_link_moves() {
    let (dir, real, link, ctx) = linked_context();
    let replace = async move {
        replace_detached(ctx, to(Expected::Any, START, Replaced::Discard), WAIT)
            .await
            .is_ok()
    };
    let loaded = repointed_mid_reload(dir.path(), &link, replace, true).await;
    only_the_locked_target(&loaded, &real);
}

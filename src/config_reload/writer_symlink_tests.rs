// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A writer locks the target `gateway.yaml` resolves to and works on that
//! target only. Each test holds the lock, lets the writer start waiting,
//! re-points the link at another config, and releases: the path no longer
//! names what the writer locked, so it must refuse and write neither config.

use std::path::PathBuf;
use std::time::Duration;

use super::*;
use crate::config::Config;
use crate::config_persistence::CommentLoss;
use crate::fs_lock::ExclusiveFileLock;
use crate::gateway::test_helpers::write_owner_only;

const START: &str = "backends:\n  a:\n    http_url: \"http://127.0.0.1:9/mcp\"\n";
const BOUND: Duration = Duration::from_secs(30); // fail, never hang

fn add_b(config: &mut Config) {
    let backend = config.backends["a"].clone();
    config.backends.insert("b".to_string(), backend);
}

/// `gateway.yaml`, a link to `real.yaml`, with `other.yaml` beside it; the
/// test holds the lock the link resolves to.
struct Linked {
    _dir: tempfile::TempDir,
    real: PathBuf,
    other: PathBuf,
    link: PathBuf,
    lock: PathBuf,
}

fn linked() -> (Linked, ExclusiveFileLock) {
    let dir = tempfile::tempdir().expect("tempdir");
    let real = dir.path().join("real.yaml");
    let other = dir.path().join("other.yaml");
    write_owner_only(&real, START).expect("write config");
    write_owner_only(&other, START).expect("write other");
    let link = dir.path().join("gateway.yaml");
    std::os::unix::fs::symlink(&real, &link).expect("symlink");
    let lock = crate::config_persistence::lock::lock_path(
        &crate::identity_grants::journal::resolved(&real),
    );
    let held = ExclusiveFileLock::try_acquire(&lock).expect("the test holds the lock");
    let linked = Linked {
        _dir: dir,
        real,
        other,
        link,
        lock,
    };
    (linked, held)
}

/// Re-point the link at `other.yaml`, then let the waiting writer go.
fn repoint_and_release(l: &Linked, held: ExclusiveFileLock) {
    std::fs::remove_file(&l.link).expect("unlink");
    std::os::unix::fs::symlink(&l.other, &l.link).expect("re-point");
    drop(held);
}

fn wrote_neither(l: &Linked) {
    let real = std::fs::read_to_string(&l.real).expect("read real");
    let other = std::fs::read_to_string(&l.other).expect("read other");
    assert_eq!(real, START, "the locked config is untouched");
    assert_eq!(other, START, "the config the link now names is untouched");
}

/// A CLI writer, which says when it starts waiting.
fn cli_race(write: impl FnOnce(PathBuf) -> Result<(), String> + Send + 'static) {
    let (l, held) = linked();
    let waiting = crate::config_persistence::when_waiting_for_lock(&l.link);
    let at = l.link.clone();
    let writer = std::thread::spawn(move || write(at));
    waiting
        .recv_timeout(BOUND)
        .expect("the writer waits for the held lock");
    repoint_and_release(&l, held);
    let refused = writer
        .join()
        .expect("writer thread")
        .expect_err("a write whose path moved refuses");
    assert!(refused.contains("moved during the write"), "{refused}");
    wrote_neither(&l);
}

/// Wait until an async writer has tried `lock` since `before`.
async fn writer_waits(lock: &std::path::Path, before: usize) {
    tokio::time::timeout(BOUND, async {
        while crate::fs_lock::lock_attempts(lock) <= before {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("the writer waits for the held lock");
}

/// An async writer, seen waiting by its lock attempts. `write` resolves to
/// its refusal, if it refused.
async fn async_race<F>(write: impl FnOnce(PathBuf) -> F)
where
    F: std::future::Future<Output = Option<String>> + Send + 'static,
{
    let (l, held) = linked();
    let before = crate::fs_lock::lock_attempts(&l.lock);
    let writer = tokio::spawn(write(l.link.clone()));
    writer_waits(&l.lock, before).await;
    repoint_and_release(&l, held);
    let refused = tokio::time::timeout(BOUND, writer).await.expect("ends");
    let refused = refused
        .expect("writer task")
        .expect("a write whose path moved refuses");
    assert!(refused.contains("moved during the write"), "{refused}");
    wrote_neither(&l);
}

#[test]
fn edit_config_refuses_when_the_link_moves() {
    cli_race(|at| {
        crate::config_persistence::edit_config(&at, CommentLoss::Rewrite, |c| {
            add_b(c);
            Ok(())
        })
        .map(drop)
    });
}

#[test]
fn edit_config_text_refuses_when_the_link_moves() {
    cli_race(|at| {
        crate::config_persistence::edit_config_text(&at, |current| {
            let current = current.expect("the config exists");
            Ok(Some(format!(
                "{current}  b:\n    http_url: \"http://127.0.0.1:9/mcp\"\n"
            )))
        })
        .map(drop)
    });
}

#[test]
#[allow(deprecated)] // the deprecated whole-config writer still locks
fn write_config_refuses_when_the_link_moves() {
    cli_race(|at| {
        let mut config = Config::load(Some(&at)).expect("config loads");
        add_b(&mut config);
        crate::config_persistence::write_config(&at, &config)
    });
}

#[tokio::test]
async fn a_no_gateway_mutation_refuses_when_the_link_moves() {
    async_race(|at| async move {
        super::write::mutate_config_and_reload(&at, None, |c| {
            add_b(c);
            Ok::<(), String>(())
        })
        .await
        .err()
        .map(|e| e.to_string())
    })
    .await;
}

#[tokio::test]
#[allow(deprecated)] // the deprecated whole-config writer still locks
async fn a_no_gateway_whole_config_write_refuses_when_the_link_moves() {
    async_race(|at| {
        let mut config = Config::load(Some(&at)).expect("config loads");
        add_b(&mut config);
        async move {
            super::write::write_config_and_reload_outcome(&at, &config, None)
                .await
                .err()
                .map(|e| e.to_string())
        }
    })
    .await;
}

/// The live gateway's whole-config writer refuses the same race.
#[tokio::test]
async fn a_live_whole_config_write_refuses_when_the_link_moves() {
    async_race(|at| {
        let running = Config::load(Some(&at)).expect("config loads");
        let mut config = running.clone();
        add_b(&mut config);
        let ctx = ReloadContext::new(
            at.clone(),
            std::sync::Arc::new(LiveConfig::new(running)),
            std::sync::Arc::new(crate::backend::BackendRegistry::new()),
            crate::config::FailsafeConfig::default(),
            Duration::from_secs(60),
        )
        .expect("context");
        async move {
            ctx.write_and_reload_outcome_within(&at, BOUND, &config)
                .await
                .err()
                .map(|e| e.to_string())
        }
    })
    .await;
}

/// The one exception to GH462: the check before the lock passed, then
/// another writer broke the config before this one held the lock. The load
/// under the lock decides and refuses, and the lock file already exists.
#[tokio::test]
async fn a_config_broken_before_the_lock_is_refused_under_it() {
    const BROKEN: &str = "backends: [\n";
    let (l, held) = linked();
    let before = crate::fs_lock::lock_attempts(&l.lock);
    let at = l.link.clone();
    let writer = tokio::spawn(async move {
        super::write::mutate_config_and_reload(&at, None, |c| {
            add_b(c);
            Ok::<(), String>(())
        })
        .await
        .is_err()
    });
    writer_waits(&l.lock, before).await;
    write_owner_only(&l.real, BROKEN).expect("break the config");
    drop(held);
    let refused = tokio::time::timeout(BOUND, writer).await.expect("ends");
    assert!(
        refused.expect("writer task"),
        "the load under the lock refuses"
    );
    let real = std::fs::read_to_string(&l.real).expect("read real");
    assert_eq!(real, BROKEN, "nothing was written over the broken config");
    assert!(l.lock.exists(), "the lock file stays: the GH462 exception");
}

/// Run a CLI `edit_config` that waits on the held lock, apply `meanwhile`,
/// release, and return its refusal.
fn cli_refusal(meanwhile: impl FnOnce(&Linked)) -> (Linked, String) {
    let (l, held) = linked();
    let waiting = crate::config_persistence::when_waiting_for_lock(&l.link);
    let at = l.link.clone();
    let writer = std::thread::spawn(move || {
        crate::config_persistence::edit_config(&at, CommentLoss::Rewrite, |c| {
            add_b(c);
            Ok(())
        })
    });
    waiting
        .recv_timeout(BOUND)
        .expect("the writer waits for the held lock");
    meanwhile(&l);
    drop(held);
    let refused = writer
        .join()
        .expect("writer thread")
        .expect_err("the writer refuses");
    (l, refused)
}

/// The target deleted while the writer waits leaves a dangling link: damage,
/// not absence (GH462). The target is not recreated from defaults.
#[test]
fn a_target_deleted_while_waiting_is_not_recreated() {
    let (l, refused) = cli_refusal(|l| std::fs::remove_file(&l.real).expect("delete target"));
    assert!(refused.contains("does not exist"), "{refused}");
    assert!(!l.real.exists(), "the deleted target stays deleted");
}

/// The link removed while the writer waits: the path names nothing it
/// locked, so nothing is written and no config appears at the path.
#[test]
fn a_link_removed_while_waiting_writes_nothing() {
    let (l, refused) = cli_refusal(|l| std::fs::remove_file(&l.link).expect("unlink"));
    assert!(refused.contains("moved during the write"), "{refused}");
    assert!(
        std::fs::symlink_metadata(&l.link).is_err(),
        "nothing appears at the path"
    );
    let real = std::fs::read_to_string(&l.real).expect("read real");
    assert_eq!(real, START, "the locked config is untouched");
}

/// The whole-config writer, which does not read the config first, still
/// refuses a target deleted while it waited: no config is recreated from
/// its caller's copy (GH462).
#[tokio::test]
#[allow(deprecated)] // the deprecated whole-config writer still locks
async fn a_whole_config_write_does_not_recreate_a_deleted_target() {
    let (l, held) = linked();
    let config = Config::load(Some(&l.link)).expect("config loads");
    let before = crate::fs_lock::lock_attempts(&l.lock);
    let at = l.link.clone();
    let writer = tokio::spawn(async move {
        super::write::write_config_and_reload_outcome(&at, &config, None)
            .await
            .is_err()
    });
    writer_waits(&l.lock, before).await;
    std::fs::remove_file(&l.real).expect("delete target");
    drop(held);
    let refused = tokio::time::timeout(BOUND, writer).await.expect("ends");
    assert!(refused.expect("writer task"), "the write refuses");
    assert!(!l.real.exists(), "the deleted target stays deleted");
}

/// A plain config deleted while the writer holds the lock is a deletion,
/// not a config still to be created: it is not recreated from the copy.
#[test]
fn a_config_deleted_during_the_edit_is_not_recreated() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("gateway.yaml");
    write_owner_only(&path, START).expect("write config");
    let at = path.clone();
    let refused = crate::config_persistence::edit_config(&path, CommentLoss::Rewrite, move |c| {
        std::fs::remove_file(&at).expect("delete");
        add_b(c);
        Ok(())
    })
    .expect_err("a deleted config refuses");
    assert!(refused.contains("deleted during the write"), "{refused}");
    assert!(!path.exists(), "the deleted config stays deleted");
}

/// An edit that changes nothing still reports on the config the path
/// names: a link moved during it refuses rather than report success.
#[test]
fn a_no_op_edit_refuses_when_the_link_moves() {
    let (l, held) = linked();
    drop(held);
    let at = l.link.clone();
    let other = l.other.clone();
    let refused = crate::config_persistence::edit_config_text(&l.link, move |_| {
        std::fs::remove_file(&at).expect("unlink");
        std::os::unix::fs::symlink(&other, &at).expect("re-point");
        Ok(None)
    })
    .expect_err("a no-op edit whose link moved refuses");
    assert!(refused.contains("moved during the write"), "{refused}");
    wrote_neither(&l);
}

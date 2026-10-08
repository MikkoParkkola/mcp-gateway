// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8042: every `gateway.yaml` writer loads, edits and writes under one
//! cross-process lock, a `.gateway.yaml.lock` sidecar next to the file. A
//! writer that cannot take it in time writes nothing (`Busy`), and a writer
//! that cannot take it at all writes nothing either: never an unlocked write.

use std::{sync::Arc, time::Duration};

use super::*;
use crate::config::Config;
use crate::config_persistence::CommentLoss;
use crate::fs_lock::ExclusiveFileLock;
use crate::gateway::test_helpers::write_owner_only;

const START: &str = "backends:\n  a:\n    http_url: \"http://127.0.0.1:9/mcp\"\n";

/// A config file in its own directory, and the path of its lock sidecar.
fn config() -> (tempfile::TempDir, std::path::PathBuf, std::path::PathBuf) {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("gateway.yaml");
    write_owner_only(&path, START).expect("write config");
    let lock = dir.path().join(".gateway.yaml.lock");
    (dir, path, lock)
}

#[allow(
    clippy::unnecessary_wraps,
    reason = "the mutate closure returns a Result"
)]
fn add_b(config: &mut Config) -> Result<(), String> {
    let backend = config.backends["a"].clone();
    config.backends.insert("b".to_string(), backend);
    Ok(())
}

/// What a write returned, for an assertion message (`ConfigMutation` has no
/// `Debug`).
fn outcome<T, E, X: std::fmt::Debug>(result: &Result<ConfigMutation<T, E>, X>) -> String {
    match result {
        Ok(ConfigMutation::Applied(..)) => "applied".to_string(),
        Ok(ConfigMutation::Rejected(_)) => "rejected".to_string(),
        Err(e) => format!("{e:?}"),
    }
}

/// R1: another process holds the lock, so the admin write waits out its
/// bound and reports `Busy` with the file untouched.
#[tokio::test]
async fn a_gateway_write_waits_for_the_lock_and_reports_busy() {
    let (_dir, path, lock) = config();
    let running = Config::load(Some(&path)).expect("config loads");
    let ctx = ReloadContext::new(
        path.clone(),
        Arc::new(LiveConfig::new(running)),
        Arc::new(crate::backend::BackendRegistry::new()),
        crate::config::FailsafeConfig::default(),
        Duration::from_secs(60),
    )
    .expect("the registry pairs with the config");
    let held = ExclusiveFileLock::try_acquire(&lock).expect("the test holds the lock");

    let result = ctx
        .mutate_and_reload_outcome_within(&path, Duration::from_millis(300), add_b)
        .await;

    assert!(
        matches!(result, Err(ConfigWriteError::Busy)),
        "a write under another writer's lock must report Busy: {}",
        outcome(&result)
    );
    assert_eq!(std::fs::read_to_string(&path).expect("read"), START);
    drop(held);
}

/// R1b: the same without a live gateway (the CLI's async path).
#[tokio::test]
async fn a_write_without_a_gateway_also_waits_for_the_lock() {
    let (_dir, path, lock) = config();
    let held = ExclusiveFileLock::try_acquire(&lock).expect("the test holds the lock");

    let result = mutate_config_and_reload_with(&path, None, CommentLoss::Refuse, add_b).await;

    assert!(
        matches!(result, Err(MutateError::Write(ConfigWriteError::Busy))),
        "a write under another writer's lock must report Busy: {}",
        outcome(&result)
    );
    assert_eq!(std::fs::read_to_string(&path).expect("read"), START);
    drop(held);
}

/// R4: a directory where the sidecar goes means the lock cannot be taken;
/// the write is refused rather than made unlocked.
#[tokio::test]
async fn a_lock_that_cannot_be_taken_refuses_the_write() {
    let (_dir, path, lock) = config();
    std::fs::create_dir(&lock).expect("a directory in the sidecar's place");

    let result = mutate_config_and_reload_with(&path, None, CommentLoss::Refuse, add_b).await;

    assert!(
        matches!(&result, Err(MutateError::Write(ConfigWriteError::Failed(m))) if m.contains("lock")),
        "an untakeable lock must refuse the write, naming the lock: {}",
        outcome(&result)
    );
    assert_eq!(std::fs::read_to_string(&path).expect("read"), START);
}

/// R5: no public config writer in `config_persistence.rs` takes a `bool`: a
/// behaviour-selecting flag is an enum.
#[test]
fn public_config_writers_take_a_mode_not_a_bool() {
    let source = include_str!("../config_persistence.rs");
    let signatures: Vec<&str> = source
        .match_indices("pub fn ")
        .map(|(at, _)| {
            let rest = &source[at..];
            &rest[..rest.find('{').unwrap_or(rest.len())]
        })
        .collect();
    assert!(!signatures.is_empty(), "no public functions found");
    for signature in &signatures {
        assert!(
            !signature.contains(": bool"),
            "a public config writer takes a bool: {signature}"
        );
    }
}

/// R8: a symlink planted where the sidecar goes is refused, never followed:
/// the sidecar sits in a user-chosen directory, and following a link would
/// lock (and on first use create) a file somewhere else.
#[cfg(unix)]
#[tokio::test]
async fn a_symlinked_lock_sidecar_refuses_the_write() {
    let (dir, path, lock) = config();
    let elsewhere = dir.path().join("elsewhere");
    std::fs::write(&elsewhere, "untouched").expect("link target");
    std::os::unix::fs::symlink(&elsewhere, &lock).expect("plant the symlink");

    let result = mutate_config_and_reload_with(&path, None, CommentLoss::Refuse, add_b).await;

    assert!(
        matches!(&result, Err(MutateError::Write(ConfigWriteError::Failed(m))) if m.contains("lock")),
        "a symlinked sidecar must refuse the write, naming the lock: {}",
        outcome(&result)
    );
    assert_eq!(std::fs::read_to_string(&path).expect("read"), START);
    assert_eq!(
        std::fs::read_to_string(&elsewhere).expect("read"),
        "untouched"
    );
}

/// R3: the lost update itself. Writer A loads, and while its edit runs,
/// writer B adds `c`. B must not land inside A's load-edit-write window: it
/// waits for A's lock and then edits A's result, so both changes survive.
///
/// Synchronised without sleeps: A's edit waits until B has either finished
/// (an unlocked writer) or tried the lock (`fs_lock::lock_attempts` counts
/// every attempt on the sidecar).
#[tokio::test]
async fn a_concurrent_writer_lands_after_the_edit_not_inside_it() {
    let (_dir, path, lock) = config();
    let b_path = path.clone();

    let result =
        mutate_config_and_reload_with(&path, None, CommentLoss::Refuse, |config: &mut Config| {
            let baseline = crate::fs_lock::lock_attempts(&lock);
            let b = std::thread::spawn(move || {
                let runtime = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .expect("runtime for writer B");
                runtime.block_on(mutate_config_and_reload_with(
                    &b_path,
                    None,
                    CommentLoss::Refuse,
                    |config: &mut Config| {
                        let backend = config.backends["a"].clone();
                        config.backends.insert("c".to_string(), backend);
                        Ok::<(), String>(())
                    },
                ))
            });
            while !b.is_finished() && crate::fs_lock::lock_attempts(&lock) <= baseline {
                std::thread::yield_now();
            }
            add_b(config)?;
            // Writer B is joined after A writes, so it is not leaked: hand it to
            // a thread that waits for it.
            std::thread::spawn(move || drop(b.join()));
            Ok::<(), String>(())
        })
        .await;
    assert!(
        matches!(result, Ok(ConfigMutation::Applied(..))),
        "writer A failed: {}",
        outcome(&result)
    );

    // Writer B finishes once A's lock is released.
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    let written = loop {
        let text = std::fs::read_to_string(&path).expect("read");
        if text.contains("\n  c:") || std::time::Instant::now() > deadline {
            break text;
        }
        tokio::task::yield_now().await;
    };
    assert!(
        written.contains("\n  b:") && written.contains("\n  c:"),
        "both writers' changes must survive; the file is:\n{written}"
    );
}

#[allow(
    clippy::unnecessary_wraps,
    reason = "the mutate closure returns a Result"
)]
fn add_c(config: &mut Config) -> Result<(), String> {
    let backend = config.backends["a"].clone();
    config.backends.insert("c".to_string(), backend);
    Ok(())
}

fn gateway(path: &std::path::Path) -> Arc<ReloadContext> {
    let running = Config::load(Some(path)).expect("config loads");
    Arc::new(
        ReloadContext::new(
            path.to_path_buf(),
            Arc::new(LiveConfig::new(running)),
            Arc::new(crate::backend::BackendRegistry::new()),
            crate::config::FailsafeConfig::default(),
            Duration::from_secs(60),
        )
        .expect("the registry pairs with the config"),
    )
}

/// R6 core: writer A is paused inside its reload, after its write and
/// before it reads the file back. Writer B (another process's path, no
/// reload context) must wait for A to publish, then add `c` on top of A's
/// result: the lock is held through the reload, not only the write.
async fn a_contender_waits_out_the_reload(
    path: &std::path::Path,
    lock: &std::path::Path,
    pause: Arc<super::reload_pause::Pause>,
    a: tokio::task::JoinHandle<bool>,
) {
    pause.reached.notified().await;
    let baseline = crate::fs_lock::lock_attempts(lock);
    let b_path = path.to_path_buf();
    let b = tokio::spawn(async move {
        mutate_config_and_reload_with(&b_path, None, CommentLoss::Refuse, add_c)
            .await
            .is_ok()
    });
    while crate::fs_lock::lock_attempts(lock) <= baseline && !b.is_finished() {
        tokio::task::yield_now().await;
    }
    let during = std::fs::read_to_string(path).expect("read");
    assert!(
        !during.contains("\n  c:"),
        "writer B wrote while writer A's reload was still in progress:\n{during}"
    );
    pause.release.notify_one();
    assert!(a.await.expect("writer A"), "writer A failed");
    assert!(b.await.expect("writer B"), "writer B failed");
    let written = std::fs::read_to_string(path).expect("read");
    assert!(
        written.contains("\n  b:") && written.contains("\n  c:"),
        "both writers' changes must survive; the file is:\n{written}"
    );
}

/// R6 for the mutation API (`mutate_and_reload_outcome`).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_writer_waits_for_a_mutation_reload_to_publish() {
    let (_dir, path, lock) = config();
    let ctx = gateway(&path);
    let pause = super::reload_pause::arm(&path);
    let a_path = path.clone();
    let a = tokio::spawn(async move {
        matches!(
            ctx.mutate_and_reload_outcome(&a_path, add_b).await,
            Ok(ConfigMutation::Applied(..))
        )
    });
    a_contender_waits_out_the_reload(&path, &lock, pause, a).await;
}

/// R6 for the whole-config API (`write_and_reload_outcome`).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_writer_waits_for_a_whole_config_reload_to_publish() {
    let (_dir, path, lock) = config();
    let ctx = gateway(&path);
    let mut with_b = Config::load_literal(Some(&path)).expect("loads");
    add_b(&mut with_b).expect("add b");
    let pause = super::reload_pause::arm(&path);
    let a_path = path.clone();
    let a =
        tokio::spawn(async move { ctx.write_and_reload_outcome(&a_path, &with_b).await.is_ok() });
    a_contender_waits_out_the_reload(&path, &lock, pause, a).await;
}

/// MIK-8120 (`MIK-WRITE-CANCEL.1`): the web UI's write is dropped after it
/// wrote `gateway.yaml` and before its reload published (the client went
/// away, and the listener cancels a disconnected request's handler). The
/// reload must still publish: the running gateway ends up on the file's
/// config, never left on the old one while the file says otherwise.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_dropped_write_still_publishes_its_reload() {
    let (_dir, path, _lock) = config();
    let ctx = gateway(&path);
    let pause = super::reload_pause::arm(&path);
    let (a_ctx, a_path) = (Arc::clone(&ctx), path.clone());
    let a = tokio::spawn(async move {
        mutate_config_and_reload_detached(a_path, Some(a_ctx), CommentLoss::Refuse, add_b)
            .await
            .is_ok()
    });
    tokio::time::timeout(Duration::from_secs(10), pause.reached.notified())
        .await
        .expect("the write reached its reload");
    a.abort();
    let _ = a.await;
    assert!(
        std::fs::read_to_string(&path)
            .expect("read")
            .contains("\n  b:"),
        "the write landed before the drop"
    );

    pause.release.notify_one();
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    while !ctx.live_config.get().backends.contains_key("b") {
        assert!(
            std::time::Instant::now() < deadline,
            "the file has `b` but the running gateway never loaded it"
        );
        tokio::task::yield_now().await;
    }
    // Both locks were released when the detached write finished: the next
    // write goes through instead of reporting Busy.
    let next = mutate_config_and_reload_with(&path, Some(&*ctx), CommentLoss::Refuse, add_c).await;
    assert!(
        matches!(next, Ok(ConfigMutation::Applied(..))),
        "the next write after the detached one: {}",
        outcome(&next)
    );
}

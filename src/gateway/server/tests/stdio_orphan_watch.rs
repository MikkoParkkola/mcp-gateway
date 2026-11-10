// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! An orphan can appear after EOF; keep observing throughout the drain.

use std::sync::Arc;
use std::sync::atomic::{AtomicI32, AtomicUsize, Ordering};
use std::time::Duration;

use tokio::io::AsyncWriteExt;
use tokio::time::timeout;

use super::super::Gateway;

const BOUND: Duration = Duration::from_secs(10);

struct Parent {
    pid: AtomicI32,
    reads: AtomicUsize,
}

async fn wait_for(mut ready: impl FnMut() -> bool) {
    timeout(BOUND, async {
        while !ready() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("watch observation reached");
}

async fn after_eof(saved: i32, change: bool) {
    let dir = crate::test_dir_keep::kept_tempdir();
    let mut config = crate::config::Config::default();
    config.tasks.store_dir = dir.path().join("tasks").display().to_string();
    config.capabilities.enabled = false;
    let mut gateway = Gateway::new(config)
        .await
        .expect("gateway boots")
        .with_data_dir(dir.path().to_path_buf());
    let parent = Arc::new(Parent {
        pid: AtomicI32::new(saved),
        reads: AtomicUsize::new(0),
    });
    gateway.test_seams.parent_pid = Some({
        let parent = Arc::clone(&parent);
        Arc::new(move || {
            parent.reads.fetch_add(1, Ordering::SeqCst);
            parent.pid.load(Ordering::SeqCst)
        })
    });
    let deadline = gateway.backends.stop_deadline();
    let (hold, drain) = gateway.stdio_drain_seams_for_test();
    let (reached, release) = hold.arm();
    let (mut stdin, input) = tokio::io::duplex(65536);
    let (output, _reader) = tokio::io::duplex(65536);
    let task = tokio::spawn(async move { gateway.run_stdio_on(input, output, None).await });
    stdin
        .write_all(b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"ping\"}\n")
        .await
        .expect("held dispatch");
    timeout(BOUND, reached.notified())
        .await
        .expect("dispatch held");
    assert_eq!(
        parent.reads.load(Ordering::SeqCst),
        1,
        "startup capture only"
    );
    stdin.shutdown().await.expect("EOF first");
    timeout(BOUND, drain.notified())
        .await
        .expect("read loop ended");
    assert!(!deadline.is_hurried());
    assert_eq!(deadline.get(), None, "drain is still held");

    if saved > 1 {
        let reads = parent.reads.load(Ordering::SeqCst);
        wait_for(|| parent.reads.load(Ordering::SeqCst) >= reads + 4).await;
        assert!(
            !deadline.is_hurried(),
            "unchanged parent across several polls"
        );
        assert_eq!(deadline.get(), None);
    }
    if change {
        parent.pid.store(7, Ordering::SeqCst);
    }
    if saved <= 1 {
        assert_eq!(deadline.get(), None, "a saved pid of 1 never arms a hurry");
    } else if change {
        wait_for(|| deadline.is_hurried()).await;
        let cut = deadline.get().expect("watch published hurry deadline");
        assert!(
            cut <= std::time::Instant::now()
                + crate::transport::KILL_RESERVE_FOR_TEST
                + crate::transport::HURRY_WINDOW
        );
    }
    release.notify_one();
    timeout(BOUND, task)
        .await
        .expect("teardown ends")
        .expect("serve task")
        .expect("stdio result");
    assert_eq!(deadline.is_hurried(), saved > 1 && change);
    if saved <= 1 {
        assert_eq!(parent.reads.load(Ordering::SeqCst), 1, "watch never armed");
    }
    // The gateway and its watch are gone: nothing still holds the reader, so
    // no poll can run after the teardown.
    assert_eq!(Arc::strong_count(&parent), 1, "watch dropped with teardown");
}

#[tokio::test]
async fn orphan_watch_hurries_when_parent_changes_after_eof() {
    after_eof(42, true).await;
}

#[tokio::test]
async fn orphan_watch_does_not_hurry_an_unchanged_parent_across_polls() {
    after_eof(42, false).await;
}

#[tokio::test]
async fn orphan_watch_never_arms_for_saved_pid_one() {
    after_eof(1, true).await;
}

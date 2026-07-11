// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-4486: OAuth cancellation-survival behavioral tests.
//!
//! The OAuth interactive browser flow in `src/transport/http/mod.rs`
//! (`HttpTransport::initialize_oauth`) wraps the handshake in `tokio::spawn`
//! so that dropping the outer future (e.g. MCP client cancels its `tools/call`
//! at its 15-30s request timeout) does not kill the OAuth task.  The task
//! keeps running, completes the browser callback, and persists the token to
//! disk — so a follow-up call finds a valid token and skips re-authorization.
//!
//! These tests pin the framework guarantees that the fix relies on.  Without
//! these properties the spawn-detach pattern would not survive cancellation,
//! and the production fix would silently regress.  A future iteration
//! (tracked under MIK-4486 follow-up) will add an end-to-end test that drives
//! a mock OAuth authorization server through the full `OAuthClient::authorize`
//! flow.

#![allow(clippy::missing_panics_doc)]

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use tokio::sync::Notify;

/// A `tokio::spawn`ed task continues to completion even when the outer
/// future awaiting its `JoinHandle` is dropped.
///
/// This is the load-bearing semantic in `HttpTransport::initialize_oauth`:
/// when the MCP client cancels the original `tools/call` (closing the
/// underlying connection drops the request handler future), the spawned
/// OAuth task is decoupled from that future's lifetime and proceeds to
/// completion — landing the token in `TokenStorage` on disk.
#[tokio::test]
async fn spawned_task_survives_outer_future_cancellation() {
    let completed = Arc::new(AtomicBool::new(false));
    let completed_clone = Arc::clone(&completed);
    let notify = Arc::new(Notify::new());
    let notify_clone = Arc::clone(&notify);

    let outer = async move {
        let task = tokio::spawn(async move {
            // Simulate the duration of an interactive browser OAuth flow.
            tokio::time::sleep(Duration::from_millis(400)).await;
            completed_clone.store(true, Ordering::SeqCst);
            notify_clone.notify_one();
        });
        // Mirror the production pattern: await the spawn inside the outer
        // future. Dropping the outer must NOT cancel the spawn.
        let _ = task.await;
    };

    // Cancel the outer well before the spawn would naturally complete.
    let outer_result = tokio::time::timeout(Duration::from_millis(50), outer).await;
    assert!(
        outer_result.is_err(),
        "outer future should have been cancelled by timeout"
    );

    // After cancellation, the detached task must still notify us.
    tokio::time::timeout(Duration::from_millis(1000), notify.notified())
        .await
        .expect("spawned task should complete despite outer cancellation");

    assert!(
        completed.load(Ordering::SeqCst),
        "spawned task must have executed its post-cancellation work"
    );
}

/// A spawn that produces a value can deliver that value through side-channel
/// state even when its `JoinHandle` is abandoned.
///
/// Production parallel: the OAuth task's "result" is the token persisted to
/// disk via `TokenStorage`. Even if the spawn's `JoinHandle.await` is dropped
/// by outer cancellation, the on-disk state remains for the next caller.
#[tokio::test]
async fn spawn_side_effect_persists_after_outer_drop() {
    let shared = Arc::new(parking_lot::RwLock::new(None::<String>));
    let shared_clone = Arc::clone(&shared);

    let outer = async move {
        let task = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(300)).await;
            // Side-effect: write to shared state (analogous to TokenStorage::save).
            *shared_clone.write() = Some("token_from_detached_task".to_string());
        });
        let _ = task.await;
    };

    // Outer races a short timeout it cannot meet.
    let _ = tokio::time::timeout(Duration::from_millis(30), outer).await;

    // Wait long enough for the detached task to finish its work.
    tokio::time::sleep(Duration::from_millis(500)).await;

    let observed = shared.read().clone();
    assert_eq!(
        observed.as_deref(),
        Some("token_from_detached_task"),
        "side effect from detached task must be observable after outer drop"
    );
}

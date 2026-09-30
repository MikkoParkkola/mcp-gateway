// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! #2245: an evicted slot's `close()` runs off the eviction path, bounded by
//! `close_stage` like the shutdown and idle-stop closes. A backend whose close
//! never completes must not stall a grant reload (and with it every later
//! revocation and the next reload) or the reaper, not even for one budget per
//! wedged slot.
//!
//! Both eviction entry points are plain `fn`s, so the compiler already rules
//! out an in-line await on a close; these tests pin what eviction still does
//! past a wedged close: every slot leaves the pool, and the close is detached
//! yet owned (drained by `stop`, and a stdio child is still reaped).

use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use async_trait::async_trait;
use serde_json::{Value, json};

use super::slot_eviction_tests::{per_user_backend, slot};
use super::*;
use crate::Result;
use crate::protocol::{JsonRpcResponse, RequestId};
use crate::transport::Transport;

const CLOSE_STAGE: Duration = Duration::from_millis(100);

/// A transport whose `close()` never completes, as a real close blocked on a
/// writer mutex held by a stuck write does.
struct WedgedClose;

#[async_trait]
impl Transport for WedgedClose {
    async fn request(&self, _method: &str, _params: Option<Value>) -> Result<JsonRpcResponse> {
        Ok(JsonRpcResponse::success_serialized(
            RequestId::Number(1),
            json!({}),
        ))
    }

    async fn notify(&self, _method: &str, _params: Option<Value>) -> Result<()> {
        Ok(())
    }

    fn is_connected(&self) -> bool {
        true
    }

    async fn close(&self) -> Result<()> {
        std::future::pending::<()>().await;
        Ok(())
    }
}

/// A per-user backend with a short `close_stage` and one wedged, idle slot
/// per binding.
fn backend_with_wedged_slots(bindings: &[&str]) -> Arc<Backend> {
    let mut backend = per_user_backend("wedged");
    Arc::get_mut(&mut backend)
        .expect("sole owner before the test starts")
        .budgets
        .close_stage = CLOSE_STAGE;
    for binding in bindings {
        backend.set_pooled_transport_for_test(&slot(binding), Arc::new(WedgedClose));
    }
    backend
}

/// GIVEN two revoked callers' idle slots whose transports never close
/// WHEN the grant reload evicts the subject's slots
/// THEN both are evicted, so the reload goes on to the next backend and subject.
#[tokio::test(start_paused = true)]
async fn a_wedged_close_does_not_stall_grant_reload_eviction() {
    let backend = backend_with_wedged_slots(&["rev:alpha", "rev:beta"]);

    let evicted = backend.evict_identity_slots("rev:");

    assert_eq!(
        evicted, 2,
        "both slots must be evicted past the stuck close"
    );
    for binding in ["rev:alpha", "rev:beta"] {
        assert!(
            !backend.pool.contains_key(&slot(binding)),
            "{binding} must be out of the pool"
        );
    }
}

/// GIVEN an expired per-user slot whose transport never closes
/// WHEN the idle reaper runs
/// THEN the slot is gone.
#[tokio::test(start_paused = true)]
async fn a_wedged_close_does_not_stall_the_idle_reaper() {
    let backend = backend_with_wedged_slots(&["idle:alpha"]);
    backend
        .pool
        .get(&slot("idle:alpha"))
        .expect("the slot exists once a transport is installed")
        .last_used
        .store(0, Ordering::Relaxed);

    let closed = backend.evict_idle_per_user_entries(Duration::from_secs(1));

    assert_eq!(closed, 1, "the expired slot must be evicted");
    assert!(!backend.pool.contains_key(&slot("idle:alpha")));
}

/// GIVEN a revoked caller's idle slot whose transport owns a real child
/// process and whose `close()` never completes
/// WHEN the grant reload evicts the slot and the close runs out its budget
/// THEN the child is still reaped: eviction held the last handle, and dropping
/// it kills the `kill_on_drop` child, so no process outlives the revocation
/// holding the revoked caller's credentials.
///
/// Real time, not a paused clock: the reap is done by the OS and tokio's orphan
/// queue. Same ownership shape as `a_close_that_times_out_still_reaps_the_child`.
// Unix-only: reaping is observed through the POSIX process table (zombie state).
#[cfg(unix)]
#[tokio::test]
async fn a_timed_out_eviction_close_still_reaps_the_child() {
    use super::pool_tests::{RealChildWedgedClose, spawn_probe_child};

    let (child, pid) = spawn_probe_child().await;
    let mut backend = per_user_backend("wedged-child");
    Arc::get_mut(&mut backend)
        .expect("sole owner before the test starts")
        .budgets
        .close_stage = CLOSE_STAGE;
    // Inline on purpose: a local binding would keep a second handle alive.
    backend.set_pooled_transport_for_test(
        &slot("rev:alpha"),
        Arc::new(RealChildWedgedClose {
            child: tokio::sync::Mutex::new(Some(child)),
        }),
    );

    let evicted = backend.evict_identity_slots("rev:");
    assert_eq!(evicted, 1);

    for _ in 0..40 {
        if is_reaped(pid) {
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let _ = std::process::Command::new("kill")
        .args(["-9", &pid.to_string()])
        .status();
    panic!("child {pid} outlived a timed-out eviction close by 2s");
}

/// A transport whose `close()` takes a moment and then records that it ran,
/// as an HTTP close sending its session DELETEs does.
struct SlowClose(Arc<std::sync::atomic::AtomicBool>);

#[async_trait]
impl Transport for SlowClose {
    async fn request(&self, method: &str, params: Option<Value>) -> Result<JsonRpcResponse> {
        WedgedClose.request(method, params).await
    }

    async fn notify(&self, _method: &str, _params: Option<Value>) -> Result<()> {
        Ok(())
    }

    fn is_connected(&self) -> bool {
        true
    }

    async fn close(&self) -> Result<()> {
        tokio::time::sleep(Duration::from_millis(50)).await;
        self.0.store(true, Ordering::SeqCst);
        Ok(())
    }
}

/// GIVEN a revoked caller's idle slot whose close takes a moment
/// WHEN the slot is evicted and the backend is stopped straight after
/// THEN `stop` returns only once that close has run: a detached close that
/// shutdown does not drain is dropped unrun when the runtime exits.
#[tokio::test(start_paused = true)]
async fn stop_drains_a_close_that_eviction_detached() {
    let closed = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let backend = per_user_backend("slow");
    backend.set_pooled_transport_for_test(
        &slot("rev:alpha"),
        Arc::new(SlowClose(Arc::clone(&closed))),
    );

    assert_eq!(backend.evict_identity_slots("rev:"), 1);
    backend.stop().await.expect("stop");

    assert!(
        closed.load(Ordering::SeqCst),
        "stop returned before the evicted transport's close ran"
    );
}

/// Reaped means gone from the process table. A killed child nobody has waited
/// on is a zombie: `is_alive` is false for it, `is_reaped` is not true (#2301).
// Unix-only: reaping is observed through the POSIX process table (zombie state).
#[cfg(unix)]
pub(super) fn is_reaped(pid: u32) -> bool {
    super::pool_tests::process_state(pid).is_none()
}

/// #2301: the probe the reap tests use must tell a zombie from a reaped
/// child. A killed child that nobody waits on is a zombie, so holding the
/// `Child` without awaiting it fails `is_reaped`; awaiting it passes.
// Unix-only: reaping is observed through the POSIX process table (zombie state).
#[cfg(unix)]
#[tokio::test]
async fn is_reaped_rejects_a_zombie_until_it_is_waited_on() {
    let (mut child, pid) = super::pool_tests::spawn_probe_child().await;
    child.start_kill().expect("signal the probe child");
    for _ in 0..200 {
        if !super::pool_tests::is_alive(pid) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(
        !super::pool_tests::is_alive(pid),
        "the killed child never stopped running"
    );
    assert!(!is_reaped(pid), "a zombie was counted as reaped");
    child.wait().await.expect("reap the probe child");
    assert!(is_reaped(pid), "a waited-on child is still in the table");
}

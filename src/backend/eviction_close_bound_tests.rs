// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! #2245: an evicted slot's `close()` is bounded by `close_stage`, like the
//! shutdown and idle-stop closes. One backend whose close never completes must
//! not stall a grant reload (and with it every later revocation) or the reaper.
//!
//! Paused clock: the wedged close never wakes, so the runtime auto-advances
//! time to the next timer. Bounded, that is `close_stage`; unbounded, it is the
//! outer `STALL` guard, which then reports the stall instead of hanging.

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
const STALL: Duration = Duration::from_secs(60);

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
/// THEN the eviction returns within the close budget, having evicted both,
/// so the reload goes on to the next backend and subject.
#[tokio::test(start_paused = true)]
async fn a_wedged_close_does_not_stall_grant_reload_eviction() {
    let backend = backend_with_wedged_slots(&["rev:alpha", "rev:beta"]);

    let started = tokio::time::Instant::now();
    let evicted = tokio::time::timeout(STALL, backend.evict_identity_slots("rev:"))
        .await
        .expect("eviction stalled on a close() that never completes");

    assert_eq!(evicted, 2, "both slots must be evicted past the stuck close");
    assert!(
        started.elapsed() < Duration::from_secs(1),
        "each close must be bounded by close_stage; took {:?}",
        started.elapsed()
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
/// THEN it returns within the close budget and the slot is gone.
#[tokio::test(start_paused = true)]
async fn a_wedged_close_does_not_stall_the_idle_reaper() {
    let backend = backend_with_wedged_slots(&["idle:alpha"]);
    backend
        .pool
        .get(&slot("idle:alpha"))
        .expect("the slot exists once a transport is installed")
        .last_used
        .store(0, Ordering::Relaxed);

    let started = tokio::time::Instant::now();
    let closed = tokio::time::timeout(
        STALL,
        backend.evict_idle_per_user_entries(Duration::from_secs(1)),
    )
    .await
    .expect("the reaper stalled on a close() that never completes");

    assert_eq!(closed, 1, "the expired slot must be evicted");
    assert!(
        started.elapsed() < Duration::from_secs(1),
        "the close must be bounded by close_stage; took {:?}",
        started.elapsed()
    );
    assert!(!backend.pool.contains_key(&slot("idle:alpha")));
}

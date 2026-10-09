// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! #2300 (original half): detached eviction closes are capped and every
//! abandoned close is counted.
//!
//! `close_evicted` spawns one task per evicted transport. Slot admission frees
//! a slot the moment it is evicted, while its close may run for a full
//! `close_stage`, so a slot cap alone does not bound the closes: two full
//! batches evicted back to back would run two caps' worth. The close permits
//! bound them; a close refused a permit is dropped at once and counted, and a
//! close that runs out its budget is counted too.
//!
//! Plain `#[test]` with its own current-thread runtime driven INSIDE
//! `with_local_recorder`: the counter is written from spawned tasks, and a
//! thread-local recorder sees them only while this thread is the one polling.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use async_trait::async_trait;
use serde_json::{Value, json};

use super::slot_eviction_tests::{per_user_backend, slot};
use crate::Result;
use crate::protocol::{JsonRpcResponse, RequestId};
use crate::transport::Transport;

/// The per-backend identity-slot cap (MIK-7547.SLOTS.1), which is also the
/// number of eviction closes allowed to run at once.
const CAP: usize = 64;
const CLOSE_STAGE: Duration = Duration::from_millis(100);
#[cfg(feature = "metrics")]
const ABANDONED: &str = "mcp_backend_eviction_close_abandoned_total";

/// Counts closes running right now and the most ever seen at once.
#[derive(Default)]
struct Running {
    now: AtomicUsize,
    peak: AtomicUsize,
}

struct RunningGuard(Arc<Running>);

impl Drop for RunningGuard {
    fn drop(&mut self) {
        self.0.now.fetch_sub(1, Ordering::SeqCst);
    }
}

/// A transport whose `close()` never completes and is counted while it runs.
struct WedgedCountedClose(Arc<Running>);

#[async_trait]
impl Transport for WedgedCountedClose {
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
        let now = self.0.now.fetch_add(1, Ordering::SeqCst) + 1;
        self.0.peak.fetch_max(now, Ordering::SeqCst);
        let _guard = RunningGuard(Arc::clone(&self.0));
        std::future::pending::<()>().await;
        Ok(())
    }
}

/// Evicts two batches of `CAP` wedged slots and checks the cap and the close
/// budget. Feature-free: the counter it leaves is read by the `metrics` row.
fn evict_two_wedged_batches(running: &Arc<Running>) {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .start_paused(true)
        .build()
        .expect("runtime");
    runtime.block_on(async {
        let mut backend = per_user_backend("wedged");
        Arc::get_mut(&mut backend)
            .expect("sole owner before the test starts")
            .budgets
            .close_stage = CLOSE_STAGE;

        for batch in ["b1", "b2"] {
            for i in 0..CAP {
                backend.set_pooled_transport_for_test(
                    &slot(&format!("{batch}:{i}")),
                    Arc::new(WedgedCountedClose(Arc::clone(running))),
                );
            }
            assert_eq!(
                backend.evict_identity_slots(&format!("{batch}:")),
                CAP,
                "every {batch} slot is evicted"
            );
            // Let the detached closes start.
            tokio::time::sleep(Duration::from_millis(1)).await;
        }

        let peak = running.peak.load(Ordering::SeqCst);
        assert!(peak > 0, "no eviction close ever ran");
        assert!(
            peak <= CAP,
            "{peak} eviction closes ran at once; cap is {CAP}"
        );

        tokio::time::sleep(CLOSE_STAGE * 2).await;
        assert_eq!(
            running.now.load(Ordering::SeqCst),
            0,
            "a close outlived its budget"
        );
    });
}

/// The cap and the close budget hold in every build.
#[test]
fn eviction_closes_are_capped() {
    evict_two_wedged_batches(&Arc::new(Running::default()));
}

/// GIVEN two full batches of idle slots whose transports never close, the
/// second evicted while the first batch's closes still run
/// WHEN each batch is evicted
/// THEN no more than `CAP` closes ever run at once, and once `close_stage` has
/// passed the abandoned counter reads every one of the `2 * CAP` closes: the
/// second batch refused a permit, the first ran out its budget.
#[cfg(feature = "metrics")]
#[test]
fn eviction_closes_are_capped_and_every_abandoned_close_is_counted() {
    let recorder = metrics_exporter_prometheus::PrometheusBuilder::new().build_recorder();
    let handle = recorder.handle();
    let running = Arc::new(Running::default());

    telemetry_metrics::with_local_recorder(&recorder, || evict_two_wedged_batches(&running));

    let rendered = handle.render();
    let expected = 2 * CAP;
    assert!(
        rendered
            .lines()
            .any(|line| line.starts_with(ABANDONED) && line.ends_with(&format!(" {expected}"))),
        "want {ABANDONED} = {expected}\n{rendered}"
    );
}

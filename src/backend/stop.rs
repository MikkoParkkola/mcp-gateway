// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Stopping a backend and draining its transports (split from `lifecycle.rs`).

use std::sync::Arc;

use std::time::Duration;

use tracing::{info, warn};

use super::Backend;
use crate::Result;
use crate::transport::Transport;

impl Backend {
    /// Stop the backend, draining every pooled transport slot.
    ///
    /// # Errors
    ///
    /// Never returns `Err` today: individual slot-close failures are logged and
    /// the remaining slots are still drained. The `Result` is retained for
    /// forward compatibility and to match the registry's stop contract.
    /// Concurrency contract: single-flight AND idempotent. Concurrent callers
    /// all wait for the SAME teardown and every one of them returns only after
    /// it has completed; a later call is a no-op. That matters because "stop
    /// returned" has to mean "everything is closed" - otherwise one caller can
    /// let the runtime exit while another's cleanup is still running, and the
    /// child processes this feature exists to reclaim survive anyway.
    pub async fn stop(&self) -> Result<()> {
        // Single-flight gate. A second caller blocks here rather than running a
        // parallel teardown, then sees `stopped` and returns - having waited for
        // the first caller's completion.
        //
        // What this buys, precisely: in the ordinary case the `lifecycle` write
        // guard below ALREADY serialises concurrent callers, so this gate is
        // not what makes them wait there. It matters where that guard does not
        // hold - its acquisition is bounded, so a caller that times out proceeds
        // WITHOUT exclusion, and two such callers would otherwise tear down in
        // parallel and each return on its own partial view. This makes the
        // guarantee unconditional rather than a side effect of a lock that is
        // allowed to give up.
        //
        // With the SHIPPED budgets this changes no observable behaviour: the
        // close stage is bounded at 10s and the lifecycle wait at 15s, so a
        // second caller's own timeout always outlasts the first's teardown.
        // That is an accident of two unrelated constants, not a guarantee -
        // shortening the lifecycle wait, or lengthening the close budget, would
        // silently reintroduce the defect. Hence both the gate and
        // `concurrent_stops_wait_for_one_teardown`, which sets its own budgets
        // so the window is reachable and the gate's absence is detectable.
        let _once = self.stop_once.lock().await;
        if self.stopped.load(std::sync::atomic::Ordering::SeqCst) {
            return Ok(());
        }

        // Exclusive: waits for any restart already in progress to finish, and
        // blocks any that has not yet started until the latch below is set.
        //
        // Bounded, because a restart holds this across `start_entry`, which runs
        // to the backend's own init timeout - and if a start hangs past even
        // that, an unbounded wait here would hang shutdown itself. Timing out
        // gives up the exclusion and reopens the narrow race it prevents, which
        // is the better of two bad outcomes at that point, so it is logged
        // loudly rather than passed over.
        let lifecycle_guard =
            tokio::time::timeout(self.budgets.lifecycle_wait, self.lifecycle.write())
                .await
                .inspect_err(|_| {
                    warn!(
                        backend = %self.name,
                        wait_secs = self.budgets.lifecycle_wait.as_secs(),
                        "Restart still in flight after the shutdown wait; proceeding \
                         without exclusion"
                    );
                })
                .ok();

        // Latched BEFORE anything is torn down. Setting it later - after the
        // pool has been walked - leaves a gap in which a restart finishing its
        // start sees `stopping == false`, approves itself, and installs a
        // transport into a slot shutdown has already visited and will not
        // revisit. The child then survives a completed shutdown.
        info!(backend = %self.name, "Stopping backend");

        // Latch and empty the pool under ONE hold of the cleanup lock, which is
        // the same lock `start_entry` publishes under. Latching first but
        // traversing afterwards is not enough: a transport published between
        // the two lands in a slot this traversal has already passed, and
        // nothing revisits it. Holding across both makes "no more transports
        // can appear" true at the moment the pool is emptied.
        //
        // No await inside - the closes happen after the guard is dropped.
        let transports: Vec<Arc<dyn Transport>> = {
            let mut cleanups = self.replaced_transport_cleanups.lock();
            cleanups.stopping = true;
            self.pool
                .iter()
                .filter_map(|entry| entry.value().transport.write().take())
                .collect()
        };

        self.close_pooled_transports(transports, self.budgets.close_stage)
            .await;

        // A start waiting on an interactive login would hold its callback
        // listener past shutdown: end the login first, within the drain
        // budget, so the start can finish and the port is free (MIK-7982).
        let _ = tokio::time::timeout(self.budgets.drain, self.login_gate.close()).await;

        self.await_starts_in_flight(self.budgets.drain).await;

        // Transports that `force_restart` replaced while they were in use are
        // NOT in `pool`, so the loop above cannot see them. Their cleanup tasks
        // own the only remaining reference and close them once their last
        // caller lets go - but a detached task is dropped unrun when the
        // runtime exits, which skips an HTTP backend's session DELETEs at the
        // reload and shutdown boundaries where they matter most. So wait for
        // them here.
        //
        // Bounded: a caller stuck forever would otherwise wedge shutdown, which
        // is worse than abandoning one session. Past the deadline the remaining
        // handles are dropped, which detaches those tasks rather than killing
        // them - they may still finish if the runtime outlives this call - and
        // the situation is logged either way.
        let drain_until = tokio::time::Instant::now() + self.budgets.drain;
        loop {
            // Re-taken each pass on purpose. The health loop only checks its
            // shutdown signal between ticks, so a `health_probe` already in
            // flight can call `force_restart` and register a new cleanup WHILE
            // this drain is running. Taking the list once would leave that last
            // one undrained - the very case this drain exists for.
            let pending: Vec<tokio::task::JoinHandle<()>> =
                std::mem::take(&mut self.replaced_transport_cleanups.lock().handles);
            if pending.is_empty() {
                // An empty list is not "no more work": a restart still holding
                // the lifecycle lock can register a cleanup after this take.
                // Exclusivity is the test for that - if the write lock is
                // available, no restart is in flight, so nothing more can
                // arrive. (Already holding it means the same thing.)
                let no_restart_in_flight =
                    lifecycle_guard.is_some() || self.lifecycle.try_write().is_ok();
                if no_restart_in_flight {
                    break;
                }
                if tokio::time::Instant::now() >= drain_until {
                    warn!(
                        backend = %self.name,
                        "Restart still in flight at the end of the shutdown drain; \
                         its cleanup may not run"
                    );
                    break;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
                continue;
            }

            let remaining = drain_until.saturating_duration_since(tokio::time::Instant::now());
            let timed_out = remaining.is_zero()
                || tokio::time::timeout(remaining, async move {
                    for handle in pending {
                        let _ = handle.await;
                    }
                })
                .await
                .is_err();

            if timed_out {
                warn!(
                    backend = %self.name,
                    deadline_secs = self.budgets.drain.as_secs(),
                    "Replaced transports still had live callers at shutdown; \
                     abandoning their cleanup"
                );
                break;
            }
        }

        // Recorded only here, at the end: a later caller may return immediately
        // on the strength of this flag, so it must not be set until the teardown
        // it stands for has actually finished.
        self.stopped
            .store(true, std::sync::atomic::Ordering::SeqCst);

        Ok(())
    }

    /// Close transports taken out of the pool, bounded as a STAGE.
    ///
    /// `close()` has no deadline of its own: `StdioTransport::close` waits on
    /// the writer mutex, which a request blocked writing to a child that has
    /// stopped reading can hold indefinitely, and HTTP closes its sessions one
    /// after another. Without a bound here one wedged backend hangs gateway
    /// shutdown forever - and stopping backends concurrently does not help,
    /// because joining them waits for the slowest.
    pub(super) async fn close_pooled_transports(
        &self,
        transports: Vec<Arc<dyn Transport>>,
        budget: Duration,
    ) {
        let until = tokio::time::Instant::now() + budget;
        for transport in transports {
            let remaining = until.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                warn!(
                    backend = %self.name,
                    "Ran out of time closing pooled transports; abandoning the rest"
                );
                return;
            }
            match tokio::time::timeout(remaining, transport.close()).await {
                Ok(Err(error)) => {
                    warn!(backend = %self.name, %error, "Failed to close pooled transport");
                }
                Err(_) => {
                    warn!(
                        backend = %self.name,
                        "Timed out closing a pooled transport; abandoning it"
                    );
                }
                Ok(Ok(())) => {}
            }
        }
    }

    /// Wait for starts that were already under way when shutdown began.
    ///
    /// Refusing to publish is not the whole guarantee: a start that has spawned
    /// its child and is waiting on the MCP handshake owns a live process right
    /// now, and the pool traversal cannot see it because it has not published.
    /// Returning without this lets that process outlive shutdown for as long as
    /// the handshake takes. At zero, every such start has resolved - published
    /// into a pool already emptied, or refused and closed.
    ///
    /// Bounded, and this is the one case where shutdown's guarantee does not
    /// hold: a start that never resolves is abandoned rather than allowed to
    /// wedge the gateway. Its process is still closed when that start finally
    /// finishes - late, and said out loud rather than quietly.
    pub(super) async fn await_starts_in_flight(&self, budget: Duration) {
        let until = tokio::time::Instant::now() + budget;
        while self
            .starts_in_flight
            .load(std::sync::atomic::Ordering::SeqCst)
            > 0
        {
            if tokio::time::Instant::now() >= until {
                warn!(
                    backend = %self.name,
                    "Backend start still in flight at the end of shutdown; its \
                     process will outlive this call until that start resolves"
                );
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }
}

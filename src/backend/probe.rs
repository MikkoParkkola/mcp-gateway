// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Health probing of a backend (split from `lifecycle.rs`).

use std::sync::Arc;

use std::sync::atomic::Ordering;
use std::time::Duration;

use tracing::{debug, info, warn};

use super::lifecycle::{ProbeInFlight, UNSERVED_ESCALATION};

use super::Backend;
use crate::transport::Transport;
use crate::{Error, Result};

impl Backend {
    /// Active health/recovery probe driven by the background health loop.
    ///    /// This is the gateway's automatic equivalent of `gateway_revive_server`.
    /// Two properties make it actually recover a wedged backend, which the old
    /// `backend.request("ping")` health check could not:
    ///
    /// 1. **It bypasses the circuit breaker.** A probe routed through
    ///    [`request`](Self::request) short-circuits on `Failsafe::admit` and
    ///    returns `CircuitOpen` *without touching the backend* -- so it could
    ///    never discover that an `Open` backend had recovered. This probe talks
    ///    to the transport directly.
    /// 2. **On success it resets a tripped breaker**; on failure it forces a
    ///    transport rebuild so the next probe targets a fresh child.
    ///
    /// `timeout` bounds the probe so a hung backend cannot stall the loop.
    ///
    /// # Errors
    ///
    /// Returns an error if the backend cannot be started, the probe times out,
    /// or the liveness call fails. A refused answer is neither: the peer is
    /// reachable and said so, and only the third consecutive refusal escalates
    /// (MIK-7217, OUTBOUND.2).
    pub async fn health_probe(&self, timeout: Duration) -> Result<()> {
        // Hold the transport for the whole probe WITHOUT claiming client activity.
        // Without this the reaper can close the transport between the health
        // loop's gate check and the probe's ping; the probe reads that as a fault
        // and calls force_restart(), so an idle backend is stopped and instantly
        // restarted. With a 10s health interval against a 60s sweep their ticks
        // coincide regularly, which would make the feature a periodic no-op - the
        // exact failure this change exists to correct.
        let _lease = self.begin_internal_activity();

        // A slot the reaper deliberately stopped is not a fault, and probing is
        // not a reason to wake it. `stop_if_idle` records this flag under the
        // same transport write guard that takes the transport, so by the time a
        // lease can be claimed the flag is already visible: either this lease
        // came first and the sweep declined, or the sweep completed and this
        // check sees it. Without the bail, the probe's ensure_started() below
        // would restart the process the sweep just released.
        if self
            .shared_entry()
            .stopped_when_idle
            .load(std::sync::atomic::Ordering::SeqCst)
        {
            return Ok(());
        }

        // `ensure_started` now respawns reliably because `is_connected()` does a
        // real liveness check (Fix C). Run non-interactive (MIK-7982 C2): the
        // probe never begins a login and never queues behind a start in flight,
        // which may be one; either answers `AuthorizationRequired` at once,
        // which is no fault to rebuild and which the health loop skips.
        let started = crate::oauth::login_gate::non_interactive(self.ensure_started()).await;
        if let Err(e) = started {
            #[cfg(test)]
            super::lifecycle::hold_at(&self.probe_error_gate).await;
            if !e.is_authorization_wait() {
                self.rebuild_from_probe().await;
            }
            return Err(e);
        }

        let transport = self.shared_transport();
        let Some(transport) = transport else {
            return Err(Error::BackendUnavailable(self.name.clone()));
        };

        // A tick that lands while the previous probe is still outstanding is
        // skipped rather than queued: see `probe_in_flight`.
        if self.probe_in_flight.swap(true, Ordering::SeqCst) {
            debug!(backend = %self.name, "Health probe already in flight; skipping this tick");
            return Ok(());
        }
        let _in_flight = ProbeInFlight(&self.probe_in_flight);

        // OUTBOUND.1: which method is a property of the peer's era, not of the
        // gateway. `ping` on a 2026-07-28 peer is a call to a method that
        // revision removed, so the probe would be asking a healthy peer a
        // question it is right to refuse.
        let method = self.liveness_method().await;

        let request = crate::oauth::login_gate::non_interactive(transport.request(method, None));
        let answer = match tokio::time::timeout(timeout, request).await {
            Ok(answer) => answer,
            Err(_elapsed) => {
                warn!(
                    backend = %self.name,
                    method,
                    timeout_ms = timeout.as_millis(),
                    "Health probe timed out; rebuilding transport"
                );
                self.unserved_consecutive.store(0, Ordering::SeqCst);
                self.rebuild_from_probe().await;
                return Err(Error::BackendTimeout(self.name.clone()));
            }
        };

        if let Some(code) = super::era::refusal_code(&answer) {
            return self.record_unserved_probe(method, code, &transport).await;
        }

        match answer {
            Ok(_) => {
                self.unserved_consecutive.store(0, Ordering::SeqCst);
                if self.is_circuit_tripped() {
                    info!(
                        backend = %self.name,
                        "Health probe succeeded; resetting tripped circuit breaker"
                    );
                    self.reset_circuit_breaker();
                }
                Ok(())
            }
            // The token step wanted a login: skip the tick, keep the login.
            Err(e) if e.is_authorization_wait() => Err(e),
            Err(e) => {
                warn!(backend = %self.name, error = %e, "Health probe failed; rebuilding transport");
                self.unserved_consecutive.store(0, Ordering::SeqCst);
                self.rebuild_from_probe().await;
                Err(e)
            }
        }
    }

    /// Record one probe answer the peer declined to serve, and escalate on the
    /// third in a row.
    ///
    /// The two things a refusal is not are what this arm exists to encode. It
    /// is not health: the peer answering "I do not serve that" says nothing
    /// about whether it serves anything, so the breaker stays as it was. It is
    /// not a fault: the transport carried a complete answer, so tearing it down
    /// would restart a working process every ten seconds.
    ///
    /// Refusing is still not free for the codes that could also come from a
    /// peer in trouble, so the count bounds the patience:
    /// [`UNSERVED_ESCALATION`] consecutive such refusals are treated as the
    /// fault they have become. The count survives an era invalidation (a
    /// modern-only code refusing a Legacy-era `ping`, row 9f), or a peer could
    /// dodge the escalation by changing which method it refuses.
    ///
    /// `method not found` is exempt. `ping` is OPTIONAL in MCP, so declining
    /// it is a stable property of the peer rather than a condition a restart
    /// can clear, and a well-formed, id-correlated JSON-RPC answer is itself
    /// proof the peer is alive and speaking the protocol - the opposite of
    /// wedged. Escalating on it rebuilt a transport whose replacement declines
    /// the same method, so the breaker tripped again on the next probes and a
    /// conformant backend shed traffic indefinitely (GH #567).
    pub(super) async fn record_unserved_probe(
        &self,
        method: &str,
        code: i32,
        transport: &Arc<dyn Transport>,
    ) -> Result<()> {
        self.unserved_total.fetch_add(1, Ordering::SeqCst);
        telemetry_metrics::counter!(
            "mcp_health_probe_unserved_total",
            "backend" => self.name.clone(),
            "code" => code.to_string()
        )
        .increment(1);

        // A code that contradicts the cached era (`-32601` to discovery, or a
        // modern-only code to a Legacy `ping`) re-probes it. Called before the
        // escalation check, so a misclassified peer is reclassified on the tick
        // that noticed.
        self.reprobe_if_code_contradicts(method, code, transport)
            .await;

        // A peer that answers at all is not the peer this escalation exists to
        // catch, and declining an optional method is the one refusal a restart
        // provably cannot change. Reset rather than merely skip: a backend
        // alternating `ping` refusals with a genuine fault must not accumulate
        // the faults across the answers that proved it alive.
        if code == crate::protocol::era::METHOD_NOT_FOUND_CODE {
            self.unserved_consecutive.store(0, Ordering::SeqCst);
            debug!(
                backend = %self.name,
                method,
                code,
                "Health probe declined an optional method; the answer is evidence of liveness"
            );
            return Ok(());
        }

        let consecutive = self.unserved_consecutive.fetch_add(1, Ordering::SeqCst) + 1;
        if consecutive < UNSERVED_ESCALATION {
            warn!(
                backend = %self.name,
                method,
                code,
                consecutive,
                "Health probe was not served"
            );
            return Ok(());
        }

        warn!(
            backend = %self.name,
            method,
            code,
            consecutive,
            "Health probe unserved {consecutive} times in a row; tripping breaker and rebuilding transport"
        );
        // The run this escalation acted on is spent: the transport below is
        // rebuilt, and a rebuilt backend starts its own count from zero.
        // Leaving the count at the threshold would escalate on every answer
        // afterwards, spending the tolerance once and never again.
        self.unserved_consecutive.store(0, Ordering::SeqCst);
        self.trip_circuit_breaker("health probe unserved");
        self.rebuild_from_probe().await;
        Err(Error::JsonRpc {
            code,
            message: format!("health probe to {method} was not served"),
            data: None,
        })
    }

    /// The probe's rebuild: a forced restart run non-interactive, so it
    /// neither ends a login in flight nor opens one (MIK-7982).
    async fn rebuild_from_probe(&self) {
        let _ = crate::oauth::login_gate::non_interactive(self.force_restart()).await;
    }
}

/// Paces the health loop (MIK-8012 PACE): the first tick returns at once, and
/// every later one a full `period` after the previous pass ENDED.
///
/// A `tokio::time::interval` schedules on a fixed grid, so after a pass slower
/// than the period (a failing rebuild can spend two discovery timeouts) the
/// next tick is already due and the rebuild is retried with no gap.
/// `MissedTickBehavior::Delay` still fires that overdue tick at once. The loop
/// creates this future after each pass, so the sleep starts when the pass ends.
pub(crate) struct HealthTicker {
    period: Duration,
    first: bool,
}

impl HealthTicker {
    pub(crate) const fn new(period: Duration) -> Self {
        Self {
            period,
            first: true,
        }
    }

    /// Wait for the next pass.
    pub(crate) async fn tick(&mut self) {
        if std::mem::take(&mut self.first) {
            return;
        }
        tokio::time::sleep(self.period).await;
    }
}

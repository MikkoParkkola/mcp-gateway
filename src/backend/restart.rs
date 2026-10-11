// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Forced restart of a backend (split from `lifecycle.rs`).

use std::sync::Arc;

use std::time::Duration;

use tracing::{debug, warn};

use super::pool::PoolKey;
use super::{Backend, RestartOutcome};

use crate::config::TransportConfig;
use crate::transport::Transport;
use crate::{Error, Result};

impl Backend {
    /// Tear down the current transport (killing any child process) and start a
    /// fresh one.
    ///
    /// Unlike [`ensure_started`](Self::ensure_started), this does **not** trust
    /// `is_connected()` -- it always rebuilds. A wedged-but-not-exited child
    /// (responds to `try_wait` as alive yet never answers requests) cannot be
    /// recovered by `ensure_started` alone; this is the escape hatch the health
    /// loop uses when a probe fails.
    ///
    /// # Errors
    ///
    /// Returns an error if the fresh transport fails to start or initialize.
    /// Returns [`RestartOutcome::SkippedStopping`] - NOT an error - when the
    /// backend is shutting down: nothing was rebuilt, and a caller reporting
    /// "revived" on the strength of an `Ok` would be lying to its operator.
    pub async fn force_restart(&self) -> Result<RestartOutcome> {
        // Rebuild only the canonical shared slot; per-user sessions are left
        // intact so one caller's health recovery cannot tear down another's
        // in-flight session (MIK-6735). The idle reaper reclaims per-user slots.
        // Held for the whole restart so shutdown cannot interleave with it. See
        // `Backend::lifecycle`: without this, the check below can pass before
        // stop() latches, and the restart then registers a cleanup after the
        // final drain or starts a child after teardown.
        let _lifecycle = self.lifecycle.read().await;

        // Refuse once shutdown has begun. `stop()` has already taken every
        // transport out of the pool; restarting here would spawn a fresh child
        // process (or a new upstream session) that nothing left alive will ever
        // close, turning a shutdown into an orphan. The health loop only checks
        // its shutdown signal between ticks, so a probe already in flight can
        // reach this point during teardown.
        if self.replaced_transport_cleanups.lock().stopping {
            debug!(backend = %self.name, "Skipping force_restart: backend is stopping");
            return Ok(RestartOutcome::SkippedStopping);
        }

        // A start stalled on an interactive login holds the start lock for
        // up to the whole authorization window, and its callback listener
        // holds the port this restart's own login binds: end that login
        // first. Starts queued behind it share its Cancelled end (MIK-7982).
        // A non-interactive restart (the health probe's rebuild) neither ends
        // a login, nor bumps the cancel epoch under a start still
        // discovering, nor queues behind a start in flight: it does nothing.
        let interactive = crate::oauth::login_gate::interactive();
        let required = || Error::AuthorizationRequired {
            backend: self.name.clone(),
        };
        if interactive {
            self.login_gate.cancel_and_join().await;
        } else if self.login_gate.in_flight() {
            return Err(required());
        }
        // Set out after this restart's own cancel, before it queues: a second
        // restart that cancels while this one waits refuses this one's login.
        // The cohort is captured here too, after the cancel, so this restart's
        // start never shares the Cancelled it caused (MIK-8339).
        let set_out = self.login_gate.epoch();
        let set_out_cohort = self.login_gate.cohort();

        let entry = self.shared_entry();
        let _guard = if interactive {
            entry.start_lock.lock().await
        } else {
            entry.start_lock.try_lock().map_err(|_| required())?
        };

        // Re-checked after the await. The lock above normally prevents shutdown
        // from interleaving at all, but it is not the only line of defence:
        // `stop()` bounds its wait for that lock, so it can proceed without it
        // rather than hang forever. Correctness must not depend on having won
        // the lock, only on this flag.
        if self.replaced_transport_cleanups.lock().stopping {
            debug!(backend = %self.name, "Abandoning force_restart: shutdown began while waiting");
            return Ok(RestartOutcome::SkippedStopping);
        }
        #[cfg(test)]
        self.rebuilds_attempted
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        #[cfg(test)]
        super::lifecycle::hold_at(&self.restart_take_gate).await;
        // A non-interactive HTTP restart builds its replacement BEFORE it lets
        // go of the pooled transport (MIK-8012, MIK-8016): it cannot log in,
        // so a replacement whose credential lapsed cannot start, and taking
        // first would leave the slot empty with nothing to put back. On success
        // `publish` writes the new transport over the slot and the old one is
        // closed once its last caller lets go; on failure nothing was removed
        // and the old one keeps serving. `start_lock` is held throughout, so no
        // other start publishes in between. Interactive restarts can log in,
        // and stdio keeps take-then-start: two children of one server at once
        // can fight over a port or lock file.
        if !interactive && matches!(self.config.transport, TransportConfig::Http { .. }) {
            let old = entry.transport.read().clone();
            return match crate::oauth::login_gate::set_out_with_cohort(
                set_out,
                Arc::clone(&set_out_cohort),
                self.start_entry_as(
                    &PoolKey::Shared,
                    &entry,
                    super::lifecycle::EraResolution::Deferred,
                ),
            )
            .await
            {
                Ok(new) => {
                    if let Some(old) = old.filter(|old| !Arc::ptr_eq(old, &new)) {
                        self.close_after_last_owner(old);
                    }
                    Ok(RestartOutcome::Rebuilt)
                }
                Err(_) if self.replaced_transport_cleanups.lock().stopping => {
                    Ok(RestartOutcome::SkippedStopping)
                }
                Err(error) => Err(error),
            };
        }
        // Take the transport out and drop the RwLock write guard *before*
        // awaiting close() -- a parking_lot guard is not Send across an await.
        // in_flight is read under that same guard so the answer cannot change
        // between the check and the take.
        let (old, busy) = {
            let mut guard = entry.transport.write();
            let busy = entry.in_flight.load(std::sync::atomic::Ordering::SeqCst) > 0;
            (guard.take(), busy)
        };
        if let Some(old) = old {
            if busy {
                // Requests are executing against this transport right now.
                // Closing it here kills a stdio child and tears down an HTTP
                // session underneath a live caller, which is a worse failure
                // than the one recovery is trying to fix.
                //
                // So close it exactly when its last user lets go, and never
                // before. No deadline is imposed on that user: the two earlier
                // attempts here both tried to answer "when is it safe?" with a
                // timer and both were rejected - a fixed cap is arbitrary, and a
                // cap derived from config is unsound because one logical attempt
                // can re-handshake and retry in ways no formula sees.
                self.close_after_last_owner(old);
            } else {
                let _ = old.close().await;
            }
        }
        // `start_entry` refuses to publish once shutdown has latched, so there
        // is no window here in which a live transport can be left behind and
        // nothing to take back. A start that failed for THAT reason is not a
        // fault worth reporting as one.
        match crate::oauth::login_gate::set_out_with_cohort(
            set_out,
            set_out_cohort,
            self.start_entry(&PoolKey::Shared, &entry),
        )
        .await
        {
            Ok(transport) => {
                // Same obligation as the cold start path: the era describes the
                // process on the other end, and this one has just been
                // replaced. Runs under the `start_lock` taken above, which is
                // the order `Backend::resolve_era` documents.
                self.resolve_era_after_start(&transport, &entry).await;
                Ok(RestartOutcome::Rebuilt)
            }
            Err(error) => {
                if self.replaced_transport_cleanups.lock().stopping {
                    Ok(RestartOutcome::SkippedStopping)
                } else {
                    Err(error)
                }
            }
        }
    }

    /// Close a replaced transport the moment its last user releases it.
    ///
    /// [`Backend::force_restart`] cannot await this inline: it is the health
    /// loop's recovery path, and the case it exists for is a WEDGED backend
    /// whose in-flight request may never return, so blocking recovery on that
    /// request would convert an interruption bug into a never-recovers bug. The
    /// fresh transport is installed immediately and the old one is closed behind
    /// it.
    ///
    /// **No deadline, deliberately.** Two earlier revisions capped this wait and
    /// both were rejected in review: any cap closes the transport underneath a
    /// request that is merely slower than the cap. The cap cannot be derived
    /// either - a single logical attempt can re-handshake and retry (see
    /// `HttpTransport`'s session-expiry path) in ways no formula predicts. So
    /// this waits for the actual condition instead of a proxy for it.
    ///
    /// The `Arc` strong count is the drain signal, not `in_flight`: `in_flight`
    /// counts requests against the SLOT, which new traffic keeps non-zero, while
    /// the strong count tracks holders of THIS transport and reaches one (ours)
    /// when the last in-flight caller is done.
    ///
    /// Precisely, and weaker than it may look: reaching one means no OTHER
    /// strong reference exists at that instant, not that none can appear
    /// afterwards. The stdio reader task holds a `Weak` and can still upgrade
    /// between the check and `close()`, so `close()` may overlap a
    /// `handle_response` call. That is benign - `handle_response` is
    /// synchronous and only routes a reply to a pending receiver - and the
    /// transport cannot be closed out from under a real caller, because a
    /// caller's own `Arc` keeps the count above one for as long as it is
    /// working. The guarantee is "no live caller", not "no future reference".
    ///
    /// Closing rather than merely dropping matters for HTTP: `close()` sends the
    /// per-session DELETEs, and dropping skips them, abandoning upstream sessions
    /// on every busy recovery with nothing guaranteeing the remote ever reclaims
    /// them. stdio would be fine either way now that its reader task holds a
    /// `Weak` (`kill_on_drop` reaps the child), but one path for both transports
    /// is simpler than two.
    ///
    /// A holder that never releases keeps this task alive. That is the intended
    /// trade - leaking one transport beats terminating a live request - and the
    /// poll backs off to seconds and warns once so it stays cheap and visible
    /// rather than silent.
    pub(super) fn close_after_last_owner(&self, old: Arc<dyn Transport>) {
        const FIRST_POLL: Duration = Duration::from_millis(20);
        const MAX_POLL: Duration = Duration::from_secs(5);
        const WARN_AFTER: Duration = Duration::from_secs(300);

        let name = self.name.clone();
        let handle = tokio::spawn(async move {
            let started = tokio::time::Instant::now();
            let mut delay = FIRST_POLL;
            let mut warned = false;

            while Arc::strong_count(&old) > 1 {
                tokio::time::sleep(delay).await;
                delay = (delay * 2).min(MAX_POLL);

                if !warned && started.elapsed() >= WARN_AFTER {
                    warned = true;
                    warn!(
                        backend = %name,
                        held_for_secs = started.elapsed().as_secs(),
                        "Replaced transport still held long after recovery; \
                         waiting rather than closing it under its holder"
                    );
                }
            }

            if let Err(error) = old.close().await {
                warn!(backend = %name, %error, "Replaced transport failed to close cleanly");
            }
        });

        // Drop handles for cleanups that already finished so a long-lived
        // backend restarted many times does not accumulate them.
        let mut pending = self.replaced_transport_cleanups.lock();
        pending.handles.retain(|h| !h.is_finished());
        pending.handles.push(handle);
    }
}

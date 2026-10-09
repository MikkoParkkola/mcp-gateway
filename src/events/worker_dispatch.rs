// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The worker's scheduling loop: when it sweeps, which due records it
//! starts, and how long it sleeps before looking again (design §6.5).

use std::sync::Arc;
use std::time::{Duration, Instant};

use chrono::Utc;
use tokio::sync::Semaphore;

use crate::events::EventsHub;
use crate::events::outbox::DeadReason;
use crate::events::services::Services;

/// How often dead-letter retention runs while the gateway is up.
const SWEEP_EVERY: Duration = Duration::from_secs(30);
/// Longest the worker sleeps with nothing scheduled (a safety net only).
const IDLE: Duration = Duration::from_secs(5);

impl EventsHub {
    /// Run the worker until the runtime stops.
    pub(in crate::events) async fn deliver_forever(self: Arc<Self>, services: &Arc<Services>) {
        let slots = Arc::new(Semaphore::new(self.config.max_in_flight));
        let mut swept: Option<Instant> = None;
        loop {
            if swept.is_none_or(|at| at.elapsed() >= SWEEP_EVERY) {
                swept = Some(Instant::now());
                self.sweep(services).await;
            }
            self.stop_expired_keys().await;
            let wait = self.dispatch(services, &slots).await;
            tokio::select! {
                () = self.runtime.wake.notified() => {}
                () = tokio::time::sleep(wait) => {}
            }
        }
    }

    /// The worker's periodic housekeeping, every [`SWEEP_EVERY`].
    pub(in crate::events) async fn sweep(&self, services: &Services) {
        self.sweep_dead_letters(services).await;
        self.sweep_lifecycle().await;
    }

    /// Start every attempt that is due, has a token and a slot; how long to
    /// sleep before looking again.
    pub(super) async fn dispatch(
        self: &Arc<Self>,
        services: &Arc<Services>,
        slots: &Arc<Semaphore>,
    ) -> Duration {
        let (held, policy) = (self.runtime.busy.lock().clone(), self.dead_policy());
        // Expired rows settle every tick, before the reconcile gate (MIK-8061),
        // on a clock that reads: before 1970 nothing is judged (MIK-8202).
        let Ok(now) = crate::clock::utc_now() else {
            return IDLE;
        };
        // Each burial is receipted before the evictions it caused.
        let due = {
            let _ordered = self.receipts.lock().await;
            let mut due = self
                .blocking(move |store| store.due(now, &held, policy))
                .await;
            if let Some(due) = &mut due {
                for record in &due.buried {
                    self.dead_lettered(services, record, DeadReason::Expired)
                        .await;
                }
                services
                    .audit_evictions(std::mem::take(&mut due.evicted))
                    .await;
            }
            due
        };
        // The catalogue is partial until the startup scan has run: a record
        // of a route removed while down must not be sent first (MIK-7772).
        if !self
            .runtime
            .reconciled
            .load(std::sync::atomic::Ordering::Acquire)
        {
            return IDLE;
        }
        let Some(due) = due else {
            return IDLE;
        };
        // A deadline already past (more expired records waiting) is now.
        let mut wait = due
            .next
            .map_or(IDLE, |at| {
                (at - Utc::now()).to_std().unwrap_or(Duration::ZERO)
            })
            .min(IDLE);
        for record in due.ready {
            let Ok(permit) = Arc::clone(slots).try_acquire_owned() else {
                // Every slot is busy: a finishing attempt wakes the worker.
                break;
            };
            if let Err(later) = self
                .runtime
                .rates
                .take(&record.subscription_id, Instant::now())
            {
                // Delayed, never dropped: the record stays due.
                wait = wait.min(later);
                drop(permit);
                continue;
            }
            self.runtime
                .busy
                .lock()
                .insert(record.subscription_id.clone());
            let (hub, services) = (Arc::clone(self), Arc::clone(services));
            tokio::spawn(async move {
                hub.attempt(&services, &record.event_id).await;
                hub.runtime.busy.lock().remove(&record.subscription_id);
                drop(permit);
                hub.runtime.wake.notify_one();
            });
        }
        wait
    }

    /// Evict the dead letters past their retention or caps, and receipt each
    /// eviction, in the receipt order a burial keeps (see `receipts`).
    pub(super) async fn sweep_dead_letters(&self, services: &Services) {
        let policy = self.dead_policy();
        let _ordered = self.receipts.lock().await;
        let evicted = self
            .blocking(move |store| store.sweep_dead(Utc::now(), policy))
            .await;
        services.audit_evictions(evicted.unwrap_or_default()).await;
    }
}

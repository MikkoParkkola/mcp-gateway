// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The hub's moving parts (design §3.2): the bounded source queue, the
//! fan-out task and the delivery worker, started once the gateway hands
//! over the services every payload must pass.

use std::collections::HashSet;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use parking_lot::Mutex;
use tokio::sync::{Notify, mpsc};

use super::dedupe::Seen;
use super::fanout::SourceEvent;
use super::outbox::{DeadPolicy, DeadReason, OutboxCaps, OutboxRecord};
use super::rate::{FailureWindows, RateLimits};
use super::records::ApiKeyRef;
use super::services::Services;
use super::store::Store;
use super::types::SourceKind;
use super::{EventSource, EventsHub};

/// Runtime state of the delivery pipeline.
/// The worker's last expiry check (design r3 L5).
pub(crate) struct ExpirySeen {
    pub at: chrono::DateTime<chrono::Utc>,
    /// The earliest deadline after `at`; `None` when no row has one.
    pub next: Option<chrono::DateTime<chrono::Utc>>,
    pub removals: u64,
    /// The store's generation at the last scan: deadlines change only
    /// with a write, and every write bumps it.
    pub generation: u64,
}

pub(crate) struct Runtime {
    queue: mpsc::Sender<SourceEvent>,
    /// Taken by [`EventsHub::start`]; `None` once the pipeline runs.
    pub(super) intake: Mutex<Option<mpsc::Receiver<SourceEvent>>>,
    /// Wakes the worker: a record was written or a subscription reactivated.
    pub wake: Notify,
    pub seen: Seen,
    pub rates: RateLimits,
    pub failures: FailureWindows,
    /// Subscriptions with an attempt between its claim and its settlement.
    pub busy: Mutex<HashSet<String>>,
    /// The gateway's controls, once [`EventsHub::start`] ran.
    pub services: std::sync::OnceLock<Arc<Services>>,
    /// Mints a per-user listener's credential through the gateway's audited
    /// path; set once at events wiring.
    pub listener_mint: std::sync::OnceLock<Arc<dyn super::ListenerMint>>,
    /// The backends the upstream-notification source listens on, once it is
    /// installed: their live connections decide HTTP eligibility (MIK-7969).
    pub backends: std::sync::OnceLock<Arc<crate::backend::BackendRegistry>>,
    /// Set once the stored subscriptions have been reconciled with the
    /// catalogue the startup capability scan built; no attempt starts before.
    pub reconciled: AtomicBool,
    /// Where the worker's last expiry check ended, the earliest deadline
    /// after it (no scan is needed before then), and the store's removal
    /// count then (design r3 L5).
    pub expiry_seen: Mutex<ExpirySeen>,
    dropped: AtomicU64,
    projection_failed: AtomicU64,
    /// Occurrences dropped because the host clock could not date them
    /// (before 1970), apart from queue-capacity drops (MIK-8202).
    clock_drops: AtomicU64,
}

impl Runtime {
    pub(crate) fn new(config: &crate::config::EventsConfig, store_dir: &std::path::Path) -> Self {
        let (queue, intake) = mpsc::channel(config.queue_depth);
        Self {
            queue,
            intake: Mutex::new(Some(intake)),
            wake: Notify::new(),
            seen: Seen::new(store_dir.join("seen"), config.seen_max_per_route),
            rates: RateLimits::new(&config.rate_limit_per_subscription),
            failures: FailureWindows::new(config.suspend_window, config.suspend_min_attempts),
            busy: Mutex::new(HashSet::new()),
            services: std::sync::OnceLock::new(),
            listener_mint: std::sync::OnceLock::new(),
            backends: std::sync::OnceLock::new(),
            reconciled: AtomicBool::new(false),
            expiry_seen: Mutex::new(ExpirySeen {
                // A constant, not a reading, when the clock cannot be read
                // (before 1970): the first readable tick scans every deadline
                // up to then, as `generation: u64::MAX` already forces.
                at: crate::clock::utc_now().unwrap_or(chrono::DateTime::<chrono::Utc>::MIN_UTC),
                next: None,
                removals: 0,
                generation: u64::MAX,
            }),
            dropped: AtomicU64::new(0),
            projection_failed: AtomicU64::new(0),
            clock_drops: AtomicU64::new(0),
        }
    }

    /// An occurrence (or one subscription's record) was dropped.
    pub(crate) fn count_drop(&self) {
        let total = self.dropped.fetch_add(1, Ordering::Relaxed) + 1;
        tracing::warn!(dropped_total = total, "events: occurrence dropped");
    }

    /// An occurrence the host clock could not date (before 1970) was dropped.
    /// Counted apart from queue drops, so a broken clock is not read as load.
    pub(crate) fn count_clock_drop(&self) {
        let total = self.clock_drops.fetch_add(1, Ordering::Relaxed) + 1;
        tracing::warn!(
            clock_drops_total = total,
            clock_unreadable = true,
            "events: occurrence dropped; the host clock reads before 1970"
        );
    }

    /// Occurrences dropped so far for a clock that could not date them.
    #[cfg(test)]
    pub(crate) fn clock_drops(&self) -> u64 {
        self.clock_drops.load(Ordering::Relaxed)
    }

    /// An inbound POST projected to no field.
    pub(crate) fn count_projection_failed(&self) {
        let total = self.projection_failed.fetch_add(1, Ordering::Relaxed) + 1;
        tracing::warn!(projection_failed_total = total, "events: projection_failed");
    }
}

impl EventsHub {
    /// Queue an occurrence without blocking; a full queue drops it (§3.2).
    pub(crate) fn emit(&self, event: SourceEvent) {
        if self.runtime.queue.try_send(event).is_err() {
            self.runtime.count_drop();
        }
    }

    /// Queue an occurrence dated by one read of the clock. On a clock that
    /// cannot be read (before 1970) nothing is queued and a clock drop is
    /// counted: an occurrence is never dated 1969, and delivery is idle on
    /// such a clock anyway (MIK-8202).
    pub(crate) fn emit_dated(
        &self,
        build: impl FnOnce(chrono::DateTime<chrono::Utc>) -> SourceEvent,
    ) {
        match crate::clock::utc_now() {
            Ok(occurred_at) => self.emit(build(occurred_at)),
            Err(_) => self.runtime.count_clock_drop(),
        }
    }

    /// An occurrence this hub could not date was dropped (see
    /// [`Runtime::count_clock_drop`]).
    pub(crate) fn count_clock_drop(&self) {
        self.runtime.count_clock_drop();
    }

    /// Start fan-out, the worker and the dead-letter sweep. Called once
    /// from the HTTP server; a second call finds the intake taken.
    pub(crate) fn start(self: &Arc<Self>, services: Services) {
        let Some(mut intake) = self.runtime.intake.lock().take() else {
            return;
        };
        // Before anything reads the store: the worker drops outbox records it
        // cannot place, and every handle derives from the key (MIK-8697 §13.6).
        self.store.bind_key(services.record_key());
        let services = Arc::new(services);
        let _ = self.runtime.services.set(Arc::clone(&services));
        let hub = Arc::clone(self);
        let fan_services = Arc::clone(&services);
        tokio::spawn(async move {
            // Nothing is matched before the first startup pass has judged the
            // routes: a subscription a narrowed route cannot serve is held
            // first (MIK-8076). Occurrences wait in the bounded intake.
            // ponytail: 50 ms poll of a flag set once; a Notify if it matters.
            while !hub
                .runtime
                .reconciled
                .load(std::sync::atomic::Ordering::Acquire)
            {
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            }
            while let Some(event) = intake.recv().await {
                hub.fan_out(&fan_services, &event).await;
            }
        });
        let hub = Arc::clone(self);
        tokio::spawn(async move { hub.deliver_forever(&services).await });
        // C8: a revocation re-checks the per-user listeners at once. Weak, so
        // the watch never keeps a dropped hub alive.
        let (weak, changed) = (Arc::downgrade(self), super::CREDENTIALS_CHANGED.subscribe());
        tokio::spawn(watch_credentials(weak, changed));
        // After a restart the upstream state is rebuilt from the store.
        let hub = Arc::clone(self);
        tokio::spawn(async move {
            // Before replay: a row observed under config that changed while
            // the gateway was down is revoked, not started.
            hub.revoke_unobservable(None).await;
            hub.revoke_inadmissible(None).await;
            hub.replay_starts().await;
        });
    }

    /// Whether a caller holding API key `key` may still see `backend` under
    /// the live config: the one check `events/list`, subscribe, fan-out and
    /// every attempt share. Before the pipeline starts there is no live
    /// config to consult and the transport's own check stands.
    pub(crate) fn live_admits(&self, key: Option<&ApiKeyRef>, backend: &str) -> bool {
        self.runtime
            .services
            .get()
            .is_none_or(|services| services.admits(key, backend))
    }

    /// The source of `kind`.
    pub(super) fn source(&self, kind: SourceKind) -> Option<Arc<dyn EventSource>> {
        self.sources
            .read()
            .iter()
            .find(|s| s.kind() == kind)
            .cloned()
    }

    pub(super) fn dead_policy(&self) -> DeadPolicy {
        DeadPolicy {
            retention: self.config.dead_letter_retention,
            max_records: self.config.dead_letter_max_records,
            max_bytes: self.config.dead_letter_max_bytes,
        }
    }

    /// The governance record of a dead letter (design 3.7).
    pub(super) async fn dead_lettered(
        &self,
        services: &Services,
        record: &OutboxRecord,
        reason: DeadReason,
    ) {
        // Stamped at fan-out from the subscription the record is for; a record
        // written before the stamp existed falls back to the store.
        let host = if record.callback_host.is_empty() {
            self.store
                .get(&record.subscription_id)
                .map(|s| super::outbox::callback_host_of(&s.url))
                .unwrap_or_default()
        } else {
            record.callback_host.clone()
        };
        services
            .audit_lifecycle(
                &super::governance::Lifecycle {
                    action: "events.dead_letter",
                    subscription_id: &record.subscription_id,
                    event_name: &record.name,
                    callback_host: &host,
                    detail: reason.as_str(),
                    event_id: Some(&record.event_id),
                    failed_with: Some(-32015),
                },
                super::governance::Attribution::Gateway,
            )
            .await;
    }

    pub(super) fn outbox_caps(&self) -> OutboxCaps {
        OutboxCaps {
            global: self.config.max_outbox,
            per_subscription: self.config.max_outbox_per_subscription,
        }
    }

    /// Run a store operation on the blocking pool; `None` (logged) when
    /// it failed, so the pipeline counts and moves on.
    pub(super) async fn blocking<T: Send + 'static>(
        &self,
        op: impl FnOnce(&Store) -> std::io::Result<T> + Send + 'static,
    ) -> Option<T> {
        let store = Arc::clone(&self.store);
        match tokio::task::spawn_blocking(move || op(&store)).await {
            Ok(Ok(value)) => Some(value),
            Ok(Err(error)) => {
                tracing::warn!(%error, "events store write failed");
                None
            }
            Err(error) => {
                tracing::warn!(%error, "events store task failed");
                None
            }
        }
    }
}

/// The watcher [`EventsHub::start`] spawns for C8: each credential change
/// re-checks the per-user listeners at once. A free function so a test can
/// drive it with the real `credentials_changed()` signal.
pub(super) async fn watch_credentials(
    weak: std::sync::Weak<EventsHub>,
    mut changed: tokio::sync::watch::Receiver<u64>,
) {
    while changed.changed().await.is_ok() {
        let Some(hub) = weak.upgrade() else {
            return;
        };
        hub.revoke_unobservable(None).await;
        hub.revoke_inadmissible(None).await;
    }
}

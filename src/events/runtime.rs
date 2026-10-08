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
use super::outbox::{DeadPolicy, OutboxCaps};
use super::rate::{FailureWindows, RateLimits};
use super::records::ApiKeyRef;
use super::services::Services;
use super::store::Store;
use super::types::SourceKind;
use super::{EventSource, EventsHub};

/// Runtime state of the delivery pipeline.
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
    /// The backends the upstream-notification source listens on, once it is
    /// installed: their live connections decide HTTP eligibility (MIK-7969).
    pub backends: std::sync::OnceLock<Arc<crate::backend::BackendRegistry>>,
    /// Set once the stored subscriptions have been reconciled with the
    /// catalogue the startup capability scan built; no attempt starts before.
    pub reconciled: AtomicBool,
    dropped: AtomicU64,
    projection_failed: AtomicU64,
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
            backends: std::sync::OnceLock::new(),
            reconciled: AtomicBool::new(false),
            dropped: AtomicU64::new(0),
            projection_failed: AtomicU64::new(0),
        }
    }

    /// An occurrence (or one subscription's record) was dropped.
    pub(crate) fn count_drop(&self) {
        let total = self.dropped.fetch_add(1, Ordering::Relaxed) + 1;
        tracing::warn!(dropped_total = total, "events: occurrence dropped");
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

    /// Start fan-out, the worker and the dead-letter sweep. Called once
    /// from the HTTP server; a second call finds the intake taken.
    pub(crate) fn start(self: &Arc<Self>, services: Services) {
        let Some(mut intake) = self.runtime.intake.lock().take() else {
            return;
        };
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
        // After a restart the upstream state is rebuilt from the store.
        let hub = Arc::clone(self);
        tokio::spawn(async move { hub.replay_starts().await });
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

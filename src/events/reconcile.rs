// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The reconcile step (Family-fix MIK-7940, design r3): a change posts a
//! cause, and one pass makes the stored rows, started keys and upstream work
//! match what the live inputs say each subscription should be.
//!
//! Backend-notification rows (design r3 D1a, D3): a row the backend source
//! no longer admits (its backend left the configuration, or it is an
//! upstream kind of a backend that turned ineligible) is withdrawn; the
//! source's `admits_now` is the one statement of that rule. Webhook and
//! REST-watch rows are held, never deleted, by the existing hold judgement
//! (D1b).

use std::sync::Arc;

use super::EventsHub;
use super::types::SourceKind;
use super::upstream::parse_name;

impl EventsHub {
    /// Reconcile backend `backend` after its registration or configuration
    /// changed: withdraw the rows it no longer admits, then stop the keys no
    /// live row holds and start the ones that now can (design r3 L2), so a
    /// re-added backend is listened to at once, not at the revive sweep.
    pub(crate) fn reconcile_backend(self: &Arc<Self>, backend: &str) {
        let Some(source) = self.source(SourceKind::BackendNotification) else {
            return;
        };
        // The judged rows themselves go to the delete, never a second
        // snapshot by name: a row re-made meanwhile is not one of them.
        let gone: Vec<_> = self
            .store
            .subscriptions()
            .into_iter()
            .filter(|sub| {
                parse_name(&sub.name).is_some_and(|(of, _)| of == backend)
                    && !source.admits_now(&sub.name)
            })
            .collect();
        if !gone.is_empty() {
            self.withdraw_rows(&gone);
        }
        let Ok(runtime) = tokio::runtime::Handle::try_current() else {
            return;
        };
        let hub = Arc::clone(self);
        runtime.spawn(async move {
            hub.reconcile_stops().await;
            hub.replay_starts_of(|kind| kind == SourceKind::BackendNotification)
                .await;
        });
    }

    /// The sweep's lifecycle half, every `SWEEP_EVERY` (design r3 L8): a
    /// safety net that no row relies on.
    pub(super) async fn sweep_lifecycle(&self) {
        // Gone subscriptions take their rate and failure state along.
        let held = self.store.live_subscription_ids(chrono::Utc::now());
        self.runtime.rates.retain(&held);
        self.runtime.failures.retain(&held);
        self.reconcile_stops().await;
        // After the stops, so freed slots are free: a watch key whose
        // capability is offered again (the startup scan finished, a reload
        // restored it) starts here, whatever changed the catalogue
        // (MIK-8053). Watch only: its start is local, while another source's
        // may reach a backend, and those are not retried every sweep.
        self.replay_starts_of(|kind| kind == SourceKind::RestWatch)
            .await;
    }

    /// Stop the keys of rows that expired since the last check, at the
    /// worker's tick rather than the sweep (design r3 D4, L5); expiry
    /// settlement still buries their records and removes the rows.
    pub(super) async fn stop_expired_keys(&self) {
        let now = chrono::Utc::now();
        let since = std::mem::replace(&mut *self.runtime.expiry_seen.lock(), now);
        if self.store.expired_between(since, now) {
            self.reconcile_stops().await;
        }
    }

    /// Stop the keys no live row holds and start those of `kind` that one
    /// now holds, in the background (design r3 G4a): callable from
    /// synchronous code, which never awaits a source.
    pub(super) fn reconcile_keys_soon(&self, kind: SourceKind) {
        let (Some(hub), Ok(runtime)) = (self.me.upgrade(), tokio::runtime::Handle::try_current())
        else {
            return;
        };
        runtime.spawn(async move {
            hub.reconcile_stops().await;
            hub.replay_starts_of(|of| of == kind).await;
        });
    }
}

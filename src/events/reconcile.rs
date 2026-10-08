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
        let gone: Vec<String> = self
            .store
            .subscriptions()
            .into_iter()
            .map(|sub| sub.name)
            .filter(|name| {
                parse_name(name).is_some_and(|(of, _)| of == backend) && !source.admits_now(name)
            })
            .collect();
        if !gone.is_empty() {
            self.withdraw(&gone);
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
}

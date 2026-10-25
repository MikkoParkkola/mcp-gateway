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
        // A key started while the backend could not be listened to is parked
        // in the listeners; wake it now, not at the revive sweep.
        source.backend_changed(backend);
        let Ok(runtime) = tokio::runtime::Handle::try_current() else {
            return;
        };
        let hub = Arc::clone(self);
        let backend = backend.to_owned();
        runtime.spawn(async move {
            hub.revoke_unobservable(Some(&backend)).await;
            hub.revoke_inadmissible(Some(&backend)).await;
            hub.reconcile_stops().await;
            hub.replay_starts_of(|kind| kind == SourceKind::BackendNotification)
                .await;
        });
    }

    /// Revoke (`-32012`) every row of `backend` (every backend when `None`)
    /// whose observation can no longer be had: its backend's identity config
    /// is not the one it was observed under, the backend moved between shared
    /// and per-user, or its identity is gone. Such a row is never re-keyed
    /// silently; its key then stops, which wipes its lease.
    pub(crate) async fn revoke_unobservable(self: &Arc<Self>, backend: Option<&str>) {
        let Some(services) = self.runtime.services.get() else {
            return;
        };
        let config = services.live.get();
        let stale: Vec<_> = self
            .store
            .subscriptions()
            .into_iter()
            .filter(|sub| {
                parse_name(&sub.name).is_some_and(|(of, _)| {
                    backend.is_none_or(|b| b == of)
                        && super::observation::observe_row(&config, of, sub).is_err()
                })
            })
            .collect();
        for sub in stale {
            self.revoke(&sub).await;
        }
    }

    /// Revoke (`-32012`) every per-user row of `backend` (every backend when
    /// `None`) whose subscriber's credential no longer passes admission:
    /// its listener stops and its lease is wiped, rather
    /// than observing until its next delivery. A refusal the clock may have
    /// caused keeps the row.
    pub(crate) async fn revoke_inadmissible(self: &Arc<Self>, backend: Option<&str>) {
        let Some(services) = self.runtime.services.get() else {
            return;
        };
        let rows: Vec<_> = self
            .store
            .subscriptions()
            .into_iter()
            .filter(|sub| sub.obs_basis.is_some())
            .filter(|sub| {
                parse_name(&sub.name).is_some_and(|(of, _)| backend.is_none_or(|b| b == of))
            })
            .collect();
        for sub in rows {
            let grant = parse_name(&sub.name).map(|(of, _)| of.to_owned());
            if services.admission(&sub, grant.as_deref()).await
                == super::services::AccessVerdict::Refuses
            {
                self.revoke(&sub).await;
            }
        }
    }

    /// The sweep's lifecycle half, every `SWEEP_EVERY` (design r3 L8): a
    /// safety net that no row relies on.
    pub(super) async fn sweep_lifecycle(&self) {
        // Gone subscriptions take their rate and failure state along; on a
        // clock that cannot be read (before 1970) nothing is pruned this pass
        // (MIK-8202).
        if let Ok(now) = crate::clock::utc_now() {
            let held = self.store.live_subscription_ids(now);
            self.runtime.rates.retain(&held);
            self.runtime.failures.retain(&held);
        }
        if let Ok(now) = crate::clock::unix_secs() {
            self.leases.wipe_expired(now).await;
        }
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
        // No lapse is judged and the watermark does not move on a clock that
        // cannot be read (before 1970); the stop it would trigger refuses on
        // that clock anyway (MIK-8202).
        let Ok(now) = crate::clock::utc_now() else {
            return;
        };
        let (lapsed, removed) = {
            let mut seen = self.runtime.expiry_seen.lock();
            let removals = self.store.removals();
            let generation = self.store.generation_now();
            let removed = removals != seen.removals;
            // A deadline can only lapse once due, or appear with a write;
            // otherwise no row needs looking at this tick.
            let scan = removed
                || generation != seen.generation
                || seen.next.is_some_and(|next| next <= now);
            let lapsed = if scan {
                let (lapsed, next, _) = self.store.lapses(seen.at, now);
                seen.next = next;
                seen.generation = generation;
                lapsed
            } else {
                false
            };
            seen.at = now;
            seen.removals = removals;
            (lapsed, removed)
        };
        // A row that expired, whose hold lapsed, or that any path removed
        // since the last tick no longer holds its key.
        if lapsed || removed {
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

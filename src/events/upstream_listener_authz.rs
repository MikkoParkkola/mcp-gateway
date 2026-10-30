// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! What a listener answers about a key: its verdict and snapshot, whether it
//! may run or is over budget, and whether a URI is authorized. Moved from
//! `upstream_listener.rs` for the file-size ceiling.

use super::{FAILED_LOOKUP, ListenerKey, MAX_PER_USER_LISTENERS, UpstreamListeners};
use crate::events::types::RpcError;
use crate::events::upstream_need::Verdict;

impl UpstreamListeners {
    /// What the backend's last good catalogue read says about `uri`;
    /// `Skip` while no listener holds one.
    pub(crate) fn verdict(&self, key: &ListenerKey, uri: &str, granted: Option<u64>) -> Verdict {
        self.answering(key).map_or(Verdict::Skip, |s| {
            s.snapshot.lock().verdict_for(uri, granted)
        })
    }

    /// Whether a listener task holds a good snapshot for `backend`.
    pub(crate) fn has_snapshot(&self, key: &ListenerKey) -> bool {
        self.answering(key)
            .is_some_and(|s| s.snapshot.lock().is_known())
    }

    /// Whether listener `key` may run now: a passthrough subscriber's
    /// listener only while they hold a lease (E2, E7). Until then it stays
    /// parked, counted with no task, and sends nothing.
    pub(crate) fn may_run(&self, key: &ListenerKey) -> bool {
        let Some(obs) = &key.obs else {
            return true;
        };
        let passthrough = self.live_config().is_some_and(|config| {
            super::super::observation::binding(&config, &key.backend).is_some_and(|b| {
                b.basis.strategy
                    == crate::identity_propagation::PropagationStrategyKind::Passthrough
            })
        });
        !passthrough
            || self.hub().is_some_and(|hub| {
                hub.leases.is_held(&super::super::lease::LeaseKey {
                    backend: key.backend.clone(),
                    obs: obs.clone(),
                })
            })
    }

    /// Whether a per-user listener `key` would be one past the backend's
    /// budget: a new one when [`MAX_PER_USER_LISTENERS`] already run.
    pub(crate) fn over_budget(&self, key: &ListenerKey) -> bool {
        if key.obs.is_none() {
            return false;
        }
        let map = self.backends.lock();
        !map.contains_key(key)
            && map
                .keys()
                .filter(|k| k.backend == key.backend && k.obs.is_some())
                .count()
                >= MAX_PER_USER_LISTENERS
    }

    /// Whether listener `key` still counts any interest.
    pub(crate) fn holds(&self, key: &ListenerKey) -> bool {
        self.backends
            .lock()
            .get(key)
            .is_some_and(|shared| !shared.need.lock().is_empty())
    }

    /// Whether a registered backend called `name` exists.
    pub(crate) fn knows(&self, name: &str) -> bool {
        #[allow(
            clippy::disallowed_methods,
            reason = "Background: the events source watches backends; no caller request"
        )]
        self.registry.get(name).is_some()
    }

    /// May `uri` be watched on `backend`? A listener's good snapshot
    /// answers; with none (subscribe time) the catalogue is read, filling
    /// it, and a backend that cannot be read admits (design §7, offline
    /// rule). `-32012` only on confirmed absence from a complete read.
    /// `granted` is the subscription's incarnation when one exists (a
    /// delivery), `None` at subscribe: a snapshot does not revoke a grant
    /// made after its read began.
    pub(crate) async fn authorize_uri(
        &self,
        key: &ListenerKey,
        uri: &str,
        granted: Option<u64>,
    ) -> Result<(), RpcError> {
        if self.has_snapshot(key) {
            return match self.verdict(key, uri, granted) {
                Verdict::Revoke => Err(RpcError::forbidden()),
                Verdict::Deliver | Verdict::Skip => Ok(()),
            };
        }
        // A per-user listener's catalogue is read only as its subscriber, by
        // its own task: a read here would be the gateway's, so it admits, as
        // a backend that cannot be read does.
        if key.obs.is_some() {
            return Ok(());
        }
        let backend = key.backend.as_str();
        #[allow(
            clippy::disallowed_methods,
            reason = "Background: the events source watches backends; no caller request"
        )]
        let Some(found) = self.registry.get(backend) else {
            return Ok(());
        };
        // A delivery attempt that already waited on a lookup that failed does
        // not wait again: it gets the verdict that failure gave.
        if FAILED_LOOKUP
            .try_with(std::cell::Cell::get)
            .unwrap_or(false)
        {
            return Ok(());
        }
        let read = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            found.read_resource_snapshot(false),
        )
        .await;
        match read {
            Ok(Ok(snapshot)) if snapshot.complete && !snapshot.uris.contains(uri) => {
                // A cached list may predate the grant: an absence
                // is confirmed by a read begun now, after it, before revoking.
                if granted.is_none() {
                    return Err(RpcError::forbidden());
                }
                if !self.may_confirm(key) {
                    return Ok(());
                }
                match tokio::time::timeout(
                    std::time::Duration::from_secs(10),
                    found.read_resource_snapshot(true),
                )
                .await
                {
                    Ok(Ok(now)) if now.complete && !now.uris.contains(uri) => {
                        Err(RpcError::forbidden())
                    }
                    Ok(Ok(_)) => Ok(()),
                    // A failed confirm counts like the first lookup's failure:
                    // the attempt does not wait on the catalogue again.
                    _ => {
                        let _ = FAILED_LOOKUP.try_with(|failed| failed.set(true));
                        Ok(())
                    }
                }
            }
            Ok(Ok(_)) => Ok(()),
            // An error is not absence (§7): admitted, as before.
            _ => {
                let _ = FAILED_LOOKUP.try_with(|failed| failed.set(true));
                Ok(())
            }
        }
    }
}

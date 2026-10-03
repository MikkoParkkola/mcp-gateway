// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! One listener task per backend that has live upstream-notification
//! subscriptions (MIK-7630 I5 design §5). This file owns the map and the
//! counted interest; the task's connection logic is `upstream_session`.
//!
//! Nothing here reaches `SubscriptionRegistry`: upstream notifications go
//! only to `EventsHub::emit`, so a downstream `subscriptions/listen` client
//! never sees them (§7).

use std::collections::HashMap;
use std::sync::{Arc, Weak};

use parking_lot::Mutex;
use tokio::sync::watch;
use tokio_util::sync::CancellationToken;

use super::EventsHub;
use super::types::RpcError;
use super::upstream_need::{Full, Interest, Need, Snapshot, Verdict};
use crate::backend::BackendRegistry;

/// What one backend's task and the event source share.
pub(super) struct Shared {
    pub name: String,
    pub need: Mutex<Need>,
    pub snapshot: Mutex<Snapshot>,
    /// Bumped on every change of the upstream filter.
    pub wake: watch::Sender<u64>,
    pub stop: CancellationToken,
}

/// The per-backend listeners of one hub.
pub(crate) struct UpstreamListeners {
    registry: Arc<BackendRegistry>,
    hub: Weak<EventsHub>,
    backends: Mutex<HashMap<String, Arc<Shared>>>,
    stop: CancellationToken,
}

impl Drop for UpstreamListeners {
    fn drop(&mut self) {
        self.stop.cancel();
    }
}

impl UpstreamListeners {
    pub(crate) fn new(registry: Arc<BackendRegistry>, hub: Weak<EventsHub>) -> Arc<Self> {
        Arc::new(Self {
            registry,
            hub,
            backends: Mutex::new(HashMap::new()),
            stop: CancellationToken::new(),
        })
    }

    /// Count one more live key for `backend`, starting its task when it is
    /// the first.
    ///
    /// # Errors
    /// [`Full`] when the backend's URI budget is spent.
    pub(crate) fn add(&self, backend: &str, interest: &Interest) -> Result<(), Full> {
        let mut map = self.backends.lock();
        let shared = Arc::clone(
            map.entry(backend.to_owned())
                .or_insert_with(|| self.start(backend)),
        );
        let outcome = shared.need.lock().add(interest);
        match outcome {
            Ok(true) => shared.wake.send_modify(|n| *n += 1),
            Ok(false) => {}
            Err(full) => {
                if shared.need.lock().is_empty() {
                    shared.stop.cancel();
                    map.remove(backend);
                }
                return Err(full);
            }
        }
        Ok(())
    }

    /// Count one key fewer; the last one stops the task.
    pub(crate) fn remove(&self, backend: &str, interest: &Interest) {
        let mut map = self.backends.lock();
        let Some(shared) = map.get(backend).cloned() else {
            return;
        };
        let changed = shared.need.lock().remove(interest);
        if shared.need.lock().is_empty() {
            shared.stop.cancel();
            map.remove(backend);
        } else if changed {
            shared.wake.send_modify(|n| *n += 1);
        }
    }

    /// What the backend's last good catalogue read says about `uri`;
    /// `Skip` while no listener holds one.
    pub(crate) fn verdict(&self, backend: &str, uri: &str) -> Verdict {
        self.backends
            .lock()
            .get(backend)
            .map_or(Verdict::Skip, |s| s.snapshot.lock().verdict(uri))
    }

    /// Whether a listener task holds a good snapshot for `backend`.
    pub(crate) fn has_snapshot(&self, backend: &str) -> bool {
        self.backends
            .lock()
            .get(backend)
            .is_some_and(|s| s.snapshot.lock().is_known())
    }

    /// Whether a registered backend called `name` exists.
    pub(crate) fn knows(&self, name: &str) -> bool {
        self.registry.get(name).is_some()
    }

    /// May `uri` be watched on `backend`? A listener's good snapshot
    /// answers; with none (subscribe time) the catalogue is read, filling
    /// it, and a backend that cannot be read admits (design §7, offline
    /// rule). `-32012` only on confirmed absence from a complete read.
    pub(crate) async fn authorize_uri(&self, backend: &str, uri: &str) -> Result<(), RpcError> {
        if self.has_snapshot(backend) {
            return match self.verdict(backend, uri) {
                Verdict::Revoke => Err(RpcError::forbidden()),
                Verdict::Deliver | Verdict::Skip => Ok(()),
            };
        }
        let Some(found) = self.registry.get(backend) else {
            return Ok(());
        };
        let read = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            found.read_resource_snapshot(false),
        )
        .await;
        match read {
            Ok(Ok(snapshot)) if snapshot.complete && !snapshot.uris.contains(uri) => {
                Err(RpcError::forbidden())
            }
            _ => Ok(()),
        }
    }

    fn start(&self, backend: &str) -> Arc<Shared> {
        let (wake, _) = watch::channel(0);
        let shared = Arc::new(Shared {
            name: backend.to_owned(),
            need: Mutex::new(Need::default()),
            snapshot: Mutex::new(Snapshot::default()),
            wake,
            stop: self.stop.child_token(),
        });
        tokio::spawn(super::upstream_session::run(
            Arc::clone(&shared),
            Arc::clone(&self.registry),
            self.hub.clone(),
        ));
        shared
    }
}

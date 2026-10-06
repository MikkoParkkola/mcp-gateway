// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The events listener's reach into a backend (MIK-7630 I5 design §5): the
//! one place `src/events` touches this module, so no backend item's
//! visibility widens. Everything runs on the shared slot.

use std::collections::HashSet;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Weak};

use futures::FutureExt;
use futures::future::{BoxFuture, Shared};
use serde_json::json;

use super::Backend;
use super::pool::{ActivityGuard, PoolKey};
use crate::protocol::era::Era;
use crate::transport::upstream_tap::UpstreamListen;
use crate::{Error, Result};

/// A weak, stream-capable view of one slot's transport.
pub(crate) type ListenHandle = Weak<dyn UpstreamListen>;

/// The handle for `transport`, as the slot stores it.
pub(super) fn handle_of<T: UpstreamListen + 'static>(
    transport: &std::sync::Arc<T>,
) -> ListenHandle {
    let strong: std::sync::Arc<dyn UpstreamListen> = transport.clone();
    std::sync::Arc::downgrade(&strong)
}

/// While held, the idle reaper leaves the shared slot's transport alone
/// without the idle clock moving (design §5, D5).
pub(crate) struct ListenLease(#[allow(dead_code, reason = "held for its Drop")] ActivityGuard);

/// A stream-capable handle on the shared slot's transport, and the era the
/// peer was last seen to speak. The `Weak` never counts toward the strong
/// count a restart waits on; the listener upgrades it per call only.
pub(crate) struct ListenTarget {
    pub handle: Weak<dyn UpstreamListen>,
    pub era: Era,
}

/// The admitted start a subscribe runs to learn the HTTP transport, shared
/// by every subscribe waiting on it; `true` when the slot started.
pub(super) type Resolution = Shared<BoxFuture<'static, bool>>;

/// The backend's last read resource URIs, and whether the read can be
/// trusted as the whole catalogue.
pub(crate) struct ResourceSnapshot {
    pub uris: HashSet<String>,
    pub complete: bool,
}

impl Backend {
    /// Take the idle lease; hold it while a stream is open.
    pub(crate) fn listen_lease(&self) -> ListenLease {
        ListenLease(self.begin_internal_activity())
    }

    /// Start the shared slot if it is stopped and return its stream handle.
    ///
    /// # Errors
    /// The backend cannot start, or its transport has no stream support.
    pub(crate) async fn listen_target(&self) -> Result<ListenTarget> {
        // The transport itself is dropped at once: only the `Weak` leaves.
        drop(self.ensure_entry_started(&PoolKey::Shared).await?);
        let handle = self
            .shared_entry()
            .listen
            .read()
            .clone()
            .ok_or_else(|| Error::Transport("transport has no event stream".to_owned()))?;
        // An unresolved era is not read as legacy: a modern peer mid
        // re-probe would be sent a legacy GET (MIK-7899 CLASS.3).
        let era = self
            .era
            .settled()
            .await
            .ok_or_else(|| Error::Transport("era not resolved".to_owned()))?;
        Ok(ListenTarget { handle, era })
    }

    /// Whether `handle` still names the shared slot's current transport.
    pub(crate) fn listens_on(&self, handle: &Weak<dyn UpstreamListen>) -> bool {
        self.shared_entry()
            .listen
            .read()
            .as_ref()
            .is_some_and(|current| Weak::ptr_eq(current, handle))
    }

    /// The HTTP transport the shared slot's live connection detected (see
    /// [`UpstreamListen::detected_streamable`]); `None` while the slot holds
    /// no transport, or before the one it holds has published its handle.
    pub(crate) fn connected_streamable(&self) -> Option<bool> {
        let entry = self.shared_entry();
        let installed = entry.transport.read();
        let installed = installed.as_ref()?;
        let handle = entry.listen.read().as_ref()?.upgrade()?;
        // A handle left by a stopped or replaced transport names another
        // allocation: only the installed transport's answer counts.
        std::ptr::addr_eq(Arc::as_ptr(installed), Arc::as_ptr(&handle))
            .then(|| handle.detected_streamable())
            .flatten()
    }

    /// Install `transport` in the shared slot as a start publishes one.
    #[cfg(test)]
    pub(crate) fn install_http_for_test(&self, transport: &Arc<crate::transport::HttpTransport>) {
        let entry = self.shared_entry();
        let erased: Arc<dyn crate::transport::Transport> = Arc::clone(transport) as _;
        *entry.transport.write() = Some(erased);
        *entry.listen.write() = Some(handle_of(transport));
    }

    /// Start the shared slot as a client request would, so an events
    /// subscribe can learn the HTTP transport (MIK-7969), and wait for it at
    /// most the backend timeout. `true` when the slot started.
    ///
    /// One start runs per backend however many subscribes wait. It is a
    /// spawned task, so a subscribe that stops waiting never cancels it: it
    /// settles, and is counted, under its own handling.
    pub(crate) async fn resolve_for_events(self: &Arc<Self>) -> bool {
        let resolution = {
            let mut running = self.events_resolution.lock();
            if let Some(resolution) = running.as_ref() {
                resolution.clone()
            } else {
                let backend = Arc::clone(self);
                #[cfg(test)]
                self.events_resolutions.fetch_add(1, Ordering::SeqCst);
                let task = tokio::spawn(async move {
                    let started = backend
                        .admitted_start()
                        .await
                        .inspect_err(|error| {
                            tracing::debug!(backend = %backend.name, %error, "events: start failed");
                        })
                        .is_ok();
                    // Held while this one was stored, so it is this one cleared.
                    *backend.events_resolution.lock() = None;
                    started
                });
                let resolution = async move { task.await.unwrap_or(false) }.boxed().shared();
                *running = Some(resolution.clone());
                resolution
            }
        };
        tokio::time::timeout(self.config.timeout, resolution)
            .await
            .unwrap_or(false)
    }

    /// The start a client request runs, without the request: the slot's
    /// admission (an open circuit or a rate limit refuses), then the start,
    /// whose failure the slot counts (`start_recorded`).
    async fn admitted_start(&self) -> Result<()> {
        let key = PoolKey::Shared;
        self.pooled_entry(&key)?.failsafe.admit(&self.name)?;
        let activity = self.begin_activity(&key)?;
        let entry = Arc::clone(activity.entry());
        self.start_recorded(&key, &entry, std::time::Instant::now())
            .await
            .map(drop)
    }

    /// Read the shared resource catalogue; `fresh` discards the cached list
    /// first so the read reaches the backend (after a `list_changed`).
    ///
    /// # Errors
    /// The backend cannot start or `resources/list` fails; the caller keeps
    /// its previous snapshot.
    pub(crate) async fn read_resource_snapshot(&self, fresh: bool) -> Result<ResourceSnapshot> {
        if fresh {
            self.shared_entry().resources_cache.invalidate_if(|_| true);
        }
        let resources = self.get_resources_for_binding(None, &[]).await?;
        Ok(ResourceSnapshot {
            // A read cut by the page cap proves nothing about absence (§7).
            complete: !self
                .shared_entry()
                .resources_truncated
                .load(Ordering::SeqCst),
            uris: resources.iter().map(|r| r.uri.clone()).collect(),
        })
    }

    /// The backend told us its tool list changed: drop the shared slot's
    /// cached list, so the re-read a `tools_changed` subscriber does next
    /// reaches the backend instead of the old list (§14).
    pub(crate) fn invalidate_tools(&self) {
        let entry = self.shared_entry();
        entry.tools_cache.invalidate_if(|_| true);
        // Derived from the list just dropped; a stale set would keep
        // permitting a resend for a tool that is no longer read-only.
        entry.resend_permitted.write().clear();
    }

    /// Test-only: fill the shared slot's tool list, as a reader's read does.
    #[cfg(test)]
    pub(crate) async fn fill_tools_for_test(&self) {
        let ttl = std::time::Duration::from_secs(300);
        self.shared_entry()
            .tools_cache
            .get_or_fetch_shared(ttl, || async { Ok(Vec::new()) })
            .await
            .expect("fill");
    }

    /// `resources/subscribe` or `resources/unsubscribe` for `uri` on the
    /// legacy channel. `Ok(false)` when the peer answers method-not-found:
    /// that backend's resource interest is unsupported (§3).
    ///
    /// # Errors
    /// The request failed or the peer answered another error.
    pub(crate) async fn legacy_resource_interest(
        &self,
        uri: &str,
        subscribe: bool,
    ) -> Result<bool> {
        let method = if subscribe {
            "resources/subscribe"
        } else {
            "resources/unsubscribe"
        };
        let answer = self.request(method, Some(json!({ "uri": uri }))).await?;
        match answer.error {
            None => Ok(true),
            Some(error) if error.code == -32601 => Ok(false),
            Some(error) => Err(Error::json_rpc(error.code, error.message)),
        }
    }
}

#[cfg(test)]
#[path = "listen_tests.rs"]
mod tests;

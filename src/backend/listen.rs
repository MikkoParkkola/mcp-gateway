// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The events listener's reach into a backend (MIK-7630 I5 design §5): the
//! one place `src/events` touches this module, so no backend item's
//! visibility widens. Everything runs on the shared slot.

use std::collections::HashSet;
use std::sync::Weak;
use std::sync::atomic::Ordering;

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
    pub era: Option<Era>,
}

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
        Ok(ListenTarget {
            handle,
            era: self.cached_era().await,
        })
    }

    /// Whether `handle` still names the shared slot's current transport.
    pub(crate) fn listens_on(&self, handle: &Weak<dyn UpstreamListen>) -> bool {
        self.shared_entry()
            .listen
            .read()
            .as_ref()
            .is_some_and(|current| Weak::ptr_eq(current, handle))
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

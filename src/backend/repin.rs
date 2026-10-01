// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Publishing a started transport, and retiring the ones a later destination
//! stamp makes stale (MIK-7700).

use std::sync::Arc;

use tracing::warn;

use super::Backend;
use super::pool::PooledEntry;
use crate::transport::Transport;

impl Backend {
    /// Make `transport` reachable in `entry`, unless shutdown has latched or
    /// the destination policy changed after it was built under `built_under`.
    ///
    /// Both checks and the publish run under the cleanup lock that `stop()`
    /// and [`Self::retire_started_transports`] take, so a transport is either
    /// published before they walk the pool, and they take it, or refused.
    pub(super) fn publish(
        &self,
        entry: &PooledEntry,
        transport: &Arc<dyn Transport>,
        built_under: crate::security::ssrf::DestinationPolicy,
    ) -> std::result::Result<(), &'static str> {
        let cleanups = self.replaced_transport_cleanups.lock();
        if cleanups.stopping {
            return Err("the backend shut down while it was starting");
        }
        if self.destination_bound() && self.destination() != built_under {
            return Err("the destination policy changed while it was starting");
        }
        *entry.transport.write() = Some(Arc::clone(transport));
        Ok(())
    }

    /// Take every started transport out of the pool and close it, so the
    /// next use rebuilds under the current destination policy (MIK-7700).
    ///
    /// Closed at once, not when the last holder lets go: a request or stream
    /// still running on a retired transport is on an unpinned connection, and
    /// pinning outranks it. Such a request fails and its retry rebuilds.
    pub(crate) fn retire_started_transports(&self) {
        let retired: Vec<Arc<dyn Transport>> = {
            let _cleanups = self.replaced_transport_cleanups.lock();
            self.pool
                .iter()
                .filter_map(|entry| entry.value().transport.write().take())
                .collect()
        };
        if retired.is_empty() {
            return;
        }
        warn!(
            backend = %self.name,
            count = retired.len(),
            "Closing transports started before the destination policy was set"
        );
        // Closing is async. Without a runtime the handles are dropped here:
        // an HTTP or WebSocket transport holds no child process, and its
        // connections close with it.
        let Ok(runtime) = tokio::runtime::Handle::try_current() else {
            warn!(backend = %self.name, "No runtime: retired transports dropped, not closed");
            return;
        };
        let name = self.name.clone();
        let handle = runtime.spawn(async move {
            for old in retired {
                if let Err(error) = old.close().await {
                    warn!(backend = %name, %error, "Retired transport failed to close cleanly");
                }
            }
        });
        // Tracked like a replaced transport's close, so `stop()` drains it.
        let mut pending = self.replaced_transport_cleanups.lock();
        pending.handles.retain(|h| !h.is_finished());
        pending.handles.push(handle);
    }
}

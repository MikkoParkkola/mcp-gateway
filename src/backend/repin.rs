// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Publishing a started transport: refused once shutdown latched, or once a
//! destination stamp landed after it was built (MIK-7700).

use std::sync::Arc;

use super::Backend;
use super::pool::PooledEntry;
use crate::transport::Transport;

impl Backend {
    /// Make `transport` reachable in `entry`, unless shutdown has latched or
    /// the destination policy changed after it was built under `built_under`.
    ///
    /// Both checks and the publish run under the cleanup lock `stop()` takes,
    /// so a transport is either published before it walks the pool, and it
    /// takes it, or refused. A start that read no policy and finishes after a
    /// pairing stamped one is refused here rather than published unpinned.
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
}

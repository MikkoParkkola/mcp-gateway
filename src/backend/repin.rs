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
    ///
    /// The listen handle goes in first, so a reader that sees the transport
    /// always sees its event stream (MIK-7897 LIFE.3a).
    ///
    /// `on_publish` runs after both checks pass and just before the slot write,
    /// in the same synchronous step, and what it returns is held until the
    /// write is done: a build-first start installs its candidate's era there
    /// and returns the era lock, so the new transport is never reachable with
    /// the old verdict, no writer can change the verdict before the transport
    /// lands, and a refused publish installs nothing (MIK-8012, MIK-8218).
    pub(super) fn publish<Held>(
        &self,
        entry: &PooledEntry,
        (transport, listen): (&Arc<dyn Transport>, Option<super::listen::ListenHandle>),
        built_under: crate::security::ssrf::DestinationPolicy,
        on_publish: impl FnOnce() -> Held,
    ) -> std::result::Result<(), &'static str> {
        let cleanups = self.replaced_transport_cleanups.lock();
        if cleanups.stopping {
            return Err("the backend shut down while it was starting");
        }
        if self.destination_bound() && self.destination() != built_under {
            return Err("the destination policy changed while it was starting");
        }
        let held = on_publish();
        #[cfg(test)]
        if let Some(between) = self.between_install_and_write.lock().take() {
            between();
        }
        *entry.listen.write() = listen;
        // The verdict a reader of the slot will see the instant the transport
        // lands in it, read before the write so nothing after it can mask it.
        #[cfg(test)]
        self.era_at_publish.lock().push(entry.era.cached_now());
        *entry.transport.write() = Some(Arc::clone(transport));
        drop(held);
        Ok(())
    }
}

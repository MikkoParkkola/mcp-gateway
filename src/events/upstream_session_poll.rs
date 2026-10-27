// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! An A2A backend's `tools_changed` (MIK-8835.A2A.2). A2A carries no MCP
//! notifications, so the listener re-reads the backend's tools through the
//! calls' own discovery path at the catalogue snapshot interval. Each list the
//! shared slot stores nudges the F24 drain (`gateway/server/tools_changed.rs`),
//! which compares the whole serialized tool list with what it last announced
//! and announces only a difference: an unchanged card stays silent, and a
//! failed read stores nothing.

use std::sync::{Arc, Weak};

use tracing::debug;

use super::{Outcome, end_ineligible, snapshot_interval};
use crate::backend::Backend;
use crate::events::EventsHub;
use crate::events::upstream_listener::Shared;

/// Poll until stopped, or until the backend is refused or replaced.
pub(super) async fn poll(
    shared: &Arc<Shared>,
    backend: &Arc<Backend>,
    hub: &Weak<EventsHub>,
    registry: &crate::backend::BackendRegistry,
) -> Outcome {
    // A per-user A2A listener has no credential-bearing read of its own: it
    // sends nothing rather than poll as the gateway.
    if shared.key.obs.is_some() {
        shared.stop.cancelled().await;
        return Outcome::Stopped;
    }
    loop {
        let ttl = backend.cache_ttl();
        let every = snapshot_interval(ttl);
        // A TTL past the snapshot ceiling would still hold the cached list at
        // the next poll, so that poll could never see a change.
        if ttl > every {
            backend.invalidate_tools();
        }
        if let Err(error) = backend.get_tools_shared().await {
            debug!(backend = %shared.name, error = %shared.error_text(&error), "upstream listener: A2A tools read failed");
        }
        tokio::select! {
            () = shared.stop.cancelled() => return Outcome::Stopped,
            () = tokio::time::sleep(every) => {}
        }
        if shared.is_ineligible() && end_ineligible(shared, hub).await {
            return Outcome::Stopped;
        }
        // A reload that replaced the backend restarts the task on the new one.
        #[allow(
            clippy::disallowed_methods,
            reason = "Background: the events source watches backends; no caller request"
        )]
        let current = registry.get(&shared.name);
        if current.is_none_or(|now| !Arc::ptr_eq(&now, backend)) {
            return super::failed();
        }
    }
}

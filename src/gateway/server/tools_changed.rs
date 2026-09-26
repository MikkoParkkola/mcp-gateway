// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Every change to the tool set reaches `announce_tools_changed` (F24).
//!
//! The HTTP server advertises `tools.listChanged: true`, so every path that
//! changes the tool set has to announce. They all feed one channel:
//! `BackendRegistry::register` and `remove` (config reload, and the admin UI's
//! add and remove, which reload) and the capability file watcher. One drain
//! announces each, so no path can be forgotten and none announces twice.

use std::sync::Arc;

use crate::gateway::router::AppState;

/// Announce every name sent on `rx` to both eras' listeners, until the senders go.
pub(super) fn spawn_drain(
    state: Arc<AppState>,
    mut rx: tokio::sync::mpsc::UnboundedReceiver<String>,
) {
    tokio::spawn(async move {
        while let Some(backend) = rx.recv().await {
            state.announce_tools_changed(&backend).await;
        }
    });
}

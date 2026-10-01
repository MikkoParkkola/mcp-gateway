// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Start the MCP Events hub (MIK-7630) for the HTTP server.

use std::sync::Arc;

use super::expand_home_path;
use crate::Result;
use crate::config::Config;
use crate::gateway::meta_mcp::MetaMcp;
use crate::gateway::WebhookRegistry;

/// Open the events store and install the hub on `meta_mcp` when
/// `events.enabled`; webhook routes become a source when webhooks are on.
/// A store that cannot be opened stops startup, like the task store.
pub(super) fn install(
    config: &Config,
    meta_mcp: &MetaMcp,
    webhooks: &Arc<parking_lot::RwLock<WebhookRegistry>>,
) -> Result<()> {
    if !config.events.enabled {
        return Ok(());
    }
    let hub = crate::events::EventsHub::open(
        &config.events,
        &expand_home_path(&config.events.store_dir),
    )?;
    if config.webhooks.enabled {
        hub.set_webhook_registry(Arc::clone(webhooks));
    }
    meta_mcp.set_events(hub);
    Ok(())
}

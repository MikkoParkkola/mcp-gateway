// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Wire the webhook registry into the meta layer and start the MCP Events
//! hub (MIK-7630) for the HTTP server.

use std::sync::Arc;

use super::expand_home_path;
use crate::Result;
use crate::config::Config;
use crate::gateway::WebhookRegistry;
use crate::gateway::meta_mcp::MetaMcp;

/// Hand the webhook registry to `meta_mcp` (for `gateway_webhook_status`)
/// when webhooks are on; then, when `events.enabled`, open the events store
/// and install the hub, with webhook routes as a source when webhooks are
/// on, and start its delivery pipeline over the live config. A store that
/// cannot be opened stops startup, like the task store.
pub(super) fn install(
    config: &Config,
    meta_mcp: &MetaMcp,
    webhooks: &Arc<parking_lot::RwLock<WebhookRegistry>>,
    live_config: &Arc<crate::config_reload::LiveConfig>,
    credentials: crate::events::LiveCredentials,
) -> Result<()> {
    if config.webhooks.enabled {
        meta_mcp.set_webhook_registry(Arc::clone(webhooks));
    }
    if !config.events.enabled {
        return Ok(());
    }
    let store_dir = expand_home_path(&config.events.store_dir);
    let hub = crate::events::EventsHub::open(&config.events, &store_dir)?;
    if config.webhooks.enabled {
        hub.set_webhook_registry(Arc::clone(webhooks));
        webhooks.write().set_events(Arc::clone(&hub));
    }
    if config.events.sources.backend_notifications {
        let registry = meta_mcp.events_backend_registry();
        let capability = config
            .capabilities
            .enabled
            .then(|| config.capabilities.name.clone());
        hub.install_backend_source_with_upstream(
            Arc::new({
                let registry = Arc::clone(&registry);
                move || {
                    let mut names: Vec<String> =
                        registry.all().iter().map(|b| b.name.clone()).collect();
                    names.extend(capability.clone());
                    names
                }
            }),
            registry,
            crate::events::upstream_live_ineligible(Arc::clone(live_config)),
        );
    }
    if config.events.sources.operational {
        let source = hub.install_operational_source(
            &meta_mcp.kill_switch(),
            &meta_mcp.events_backend_registry(),
        );
        #[cfg(feature = "cost-governance")]
        if let Some(budget) = &meta_mcp.budget_enforcer {
            source.report_budgets(budget);
        }
        #[cfg(not(feature = "cost-governance"))]
        let _ = source;
    }
    if config.events.sources.schedule {
        hub.install_schedule_source(&store_dir);
    }
    hub.start(meta_mcp.events_services(Arc::clone(live_config), credentials));
    meta_mcp.set_events(hub);
    meta_mcp.reconcile_events_after_scan();
    Ok(())
}

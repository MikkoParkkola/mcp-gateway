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
    meta_mcp: &Arc<MetaMcp>,
    registry: &Arc<crate::backend::BackendRegistry>,
    webhooks: &Arc<parking_lot::RwLock<WebhookRegistry>>,
    live_config: &Arc<crate::config_reload::LiveConfig>,
    credentials: crate::events::LiveCredentials,
    counters: &Arc<crate::counters::CounterStore>,
) -> Result<()> {
    // The kill switch and breakers mark the charts in every events
    // configuration. Their observer slots are set once: when the operational
    // source is installed below it carries the markers, otherwise this does.
    // A mark keeps a server name only when it is configured, by the same
    // test the counters use. Weak: the kill switch the observer sits in is
    // the gateway's own.
    let markers = crate::events::Markers {
        store: Arc::clone(counters),
        known: {
            let meta = Arc::downgrade(meta_mcp);
            Arc::new(move |name: &str| meta.upgrade().is_some_and(|m| m.configured_server(name)))
        },
    };
    if !(config.events.enabled && config.events.sources.operational) {
        crate::events::install_marker_observers(&meta_mcp.kill_switch(), registry, markers.clone());
    }
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
        let registry = Arc::clone(registry);
        let capability = config
            .capabilities
            .enabled
            .then(|| config.capabilities.name.clone());
        hub.install_backend_source_with_listeners(
            Arc::new({
                let registry = Arc::clone(&registry);
                move || {
                    #[allow(
                        clippy::disallowed_methods,
                        reason = "Lifecycle: gateway startup, wiring or shutdown; no caller request"
                    )]
                    let mut names: Vec<String> =
                        registry.all().iter().map(|b| b.name.clone()).collect();
                    names.extend(capability.clone());
                    names
                }
            }),
            Arc::clone(&registry),
            crate::events::upstream_live_ineligible(Arc::clone(live_config), Arc::clone(&registry)),
            crate::events::upstream_listener_ineligible(Arc::clone(live_config), registry),
        );
    }
    if config.events.sources.operational {
        let source =
            hub.install_operational_source(&meta_mcp.kill_switch(), registry, Some(markers));
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
    // A per-user listener mints through the same audited path a call uses.
    // Weak: the hub never keeps the meta layer alive.
    hub.set_listener_mint(Arc::new(ListenerMint(Arc::downgrade(meta_mcp))));
    hub.start(meta_mcp.events_services(Arc::clone(live_config), credentials));
    meta_mcp.set_events(hub);
    meta_mcp.reconcile_events_after_scan();
    Ok(())
}

/// The events hub's way to mint a per-user listener's credential.
struct ListenerMint(std::sync::Weak<MetaMcp>);

#[async_trait::async_trait]
impl crate::events::ListenerMint for ListenerMint {
    async fn mint(
        &self,
        backend: &str,
        identity: &crate::key_server::oidc::VerifiedIdentity,
    ) -> Result<Vec<(String, String)>> {
        let meta = self
            .0
            .upgrade()
            .ok_or_else(|| crate::Error::Transport("gateway stopping".to_owned()))?;
        meta.mint_listener_credential(backend, identity).await
    }
}

#[cfg(test)]
#[path = "events_wiring_tests.rs"]
mod tests;

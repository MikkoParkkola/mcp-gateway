// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Self-contained steps of `Gateway::run`, each the right-hand side of one
//! `let` in `run`, moved verbatim and called at the same point (MIK-8144).

use std::sync::Arc;

use tracing::{debug, info, warn};

use super::Gateway;
use super::account_bindings;
use super::warmstart::WarmerGuard;
use crate::Result;
use crate::capability::{CapabilityBackend, CapabilityExecutor, CapabilityWatcher};
use crate::config_reload::{ConfigWatcher, IdentityGrantSink, LiveConfig};
use crate::gateway::meta_mcp::MetaMcp;
use crate::gateway::oauth::GatewayKeyPair;
use crate::gateway::streaming::NotificationMultiplexer;
use crate::gateway::webhooks::WebhookRegistry;
use crate::key_server::{KeyServer, store::spawn_reaper};

impl Gateway {
    #[allow(clippy::too_many_lines)]
    pub(super) async fn start_capability_watcher(
        &self,
        meta_mcp: &Arc<MetaMcp>,
        webhook_registry: &Arc<parking_lot::RwLock<WebhookRegistry>>,
        shutdown_tx: &tokio::sync::broadcast::Sender<()>,
    ) -> Result<Option<CapabilityWatcher>> {
        let step = if self.config.capabilities.enabled {
            // Declared synchronously, BEFORE the loader task is spawned: the
            // declared catalogue is what the capability registration boundary
            // checks against. Installation of the strategies themselves happens
            // below, still before this gateway serves.
            let account_strategies = meta_mcp.account_strategies();
            account_bindings::declare_account_descriptors(&self.config, &account_strategies);
            let executor = Arc::new(
                CapabilityExecutor::for_config(&self.config.capabilities)
                    .with_env(Arc::clone(&self.env))
                    .with_policy_epoch(Arc::clone(&meta_mcp.policy_epoch))
                    .with_account_strategies(account_strategies),
            );
            let cap_backend = Arc::new(CapabilityBackend::new(
                &self.config.capabilities.name,
                executor,
            ));
            // The scan below runs in the background; readiness waits on it.
            cap_backend.begin_initial_scan();
            meta_mcp.set_capabilities(Arc::clone(&cap_backend));

            let capability_dirs = self.config.capabilities.directories.clone();
            let capability_name = self.config.capabilities.name.clone();

            // Register watched directories synchronously BEFORE spawning the
            // async loader. The capability file watcher (started below at
            // CapabilityWatcher::start) reads `backend.watched_directories()`
            // at startup; if the spawned loader has not yet populated them,
            // the watcher logs "No capability directories to watch" and gives
            // up. Pre-registering closes that race so hot-reload works from
            // boot regardless of loader scheduling.
            cap_backend.register_directories(&capability_dirs);

            let cap_backend_for_load = Arc::clone(&cap_backend);
            let registry_for_load = Arc::clone(&self.backends);
            let webhook_registry_for_load = Arc::clone(webhook_registry);
            let webhooks_enabled = self.config.webhooks.enabled;

            // AN ACCOUNT-BOUND DEPLOYMENT SCANS BEFORE IT SERVES. The background
            // scan exists so a large directory does not delay the listener.
            // But when the configuration declares `accounts.descriptors`, the
            // scan is also the ADMISSION GATE that rejects a capability whose
            // `auth.account` names no declared descriptor or whose `auth.key`
            // is not that descriptor's `oauth:<provider>`
            // (`CapabilityBackend::register_capability`). Run concurrently, the
            // first requests would see a partial catalogue, so an account-bound
            // gateway completes the whole scan HERE, before `start` serves.
            let accounts_configured = self.config.accounts.as_ref().is_some_and(|accounts| {
                accounts.enabled
                    && accounts
                        .descriptors
                        .as_ref()
                        .is_some_and(|descriptors| !descriptors.is_empty())
            });

            let scan = async move {
                if !accounts_configured {
                    // Let the HTTP listener bind before large capability scans start.
                    CapabilityBackend::settle_before_initial_scan().await;
                }

                let mut total_caps = 0;
                // Every capability the account admission gate refused during the
                // INITIAL scan. A missing or unreadable optional directory is
                // NOT collected here — that stays benign, exactly as before.
                let mut refused: Vec<String> = Vec::new();
                for dir in &capability_dirs {
                    match cap_backend_for_load
                        .load_from_directory_reporting(dir)
                        .await
                    {
                        Ok(report) => {
                            total_caps += report.admitted;
                            debug!(directory = %dir, count = report.admitted, "Loaded capabilities");
                            refused.extend(report.rejected);
                        }
                        Err(e) => {
                            cap_backend_for_load.mark_initial_scan_failed(); // not fatal
                            debug!(directory = %dir, error = %e, "Failed to load capabilities");
                        }
                    }
                }

                if webhooks_enabled {
                    for cap in cap_backend_for_load.list_capabilities() {
                        if !cap.webhooks.is_empty() {
                            webhook_registry_for_load.write().register_capability(&cap);
                        }
                    }
                }

                // Readiness waits on this (MIK-7268), and clients served during the
                // scan hear of its catalogue; refusals are reported below.
                cap_backend_for_load.finish_initial_scan(&registry_for_load);
                if total_caps > 0 {
                    info!(capabilities = total_caps, name = %capability_name, "Capability backend ready");
                }

                if refused.is_empty() {
                    Ok(())
                } else {
                    Err(crate::Error::Config(format!(
                        "{} capabilit{} rejected by the account admission gate: {}",
                        refused.len(),
                        if refused.len() == 1 { "y" } else { "ies" },
                        refused.join("; ")
                    )))
                }
            };

            if accounts_configured {
                // Completed before serving, and its refusals are FATAL: an
                // invalid `auth.account` binding present at boot fails startup
                // rather than being logged behind a listener that is already
                // answering. A missing optional directory is still benign.
                scan.await?;
                info!("Capability scan completed before serving (accounts.descriptors configured)");
            } else {
                tokio::spawn(async move {
                    if let Err(error) = scan.await {
                        warn!(error = %error, "Capability scan reported refusals");
                    }
                });
            }

            cap_backend.spawn_listing_watch(Arc::clone(&self.backends), shutdown_tx.subscribe());
            // Start file watcher for hot-reload
            match CapabilityWatcher::start(
                Arc::clone(&cap_backend),
                shutdown_tx.subscribe(),
                Some(self.backends.catalogue_hook()),
            ) {
                Ok(w) => {
                    info!("Capability hot-reload enabled");
                    Some(w)
                }
                Err(e) => {
                    warn!(error = %e, "Failed to start capability watcher, hot-reload disabled");
                    None
                }
            }
        } else {
            None
        };
        Ok(step)
    }

    pub(super) fn start_key_server(
        &self,
        shutdown_tx: &tokio::sync::broadcast::Sender<()>,
    ) -> Result<Option<Arc<KeyServer>>> {
        let step = if self.config.key_server.enabled {
            let mut ks_config = self.config.key_server.clone();
            // Resolve admin token (expand env:VAR_NAME)
            ks_config.admin_token = ks_config.resolve_admin_token(self.env.startup())?;

            let cleanup_interval = std::time::Duration::from_secs(ks_config.cleanup_interval_secs);
            let ks = Arc::new(KeyServer::new(ks_config));

            spawn_reaper(
                Arc::clone(&ks.store),
                cleanup_interval,
                shutdown_tx.subscribe(),
            );

            info!(
                token_ttl_secs = self.config.key_server.token_ttl_secs,
                providers = self.config.key_server.oidc.len(),
                policies = self.config.key_server.policies.len(),
                "Key server enabled"
            );
            Some(ks)
        } else {
            None
        };
        Ok(step)
    }

    pub(super) fn webhook_routes(
        &self,
        webhook_registry: &Arc<parking_lot::RwLock<WebhookRegistry>>,
        multiplexer: &Arc<NotificationMultiplexer>,
    ) -> Option<axum::Router<()>> {
        if self.config.webhooks.enabled {
            info!(
                enabled = true,
                base_path = %self.config.webhooks.base_path,
                "Webhook receiver enabled"
            );
            Some(WebhookRegistry::create_dynamic_routes(
                Arc::clone(webhook_registry),
                Arc::clone(multiplexer),
            ))
        } else {
            None
        }
    }

    pub(super) fn start_config_watcher(
        &self,
        live_config: &Arc<LiveConfig>,
        identity_grant_sink: Option<Arc<IdentityGrantSink>>,
        capabilities: Option<Arc<crate::capability::CapabilityBackend>>,
        shutdown_tx: &tokio::sync::broadcast::Sender<()>,
        warmer: &WarmerGuard,
    ) -> Option<ConfigWatcher> {
        if let Some(path) = self.reload_path() {
            match ConfigWatcher::start_with_hook(
                path.clone(),
                Arc::clone(live_config),
                Arc::clone(&self.backends),
                &self.config,
                Arc::clone(&self.env),
                identity_grant_sink,
                capabilities,
                shutdown_tx.subscribe(),
                Some(warmer.hook()),
            ) {
                Ok(w) => {
                    info!(path = %path.display(), "Config hot-reload enabled");
                    Some(w)
                }
                Err(e) => {
                    warn!(error = %e, "Failed to start config watcher, hot-reload disabled");
                    None
                }
            }
        } else {
            None
        }
    }

    pub(super) fn generate_gateway_key_pair() -> GatewayKeyPair {
        match GatewayKeyPair::generate() {
            Ok(kp) => {
                info!(kid = %kp.key_info().kid, "Gateway RSA key pair generated (JWKS available at /.well-known/jwks.json)");
                kp
            }
            Err(e) => {
                warn!(error = %e, "Failed to generate gateway RSA key pair; JWKS will be empty");
                // Fallback: return a trivially unusable key pair that won't block startup.
                // This path should not occur on any normal platform.
                GatewayKeyPair::generate().unwrap_or_else(|_| {
                    // Last resort: produce a dummy pair (panics on catastrophic failure).
                    GatewayKeyPair::generate().expect("RSA key pair generation failed twice")
                })
            }
        }
    }

    pub(super) fn managed_recovery_adapters(&self) -> Vec<String> {
        self.config
            .tasks
            .recovery_adapters
            .iter()
            .filter(|name| self.backends.get(name).is_some())
            .cloned()
            .collect()
    }
}

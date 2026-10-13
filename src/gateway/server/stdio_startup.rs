// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Stdio startup catalogue installation.

use std::sync::Arc;

use tracing::debug;

use super::Gateway;
use super::account_bindings;
use super::warmstart::WarmerGuard;
use crate::Result;
use crate::capability::{CapabilityBackend, CapabilityExecutor};
use crate::config_reload::{IdentityGrantSink, LiveConfig, ReloadContext};
use crate::gateway::meta_mcp::MetaMcp;
use crate::gateway::oauth::GatewayKeyPair;

const PARENT_TARGET: &str = "mcp_gateway::gateway::server::stdio_loop";

impl Gateway {
    pub(super) async fn install_stdio_startup_catalogue(
        &self,
        meta_mcp: &Arc<MetaMcp>,
        grant_sink: &Option<Arc<IdentityGrantSink>>,
        warmer: &WarmerGuard,
    ) -> Result<()> {
        // Account strategies must exist before stdio can admit a request, just
        // as they do before the HTTP listener starts serving.
        if self.config.accounts.is_some() {
            let gateway_key_pair = Arc::new(GatewayKeyPair::generate().map_err(|error| {
                crate::Error::Config(format!(
                    "stdio account signing key generation failed: {error}"
                ))
            })?);
            let account_custody = self.custody.as_ref().map(|custody| {
                Arc::clone(custody) as Arc<dyn crate::personal_accounts::AccountCustody>
            });
            account_bindings::install_account_strategies(
                &self.config,
                account_custody.as_ref(),
                &gateway_key_pair,
                &meta_mcp,
                account_bindings::ServeMode::Stdio,
            )?;
        }

        if self.config.capabilities.enabled {
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
            let mut refused = Vec::new();
            for dir in &self.config.capabilities.directories {
                match cap_backend.load_from_directory_reporting(dir).await {
                    Ok(report) => {
                        debug!(target: PARENT_TARGET, directory = %dir, count = report.admitted, "Loaded capabilities (stdio)");
                        refused.extend(report.rejected);
                    }
                    Err(error) => {
                        debug!(target: PARENT_TARGET, directory = %dir, %error, "Failed to load optional capabilities (stdio)");
                    }
                }
            }
            if !refused.is_empty() {
                return Err(crate::Error::Config(format!(
                    "capabilities rejected by the account admission gate: {}",
                    refused.join("; ")
                )));
            }
            cap_backend.mark_initial_scan_complete();
            meta_mcp.set_capabilities(cap_backend);
        }

        if self.config.playbooks.enabled {
            let mut engine = crate::playbook::PlaybookEngine::new();
            for dir in &self.config.playbooks.directories {
                if let Ok(count) = engine.load_from_directory(dir) {
                    debug!(target: PARENT_TARGET, directory = %dir, count, "Loaded playbooks (stdio)");
                }
            }
            meta_mcp.set_playbook_engine(engine);
        }

        // Give stdio the same explicit reload context as HTTP, built once the
        // capability backend is installed, so a reload refreshes and announces
        // the catalogue the session serves (MIK-8278).
        if let Some(path) = self.reload_path() {
            let live_config = Arc::new(
                LiveConfig::new(self.config.clone())
                    .with_policy_epoch(Arc::clone(&meta_mcp.policy_epoch)),
            );
            let reload_ctx = Arc::new(
                ReloadContext::new(
                    path.clone(),
                    Arc::clone(&live_config),
                    Arc::clone(&self.backends),
                    self.config.failsafe.clone(),
                    self.config.meta_mcp.cache_ttl,
                )?
                .with_env(Arc::clone(&self.env))
                .with_identity_grant_sink_opt(grant_sink.clone())
                .with_capabilities(meta_mcp.get_capabilities())
                .with_on_registered(warmer.hook()),
            );
            meta_mcp.set_reload_context(reload_ctx);
        }

        Ok(())
    }
}

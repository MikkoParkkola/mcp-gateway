// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Constructors and managed account custody (moved from `server/mod.rs`, MIK-8144).

use std::sync::Arc;

use tracing::{info, warn};

use super::Gateway;
#[cfg(test)]
use super::test_seams;
use crate::backend::{Backend, BackendRegistry, runtime_plan_for_backend};
use crate::config::Config;
use crate::security::{posture, ssrf::DestinationPolicy};
use crate::{Error, Result};

impl Gateway {
    /// Create a new gateway
    ///
    /// # Errors
    ///
    /// Returns an error if backend registration fails.
    #[allow(clippy::unused_async)] // async for future initialization needs
    pub async fn new(config: Config) -> Result<Self> {
        Self::new_with_path(config, None).await
    }

    /// Create a new gateway with a config file path for hot-reload support.
    ///
    /// When `config_path` is `Some`, config changes to that file trigger
    /// automatic diff + patch at runtime.
    ///
    /// # Errors
    ///
    /// Returns an error if the config is invalid, or if backend registration
    /// fails.
    pub async fn new_with_path(
        config: Config,
        config_path: Option<std::path::PathBuf>,
    ) -> Result<Self> {
        // The process environment and nothing else, which is what this
        // constructor has always validated against: `LiveEnv::default` is
        // `EnvOverlay::none`, and `Config::validate` is `validate_with_env`
        // against exactly that. A caller building a `Config` in memory has no
        // env files, so nothing here changes for it.
        Self::new_with_env(
            config,
            Arc::new(crate::config::LiveEnv::default()),
            config_path,
        )
        .await
    }

    /// Build an ordinary gateway that resolves through `env` — the one place
    /// normal construction happens.
    ///
    /// The config is validated against the overlay it will ACTUALLY resolve
    /// against, and the same `LiveEnv` is the one the gateway keeps. Validating
    /// against the process environment and attaching the overlay afterwards is
    /// not equivalent: an `env:` reference an env file supplies is a value here
    /// and nothing at all there, so a valid deployment was refused at the
    /// validation it never reached its own environment for.
    ///
    /// Validation happens before any backend is built, so a refused config
    /// costs nothing, and the overlay snapshot is scoped to that step rather
    /// than held across the await this returns through.
    ///
    /// # Errors
    ///
    /// Returns an error if the config is invalid against `env`, or if backend
    /// registration fails.
    #[allow(unknown_lints, clippy::unused_async, clippy::unused_async_trait_impl)] // async for future initialization needs
    pub(super) async fn new_with_env(
        mut config: Config,
        env: Arc<crate::config::LiveEnv>,
        config_path: Option<std::path::PathBuf>,
    ) -> Result<Self> {
        // A config built in memory never passed through `Config::load`.
        // Before validation, so the ranges of what it forces are checked.
        posture::resolve(&mut config, posture::FirewallBuild::CURRENT)?;
        {
            // A cheap snapshot, dropped here: nothing environmental is held
            // while the gateway is built or awaited on.
            let overlay = env.get();
            config.validate_with_env(&overlay)?;
            let chain = &mut config.security.signature_chain; // key identity, as at load
            crate::config::SignatureChainConfig::resolve_section(chain, &overlay)?;
        }
        posture::log_startup(&config);

        let backends = Arc::new(BackendRegistry::new());
        backends.enforce_destinations(
            DestinationPolicy::for_posture(config.security.posture),
            &config.security.hardened.private_backends,
        )?;

        // The EFFECTIVE configuration a bound backend runs with, resolved
        // before any backend is constructed. A `personal_managed` binding
        // compiles to vault propagation and DROPS the backend's own oauth
        // block here, which is what keeps the legacy `OAuthClient` from ever
        // being instantiated for a backend whose credential is in custody —
        // the constructor below reads that field to decide whether to build
        // one, so the decision has to be made before it, not after.
        let bound_accounts = crate::config::account_bindings::compile(&config)?;

        // Register backends
        for (name, backend_config) in config.enabled_backends() {
            let effective = match bound_accounts.get(name) {
                Some(bound) => bound.effective(backend_config),
                None => backend_config.clone(),
            };
            let runtime_plan = runtime_plan_for_backend(name, &effective, &config.runtime);
            let backend = Backend::new_with_runtime_plan(
                name,
                effective,
                &config.failsafe,
                config.meta_mcp.cache_ttl,
                runtime_plan,
            );
            // Construction time: this registry is brand new and cannot be
            // shutting down, so a refusal here is unreachable. Asserted rather
            // than ignored, so the day that stops being true is not silent.
            assert!(
                backends.register(Arc::new(backend)),
                "a freshly built registry refused a backend registration"
            );
            info!(backend = %name, transport = %backend_config.transport.transport_type(), "Registered backend");
        }
        if let Some(warning) = config.remote_provenance_warning() {
            warn!("{warning}");
        }

        Ok(Self {
            #[cfg(test)]
            test_seams: test_seams::TestSeams::default(),
            config,
            config_path,
            watched_config: None,
            backends,
            shutdown_tx: None,
            // The environment the config was just validated against, retained:
            // every later resolution answers from the same overlay the decision
            // to start was made on.
            env,
            #[cfg(feature = "firewall")]
            reads: crate::security::firewall::tenant_reads::ReadHistory::shared(),
            // Attached by `start_account_custody`, so this constructor stays
            // exactly what it was for a caller building a Config in memory.
            custody: None,
        })
    }

    /// Resolve env-file-supplied values through `env`.
    ///
    /// Set from the startup evaluation. Without it the gateway falls back to
    /// the process environment, which is what a caller building a `Config` in
    /// memory wants and what an env file no longer reaches.
    #[must_use]
    pub fn with_env(mut self, env: Arc<crate::config::LiveEnv>) -> Self {
        self.env = env;
        self
    }

    /// Watch and hot-reload `path`, a config file found by discovery (#1868).
    ///
    /// This only sets the watched path: the config watcher, the env-file poll
    /// and the reload context use it when no config path was named. It does
    /// not change `config_path`, so the governance store location, admin
    /// config writes and the shadow scan behave exactly as for a gateway
    /// started without `--config`. A named config path still wins.
    #[must_use]
    pub fn with_watched_config(mut self, path: std::path::PathBuf) -> Self {
        self.watched_config = Some(path);
        self
    }

    /// The config file this gateway watches and reloads: the named one, else
    /// the one discovery found.
    pub(super) fn reload_path(&self) -> Option<&std::path::PathBuf> {
        self.config_path.as_ref().or(self.watched_config.as_ref())
    }

    /// [`Self::new_evaluated`] with the account transport supplied.
    ///
    /// Not a second constructor: it calls the SAME body with `Some(http)` where
    /// `new_evaluated` passes `None`. Exists so a wire test can point a real
    /// startup at a real loopback endpoint; there is no fake provider type it
    /// could accept.
    #[cfg(test)]
    pub(crate) async fn new_evaluated_with_account_http(
        config: Config,
        env: Arc<crate::config::LiveEnv>,
        config_path: Option<std::path::PathBuf>,
        http: crate::personal_accounts::GatewayProviderHttp,
    ) -> Result<Self> {
        Self::new_evaluated_inner(config, env, config_path, Some(http)).await
    }

    /// THE evaluated construction. One body: validation through the overlay,
    /// custody start, one error mapping. The `http` parameter does not exist
    /// outside `cfg(test)`, so production neither names nor carries it.
    ///
    /// Constructed WITH the environment, never validated without it and
    /// handed the overlay afterwards: the account key is an env-file
    /// assignment, so a validation against the process environment refuses
    /// the very config this constructor exists to accept.
    pub(super) async fn new_evaluated_inner(
        config: Config,
        env: Arc<crate::config::LiveEnv>,
        config_path: Option<std::path::PathBuf>,
        #[cfg(test)] http: Option<crate::personal_accounts::GatewayProviderHttp>,
    ) -> Result<Self> {
        let mut gateway = Self::new_with_env(config, env, config_path).await?;
        gateway
            .start_account_custody_inner(
                #[cfg(test)]
                http,
            )
            .await
            .map_err(|e| Error::Config(format!("personal account custody could not start: {e}")))?;
        Ok(gateway)
    }

    /// Resolve the `accounts` block and bring custody up, or do nothing.
    ///
    /// Both halves are real: the block is resolved through the overlay, then the
    /// refresh provider is bootstrapped and the store is opened on a blocking
    /// thread. Exactly one custody handle is attached, and only on success.
    ///
    /// Separate from [`Self::new_evaluated`] because the typed outcome is the
    /// difference between "this deployment is misconfigured" and "another owner
    /// holds the store", and the crate `Error` cannot carry that distinction.
    ///
    /// The key resolves through the env overlay, never the process environment:
    /// an env file assigns it and no process ever sees it.
    ///
    /// # Errors
    ///
    /// Returns the configuration layer's refusal, or the store's own.
    #[cfg(test)]
    pub(crate) async fn start_account_custody(
        &mut self,
    ) -> std::result::Result<(), crate::personal_accounts::CustodyBootstrapError> {
        self.start_account_custody_inner(
            #[cfg(test)]
            None,
        )
        .await
    }

    /// Shared custody startup body. The transport parameter
    /// exists only under `cfg(test)`; the production path is unchanged and
    /// builds its client exactly where it always did, inside `start_custody`.
    async fn start_account_custody_inner(
        &mut self,
        #[cfg(test)] http: Option<crate::personal_accounts::GatewayProviderHttp>,
    ) -> std::result::Result<(), crate::personal_accounts::CustodyBootstrapError> {
        let resolved = {
            // Scoped, so no environment read is held across the await below.
            let overlay = self.env.get();
            match crate::personal_accounts::config::resolve(
                self.config.accounts.as_ref(),
                &*overlay,
            ) {
                Ok(resolved) => resolved,
                // `enabled: false` is an operator's decision, not a fault:
                // schema and deployment are validated ABOVE this refusal, so a
                // disabled block has been checked and declined. It is the second
                // producer of `None` here, alongside an omitted block, and means
                // the same thing: ordinary startup, no store, no lock, nothing
                // created on disk.
                //
                // INVARIANT RELIED ON, and it is now enforced rather than
                // structural: `personal_managed` descriptors ARE representable,
                // and `config::validate_descriptors` — run inside
                // `Config::validate_with_env`, before any gateway exists —
                // refuses a managed descriptor under `enabled: false`. So a
                // block reaching this arm has no managed descriptor to lose.
                // This arm still cannot make that distinction and must not be
                // taught to.
                //
                // Only the gateway's own start softens `NotEnabled`. Config
                // resolution keeps refusing it, because every later descriptor
                // caller needs that refusal.
                Err(crate::personal_accounts::config::AccountsConfigError::NotEnabled) => None,
                Err(error) => {
                    return Err(crate::personal_accounts::CustodyBootstrapError::Config(
                        error,
                    ));
                }
            }
        };
        // Omitted `accounts` preserves ordinary construction: no store, no lock,
        // and no default custody invented on the operator's behalf.
        let Some(resolved) = resolved else {
            return Ok(());
        };
        // The descriptors as configured. Absent means a store-only deployment:
        // custody still starts, with nothing to discover.
        let descriptors = self
            .config
            .accounts
            .as_ref()
            .and_then(|accounts| accounts.descriptors.clone())
            .unwrap_or_default();
        // The SAME `LiveEnv` this gateway was validated against and keeps: the
        // client secret an env file assigns is resolved from that overlay at
        // refresh time and never from the process environment.
        #[cfg(not(test))]
        let custody = crate::personal_accounts::start_custody(
            resolved.store,
            descriptors,
            Arc::clone(&self.env),
        )
        .await?;
        // Test-only dispatch. `None` runs the identical production call; the
        // supplied arm differs by the transport instance and nothing else, and
        // both arms end in the same `start_custody_with_http` body.
        #[cfg(test)]
        let custody = match http {
            Some(http) => {
                crate::personal_accounts::start_custody_with_http(
                    http,
                    resolved.store,
                    descriptors,
                    Arc::clone(&self.env),
                )
                .await?
            }
            None => {
                crate::personal_accounts::start_custody(
                    resolved.store,
                    descriptors,
                    Arc::clone(&self.env),
                )
                .await?
            }
        };
        self.custody = Some(Arc::new(custody));
        Ok(())
    }

    /// The managed custody this gateway owns, if any.
    #[must_use]
    pub(crate) fn account_custody(&self) -> Option<&Arc<crate::personal_accounts::GatewayCustody>> {
        self.custody.as_ref()
    }

    /// Drain account work and release the custody store, keeping the gateway.
    ///
    /// Takes `&self`, like the handle it delegates to: both file locks are freed
    /// while this gateway — and the handle that now refuses — stay alive.
    /// Idempotent, and a no-op when no `accounts` block was configured.
    ///
    /// # Errors
    ///
    /// Returns the custody handle's own refusal if the drain cannot complete.
    pub(crate) async fn shutdown_account_custody(
        &self,
    ) -> std::result::Result<(), crate::personal_accounts::CustodyError> {
        match self.account_custody() {
            Some(custody) => custody.shutdown().await,
            None => Ok(()),
        }
    }
}

// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Backend construction and connection lifecycle: creation, starting pool
//! slots (stdio/HTTP transport launch, OAuth client setup, runtime-provider
//! policy enforcement), stopping, and health-probe-driven recovery.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use dashmap::DashMap;
use reqwest::Client;
use tokio::sync::Semaphore;
use tracing::{info, warn};

use super::Backend;
use super::cached_metadata::CachedMetadata;
use super::pool::{PoolKey, PooledEntry, now_unix_secs};
use crate::config::{BackendConfig, RuntimeConfig, TransportConfig};
use crate::oauth::{OAuthClient, OAuthClientConfig, TokenStorage};
use crate::runtime::{RuntimeLaunchCommand, RuntimeLaunchMode, RuntimePlan, RuntimeProviderKind};
use crate::transport::{HttpTransport, StdioTransport, Transport};
use crate::{Error, Result};

/// Compile the runtime profile selected by a backend into a live-start plan.
#[must_use]
pub fn runtime_plan_for_backend(
    name: &str,
    config: &BackendConfig,
    runtime_config: &RuntimeConfig,
) -> Option<RuntimePlan> {
    let profile_name = config.runtime_profile.as_deref()?;
    let executable_hint = stdio_executable_hint(&config.transport);
    runtime_config.plan_backend_profile(profile_name, name, executable_hint.as_deref())
}

fn stdio_executable_hint(transport: &TransportConfig) -> Option<String> {
    let TransportConfig::Stdio { command, .. } = transport else {
        return None;
    };
    shlex::split(command)?.into_iter().next()
}

pub(super) struct ResolvedStdioLaunch {
    pub(super) command: String,
    pub(super) env: HashMap<String, String>,
}

fn container_stdio_bridge_command(plan: &RuntimePlan) -> Result<String> {
    let command = plan.launch_command.as_ref().ok_or_else(|| {
        Error::Config(format!(
            "runtime provider {:?} has no structured launch command for stdio bridge",
            plan.provider
        ))
    })?;
    if command.args.first().map(String::as_str) != Some("run") {
        return Err(Error::Config(format!(
            "runtime provider {:?} launch command is not a container run command",
            plan.provider
        )));
    }

    let mut args = vec![
        "run".to_string(),
        "--interactive".to_string(),
        "--rm".to_string(),
    ];
    let mut skip_restart_value = false;
    for arg in command.args.iter().skip(1) {
        if skip_restart_value {
            skip_restart_value = false;
            continue;
        }
        match arg.as_str() {
            "--detach" | "-d" | "--interactive" | "-i" | "--rm" => {}
            "--restart" => skip_restart_value = true,
            value if value.starts_with("--restart=") => {}
            _ => args.push(arg.clone()),
        }
    }

    Ok(RuntimeLaunchCommand {
        program: command.program.clone(),
        args,
        mode: RuntimeLaunchMode::RunToCompletion,
    }
    .display_command())
}

fn filter_runtime_env(
    env: &HashMap<String, String>,
    allowed_keys: &[String],
) -> HashMap<String, String> {
    allowed_keys
        .iter()
        .filter_map(|key| env.get(key).map(|value| (key.clone(), value.clone())))
        .collect()
}

impl Backend {
    /// Create a new backend
    #[must_use]
    pub fn new(
        name: &str,
        config: BackendConfig,
        failsafe_config: &crate::config::FailsafeConfig,
        cache_ttl: Duration,
    ) -> Self {
        Self::new_with_runtime_plan(name, config, failsafe_config, cache_ttl, None)
    }

    /// Create a new backend with an optional precompiled runtime plan.
    #[must_use]
    pub fn new_with_runtime_plan(
        name: &str,
        config: BackendConfig,
        failsafe_config: &crate::config::FailsafeConfig,
        cache_ttl: Duration,
        runtime_plan: Option<RuntimePlan>,
    ) -> Self {
        Self {
            name: name.to_string(),
            config,
            runtime_plan,
            pool: {
                let pool = DashMap::new();
                pool.insert(
                    PoolKey::Shared,
                    Arc::new(PooledEntry::new(name, failsafe_config)),
                );
                pool
            },
            failsafe_config: failsafe_config.clone(),
            tools_cache: CachedMetadata::new(),
            resources_cache: CachedMetadata::new(),
            resource_templates_cache: CachedMetadata::new(),
            prompts_cache: CachedMetadata::new(),
            cache_ttl,
            last_used: std::sync::atomic::AtomicU64::new(0),
            semaphore: Semaphore::new(100), // Max concurrent requests
            request_count: std::sync::atomic::AtomicU64::new(0),
        }
    }

    /// Ensure backend is started
    ///
    /// # Errors
    ///
    /// Returns an error if the transport fails to start.
    pub async fn ensure_started(&self) -> Result<()> {
        self.ensure_entry_started(&PoolKey::Shared).await?;
        Ok(())
    }

    /// Ensure the pooled entry for `key` is started, returning a clone of the
    /// live transport.
    ///
    /// Double-checked under the entry's own start lock so concurrent callers for
    /// the same slot never spawn duplicate connections, while different slots
    /// (distinct users) start independently and in parallel.
    ///
    /// TOCTOU guard against `evict_idle_per_user_entries` (MIK-6735 POOL race
    /// fix): the idle evictor can `remove_if` a per-user slot from `pool`
    /// concurrently with this method building that same slot's transport —
    /// the slot was cloned out via `pooled_entry` before it was touched, so
    /// the evictor's idleness re-check still sees it as stale and wins the
    /// race. If that happens, `entry` becomes orphaned: no longer reachable
    /// via `self.pool`, and `PooledEntry` has no async `Drop` to close a
    /// transport stored on an orphaned instance, so it would otherwise leak
    /// the connection until OS teardown. After `start_entry` returns, this
    /// method re-checks (by `Arc::ptr_eq`) that `key` still maps to the exact
    /// entry it started; if the evictor won, it closes the just-built
    /// transport itself — the side that loses the race owns the close — and
    /// retries once against a fresh entry (bounded so a hypothetical
    /// coincidence of repeated evictions cannot spin forever).
    ///
    /// # Errors
    ///
    /// Returns an error if the transport fails to start, or if the entry is
    /// repeatedly evicted out from under every start attempt.
    pub(super) async fn ensure_entry_started(&self, key: &PoolKey) -> Result<Arc<dyn Transport>> {
        const MAX_RACE_RETRIES: u8 = 3;

        for _attempt in 0..MAX_RACE_RETRIES {
            let entry = self.pooled_entry(key);

            // Update last-used clocks (backend-wide + per-slot for idle eviction).
            self.last_used.store(now_unix_secs(), Ordering::Relaxed);
            entry.touch();

            {
                let transport = entry.transport.read();
                if let Some(t) = transport.as_ref()
                    && t.is_connected()
                {
                    return Ok(Arc::clone(t));
                }
            }

            let _start_guard = entry.start_lock.lock().await;

            {
                let transport = entry.transport.read();
                if let Some(t) = transport.as_ref()
                    && t.is_connected()
                {
                    return Ok(Arc::clone(t));
                }
            }

            // Start transport for this slot.
            let transport = self.start_entry(key, &entry).await?;

            // Reconcile: did the evictor remove this exact entry while we
            // were building its transport?
            if let Some(transport) = self.reconcile_after_start(key, &entry, transport).await {
                return Ok(transport);
            }
            // Lost the race: `reconcile_after_start` already closed the
            // orphaned transport. Loop and re-derive a fresh entry for `key`.
        }

        Err(Error::BackendUnavailable(self.name.clone()))
    }

    /// After [`Backend::start_entry`] builds and stores a transport into
    /// `entry` for `key`, verify `entry` is still the exact instance the pool
    /// has registered under `key` (by `Arc::ptr_eq`) -- i.e. that
    /// [`Backend::evict_idle_per_user_entries`] did not `remove_if` it out
    /// from under this in-flight start.
    ///
    /// Returns `Some(transport)` when `entry` is still live: the transport is
    /// visible to every future caller of `pooled_entry(key)` and callers here
    /// own nothing extra to clean up. Returns `None` when the race was lost:
    /// `entry` is orphaned (unreachable via `self.pool`), so nothing else will
    /// ever call `close()` on the transport just stored into it -- there is no
    /// async `Drop` for `PooledEntry` -- which would otherwise leak the
    /// underlying connection until OS teardown. In that case this method
    /// takes the transport back out and closes it itself before returning
    /// `None`, so the side that loses the race is the side that owns the
    /// close.
    pub(super) async fn reconcile_after_start(
        &self,
        key: &PoolKey,
        entry: &Arc<PooledEntry>,
        transport: Arc<dyn Transport>,
    ) -> Option<Arc<dyn Transport>> {
        let still_registered = self
            .pool
            .get(key)
            .is_some_and(|slot| Arc::ptr_eq(slot.value(), entry));
        if still_registered {
            return Some(transport);
        }

        warn!(
            backend = %self.name,
            ?key,
            "Pooled entry evicted mid-start; closing the orphaned transport \
             we just built to avoid a connection leak"
        );
        // Bind the taken value before awaiting: `if let Some(x) = guard.take() {
        // ... x.await ... }` would extend the `parking_lot::RwLockWriteGuard`
        // temporary's lifetime across the `.await` (not `Send`), so the guard
        // must be dropped by the end of this `let` statement first.
        let orphaned = entry.transport.write().take();
        if let Some(orphaned) = orphaned {
            let _ = orphaned.close().await;
        }
        None
    }

    /// Start the backend's canonical (shared) transport.
    ///
    /// # Errors
    ///
    /// Returns an error if the transport fails to connect or initialize.
    pub async fn start(&self) -> Result<()> {
        // Explicit/background warm-start must enter through the same
        // single-flight lock as request-triggered startup. Calling
        // `start_entry` directly here lets a slow warm-start race a request and
        // launch two copies of a singleton stdio backend.
        self.ensure_entry_started(&PoolKey::Shared).await?;
        Ok(())
    }

    /// Build a fresh transport for the pooled `entry`, store it, and return a
    /// clone. Per-user slots build the same transport shape as the shared slot;
    /// end-user identity is carried per-request via headers, not baked into the
    /// connection, so each user simply gets an independent session lifecycle.
    ///
    /// # Errors
    ///
    /// Returns an error if the transport fails to connect or initialize.
    async fn start_entry(&self, key: &PoolKey, entry: &PooledEntry) -> Result<Arc<dyn Transport>> {
        info!(backend = %self.name, ?key, "Starting backend transport");

        let transport: Arc<dyn Transport> = match &self.config.transport {
            TransportConfig::Stdio {
                command,
                cwd,
                protocol_version,
            } => {
                let launch = self.resolve_stdio_runtime_launch(command)?;
                let transport = StdioTransport::new(
                    &launch.command,
                    launch.env,
                    cwd.clone(),
                    self.config.timeout,
                    protocol_version.clone(),
                );
                transport.start().await?;
                transport
            }
            TransportConfig::Http {
                http_url,
                streamable_http,
                protocol_version,
            } => {
                // Create OAuth client if configured
                let oauth_client = self.create_oauth_client(http_url)?;

                let transport = HttpTransport::new_with_oauth(
                    http_url,
                    self.config.headers.clone(),
                    self.config.timeout,
                    *streamable_http,
                    oauth_client,
                    protocol_version.clone(),
                )?;
                // MIK-6735 fix 2: a per-user pool slot's transport serves
                // exactly one caller identity for its whole lifetime, which
                // is what makes the transport's internal session-map
                // single-tenant debug_assert provably safe -- tell it so.
                if matches!(key, PoolKey::PerUser { .. }) {
                    transport.mark_single_tenant();
                }
                transport.initialize().await?;
                transport
            }
            #[cfg(feature = "a2a")]
            TransportConfig::A2a { a2a_url, .. } => {
                // A2A backends are managed by A2aProvider, not the legacy
                // Backend/Transport stack.  Reaching this branch means an A2A
                // backend was incorrectly started through the legacy path.
                return Err(crate::Error::Config(format!(
                    "A2A backend '{name}' (url: {a2a_url}) must be started via A2aProvider, \
                     not the legacy Backend::start() path",
                    name = self.name,
                )));
            }
        };

        *entry.transport.write() = Some(Arc::clone(&transport));

        // Note: Tools are fetched lazily on first get_tools() call
        // We can't pre-cache here because get_tools() -> ensure_started() -> start()
        // would create infinite async recursion

        Ok(transport)
    }

    /// Create OAuth client if OAuth is configured for this backend
    pub(super) fn create_oauth_client(&self, resource_url: &str) -> Result<Option<OAuthClient>> {
        let oauth_config = match &self.config.oauth {
            Some(cfg) if cfg.enabled => cfg,
            _ => return Ok(None),
        };

        // F3 sink-side guard. Config::validate() rejects this pairing at load,
        // but programmatic `Backend::new*()` and hot-reload `apply_patch()` build
        // backends from a raw BackendConfig without revalidating. Enforce again
        // here -- the last chokepoint before an OAuth client is created -- so an
        // enabled backend OAuth client is never spun up alongside
        // identity_propagation. The backend OAuth persists a gateway-held token
        // during initialize(), authenticating the transport session as the
        // gateway before any per-request per-user override, silently defeating
        // per-user propagation. Fail closed at the sink.
        if self.config.identity_propagation.is_some() {
            return Err(Error::ConfigValidation(format!(
                "backend '{}' cannot combine identity_propagation with its own enabled oauth \
                 client: the backend oauth persists a gateway-held token during initialize(), \
                 authenticating the transport session as the gateway before the per-request \
                 credential override -- silently defeating per-user propagation (F3).",
                self.name
            )));
        }

        info!(backend = %self.name, "Initializing OAuth client");

        // Create HTTP client for OAuth requests
        let http_client = Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .map_err(|e| Error::OAuth(format!("Failed to create OAuth HTTP client: {e}")))?;

        // Get or create token storage
        let storage = Arc::new(
            TokenStorage::default_location()
                .map_err(|e| Error::OAuth(format!("Failed to create token storage: {e}")))?,
        );

        // Create OAuth client
        let oauth = OAuthClient::new(
            http_client,
            self.name.clone(),
            resource_url.to_string(),
            oauth_config.scopes.clone(),
            storage,
            OAuthClientConfig {
                client_id: oauth_config.client_id.clone(),
                client_secret: oauth_config.client_secret.clone(),
                callback_host: oauth_config.callback_host.clone(),
                callback_port: oauth_config.callback_port,
                callback_path: oauth_config.callback_path.clone(),
                token_refresh_buffer_secs: oauth_config.token_refresh_buffer_secs,
            },
        );

        Ok(Some(oauth))
    }

    pub(super) fn resolve_stdio_runtime_launch(
        &self,
        configured_command: &str,
    ) -> Result<ResolvedStdioLaunch> {
        let Some(plan) = self.runtime_plan.as_ref() else {
            return Ok(ResolvedStdioLaunch {
                command: configured_command.to_string(),
                env: self.config.env.clone(),
            });
        };
        self.enforce_stdio_runtime_plan(plan)?;

        match plan.provider {
            RuntimeProviderKind::LocalProcess => {
                info!(
                    backend = %self.name,
                    provider = ?plan.provider,
                    policy_id = %plan.policy.id,
                    "RuntimeProvider profile accepted before stdio backend start"
                );
                Ok(ResolvedStdioLaunch {
                    command: configured_command.to_string(),
                    env: self.config.env.clone(),
                })
            }
            RuntimeProviderKind::Docker | RuntimeProviderKind::Podman => {
                let command = container_stdio_bridge_command(plan)?;
                info!(
                    backend = %self.name,
                    provider = ?plan.provider,
                    policy_id = %plan.policy.id,
                    "RuntimeProvider container stdio bridge accepted before backend start"
                );
                Ok(ResolvedStdioLaunch {
                    command,
                    env: filter_runtime_env(&self.config.env, &plan.policy.env.allowed_keys),
                })
            }
            RuntimeProviderKind::Systemd
            | RuntimeProviderKind::Launchd
            | RuntimeProviderKind::Kubernetes => Err(Error::Config(format!(
                "backend '{}' runtime profile selected {:?}, but live stdio backend lifecycle currently supports local_process plus docker/podman stdio bridge",
                self.name, plan.provider
            ))),
        }
    }

    fn enforce_stdio_runtime_plan(&self, plan: &RuntimePlan) -> Result<()> {
        if plan.is_denied() {
            let reasons = plan
                .denied
                .iter()
                .map(|denial| format!("{:?}", denial.reason))
                .collect::<Vec<_>>()
                .join(", ");
            return Err(Error::Config(format!(
                "backend '{}' runtime profile '{}' denied by policy: {reasons}",
                self.name, plan.policy.id
            )));
        }
        if plan.requires_confirmation() {
            let confirmations = plan
                .confirmations
                .iter()
                .map(|confirmation| confirmation.id.as_str())
                .collect::<Vec<_>>()
                .join(", ");
            return Err(Error::Config(format!(
                "backend '{}' runtime profile '{}' requires confirmations before live start: {confirmations}",
                self.name, plan.policy.id
            )));
        }
        Ok(())
    }

    /// Stop the backend, draining every pooled transport slot.
    ///
    /// # Errors
    ///
    /// Never returns `Err` today: individual slot-close failures are logged and
    /// the remaining slots are still drained. The `Result` is retained for
    /// forward compatibility and to match the registry's stop contract.
    pub async fn stop(&self) -> Result<()> {
        info!(backend = %self.name, "Stopping backend");

        // Take every slot's transport out first (dropping the parking_lot write
        // guards) so no lock is held across the async close().
        let transports: Vec<Arc<dyn Transport>> = self
            .pool
            .iter()
            .filter_map(|entry| entry.value().transport.write().take())
            .collect();

        for transport in transports {
            if let Err(e) = transport.close().await {
                warn!(backend = %self.name, error = %e, "Failed to close pooled transport");
            }
        }

        Ok(())
    }

    /// Check if backend is running (canonical shared slot connected).
    pub fn is_running(&self) -> bool {
        self.pool
            .get(&PoolKey::Shared)
            .and_then(|entry| {
                entry
                    .value()
                    .transport
                    .read()
                    .as_ref()
                    .map(|t| t.is_connected())
            })
            .unwrap_or(false)
    }

    /// Tear down the current transport (killing any child process) and start a
    /// fresh one.
    ///
    /// Unlike [`ensure_started`](Self::ensure_started), this does **not** trust
    /// `is_connected()` -- it always rebuilds. A wedged-but-not-exited child
    /// (responds to `try_wait` as alive yet never answers requests) cannot be
    /// recovered by `ensure_started` alone; this is the escape hatch the health
    /// loop uses when a probe fails.
    ///
    /// # Errors
    ///
    /// Returns an error if the fresh transport fails to start or initialize.
    pub async fn force_restart(&self) -> Result<()> {
        // Rebuild only the canonical shared slot; per-user sessions are left
        // intact so one caller's health recovery cannot tear down another's
        // in-flight session (MIK-6735). The idle reaper reclaims per-user slots.
        let entry = self.pooled_entry(&PoolKey::Shared);
        let _guard = entry.start_lock.lock().await;
        // Take the transport out and drop the RwLock write guard *before*
        // awaiting close() -- a parking_lot guard is not Send across an await.
        let old = entry.transport.write().take();
        if let Some(old) = old {
            let _ = old.close().await;
        }
        self.start_entry(&PoolKey::Shared, &entry).await?;
        Ok(())
    }

    /// Active health/recovery probe driven by the background health loop.
    ///
    /// This is the gateway's automatic equivalent of `gateway_revive_server`.
    /// Two properties make it actually recover a wedged backend, which the old
    /// `backend.request("ping")` health check could not:
    ///
    /// 1. **It bypasses the circuit breaker.** A probe routed through
    ///    [`request`](Self::request) short-circuits on `can_proceed()` and
    ///    returns `CircuitOpen` *without touching the backend* -- so it could
    ///    never discover that an `Open` backend had recovered. This probe talks
    ///    to the transport directly.
    /// 2. **On success it resets a tripped breaker**; on failure it forces a
    ///    transport rebuild so the next probe targets a fresh child.
    ///
    /// `timeout` bounds the probe so a hung backend cannot stall the loop.
    ///
    /// # Errors
    ///
    /// Returns an error if the backend cannot be started, the probe times out,
    /// or the `ping` call fails. The breaker is left for organic traffic to
    /// trip -- this probe never records failures, only recoveries.
    pub async fn health_probe(&self, timeout: Duration) -> Result<()> {
        // `ensure_started` now respawns reliably because `is_connected()` does a
        // real liveness check (Fix C).
        if let Err(e) = self.ensure_started().await {
            let _ = self.force_restart().await;
            return Err(e);
        }

        let transport = self.shared_transport();
        let Some(transport) = transport else {
            return Err(Error::BackendUnavailable(self.name.clone()));
        };

        match tokio::time::timeout(timeout, transport.request("ping", None)).await {
            Ok(Ok(response)) => {
                if let Err(error) = validate_health_probe_response(response) {
                    warn!(backend = %self.name, error = %error, "Health probe failed; rebuilding transport");
                    let _ = self.force_restart().await;
                    return Err(error);
                }
                if self.is_circuit_tripped() {
                    info!(
                        backend = %self.name,
                        "Health probe succeeded; resetting tripped circuit breaker"
                    );
                    self.reset_circuit_breaker();
                }
                Ok(())
            }
            Ok(Err(e)) => {
                warn!(backend = %self.name, error = %e, "Health probe failed; rebuilding transport");
                let _ = self.force_restart().await;
                Err(e)
            }
            Err(_elapsed) => {
                warn!(
                    backend = %self.name,
                    timeout_ms = timeout.as_millis(),
                    "Health probe timed out; rebuilding transport"
                );
                let _ = self.force_restart().await;
                Err(Error::BackendTimeout(self.name.clone()))
            }
        }
    }
}

/// Accept a successful ping or the standard `-32601 Method not found` response.
///
/// MCP servers predating `ping` still prove that their initialized JSON-RPC
/// transport is alive by returning a correlated method-not-found response. Any
/// other JSON-RPC error or malformed envelope remains a failed health probe.
fn validate_health_probe_response(response: crate::protocol::JsonRpcResponse) -> Result<()> {
    let Some(id) = response.id.clone() else {
        return Err(Error::Protocol(
            "health probe response is missing its request id".to_string(),
        ));
    };
    let response = crate::transport::validate_json_rpc_response(response, &id)?;
    match response.error {
        None => Ok(()),
        Some(error) if error.code == -32601 => Ok(()),
        Some(error) => Err(Error::JsonRpc {
            code: error.code,
            message: error.message,
            data: error.data,
        }),
    }
}

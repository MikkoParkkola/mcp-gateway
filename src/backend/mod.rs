//! Backend management

use std::collections::HashMap;
use std::future::Future;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use dashmap::DashMap;
use parking_lot::RwLock;
use reqwest::Client;
use serde_json::Value;
use tokio::sync::{Mutex, Semaphore, watch};
use tracing::{debug, info, warn};

use crate::config::{BackendConfig, RuntimeConfig, TransportConfig};
use crate::failsafe::{Failsafe, with_retry};
use crate::oauth::{OAuthClient, OAuthClientConfig, TokenStorage};
use crate::protocol::{
    JsonRpcResponse, Prompt, PromptsListResult, Resource, ResourceTemplate, ResourcesListResult,
    ResourcesTemplatesListResult, Tool, ToolAnnotations, ToolsListResult,
};
use crate::runtime::{
    RuntimeDenyReason, RuntimeLaunchCommand, RuntimeLaunchMode, RuntimeLicenseTier, RuntimePlan,
    RuntimeProviderKind,
};
use crate::transport::{HttpTransport, StdioTransport, Transport};
use crate::{Error, Result};

struct CachedMetadata<T> {
    state: RwLock<CachedMetadataState<T>>,
}

struct CachedMetadataState<T> {
    value: Option<Arc<T>>,
    cached_at: Option<Instant>,
    in_flight: Option<watch::Sender<()>>,
}

impl<T> Default for CachedMetadataState<T> {
    fn default() -> Self {
        Self {
            value: None,
            cached_at: None,
            in_flight: None,
        }
    }
}

enum CacheFetchState<'a, T> {
    Cached(Arc<T>),
    Wait(watch::Receiver<()>),
    Fetch(FetchPermit<'a, T>),
}

struct FetchPermit<'a, T> {
    cache: &'a CachedMetadata<T>,
    sender: watch::Sender<()>,
}

impl<T> Drop for FetchPermit<'_, T> {
    fn drop(&mut self) {
        self.cache.state.write().in_flight = None;
        let _ = self.sender.send(());
    }
}

impl<T> CachedMetadata<T> {
    fn new() -> Self {
        Self {
            state: RwLock::new(CachedMetadataState::default()),
        }
    }

    fn with_cached<R>(&self, map: impl FnOnce(Option<&Arc<T>>) -> R) -> R {
        let state = self.state.read();
        map(state.value.as_ref())
    }

    fn is_fresh(&self, ttl: Duration) -> bool {
        let state = self.state.read();
        matches!(
            (&state.value, state.cached_at),
            (Some(_), Some(cached_at)) if cached_at.elapsed() < ttl
        )
    }

    fn snapshot_shared(&self) -> Option<Arc<T>> {
        let state = self.state.read();
        state.value.clone()
    }

    fn store_shared(&self, value: Arc<T>) {
        let mut state = self.state.write();
        state.value = Some(value);
        state.cached_at = Some(Instant::now());
    }

    fn acquire(&self, ttl: Duration) -> CacheFetchState<'_, T> {
        {
            let state = self.state.read();
            if let Some(value) = Self::fresh_value(&state, ttl) {
                return CacheFetchState::Cached(value);
            }
            if let Some(sender) = state.in_flight.as_ref() {
                return CacheFetchState::Wait(sender.subscribe());
            }
        }

        let mut state = self.state.write();
        if let Some(value) = Self::fresh_value(&state, ttl) {
            return CacheFetchState::Cached(value);
        }
        if let Some(sender) = state.in_flight.as_ref() {
            return CacheFetchState::Wait(sender.subscribe());
        }

        let (sender, _receiver) = watch::channel(());
        state.in_flight = Some(sender.clone());
        CacheFetchState::Fetch(FetchPermit {
            cache: self,
            sender,
        })
    }

    async fn get_or_fetch_shared<F, Fut>(&self, ttl: Duration, fetch: F) -> Result<Arc<T>>
    where
        F: Fn() -> Fut,
        Fut: Future<Output = Result<T>>,
    {
        loop {
            match self.acquire(ttl) {
                CacheFetchState::Cached(value) => return Ok(value),
                CacheFetchState::Wait(mut receiver) => {
                    let _ = receiver.changed().await;
                }
                CacheFetchState::Fetch(permit) => {
                    let result = fetch().await.map(Arc::new);
                    if let Ok(value) = &result {
                        self.store_shared(Arc::clone(value));
                    }
                    drop(permit);
                    return result;
                }
            }
        }
    }

    fn fresh_value(state: &CachedMetadataState<T>, ttl: Duration) -> Option<Arc<T>> {
        if let (Some(value), Some(cached_at)) = (&state.value, state.cached_at)
            && cached_at.elapsed() < ttl
        {
            return Some(Arc::clone(value));
        }

        None
    }
}

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

/// Seconds since the Unix epoch, saturating to 0 on a pre-epoch clock.
fn now_unix_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Identifies one transport/session slot in a backend's connection pool
/// (MIK-6735).
///
/// A backend always owns the canonical [`PoolKey::Shared`] slot — the
/// single-tenant default that also backs init, metadata, and canonical traffic.
/// When `identity_propagation.session_mode = per_user` is configured and a
/// caller identity is present, the backend additionally owns one
/// [`PoolKey::PerUser`] slot per stable identity binding, so two distinct users
/// never share a backend transport or its upstream MCP session (IDP.7).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum PoolKey {
    /// The canonical single-tenant slot. Every non-per-user backend, and every
    /// per-user backend request that lacks a resolved identity, collapses here
    /// so single-tenant behavior is preserved byte-for-byte (IDP.5).
    Shared,
    /// A per-user slot keyed by the caller's stable identity binding
    /// (`PropagatedCredential::cache_binding`, MIK-6784).
    PerUser { binding: String },
}

/// One pooled transport slot: its lazily started transport, a start lock that
/// serializes connection setup for that slot, a last-used clock driving idle
/// eviction of per-user slots, and this slot's own failsafe mechanisms.
///
/// The failsafe (circuit breaker + rate limiter + retry policy + health
/// tracker) is owned per-slot, not per-backend (MIK-6735 fix 1, adversarial
/// review of commit bfd62b91). Gating `request_with_headers` on a single
/// backend-wide `Failsafe` meant one caller identity's transport failing
/// enough tripped the breaker for every OTHER identity sharing the same
/// backend too — the exact cross-tenant blast radius the per-user pool
/// exists to eliminate. Each slot now fails independently: the Shared slot
/// keeps its own failsafe (behavior for non-per-user backends is byte-for-
/// byte unchanged), and each `PerUser` slot gets a fresh one the moment it is
/// first created.
struct PooledEntry {
    transport: RwLock<Option<Arc<dyn Transport>>>,
    start_lock: Mutex<()>,
    last_used: AtomicU64,
    failsafe: Failsafe,
}

impl PooledEntry {
    fn new(name: &str, failsafe_config: &crate::config::FailsafeConfig) -> Self {
        Self {
            transport: RwLock::new(None),
            start_lock: Mutex::new(()),
            last_used: AtomicU64::new(now_unix_secs()),
            failsafe: Failsafe::new(name, failsafe_config),
        }
    }

    /// Mark this slot as used now, deferring its idle eviction.
    fn touch(&self) {
        self.last_used.store(now_unix_secs(), Ordering::Relaxed);
    }
}

/// MCP Backend - manages connection to a single MCP server
pub struct Backend {
    /// Backend name
    pub name: String,
    /// Configuration
    config: BackendConfig,
    /// Runtime plan compiled from the backend's configured runtime profile.
    runtime_plan: Option<RuntimePlan>,
    /// Per-identity transport/session pool (MIK-6735). Always holds the
    /// canonical [`PoolKey::Shared`] slot; gains one [`PoolKey::PerUser`] slot
    /// per caller identity when `session_mode = per_user`. Each slot carries its
    /// own transport and start lock, so concurrent warm-start/client requests do
    /// not spawn duplicate connections for the same slot and distinct users
    /// never share a session (IDP.7).
    pool: DashMap<PoolKey, Arc<PooledEntry>>,
    /// Failsafe configuration, cloned so a freshly created pool slot
    /// (`pooled_entry`) can build its own independent `Failsafe` (MIK-6735
    /// fix 1). The per-backend `Failsafe` this replaced is gone; every slot,
    /// including Shared, now owns one.
    failsafe_config: crate::config::FailsafeConfig,
    /// Cached tools
    tools_cache: CachedMetadata<Vec<Tool>>,
    /// Cached resources
    resources_cache: CachedMetadata<Vec<Resource>>,
    /// Cached resource templates
    resource_templates_cache: CachedMetadata<Vec<ResourceTemplate>>,
    /// Cached prompts
    prompts_cache: CachedMetadata<Vec<Prompt>>,
    /// Cache TTL
    cache_ttl: Duration,
    /// Last used timestamp
    last_used: AtomicU64,
    /// Concurrency limiter
    semaphore: Semaphore,
    /// Request counter
    request_count: AtomicU64,
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
            last_used: AtomicU64::new(0),
            semaphore: Semaphore::new(100), // Max concurrent requests
            request_count: AtomicU64::new(0),
        }
    }

    /// The backend's configured session mode, if identity propagation is set.
    fn session_mode(&self) -> Option<crate::identity_propagation::SessionMode> {
        self.config
            .identity_propagation
            .as_ref()
            .map(|c| c.session_mode)
    }

    /// Derive the pool slot for a request carrying `identity_key`.
    ///
    /// Only a `per_user` backend with a concrete caller identity gets its own
    /// slot; every other case — no identity propagation, `stateless`, or
    /// `per_user` without a resolved identity — collapses to the shared
    /// canonical slot, preserving single-tenant behavior byte-for-byte (IDP.5).
    fn pool_key_for(&self, identity_key: Option<&str>) -> PoolKey {
        use crate::identity_propagation::SessionMode;
        match (self.session_mode(), identity_key) {
            (Some(SessionMode::PerUser), Some(binding)) => PoolKey::PerUser {
                binding: binding.to_string(),
            },
            _ => PoolKey::Shared,
        }
    }

    /// Fetch (or lazily create) the pooled entry for `key`. The `Arc` is cloned
    /// out so the `DashMap` shard guard is released before any `.await`.
    ///
    /// Logs + gauges the live slot count on creation only (MIK-6735 fix 3) —
    /// minimal observability into per-user pool growth without a per-request
    /// cost on the (overwhelmingly more common) cache-hit path.
    fn pooled_entry(&self, key: &PoolKey) -> Arc<PooledEntry> {
        let mut created = false;
        let entry = Arc::clone(
            self.pool
                .entry(key.clone())
                .or_insert_with(|| {
                    created = true;
                    Arc::new(PooledEntry::new(&self.name, &self.failsafe_config))
                })
                .value(),
        );
        if created {
            #[allow(clippy::cast_precision_loss)] // pool size is never remotely close to 2^52
            let live = self.pool.len() as f64;
            telemetry_metrics::gauge!(
                "mcp_backend_pool_slots",
                "backend" => self.name.clone()
            )
            .set(live);
            tracing::debug!(backend = %self.name, ?key, live_slots = live, "Pool slot created");
        }
        entry
    }

    /// The canonical shared slot's `PooledEntry`. Inserted at construction and
    /// never evicted (`evict_idle_per_user_entries` explicitly skips it), so
    /// this is always present — used by status/metrics/health-loop accessors
    /// that intentionally report the backend-wide, single-tenant view
    /// regardless of how many per-user slots exist (MIK-6735 fix 1).
    fn shared_entry(&self) -> Arc<PooledEntry> {
        Arc::clone(
            self.pool
                .get(&PoolKey::Shared)
                .expect("PoolKey::Shared is inserted at construction and never evicted")
                .value(),
        )
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
    async fn ensure_entry_started(&self, key: &PoolKey) -> Result<Arc<dyn Transport>> {
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
    /// has registered under `key` (by `Arc::ptr_eq`) — i.e. that
    /// [`Backend::evict_idle_per_user_entries`] did not `remove_if` it out
    /// from under this in-flight start.
    ///
    /// Returns `Some(transport)` when `entry` is still live: the transport is
    /// visible to every future caller of `pooled_entry(key)` and callers here
    /// own nothing extra to clean up. Returns `None` when the race was lost:
    /// `entry` is orphaned (unreachable via `self.pool`), so nothing else will
    /// ever call `close()` on the transport just stored into it — there is no
    /// async `Drop` for `PooledEntry` — which would otherwise leak the
    /// underlying connection until OS teardown. In that case this method
    /// takes the transport back out and closes it itself before returning
    /// `None`, so the side that loses the race is the side that owns the
    /// close.
    async fn reconcile_after_start(
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
        let entry = self.pooled_entry(&PoolKey::Shared);
        self.start_entry(&PoolKey::Shared, &entry).await?;
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
                // single-tenant debug_assert provably safe — tell it so.
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
    fn create_oauth_client(&self, resource_url: &str) -> Result<Option<OAuthClient>> {
        let oauth_config = match &self.config.oauth {
            Some(cfg) if cfg.enabled => cfg,
            _ => return Ok(None),
        };

        // F3 sink-side guard. Config::validate() rejects this pairing at load,
        // but programmatic `Backend::new*()` and hot-reload `apply_patch()` build
        // backends from a raw BackendConfig without revalidating. Enforce again
        // here — the last chokepoint before an OAuth client is created — so an
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
                 credential override — silently defeating per-user propagation (F3).",
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

    fn resolve_stdio_runtime_launch(
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

    /// Get cached tools (or fetch if needed)
    ///
    /// Check if this backend has cached tools (non-blocking).
    ///
    /// Returns `true` if tools are cached and the cache hasn't expired.
    /// Used by `search_tools` to skip unstarted backends.
    #[must_use]
    pub fn has_cached_tools(&self) -> bool {
        self.tools_cache.is_fresh(self.cache_ttl)
    }

    /// Return the number of tools in the cache (non-blocking, no network I/O).
    ///
    /// Returns `0` when the cache is empty or has never been populated.
    /// This is intentionally best-effort: it reads whatever is in the cache
    /// without triggering a refresh, so the count may be stale.
    #[must_use]
    pub fn cached_tools_count(&self) -> usize {
        self.tools_cache
            .with_cached(|tools| tools.map_or(0, |tools| tools.len()))
    }

    /// Return the names of all cached tools (non-blocking, no network I/O).
    ///
    /// Returns an empty `Vec` when the cache is empty or has never been populated.
    /// Intended for producing "did you mean?" suggestions on unknown tool names.
    #[must_use]
    pub fn get_cached_tool_names(&self) -> Vec<String> {
        self.tools_cache.with_cached(|tools| {
            tools
                .map(|tools| tools.iter().map(|t| t.name.clone()).collect())
                .unwrap_or_default()
        })
    }

    /// Return a single tool by exact name from the cache (non-blocking, no network I/O).
    ///
    /// Returns `None` when the cache is empty, has never been populated, or does
    /// not contain a tool with the given name.  Intended for resolving surfaced
    /// tool schemas at `tools/list` time.
    #[must_use]
    pub fn get_cached_tool(&self, name: &str) -> Option<Tool> {
        self.tools_cache.with_cached(|tools| {
            tools.and_then(|tools| tools.iter().find(|t| t.name == name).cloned())
        })
    }

    /// Return a snapshot of all cached tools (non-blocking, no network I/O).
    ///
    /// Returns an empty shared vector when the cache is empty or has never been
    /// populated. Used by the `spec-preview` filtered `tools/list`
    /// implementation to avoid cloning the full tool list on every cache hit.
    #[must_use]
    pub fn get_cached_tools_snapshot(&self) -> Arc<Vec<Tool>> {
        self.tools_cache
            .snapshot_shared()
            .unwrap_or_else(|| Arc::new(Vec::new()))
    }

    async fn get_cached_list_shared<T, F>(
        &self,
        cache: &CachedMetadata<Vec<T>>,
        method: &str,
        kind: &'static str,
        parse: F,
    ) -> Result<Arc<Vec<T>>>
    where
        F: Fn(Value) -> Result<Vec<T>>,
    {
        cache
            .get_or_fetch_shared(self.cache_ttl, || async {
                self.ensure_started().await?;

                let response = self.request_internal(method, None).await?;
                if let Some(error) = response.error {
                    return Err(Error::json_rpc(error.code, error.message));
                }
                let items = if let Some(result) = response.result {
                    parse(result)?
                } else {
                    Vec::new()
                };

                debug!(backend = %self.name, kind, count = items.len(), "Backend metadata cached");

                Ok(items)
            })
            .await
    }

    /// # Errors
    ///
    /// Returns an error if the backend cannot start or the tools request fails.
    pub async fn get_tools_shared(&self) -> Result<Arc<Vec<Tool>>> {
        self.get_cached_list_shared(&self.tools_cache, "tools/list", "tools", |result| {
            let mut tools = serde_json::from_value::<ToolsListResult>(result)?.tools;
            normalize_tool_annotations(&self.name, &mut tools);
            Ok(tools)
        })
        .await
    }

    /// # Errors
    ///
    /// Returns an error if the backend cannot start or the tools request fails.
    pub async fn get_tools(&self) -> Result<Vec<Tool>> {
        self.get_tools_shared()
            .await
            .map(|tools| tools.as_ref().clone())
    }

    /// Get cached resources (or fetch if needed) without cloning the cached list.
    ///
    /// # Errors
    ///
    /// Returns an error if the backend cannot start or the resources request fails.
    pub async fn get_resources_shared(&self) -> Result<Arc<Vec<Resource>>> {
        self.get_cached_list_shared(
            &self.resources_cache,
            "resources/list",
            "resources",
            |result| Ok(serde_json::from_value::<ResourcesListResult>(result)?.resources),
        )
        .await
    }

    /// Get cached resources (or fetch if needed)
    ///
    /// # Errors
    ///
    /// Returns an error if the backend cannot start or the resources request fails.
    pub async fn get_resources(&self) -> Result<Vec<Resource>> {
        self.get_resources_shared()
            .await
            .map(|resources| resources.as_ref().clone())
    }

    /// Get cached resource templates (or fetch if needed) without cloning the cache.
    ///
    /// # Errors
    ///
    /// Returns an error if the backend cannot start or the templates request fails.
    pub async fn get_resource_templates_shared(&self) -> Result<Arc<Vec<ResourceTemplate>>> {
        self.get_cached_list_shared(
            &self.resource_templates_cache,
            "resources/templates/list",
            "resource_templates",
            |result| {
                Ok(
                    serde_json::from_value::<ResourcesTemplatesListResult>(result)?
                        .resource_templates,
                )
            },
        )
        .await
    }

    /// Get cached resource templates (or fetch if needed)
    ///
    /// # Errors
    ///
    /// Returns an error if the backend cannot start or the templates request fails.
    pub async fn get_resource_templates(&self) -> Result<Vec<ResourceTemplate>> {
        self.get_resource_templates_shared()
            .await
            .map(|templates| templates.as_ref().clone())
    }

    /// Get cached prompts (or fetch if needed) without cloning the cached list.
    ///
    /// # Errors
    ///
    /// Returns an error if the backend cannot start or the prompts request fails.
    pub async fn get_prompts_shared(&self) -> Result<Arc<Vec<Prompt>>> {
        self.get_cached_list_shared(&self.prompts_cache, "prompts/list", "prompts", |result| {
            Ok(serde_json::from_value::<PromptsListResult>(result)?.prompts)
        })
        .await
    }

    /// Get cached prompts (or fetch if needed)
    ///
    /// # Errors
    ///
    /// Returns an error if the backend cannot start or the prompts request fails.
    pub async fn get_prompts(&self) -> Result<Vec<Prompt>> {
        self.get_prompts_shared()
            .await
            .map(|prompts| prompts.as_ref().clone())
    }

    /// Clone the canonical shared slot's live transport, if started.
    fn shared_transport(&self) -> Option<Arc<dyn Transport>> {
        self.pool
            .get(&PoolKey::Shared)
            .and_then(|entry| entry.value().transport.read().clone())
    }

    /// Internal request without `ensure_started` (to avoid recursion)
    async fn request_internal(
        &self,
        method: &str,
        params: Option<Value>,
    ) -> Result<JsonRpcResponse> {
        let transport = self
            .shared_transport()
            .ok_or_else(|| Error::BackendUnavailable(self.name.clone()))?;

        transport.request(method, params).await
    }

    /// Send a request to the backend
    ///
    /// # Errors
    ///
    /// Returns an error if the backend is unavailable, the concurrency limit
    /// is reached, or the request itself fails after retries.
    #[tracing::instrument(
        skip(self, params),
        fields(
            backend = %self.name,
            method = %method,
            request_id = %uuid::Uuid::new_v4()
        )
    )]
    pub async fn request(&self, method: &str, params: Option<Value>) -> Result<JsonRpcResponse> {
        self.request_with_headers(method, params, &[], None).await
    }

    /// This backend's end-user identity-propagation config, if configured
    /// (MIK-6704 / ADR-007). `None` → static-credential behavior unchanged.
    #[must_use]
    pub fn identity_propagation_config(
        &self,
    ) -> Option<&crate::identity_propagation::IdentityPropagationConfig> {
        self.config.identity_propagation.as_ref()
    }

    /// Whether this backend's configured transport can carry per-request
    /// outbound headers, e.g. a propagated end-user identity credential
    /// (MIK-6710).
    ///
    /// Delegates to [`TransportConfig::carries_identity_headers`], which is
    /// evaluated from config alone — valid before [`Backend::start`] has ever
    /// run. The identity-propagation dispatch gate
    /// (`MetaMcp::resolve_caller_credential`, the direct backend route's
    /// passthrough branch) checks this BEFORE minting or forwarding a
    /// credential, so a `required` backend bound to a transport that would
    /// silently drop `extra_headers` (stdio, websocket) is refused instead of
    /// running unauthenticated.
    #[must_use]
    pub fn transport_carries_identity_headers(&self) -> bool {
        self.config.transport.carries_identity_headers()
    }

    /// Whether this backend relies on a single gateway-held OAuth token that is
    /// NOT blessed for shared use (ADR-008 INV-2).
    ///
    /// `true` means the gateway stores one token for this backend and would
    /// attach it to any caller's request — unsafe on a multi-user gateway
    /// unless a per-user credential is supplied instead. The dispatch guard
    /// uses this to fail closed. `oauth.shared_account = true` opts out (the
    /// operator has declared the account genuinely shared).
    #[must_use]
    pub fn oauth_requires_per_user_isolation(&self) -> bool {
        self.config
            .oauth
            .as_ref()
            .is_some_and(|o| o.enabled && !o.shared_account)
    }

    /// Send a request, adding per-request outbound headers (e.g. a propagated
    /// end-user identity credential — MIK-6704). The headers are forwarded by
    /// value to the transport's `request_with_headers`, never stored on the
    /// backend, so concurrent per-user requests stay isolated (IDP.3).
    ///
    /// `identity_key` is the caller's stable identity binding (MIK-6784); the
    /// transport uses it to partition upstream `MCP-Session-Id` state so one
    /// user's session is never reused for another. `None` selects the shared
    /// default bucket (single-tenant behavior unchanged).
    ///
    /// # Errors
    ///
    /// Returns an error if the backend is unavailable, the concurrency limit
    /// is reached, or the request itself fails after retries.
    pub async fn request_with_headers(
        &self,
        method: &str,
        params: Option<Value>,
        extra_headers: &[(String, String)],
        identity_key: Option<&str>,
    ) -> Result<JsonRpcResponse> {
        let start_time = std::time::Instant::now();

        // Derive the per-identity pool slot FIRST (MIK-6735 fix 1, adversarial
        // review of commit bfd62b91). Each slot owns its own circuit breaker +
        // rate limiter + health tracker, so which slot's failsafe to gate on
        // must be known before the `can_proceed()` check runs — gating on a
        // single backend-wide `Failsafe` let one caller identity's outage trip
        // the breaker for every other identity sharing the backend, the exact
        // cross-tenant blast radius this pool exists to eliminate. A non-per-
        // user backend, or a per-user backend request without a resolved
        // identity, collapses to the shared canonical slot (IDP.5); a per-user
        // request gets its own transport/session/failsafe so users never
        // collide (IDP.7).
        let key = self.pool_key_for(identity_key);
        let entry = self.pooled_entry(&key);

        // Check THIS slot's failsafe, not the backend's.
        if !entry.failsafe.can_proceed() {
            telemetry_metrics::gauge!(
                "mcp_backend_circuit_state",
                "backend" => self.name.clone()
            )
            .set(0.0_f64);
            tracing::warn!(backend = %self.name, ?key, "Request rejected by circuit breaker");
            return Err(Error::CircuitOpen(self.name.clone()));
        }
        telemetry_metrics::gauge!(
            "mcp_backend_circuit_state",
            "backend" => self.name.clone()
        )
        .set(1.0_f64);

        // Acquire semaphore
        let _permit = self.semaphore.acquire().await.map_err(|_| {
            tracing::warn!("Concurrency limit reached");
            Error::BackendUnavailable("Concurrency limit reached".to_string())
        })?;

        self.request_count.fetch_add(1, Ordering::Relaxed);

        // Ensure this slot's transport is live.
        let transport = self.ensure_entry_started(&key).await?;

        // Execute with retry
        let name = self.name.clone();
        // Own the identity key so the retry closure (Fn, invoked once per
        // attempt) can hand a borrow to each attempt's future without tying the
        // closure to the caller's borrow lifetime (MIK-6784).
        let identity_key = identity_key.map(str::to_string);
        let result = with_retry(&entry.failsafe.retry_policy, &name, || {
            let transport = Arc::clone(&transport);
            let method = method.to_string();
            let params = params.clone();
            let extra_headers = extra_headers.to_vec();
            let identity_key = identity_key.clone();
            async move {
                transport
                    .request_with_headers(&method, params, &extra_headers, identity_key.as_deref())
                    .await
            }
        })
        .await;

        // Calculate latency
        let latency = start_time.elapsed();

        // Record success/failure against the SAME slot's failsafe used for the
        // `can_proceed()` gate above, so gating and recording are always
        // symmetric even if a concurrent idle-eviction later replaces this
        // slot's `PooledEntry` for `key` (MIK-6735 fix 1).
        match &result {
            Ok(_) => {
                tracing::info!(
                    latency_ms = latency.as_millis(),
                    "Request completed successfully"
                );
                entry.failsafe.record_success(latency);
                telemetry_metrics::counter!(
                    "mcp_backend_requests_total",
                    "backend" => self.name.clone(),
                    "status" => "ok"
                )
                .increment(1);
            }
            Err(e) => {
                tracing::error!(error = %e, latency_ms = latency.as_millis(), "Request failed");
                entry.failsafe.record_failure(&e.to_string(), latency);
                telemetry_metrics::counter!(
                    "mcp_backend_requests_total",
                    "backend" => self.name.clone(),
                    "status" => "error"
                )
                .increment(1);
            }
        }
        telemetry_metrics::histogram!(
            "mcp_backend_request_duration_seconds",
            "backend" => self.name.clone()
        )
        .record(latency.as_secs_f64());

        result
    }

    /// Send a notification to the backend via the canonical shared slot's
    /// session (non-per-user backends; single-tenant behavior unchanged).
    ///
    /// # Errors
    ///
    /// Returns an error if the backend is unavailable, the concurrency limit
    /// is reached, or the notification cannot be sent.
    pub async fn notify(&self, method: &str, params: Option<Value>) -> Result<()> {
        self.notify_with_headers(method, params, None).await
    }

    /// Send a notification carrying the caller's identity key so it is routed
    /// through the SAME pool slot — and the SAME upstream `MCP-Session-Id`
    /// bucket — that a prior `request_with_headers` call for that identity
    /// used (MIK-6735 fix 2, adversarial review of commit bfd62b91).
    ///
    /// Before this fix, every notification hardcoded `ensure_started()` (the
    /// canonical Shared slot) regardless of the caller's identity, so on a
    /// `PerUser` backend a notification correlating a request that went
    /// through a per-user slot (e.g. `notifications/cancelled`) went out on
    /// the wrong upstream session — or, even once routed to the right
    /// transport instance, with no session ID at all, since
    /// [`crate::transport::Transport::notify`] never threaded an identity key
    /// through to the transport's session-bucket lookup either. Both layers
    /// are fixed together here: `identity_key` selects the same `PoolKey` as
    /// `request_with_headers` (IDP.7), and is forwarded to
    /// [`crate::transport::Transport::notify_with_headers`] so an HTTP
    /// transport selects the matching `MCP-Session-Id` bucket. `None`
    /// preserves the unchanged Shared-slot path (IDP.5).
    ///
    /// # Errors
    ///
    /// Returns an error if the backend is unavailable, the concurrency limit
    /// is reached, or the notification cannot be sent.
    #[tracing::instrument(
        skip(self, params),
        fields(
            backend = %self.name,
            method = %method,
            request_id = %uuid::Uuid::new_v4()
        )
    )]
    pub async fn notify_with_headers(
        &self,
        method: &str,
        params: Option<Value>,
        identity_key: Option<&str>,
    ) -> Result<()> {
        let start_time = std::time::Instant::now();

        // Derive the same slot `request_with_headers` would use for this
        // identity, and gate/record against ITS failsafe (mirrors fix 1).
        let key = self.pool_key_for(identity_key);
        let entry = self.pooled_entry(&key);

        if !entry.failsafe.can_proceed() {
            telemetry_metrics::gauge!(
                "mcp_backend_circuit_state",
                "backend" => self.name.clone()
            )
            .set(0.0_f64);
            tracing::warn!(backend = %self.name, ?key, "Notification rejected by circuit breaker");
            return Err(Error::CircuitOpen(self.name.clone()));
        }
        telemetry_metrics::gauge!(
            "mcp_backend_circuit_state",
            "backend" => self.name.clone()
        )
        .set(1.0_f64);

        let _permit = self.semaphore.acquire().await.map_err(|_| {
            tracing::warn!("Concurrency limit reached");
            Error::BackendUnavailable("Concurrency limit reached".to_string())
        })?;

        self.request_count.fetch_add(1, Ordering::Relaxed);

        let transport = self.ensure_entry_started(&key).await?;

        let result = transport
            .notify_with_headers(method, params, identity_key)
            .await;
        let latency = start_time.elapsed();

        match &result {
            Ok(()) => {
                tracing::info!(
                    latency_ms = latency.as_millis(),
                    "Notification sent successfully"
                );
                entry.failsafe.record_success(latency);
                telemetry_metrics::counter!(
                    "mcp_backend_requests_total",
                    "backend" => self.name.clone(),
                    "status" => "ok"
                )
                .increment(1);
            }
            Err(e) => {
                tracing::error!(error = %e, latency_ms = latency.as_millis(), "Notification failed");
                entry.failsafe.record_failure(&e.to_string(), latency);
                telemetry_metrics::counter!(
                    "mcp_backend_requests_total",
                    "backend" => self.name.clone(),
                    "status" => "error"
                )
                .increment(1);
            }
        }
        telemetry_metrics::histogram!(
            "mcp_backend_request_duration_seconds",
            "backend" => self.name.clone()
        )
        .record(latency.as_secs_f64());

        result
    }

    #[cfg(test)]
    pub(crate) fn set_transport_for_test(&self, transport: Arc<dyn Transport>) {
        let entry = self.pooled_entry(&PoolKey::Shared);
        *entry.transport.write() = Some(transport);
    }

    /// Test-only: inject a transport into a specific pool slot so isolation
    /// tests can seed distinct per-user sessions (MIK-6735 POOL.4).
    #[cfg(test)]
    fn set_pooled_transport_for_test(&self, key: &PoolKey, transport: Arc<dyn Transport>) {
        let entry = self.pooled_entry(key);
        *entry.transport.write() = Some(transport);
    }

    /// Test-only: clone the transport `Arc` stored in a specific pool slot, so
    /// isolation tests can assert distinct instances via `Arc::ptr_eq`.
    #[cfg(test)]
    fn pooled_transport_for_test(&self, key: &PoolKey) -> Option<Arc<dyn Transport>> {
        self.pool
            .get(key)
            .and_then(|entry| entry.value().transport.read().clone())
    }

    /// Test-only: trip this backend's canonical Shared-slot circuit breaker
    /// open by recording `failure_threshold` consecutive failures.
    #[cfg(test)]
    pub(crate) fn trip_circuit_breaker_for_test(&self) {
        self.trip_circuit_breaker_for_test_key(&PoolKey::Shared);
    }

    /// Test-only: trip an arbitrary pool slot's circuit breaker open
    /// (MIK-6735 fix 1) — generalizes [`Self::trip_circuit_breaker_for_test`]
    /// (Shared-only) to any [`PoolKey`], so cross-tenant isolation tests can
    /// trip one identity's slot without touching another's.
    #[cfg(test)]
    fn trip_circuit_breaker_for_test_key(&self, key: &PoolKey) {
        let entry = self.pooled_entry(key);
        let threshold = entry.failsafe.circuit_breaker.stats().failure_threshold;
        for _ in 0..threshold {
            entry
                .failsafe
                .circuit_breaker
                .record_failure("test-trip", std::time::Duration::ZERO);
        }
    }

    /// Return `true` if this backend is configured for pass-through mode.
    ///
    /// When `true`, the direct `/mcp/{name}` endpoint skips tool policy
    /// enforcement and input sanitization for `tools/call` requests.
    /// This must only be enabled for fully-trusted internal backends.
    #[must_use]
    pub fn passthrough(&self) -> bool {
        self.config.passthrough
    }

    /// Return the HTTP URL if this backend uses an HTTP-based transport.
    ///
    /// Returns `None` for stdio backends.
    #[must_use]
    pub fn transport_url(&self) -> Option<&str> {
        match &self.config.transport {
            TransportConfig::Http { http_url, .. } => Some(http_url.as_str()),
            TransportConfig::Stdio { .. } => None,
            #[cfg(feature = "a2a")]
            TransportConfig::A2a { a2a_url, .. } => Some(a2a_url.as_str()),
        }
    }

    /// Get backend status.
    ///
    /// Reports the canonical Shared slot's circuit/health state (MIK-6735
    /// fix 1): this is the backend-wide, single-tenant view — the same one
    /// `status()` reported before per-user slots existed — and deliberately
    /// does not aggregate across per-user slots, which each fail
    /// independently and are not surfaced individually here.
    pub fn status(&self) -> BackendStatus {
        let entry = self.shared_entry();
        let health = entry.failsafe.health_metrics();
        BackendStatus {
            name: self.name.clone(),
            running: self.is_running(),
            transport: self.config.transport.transport_type().to_string(),
            tools_cached: self.cached_tools_count(),
            circuit_state: entry.failsafe.circuit_breaker.state().as_str().to_string(),
            request_count: self.request_count.load(Ordering::Relaxed),
            healthy: health.healthy,
            consecutive_failures: health.consecutive_failures,
            latency_p95_ms: health.latency_p95_ms,
            runtime: self.runtime_status(),
        }
    }

    fn runtime_status(&self) -> Option<BackendRuntimeStatus> {
        let plan = self.runtime_plan.as_ref()?;
        let state = if plan.is_denied() {
            BackendRuntimeState::Denied
        } else if plan.requires_confirmation() {
            BackendRuntimeState::ConfirmationRequired
        } else {
            BackendRuntimeState::Ready
        };

        Some(BackendRuntimeStatus {
            profile: self
                .config
                .runtime_profile
                .clone()
                .unwrap_or_else(|| plan.policy.id.clone()),
            provider: plan.provider,
            policy_id: plan.policy.id.clone(),
            license_tier: plan.audit.license_tier,
            state,
            denied_reasons: plan.denied.iter().map(|denial| denial.reason).collect(),
            confirmation_ids: plan
                .confirmations
                .iter()
                .map(|confirmation| confirmation.id.clone())
                .collect(),
            restart_max_attempts: plan.policy.restart.max_restarts,
            restart_backoff_secs: plan.policy.restart.backoff_secs,
            health_check: plan.lifecycle.health_check.clone(),
            restart_command_hint: plan.lifecycle.restart_command_hint.clone(),
            rollback_step: plan.rollback_step.clone(),
        })
    }

    /// Get circuit breaker stats for this backend's canonical Shared slot
    /// (MIK-6735 fix 1).
    pub fn circuit_breaker_stats(&self) -> crate::failsafe::CircuitBreakerStats {
        self.shared_entry().failsafe.circuit_breaker.stats()
    }

    /// Force this backend's canonical Shared-slot circuit breaker back to
    /// `Closed` (MIK-5983; slot-scoped per MIK-6735 fix 1).
    ///
    /// Called by `gateway_revive_server` so the documented manual recovery
    /// path also clears a tripped breaker, not just the kill switch.
    pub fn reset_circuit_breaker(&self) {
        self.shared_entry().failsafe.circuit_breaker.reset();
    }

    /// Whether this backend's canonical Shared-slot circuit breaker is
    /// currently tripped (`Open` or `HalfOpen` — i.e. not `Closed`; slot-scoped
    /// per MIK-6735 fix 1).
    #[must_use]
    pub fn is_circuit_tripped(&self) -> bool {
        self.shared_entry().failsafe.circuit_breaker.state()
            != crate::failsafe::CircuitState::Closed
    }

    /// Tear down the current transport (killing any child process) and start a
    /// fresh one.
    ///
    /// Unlike [`ensure_started`](Self::ensure_started), this does **not** trust
    /// `is_connected()` — it always rebuilds. A wedged-but-not-exited child
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
        // awaiting close() — a parking_lot guard is not Send across an await.
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
    ///    returns `CircuitOpen` *without touching the backend* — so it could
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
    /// trip — this probe never records failures, only recoveries.
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
            Ok(Ok(_)) => {
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

    /// Get health metrics for this backend's canonical Shared slot (MIK-6735
    /// fix 1).
    pub fn health_metrics(&self) -> crate::failsafe::HealthMetrics {
        self.shared_entry().failsafe.health_metrics()
    }

    /// Idle-evict per-user pool slots whose last use predates `idle_ttl`,
    /// closing their transports. The canonical [`PoolKey::Shared`] slot is never
    /// evicted (it backs init, metadata, and single-tenant traffic). Returns the
    /// number of slots closed (MIK-6735 POOL.2).
    pub async fn evict_idle_per_user_entries(&self, idle_ttl: Duration) -> usize {
        let cutoff = idle_ttl.as_secs();

        // First pass: collect candidate keys without holding a guard across the
        // async close(). Skip the shared slot outright.
        let candidates: Vec<PoolKey> = self
            .pool
            .iter()
            .filter(|entry| !matches!(entry.key(), PoolKey::Shared))
            .map(|entry| entry.key().clone())
            .collect();

        let mut closed = 0;
        for key in candidates {
            // Atomically remove only if STILL idle — re-checked inside the shard
            // lock so a request that touched the slot after the first pass keeps
            // it alive and is never torn down mid-flight.
            let removed = self.pool.remove_if(&key, |k, entry| {
                !matches!(k, PoolKey::Shared)
                    && now_unix_secs().saturating_sub(entry.last_used.load(Ordering::Relaxed))
                        >= cutoff
            });
            if let Some((_, entry)) = removed {
                let transport = entry.transport.write().take();
                if let Some(transport) = transport {
                    let _ = transport.close().await;
                }
                closed += 1;
            }
        }
        if closed > 0 {
            // MIK-6735 fix 3: gauge + log the live slot count after eviction,
            // mirroring the creation-side observability in `pooled_entry`.
            #[allow(clippy::cast_precision_loss)] // pool size is never remotely close to 2^52
            let live = self.pool.len() as f64;
            telemetry_metrics::gauge!(
                "mcp_backend_pool_slots",
                "backend" => self.name.clone()
            )
            .set(live);
            tracing::debug!(
                backend = %self.name,
                evicted = closed,
                live_slots = live,
                "Idle per-user pool slots evicted"
            );
        }
        closed
    }
}

struct ResolvedStdioLaunch {
    command: String,
    env: HashMap<String, String>,
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

/// Backend status information
#[derive(Debug, Clone, serde::Serialize)]
pub struct BackendStatus {
    /// Backend name
    pub name: String,
    /// Whether backend is running
    pub running: bool,
    /// Transport type
    pub transport: String,
    /// Number of cached tools
    pub tools_cached: usize,
    /// Circuit breaker state
    pub circuit_state: String,
    /// Total request count
    pub request_count: u64,
    /// Health-tracker liveness (flips false after consecutive failures, e.g.
    /// timeouts under load, *before* the circuit breaker trips Open). `/health`
    /// must consider this so it does not report healthy while a backend is
    /// silently timing out (see issue #5080 / MIK-5080).
    pub healthy: bool,
    /// Consecutive failures recorded by the health tracker.
    pub consecutive_failures: u64,
    /// 95th percentile latency in milliseconds, if any samples exist.
    pub latency_p95_ms: Option<u64>,
    /// Runtime profile lifecycle state for admin/operator surfaces.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub runtime: Option<BackendRuntimeStatus>,
}

/// Runtime profile status information exposed through backend status.
#[derive(Debug, Clone, serde::Serialize, PartialEq, Eq)]
pub struct BackendRuntimeStatus {
    /// Runtime profile selected by this backend.
    pub profile: String,
    /// Provider selected by the compiled runtime plan.
    pub provider: RuntimeProviderKind,
    /// Policy id used for audit correlation.
    pub policy_id: String,
    /// License tier that owns this runtime provider capability.
    pub license_tier: RuntimeLicenseTier,
    /// Whether the runtime plan is ready, denied, or waiting for approval.
    pub state: BackendRuntimeState,
    /// Fail-closed denial reasons, when any.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub denied_reasons: Vec<RuntimeDenyReason>,
    /// Confirmation ids required before live start or provider apply.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub confirmation_ids: Vec<String>,
    /// Maximum restart attempts from the compiled policy.
    pub restart_max_attempts: u32,
    /// Restart backoff from the compiled policy.
    pub restart_backoff_secs: u64,
    /// Provider-specific health check instruction or command.
    pub health_check: String,
    /// Provider-specific restart command hint, when available.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub restart_command_hint: Option<String>,
    /// Rollback instruction for this runtime plan.
    pub rollback_step: String,
}

/// Compiled runtime plan state for a backend.
#[derive(Debug, Clone, Copy, serde::Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum BackendRuntimeState {
    /// Policy passed without pending human gates.
    Ready,
    /// Policy requires explicit human approval before execution.
    ConfirmationRequired,
    /// Policy denied execution and must fail closed.
    Denied,
}

/// Backend registry - manages all backends
pub struct BackendRegistry {
    /// Backends by name
    backends: DashMap<String, Arc<Backend>>,
}

impl BackendRegistry {
    /// Create a new registry
    #[must_use]
    pub fn new() -> Self {
        Self {
            backends: DashMap::new(),
        }
    }

    /// Register a backend
    pub fn register(&self, backend: Arc<Backend>) {
        self.backends.insert(backend.name.clone(), backend);
    }

    /// Get a backend by name
    #[must_use]
    pub fn get(&self, name: &str) -> Option<Arc<Backend>> {
        self.backends.get(name).map(|b| Arc::clone(&*b))
    }

    /// Get all backends
    #[must_use]
    pub fn all(&self) -> Vec<Arc<Backend>> {
        self.backends.iter().map(|b| Arc::clone(&*b)).collect()
    }

    /// Get all backend statuses
    #[must_use]
    pub fn statuses(&self) -> HashMap<String, BackendStatus> {
        self.backends
            .iter()
            .map(|b| (b.name.clone(), b.status()))
            .collect()
    }

    /// Remove a backend by name (deregister without stopping).
    ///
    /// If the backend must be stopped before removal, call `backend.stop()`
    /// first.  Returns `true` when the backend was present and removed.
    pub fn remove(&self, name: &str) -> bool {
        self.backends.remove(name).is_some()
    }

    /// Stop all backends
    pub async fn stop_all(&self) {
        for backend in &self.backends {
            if let Err(e) = backend.stop().await {
                warn!(backend = %backend.name, error = %e, "Failed to stop backend");
            }
        }
    }
}

impl Default for BackendRegistry {
    fn default() -> Self {
        Self::new()
    }
}

pub(crate) fn normalize_tool_annotations(server: &str, tools: &mut [Tool]) {
    for tool in tools {
        let inferred_read_only = infer_read_only_tool(&tool.name);
        let annotations = tool
            .annotations
            .get_or_insert_with(ToolAnnotations::default);
        let read_only = annotations.read_only_hint.unwrap_or(inferred_read_only);
        let destructive = annotations
            .destructive_hint
            .unwrap_or_else(|| infer_destructive_tool(&tool.name, read_only));

        annotations.read_only_hint = Some(read_only);
        annotations.destructive_hint = Some(destructive);
        annotations.idempotent_hint = Some(
            annotations
                .idempotent_hint
                .unwrap_or_else(|| infer_idempotent_tool(&tool.name, read_only, destructive)),
        );
        annotations.open_world_hint = Some(
            annotations
                .open_world_hint
                .unwrap_or_else(|| infer_open_world_tool(server, &tool.name)),
        );
    }
}

fn infer_read_only_tool(name: &str) -> bool {
    let name = name.to_ascii_lowercase();
    let read_prefixes = [
        "analyze",
        "auth_lookup",
        "benchmark",
        "calculate",
        "check",
        "classify",
        "count",
        "describe",
        "detect",
        "estimate",
        "fetch",
        "find",
        "fingerprint",
        "get",
        "health",
        "info",
        "list",
        "lookup",
        "preview",
        "query",
        "read",
        "recall",
        "search",
        "status",
        "suggest",
        "validate",
        "verify",
    ];
    read_prefixes
        .iter()
        .any(|prefix| name == *prefix || name.starts_with(&format!("{prefix}_")))
}

fn infer_destructive_tool(name: &str, read_only: bool) -> bool {
    if read_only {
        return false;
    }

    let name = name.to_ascii_lowercase();
    let destructive_words = [
        "archive", "bash", "clear", "delete", "forget", "kill", "login", "post", "remove", "run",
        "send", "submit", "type", "write",
    ];
    destructive_words.iter().any(|word| name.contains(word))
}

fn infer_idempotent_tool(name: &str, read_only: bool, destructive: bool) -> bool {
    if read_only {
        return true;
    }
    if destructive {
        return false;
    }

    let name = name.to_ascii_lowercase();
    name.starts_with("set_")
        || name.starts_with("clear_")
        || name.starts_with("focus_")
        || name.starts_with("connect")
}

fn infer_open_world_tool(server: &str, name: &str) -> bool {
    let server = server.to_ascii_lowercase();
    let name = name.to_ascii_lowercase();

    if matches!(
        server.as_str(),
        "hebb" | "metacognition" | "pithy" | "cached-grep" | "haiku-file-reader"
    ) {
        return false;
    }

    if name.contains("validate") || name.contains("fingerprint") || name.contains("auth_lookup") {
        return false;
    }

    true
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    use async_trait::async_trait;
    use serde_json::json;
    use tokio::sync::Barrier;
    use tokio::time::sleep;

    use super::*;
    use crate::protocol::{RequestId, ToolsListResult};

    struct MockTransport {
        response: JsonRpcResponse,
        delay: Duration,
        connected: AtomicBool,
        requests: AtomicUsize,
    }

    impl MockTransport {
        fn new(response: JsonRpcResponse, delay: Duration) -> Self {
            Self {
                response,
                delay,
                connected: AtomicBool::new(true),
                requests: AtomicUsize::new(0),
            }
        }
    }

    #[async_trait]
    impl Transport for MockTransport {
        async fn request(&self, method: &str, _params: Option<Value>) -> Result<JsonRpcResponse> {
            assert_eq!(method, "tools/list");
            self.requests.fetch_add(1, Ordering::SeqCst);
            sleep(self.delay).await;
            Ok(self.response.clone())
        }

        async fn notify(&self, _method: &str, _params: Option<Value>) -> Result<()> {
            Ok(())
        }

        fn is_connected(&self) -> bool {
            self.connected.load(Ordering::Relaxed)
        }

        async fn close(&self) -> Result<()> {
            self.connected.store(false, Ordering::Relaxed);
            Ok(())
        }
    }

    // Method-agnostic transport for health-probe / recovery tests: answers any
    // request with success unless `fail` is set, with a settable `connected`
    // flag. Distinct from MockTransport, which hard-asserts "tools/list".
    struct RecoveryMock {
        connected: AtomicBool,
        fail: AtomicBool,
        pings: AtomicUsize,
    }

    impl RecoveryMock {
        fn connected() -> Self {
            Self {
                connected: AtomicBool::new(true),
                fail: AtomicBool::new(false),
                pings: AtomicUsize::new(0),
            }
        }
    }

    #[async_trait]
    impl Transport for RecoveryMock {
        async fn request(&self, _method: &str, _params: Option<Value>) -> Result<JsonRpcResponse> {
            self.pings.fetch_add(1, Ordering::SeqCst);
            if self.fail.load(Ordering::Relaxed) {
                return Err(Error::BackendUnavailable("probe failed".to_string()));
            }
            Ok(JsonRpcResponse::success_serialized(
                RequestId::Number(1),
                json!({}),
            ))
        }

        async fn notify(&self, _method: &str, _params: Option<Value>) -> Result<()> {
            Ok(())
        }

        fn is_connected(&self) -> bool {
            self.connected.load(Ordering::Relaxed)
        }

        async fn close(&self) -> Result<()> {
            self.connected.store(false, Ordering::Relaxed);
            Ok(())
        }
    }

    #[tokio::test]
    async fn is_circuit_tripped_reflects_breaker_state() {
        let backend = Backend::new(
            "test",
            BackendConfig::default(),
            &crate::config::FailsafeConfig::default(),
            Duration::from_secs(60),
        );
        assert!(!backend.is_circuit_tripped());
        backend.trip_circuit_breaker_for_test();
        assert!(backend.is_circuit_tripped());
        backend.reset_circuit_breaker();
        assert!(!backend.is_circuit_tripped());
    }

    // Headline regression: a successful health probe must auto-reset a tripped
    // breaker. This is the recovery the old health check could never perform,
    // because it pinged through the breaker (which short-circuits when Open).
    #[tokio::test]
    async fn health_probe_resets_tripped_breaker_on_success() {
        let backend = Arc::new(Backend::new(
            "test",
            BackendConfig::default(),
            &crate::config::FailsafeConfig::default(),
            Duration::from_secs(60),
        ));
        let mock = Arc::new(RecoveryMock::connected());
        backend.set_transport_for_test(mock.clone() as Arc<dyn Transport>);

        backend.trip_circuit_breaker_for_test();
        assert!(backend.is_circuit_tripped(), "precondition: breaker open");

        backend
            .health_probe(Duration::from_secs(5))
            .await
            .expect("probe should succeed");

        assert!(
            !backend.is_circuit_tripped(),
            "a successful probe must reset the tripped breaker"
        );
        assert_eq!(mock.pings.load(Ordering::SeqCst), 1);
    }

    // A failing probe must NOT reset the breaker — recovery is success-gated.
    #[tokio::test]
    async fn health_probe_failure_leaves_breaker_tripped() {
        let backend = Arc::new(Backend::new(
            "test",
            BackendConfig::default(),
            &crate::config::FailsafeConfig::default(),
            Duration::from_secs(60),
        ));
        let mock = Arc::new(RecoveryMock::connected());
        mock.fail.store(true, Ordering::Relaxed);
        backend.set_transport_for_test(mock.clone() as Arc<dyn Transport>);

        backend.trip_circuit_breaker_for_test();
        let result = backend.health_probe(Duration::from_secs(5)).await;

        assert!(result.is_err(), "failed probe returns Err");
        assert!(
            backend.is_circuit_tripped(),
            "a failed probe must leave the breaker tripped"
        );
    }

    #[test]
    fn oauth_requires_per_user_isolation_reflects_config() {
        let mk = |oauth: Option<crate::config::OAuthConfig>| {
            Backend::new(
                "b",
                BackendConfig {
                    oauth,
                    ..BackendConfig::default()
                },
                &crate::config::FailsafeConfig::default(),
                Duration::from_secs(60),
            )
        };
        let oauth = |enabled: bool, shared: bool| crate::config::OAuthConfig {
            enabled,
            scopes: vec![],
            client_id: None,
            client_secret: None,
            callback_host: None,
            callback_port: None,
            callback_path: None,
            token_refresh_buffer_secs: 300,
            shared_account: shared,
        };
        // Enabled, gateway-held, not blessed shared → guard MUST fire.
        assert!(
            mk(Some(oauth(true, false))).oauth_requires_per_user_isolation(),
            "enabled non-shared gateway-held OAuth must require per-user isolation"
        );
        // Operator blessed the account as shared → no isolation required.
        assert!(
            !mk(Some(oauth(true, true))).oauth_requires_per_user_isolation(),
            "shared_account=true opts out of the isolation guard"
        );
        // OAuth disabled → nothing to isolate.
        assert!(!mk(Some(oauth(false, false))).oauth_requires_per_user_isolation());
        // No OAuth config → nothing to isolate.
        assert!(!mk(None).oauth_requires_per_user_isolation());
    }

    // F3 sink-side guard (MIK-6746): even when Config::validate() is bypassed
    // by programmatic construction, create_oauth_client() must refuse to build a
    // backend OAuth client for a backend that also declares identity_propagation.
    // The backend OAuth would persist a gateway-held token during initialize(),
    // authenticating the transport session as the gateway before any per-request
    // per-user override — silently defeating per-user propagation. Fail closed at
    // the last chokepoint. Contradiction holds for BOTH implemented strategies.
    #[test]
    fn create_oauth_client_refuses_identity_propagation_backends() {
        let oauth_enabled = crate::config::OAuthConfig {
            enabled: true,
            scopes: vec![],
            client_id: None,
            client_secret: None,
            callback_host: None,
            callback_port: None,
            callback_path: None,
            token_refresh_buffer_secs: 300,
            shared_account: false,
        };
        let idp = |strategy: crate::identity_propagation::PropagationStrategyKind| {
            crate::identity_propagation::IdentityPropagationConfig {
                strategy,
                audience: "https://backend.example".to_string(),
                required: true,
                session_mode: crate::identity_propagation::SessionMode::Stateless,
                token_exchange_endpoint: None,
                token_exchange_scope: None,
            }
        };
        let mk = |strategy| {
            Backend::new(
                "b",
                BackendConfig {
                    oauth: Some(oauth_enabled.clone()),
                    identity_propagation: Some(idp(strategy)),
                    ..BackendConfig::default()
                },
                &crate::config::FailsafeConfig::default(),
                Duration::from_secs(60),
            )
        };
        for strategy in [
            crate::identity_propagation::PropagationStrategyKind::SignedAssertion,
            crate::identity_propagation::PropagationStrategyKind::Passthrough,
        ] {
            let backend = mk(strategy);
            match backend.create_oauth_client("https://backend.example") {
                Err(Error::ConfigValidation(_)) => {}
                Err(other) => {
                    panic!("expected ConfigValidation, got {other:?} for {strategy:?}")
                }
                Ok(_) => panic!(
                    "enabled backend oauth + identity_propagation must fail closed for {strategy:?}"
                ),
            }
        }

        // shared_account=true does NOT exempt: sharing one gateway-held token
        // still contradicts per-user propagation.
        let shared = Backend::new(
            "b",
            BackendConfig {
                oauth: Some(crate::config::OAuthConfig {
                    shared_account: true,
                    ..oauth_enabled.clone()
                }),
                identity_propagation: Some(idp(
                    crate::identity_propagation::PropagationStrategyKind::SignedAssertion,
                )),
                ..BackendConfig::default()
            },
            &crate::config::FailsafeConfig::default(),
            Duration::from_secs(60),
        );
        assert!(
            shared
                .create_oauth_client("https://backend.example")
                .is_err(),
            "shared_account=true must not exempt the F3 guard"
        );

        // No identity_propagation → enabled backend oauth proceeds (returns a
        // client), proving the guard does not over-reach.
        let plain = Backend::new(
            "b",
            BackendConfig {
                oauth: Some(oauth_enabled.clone()),
                ..BackendConfig::default()
            },
            &crate::config::FailsafeConfig::default(),
            Duration::from_secs(60),
        );
        assert!(
            plain.create_oauth_client("https://backend.example").is_ok(),
            "backend oauth without identity_propagation must still be allowed"
        );
    }

    #[test]
    fn backend_status_surfaces_ready_runtime_profile_lifecycle() {
        let cfg = BackendConfig {
            transport: TransportConfig::Stdio {
                command: "mcp-docs-server --stdio".to_string(),
                cwd: None,
                protocol_version: None,
            },
            runtime_profile: Some("containerized".to_string()),
            ..BackendConfig::default()
        };

        let mut runtime = crate::config::RuntimeConfig::default();
        runtime.availability.docker = true;
        runtime.profiles.insert(
            "containerized".to_string(),
            crate::config::RuntimeProfileConfig {
                provider: Some(crate::runtime::RuntimeProviderKind::Docker),
                image: Some("ghcr.io/example/docs-mcp:1".to_string()),
                restart: crate::runtime::RuntimeRestartPolicy {
                    max_restarts: 4,
                    backoff_secs: 11,
                },
                ..crate::config::RuntimeProfileConfig::default()
            },
        );
        let plan = runtime_plan_for_backend("docs", &cfg, &runtime).expect("runtime plan");
        let backend = Backend::new_with_runtime_plan(
            "docs",
            cfg,
            &crate::config::FailsafeConfig::default(),
            Duration::from_secs(60),
            Some(plan),
        );

        let status = backend.status();
        let runtime = status.runtime.expect("runtime status");
        assert_eq!(runtime.profile, "containerized");
        assert_eq!(
            runtime.provider,
            crate::runtime::RuntimeProviderKind::Docker
        );
        assert_eq!(
            runtime.license_tier,
            crate::runtime::RuntimeLicenseTier::FreeCore
        );
        assert_eq!(runtime.state, BackendRuntimeState::Ready);
        assert!(runtime.denied_reasons.is_empty());
        assert!(runtime.confirmation_ids.is_empty());
        assert_eq!(runtime.restart_max_attempts, 4);
        assert_eq!(runtime.restart_backoff_secs, 11);
        assert!(runtime.health_check.contains("docker inspect"));
        assert_eq!(
            runtime.restart_command_hint.as_deref(),
            Some("docker restart mcp-gateway-docs")
        );
        assert!(runtime.rollback_step.contains("docker rm --force"));
    }

    #[test]
    fn backend_status_surfaces_confirmation_required_runtime_profile() {
        let cfg = BackendConfig {
            transport: TransportConfig::Stdio {
                command: "mcp-docs-server --stdio".to_string(),
                cwd: None,
                protocol_version: None,
            },
            runtime_profile: Some("local_privileged".to_string()),
            ..BackendConfig::default()
        };

        let mut runtime = crate::config::RuntimeConfig::default();
        runtime.profiles.insert(
            "local_privileged".to_string(),
            crate::config::RuntimeProfileConfig {
                provider: Some(crate::runtime::RuntimeProviderKind::LocalProcess),
                privileged: true,
                ..crate::config::RuntimeProfileConfig::default()
            },
        );
        let plan = runtime_plan_for_backend("docs", &cfg, &runtime).expect("runtime plan");
        let backend = Backend::new_with_runtime_plan(
            "docs",
            cfg,
            &crate::config::FailsafeConfig::default(),
            Duration::from_secs(60),
            Some(plan),
        );

        let status = backend.status();
        let runtime = status.runtime.expect("runtime status");
        assert_eq!(runtime.profile, "local_privileged");
        assert_eq!(
            runtime.provider,
            crate::runtime::RuntimeProviderKind::LocalProcess
        );
        assert_eq!(runtime.state, BackendRuntimeState::ConfirmationRequired);
        assert!(runtime.denied_reasons.is_empty());
        assert_eq!(runtime.confirmation_ids, vec!["runtime.privileged"]);
        assert!(runtime.health_check.contains("stdio"));
        assert_eq!(
            runtime.restart_command_hint.as_deref(),
            Some("restart the gateway-managed child process")
        );
        assert!(runtime.rollback_step.contains("direct-launch"));
    }

    #[test]
    fn stdio_backend_uses_container_runtime_bridge_command() {
        let cfg = BackendConfig {
            transport: TransportConfig::Stdio {
                command: "definitely-not-a-real-mcp-server".to_string(),
                cwd: None,
                protocol_version: None,
            },
            env: HashMap::from([
                ("SAFE_HANDLE".to_string(), "safe-value".to_string()),
                ("UNDECLARED_ENV".to_string(), "must-not-pass".to_string()),
            ]),
            runtime_profile: Some("containerized".to_string()),
            ..BackendConfig::default()
        };

        let mut runtime = crate::config::RuntimeConfig::default();
        runtime.availability.docker = true;
        runtime.profiles.insert(
            "containerized".to_string(),
            crate::config::RuntimeProfileConfig {
                provider: Some(crate::runtime::RuntimeProviderKind::Docker),
                image: Some("ghcr.io/example/server:latest".to_string()),
                env_keys: vec!["SAFE_HANDLE".to_string()],
                ..crate::config::RuntimeProfileConfig::default()
            },
        );
        let plan = runtime_plan_for_backend("docs", &cfg, &runtime).expect("runtime plan");
        let backend = Backend::new_with_runtime_plan(
            "docs",
            cfg,
            &crate::config::FailsafeConfig::default(),
            Duration::from_secs(60),
            Some(plan),
        );

        let launch = backend
            .resolve_stdio_runtime_launch("definitely-not-a-real-mcp-server")
            .expect("container stdio bridge launch");
        let parts = shlex::split(&launch.command).expect("bridge command is shell-splitable");

        assert_eq!(parts.first().map(String::as_str), Some("docker"));
        assert_eq!(parts.get(1).map(String::as_str), Some("run"));
        assert_eq!(
            parts.get(2..6),
            Some(
                &[
                    "--interactive".to_string(),
                    "--rm".to_string(),
                    "--name".to_string(),
                    "mcp-gateway-docs".to_string()
                ][..]
            ),
            "bridge flags must not split paired docker options: {parts:?}"
        );
        assert!(parts.contains(&"--interactive".to_string()));
        assert!(parts.contains(&"--rm".to_string()));
        assert!(!parts.contains(&"--detach".to_string()));
        assert!(
            !parts.iter().any(|arg| arg.starts_with("--restart=")),
            "stdio bridge must drop detached restart policy flags: {parts:?}"
        );
        assert!(parts.contains(&"--network=none".to_string()));
        assert!(parts.contains(&"--read-only".to_string()));
        assert!(parts.contains(&"--cap-drop=ALL".to_string()));
        assert!(parts.contains(&"SAFE_HANDLE".to_string()));
        assert!(!parts.contains(&"UNDECLARED_ENV".to_string()));
        assert!(parts.contains(&"ghcr.io/example/server:latest".to_string()));
        assert_eq!(
            launch.env,
            HashMap::from([("SAFE_HANDLE".to_string(), "safe-value".to_string())])
        );
    }

    #[tokio::test]
    async fn stdio_backend_requires_runtime_confirmations_before_spawn() {
        let cfg = BackendConfig {
            transport: TransportConfig::Stdio {
                command: "definitely-not-a-real-mcp-server".to_string(),
                cwd: None,
                protocol_version: None,
            },
            runtime_profile: Some("local_privileged".to_string()),
            ..BackendConfig::default()
        };

        let mut runtime = crate::config::RuntimeConfig::default();
        runtime.profiles.insert(
            "local_privileged".to_string(),
            crate::config::RuntimeProfileConfig {
                provider: Some(crate::runtime::RuntimeProviderKind::LocalProcess),
                privileged: true,
                ..crate::config::RuntimeProfileConfig::default()
            },
        );
        let plan = runtime_plan_for_backend("docs", &cfg, &runtime).expect("runtime plan");
        assert_eq!(
            plan.launch_command
                .as_ref()
                .map(|command| command.program.as_str()),
            Some("definitely-not-a-real-mcp-server")
        );
        let backend = Backend::new_with_runtime_plan(
            "docs",
            cfg,
            &crate::config::FailsafeConfig::default(),
            Duration::from_secs(60),
            Some(plan),
        );

        let err = backend
            .start()
            .await
            .expect_err("missing runtime confirmation rejected");
        assert!(
            err.to_string().contains("requires confirmations"),
            "confirmation-required runtime plan should fail closed before spawn: {err}"
        );
    }

    fn sample_tool(name: &str) -> Tool {
        Tool {
            name: name.to_string(),
            title: None,
            description: Some(format!("{name} tool")),
            input_schema: json!({"type": "object"}),
            output_schema: None,
            annotations: None,
            role: None,
            projection: None,
        }
    }

    #[test]
    fn normalize_tool_annotations_fills_missing_hints() {
        let mut tools = vec![sample_tool("search_messages"), sample_tool("send_message")];

        normalize_tool_annotations("beeper", &mut tools);

        let search = tools[0].annotations.as_ref().unwrap();
        assert_eq!(search.read_only_hint, Some(true));
        assert_eq!(search.destructive_hint, Some(false));
        assert_eq!(search.idempotent_hint, Some(true));
        assert_eq!(search.open_world_hint, Some(true));

        let send = tools[1].annotations.as_ref().unwrap();
        assert_eq!(send.read_only_hint, Some(false));
        assert_eq!(send.destructive_hint, Some(true));
        assert_eq!(send.idempotent_hint, Some(false));
        assert_eq!(send.open_world_hint, Some(true));
    }

    #[test]
    fn normalize_tool_annotations_preserves_existing_true_hints_and_adds_false_hints() {
        let mut tool = sample_tool("recall");
        tool.annotations = Some(ToolAnnotations {
            read_only_hint: Some(true),
            destructive_hint: None,
            idempotent_hint: None,
            open_world_hint: None,
            title: None,
        });
        let mut tools = vec![tool];

        normalize_tool_annotations("hebb", &mut tools);

        let annotations = tools[0].annotations.as_ref().unwrap();
        assert_eq!(annotations.read_only_hint, Some(true));
        assert_eq!(annotations.destructive_hint, Some(false));
        assert_eq!(annotations.idempotent_hint, Some(true));
        assert_eq!(annotations.open_world_hint, Some(false));
    }

    #[test]
    fn normalize_tool_annotations_preserves_downstream_annotation_title_and_hints() {
        let mut tool = sample_tool("remote_write");
        tool.annotations = Some(ToolAnnotations {
            title: Some("Remote Write".to_string()),
            read_only_hint: Some(false),
            destructive_hint: Some(false),
            idempotent_hint: Some(false),
            open_world_hint: Some(false),
        });
        let mut tools = vec![tool];

        normalize_tool_annotations("remote-api", &mut tools);

        let annotations = tools[0].annotations.as_ref().unwrap();
        assert_eq!(annotations.title.as_deref(), Some("Remote Write"));
        assert_eq!(annotations.read_only_hint, Some(false));
        assert_eq!(annotations.destructive_hint, Some(false));
        assert_eq!(annotations.idempotent_hint, Some(false));
        assert_eq!(annotations.open_world_hint, Some(false));
    }

    #[test]
    fn cached_metadata_tracks_freshness() {
        let cache = CachedMetadata::new();
        assert!(!cache.is_fresh(Duration::from_secs(60)));

        cache.store_shared(Arc::new(vec![1, 2, 3]));

        assert!(cache.is_fresh(Duration::from_secs(60)));
        let snapshot = cache.snapshot_shared().unwrap();
        assert_eq!(snapshot.as_ref(), &vec![1, 2, 3]);
        assert_eq!(snapshot.len(), 3);
    }

    #[tokio::test]
    async fn cached_metadata_shared_reads_reuse_arc() {
        let cache = CachedMetadata::new();

        let first = cache
            .get_or_fetch_shared(Duration::from_secs(60), || async { Ok(vec![1, 2, 3]) })
            .await
            .unwrap();
        let second = cache
            .get_or_fetch_shared(Duration::from_secs(60), || async {
                panic!("fresh cache hit should not refetch")
            })
            .await
            .unwrap();

        assert!(Arc::ptr_eq(&first, &second));
    }

    #[tokio::test]
    async fn cached_metadata_retries_after_fetch_error() {
        let cache = CachedMetadata::new();
        let attempts = AtomicUsize::new(0);

        let first = cache
            .get_or_fetch_shared(Duration::from_secs(60), || async {
                let attempt = attempts.fetch_add(1, Ordering::SeqCst);
                if attempt == 0 {
                    Err(Error::BackendUnavailable("boom".to_string()))
                } else {
                    Ok(vec![7])
                }
            })
            .await;
        assert!(first.is_err());

        let second = cache
            .get_or_fetch_shared(Duration::from_secs(60), || async {
                let attempt = attempts.fetch_add(1, Ordering::SeqCst);
                if attempt == 0 {
                    Err(Error::BackendUnavailable("boom".to_string()))
                } else {
                    Ok(vec![7])
                }
            })
            .await;

        assert_eq!(second.unwrap().as_ref(), &vec![7]);
        assert_eq!(attempts.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn get_tools_singleflight_coalesces_concurrent_requests() {
        let backend = Arc::new(Backend::new(
            "test",
            BackendConfig::default(),
            &crate::config::FailsafeConfig::default(),
            Duration::from_secs(60),
        ));
        let response = JsonRpcResponse::success_serialized(
            RequestId::Number(1),
            ToolsListResult {
                tools: vec![sample_tool("echo")],
                next_cursor: None,
            },
        );
        let transport = Arc::new(MockTransport::new(response, Duration::from_millis(25)));
        let transport_dyn: Arc<dyn Transport> = transport.clone();
        backend.set_transport_for_test(transport_dyn);

        let barrier = Arc::new(Barrier::new(6));
        let mut tasks = Vec::new();
        for _ in 0..5 {
            let backend = Arc::clone(&backend);
            let barrier = Arc::clone(&barrier);
            tasks.push(tokio::spawn(async move {
                barrier.wait().await;
                backend.get_tools().await.unwrap()
            }));
        }

        barrier.wait().await;

        for task in tasks {
            let tools = task.await.unwrap();
            assert_eq!(tools.len(), 1);
            assert_eq!(tools[0].name, "echo");
        }

        assert_eq!(transport.requests.load(Ordering::SeqCst), 1);
        assert!(backend.has_cached_tools());
        assert_eq!(backend.cached_tools_count(), 1);
        assert_eq!(
            backend.get_cached_tool("echo").map(|tool| tool.name),
            Some("echo".to_string())
        );
    }

    #[tokio::test]
    async fn get_tools_does_not_cache_json_rpc_error_response() {
        let backend = Arc::new(Backend::new(
            "test",
            BackendConfig::default(),
            &crate::config::FailsafeConfig::default(),
            Duration::from_secs(60),
        ));
        let response = JsonRpcResponse::error(Some(RequestId::Number(1)), -32000, "backend down");
        let transport = Arc::new(MockTransport::new(response, Duration::from_millis(0)));
        let transport_dyn: Arc<dyn Transport> = transport.clone();
        backend.set_transport_for_test(transport_dyn);

        let result = backend.get_tools().await;

        assert!(result.is_err());
        assert!(!backend.has_cached_tools());
        assert_eq!(transport.requests.load(Ordering::SeqCst), 1);
    }

    // ---- MIK-6735: per-user transport/session pool ----

    // Method-agnostic transport that echoes the session tag it was built for,
    // so a routed request proves which pool slot served it.
    struct SessionMock {
        session: String,
        requests: AtomicUsize,
        notifications: AtomicUsize,
        closed: AtomicBool,
    }

    impl SessionMock {
        fn new(session: &str) -> Self {
            Self {
                session: session.to_string(),
                requests: AtomicUsize::new(0),
                notifications: AtomicUsize::new(0),
                closed: AtomicBool::new(false),
            }
        }
    }

    #[async_trait]
    impl Transport for SessionMock {
        async fn request(&self, _method: &str, _params: Option<Value>) -> Result<JsonRpcResponse> {
            self.requests.fetch_add(1, Ordering::SeqCst);
            Ok(JsonRpcResponse::success_serialized(
                RequestId::Number(1),
                json!({ "session": self.session }),
            ))
        }

        async fn notify(&self, _method: &str, _params: Option<Value>) -> Result<()> {
            self.notifications.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }

        fn is_connected(&self) -> bool {
            true
        }

        async fn close(&self) -> Result<()> {
            self.closed.store(true, Ordering::SeqCst);
            Ok(())
        }
    }

    fn per_user_backend() -> Arc<Backend> {
        let idp = crate::identity_propagation::IdentityPropagationConfig {
            strategy: crate::identity_propagation::PropagationStrategyKind::SignedAssertion,
            audience: "https://mem.internal".to_string(),
            required: true,
            session_mode: crate::identity_propagation::SessionMode::PerUser,
            token_exchange_endpoint: None,
            token_exchange_scope: None,
        };
        let cfg = BackendConfig {
            transport: TransportConfig::Http {
                http_url: "https://mem.internal/mcp".to_string(),
                streamable_http: false,
                protocol_version: None,
            },
            identity_propagation: Some(idp),
            ..BackendConfig::default()
        };
        Arc::new(Backend::new(
            "mem",
            cfg,
            &crate::config::FailsafeConfig::default(),
            Duration::from_secs(60),
        ))
    }

    fn per_user_key(binding: &str) -> PoolKey {
        PoolKey::PerUser {
            binding: binding.to_string(),
        }
    }

    // POOL.4 (headline isolation guarantee): two callers on a per_user backend
    // are served by distinct transport instances and distinct sessions, and a
    // caller reusing its identity reuses its one slot — userA traffic never
    // touches userB's session (IDP.7).
    #[tokio::test]
    async fn per_user_requests_route_to_isolated_transport_slots() {
        let backend = per_user_backend();

        let mock_a = Arc::new(SessionMock::new("A"));
        let mock_b = Arc::new(SessionMock::new("B"));
        backend.set_pooled_transport_for_test(
            &per_user_key("userA"),
            mock_a.clone() as Arc<dyn Transport>,
        );
        backend.set_pooled_transport_for_test(
            &per_user_key("userB"),
            mock_b.clone() as Arc<dyn Transport>,
        );

        let resp_a = backend
            .request_with_headers("tools/list", None, &[], Some("userA"))
            .await
            .unwrap();
        let resp_b = backend
            .request_with_headers("tools/list", None, &[], Some("userB"))
            .await
            .unwrap();
        assert_eq!(resp_a.result.unwrap()["session"], json!("A"));
        assert_eq!(resp_b.result.unwrap()["session"], json!("B"));

        let transport_a = backend
            .pooled_transport_for_test(&per_user_key("userA"))
            .unwrap();
        let transport_b = backend
            .pooled_transport_for_test(&per_user_key("userB"))
            .unwrap();
        assert!(
            !Arc::ptr_eq(&transport_a, &transport_b),
            "distinct users must not share a transport instance"
        );

        // Same identity reuses the one slot; userB is untouched by userA traffic.
        backend
            .request_with_headers("tools/list", None, &[], Some("userA"))
            .await
            .unwrap();
        assert_eq!(
            mock_a.requests.load(Ordering::SeqCst),
            2,
            "userA must reuse its own slot"
        );
        assert_eq!(
            mock_b.requests.load(Ordering::SeqCst),
            1,
            "userB session must not serve userA traffic"
        );
    }

    // MIK-6735 fix 1 (adversarial review of commit bfd62b91): the headline
    // regression this fix closes. Before the fix, `request_with_headers`
    // gated every caller on ONE backend-wide `Failsafe`, so tripping the
    // breaker for userA's traffic also rejected userB's — one identity's
    // outage took down every other tenant sharing the backend, exactly the
    // blast radius the per-user pool exists to eliminate. Each slot must now
    // fail independently: tripping userA's slot rejects ONLY userA, and
    // userB's request on its own (untripped) slot still succeeds.
    #[tokio::test]
    async fn cross_tenant_circuit_breaker_trip_does_not_reject_other_identity() {
        let backend = per_user_backend();
        backend
            .set_pooled_transport_for_test(&per_user_key("userA"), Arc::new(SessionMock::new("A")));
        let mock_b = Arc::new(SessionMock::new("B"));
        backend.set_pooled_transport_for_test(&per_user_key("userB"), mock_b.clone());

        // Trip ONLY userA's slot.
        backend.trip_circuit_breaker_for_test_key(&per_user_key("userA"));

        let err = backend
            .request_with_headers("tools/list", None, &[], Some("userA"))
            .await
            .expect_err("userA's own tripped slot must reject its traffic");
        assert!(
            matches!(err, Error::CircuitOpen(_)),
            "expected CircuitOpen for userA, got {err:?}"
        );

        // userB's slot was never tripped and must be entirely unaffected.
        let resp_b = backend
            .request_with_headers("tools/list", None, &[], Some("userB"))
            .await
            .expect("userB's untripped slot must still serve requests");
        assert_eq!(resp_b.result.unwrap()["session"], json!("B"));
        assert_eq!(mock_b.requests.load(Ordering::SeqCst), 1);

        // The canonical Shared slot (and thus backend-wide status/metrics
        // accessors) must also be unaffected by a per-user slot tripping.
        assert!(
            !backend.is_circuit_tripped(),
            "Shared slot must stay closed when only a PerUser slot tripped"
        );
    }

    // MIK-6735 fix 2: before this fix, `Backend::notify` unconditionally used
    // `ensure_started()` (the canonical Shared slot) regardless of the
    // caller's identity, so a notification correlating a per-user request
    // went out on the WRONG transport instance (and, once routed correctly,
    // still the wrong upstream session — fixed at the `Transport` layer by
    // `notify_with_headers`). Assert `notify_with_headers` routes to the SAME
    // slot `request_with_headers` uses for that identity: userA's
    // notification reaches only userA's transport, never userB's.
    #[tokio::test]
    async fn notify_with_headers_routes_to_the_callers_own_pool_slot() {
        let backend = per_user_backend();
        let mock_a = Arc::new(SessionMock::new("A"));
        let mock_b = Arc::new(SessionMock::new("B"));
        backend.set_pooled_transport_for_test(&per_user_key("userA"), mock_a.clone());
        backend.set_pooled_transport_for_test(&per_user_key("userB"), mock_b.clone());

        backend
            .notify_with_headers("notifications/cancelled", None, Some("userA"))
            .await
            .expect("userA's notification must succeed");

        assert_eq!(
            mock_a.notifications.load(Ordering::SeqCst),
            1,
            "userA's notification must reach userA's own transport slot"
        );
        assert_eq!(
            mock_b.notifications.load(Ordering::SeqCst),
            0,
            "userA's notification must never reach userB's transport slot"
        );

        // Plain `notify` (no identity) is a pass-through to the Shared slot,
        // never a per-user slot — single-tenant behavior unchanged (IDP.5).
        backend.set_pooled_transport_for_test(&PoolKey::Shared, Arc::new(SessionMock::new("S")));
        backend
            .notify("notifications/cancelled", None)
            .await
            .expect("shared-slot notification must succeed");
        assert_eq!(
            mock_a.notifications.load(Ordering::SeqCst),
            1,
            "an identity-less notify must not touch a per-user slot"
        );
    }

    // POOL.1 / IDP.5: without a resolved per-user identity — or on a backend
    // that is not per_user at all — every request collapses to the shared
    // canonical slot, preserving single-tenant behavior byte-for-byte.
    #[test]
    fn pool_key_collapses_to_shared_without_per_user_identity() {
        let backend = per_user_backend();
        assert_eq!(backend.pool_key_for(None), PoolKey::Shared);
        assert_eq!(backend.pool_key_for(Some("userA")), per_user_key("userA"));

        let plain = Backend::new(
            "plain",
            BackendConfig::default(),
            &crate::config::FailsafeConfig::default(),
            Duration::from_secs(60),
        );
        assert_eq!(
            plain.pool_key_for(Some("userA")),
            PoolKey::Shared,
            "a non-idp backend never mints a per-user slot"
        );
    }

    // POOL.2: idle per-user slots are evicted and their transports closed, the
    // shared canonical slot is NEVER evicted, and a later request lazily
    // re-creates a fresh slot.
    #[tokio::test]
    async fn evict_idle_per_user_entries_reaps_idle_users_but_spares_shared() {
        let backend = per_user_backend();
        backend
            .set_pooled_transport_for_test(&per_user_key("userA"), Arc::new(SessionMock::new("A")));

        // Age BOTH the user slot and the shared slot into the deep past.
        for key in [per_user_key("userA"), PoolKey::Shared] {
            backend
                .pool
                .get(&key)
                .unwrap()
                .value()
                .last_used
                .store(0, Ordering::Relaxed);
        }

        let closed = backend
            .evict_idle_per_user_entries(Duration::from_secs(1))
            .await;
        assert_eq!(closed, 1, "only the per-user slot is reaped");
        assert!(
            backend
                .pooled_transport_for_test(&per_user_key("userA"))
                .is_none(),
            "evicted per-user slot is gone"
        );
        assert!(
            backend.pool.contains_key(&PoolKey::Shared),
            "shared canonical slot must survive eviction even when idle"
        );

        // A fresh request re-creates the slot lazily with a new transport.
        backend.set_pooled_transport_for_test(
            &per_user_key("userA"),
            Arc::new(SessionMock::new("A2")),
        );
        let resp = backend
            .request_with_headers("tools/list", None, &[], Some("userA"))
            .await
            .unwrap();
        assert_eq!(resp.result.unwrap()["session"], json!("A2"));
    }

    // POOL.3 companion: a per_user request and a no-identity request on the same
    // backend land in different slots, so canonical/init traffic (shared) is
    // never commingled with a user's session.
    #[tokio::test]
    async fn shared_and_per_user_slots_are_separate_on_one_backend() {
        let backend = per_user_backend();
        backend
            .set_pooled_transport_for_test(&PoolKey::Shared, Arc::new(SessionMock::new("shared")));
        backend
            .set_pooled_transport_for_test(&per_user_key("userA"), Arc::new(SessionMock::new("A")));

        let shared = backend
            .request_with_headers("tools/list", None, &[], None)
            .await
            .unwrap();
        let user = backend
            .request_with_headers("tools/list", None, &[], Some("userA"))
            .await
            .unwrap();
        assert_eq!(shared.result.unwrap()["session"], json!("shared"));
        assert_eq!(user.result.unwrap()["session"], json!("A"));
    }

    // POOL race fix (adversarial review): `evict_idle_per_user_entries` can
    // `remove_if` a per-user slot out of `pool` WHILE `ensure_entry_started`
    // is mid-build for that exact slot — the entry is cloned out of the pool
    // via `pooled_entry` before it is touched, so the evictor's idleness
    // re-check still sees it as stale and wins. `PooledEntry` has no async
    // `Drop`, so a transport stored into an orphaned entry would otherwise
    // leak the connection until OS teardown. This drives `reconcile_after_start`
    // (the exact method `ensure_entry_started` calls after `start_entry`)
    // directly, simulating the evictor having already won, and asserts the
    // orphaned transport is closed rather than leaked.
    #[tokio::test]
    async fn reconcile_after_start_closes_orphaned_transport_when_evictor_wins_race() {
        let backend = per_user_backend();
        let key = per_user_key("userA");

        // Simulate ensure_entry_started's in-flight state: an entry was
        // cloned out of the pool (as pooled_entry would) and start_entry
        // just finished building its transport into it.
        let entry = backend.pooled_entry(&key);
        let transport = Arc::new(SessionMock::new("A"));
        *entry.transport.write() = Some(Arc::clone(&transport) as Arc<dyn Transport>);

        // The evictor wins the race: it removes this exact entry from the
        // pool before the build above is reconciled.
        let removed = backend.pool.remove(&key);
        assert!(
            removed.is_some_and(|(_, removed_entry)| Arc::ptr_eq(&removed_entry, &entry)),
            "the entry removed by the simulated evictor must be the SAME entry \
             the in-flight start was building into"
        );

        let outcome = backend
            .reconcile_after_start(&key, &entry, Arc::clone(&transport) as Arc<dyn Transport>)
            .await;

        assert!(
            outcome.is_none(),
            "a lost race must be reported so ensure_entry_started retries \
             against a fresh entry instead of handing back a doomed transport"
        );
        assert!(
            transport.closed.load(Ordering::SeqCst),
            "the orphaned transport must be closed by the side that lost the \
             race, not silently dropped/leaked"
        );
        assert!(
            entry.transport.read().is_none(),
            "the orphaned entry's transport slot must be cleared after close"
        );
    }

    // Companion happy-path: when nobody evicted the entry mid-build,
    // reconcile_after_start must hand the transport back untouched and never
    // close a live, still-registered connection.
    #[tokio::test]
    async fn reconcile_after_start_keeps_transport_when_still_registered() {
        let backend = per_user_backend();
        let key = per_user_key("userA");

        let entry = backend.pooled_entry(&key);
        let transport = Arc::new(SessionMock::new("A"));
        *entry.transport.write() = Some(Arc::clone(&transport) as Arc<dyn Transport>);

        // No eviction happened: `entry` is still the pool's registered slot.
        let outcome = backend
            .reconcile_after_start(&key, &entry, Arc::clone(&transport) as Arc<dyn Transport>)
            .await;

        assert!(
            outcome.is_some(),
            "a still-registered entry must hand its transport back, not report a lost race"
        );
        assert!(
            !transport.closed.load(Ordering::SeqCst),
            "the winning side's live transport must never be closed"
        );
    }
}

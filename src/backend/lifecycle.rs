// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Backend construction and connection lifecycle: creation, starting pool
//! slots (stdio/HTTP transport launch, OAuth client setup, runtime-provider
//! policy enforcement), stopping, and health-probe-driven recovery.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use dashmap::DashMap;
use reqwest::Client;
use tokio::sync::Semaphore;
use tracing::{info, warn};

use super::Backend;
use super::cached_metadata::CachedMetadata;
use super::pool::{PoolKey, PooledEntry};
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

            // NOTE: deliberately does NOT touch the idle clocks. `last_used` means
            // "when did a CLIENT last use this backend", and is written only by the
            // request/notify paths in `ops.rs`. Touching it here is what made idle
            // stopping unreachable in an earlier attempt: `health_probe` ->
            // `ensure_started` -> here, on a 10s default health interval against a
            // 300s deadline, refreshed the clock forever. The health loop kept every
            // backend permanently warm and the feature was a silent no-op.

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

        // Whatever the reason for starting - a client request, a health-driven
        // force_restart, warm start - this slot is no longer stopped-for-idleness.
        // Clearing here rather than in `ensure_entry_started` is deliberate:
        // `force_restart` calls this directly, and clearing only in the former
        // left a restarted backend flagged dormant while actually running.
        entry
            .stopped_when_idle
            .store(false, std::sync::atomic::Ordering::SeqCst);

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
        // in_flight is read under that same guard so the answer cannot change
        // between the check and the take.
        let (old, busy) = {
            let mut guard = entry.transport.write();
            let busy = entry.in_flight.load(std::sync::atomic::Ordering::SeqCst) > 0;
            (guard.take(), busy)
        };
        if let Some(old) = old {
            if busy {
                // Requests are executing against this transport right now.
                // Closing it here kills a stdio child and tears down an HTTP
                // session underneath a live caller, which is a worse failure
                // than the one recovery is trying to fix.
                Self::close_when_drained(self.name.clone(), old, self.max_legitimate_hold(&entry));
            } else {
                let _ = old.close().await;
            }
        }
        self.start_entry(&PoolKey::Shared, &entry).await?;
        Ok(())
    }

    /// Close a replaced transport once the requests still holding it finish.
    ///
    /// [`Backend::force_restart`] cannot await the drain inline. It is the health
    /// loop's recovery path, and the case it exists for is a WEDGED backend whose
    /// in-flight request may never return; blocking recovery on that request
    /// converts an interruption bug into a never-recovers bug. So the fresh
    /// transport is installed immediately and the old one is closed behind it,
    /// bounded so a hung holder cannot leak it forever.
    ///
    /// The `Arc` strong count, not `in_flight`, is the drain signal. `in_flight`
    /// counts requests against the SLOT, which new traffic keeps non-zero, so
    /// waiting on it could defer the close indefinitely under load. The strong
    /// count tracks holders of THIS transport specifically, and drops to one
    /// (ours) exactly when the last in-flight caller is done with it.
    ///
    /// Dropping it instead of closing is not sufficient for both transports:
    /// stdio reaps its child via `kill_on_drop`, but `HttpTransport`'s `Drop`
    /// only aborts the token-refresh task and never tears down the session.
    ///
    /// `cap` bounds the wait so a genuinely hung holder cannot leak the
    /// transport forever. It must come from [`Backend::max_legitimate_hold`]:
    /// a constant here would close the transport underneath requests that are
    /// merely slower than the constant, which is the same correctness defect
    /// with a delay in front of it.
    fn close_when_drained(name: String, old: Arc<dyn Transport>, cap: Duration) {
        const POLL: Duration = Duration::from_millis(50);

        tokio::spawn(async move {
            let deadline = tokio::time::Instant::now() + cap;
            while Arc::strong_count(&old) > 1 && tokio::time::Instant::now() < deadline {
                tokio::time::sleep(POLL).await;
            }
            if Arc::strong_count(&old) > 1 {
                // Past this point no request can still be running legitimately,
                // so a holder here is hung rather than slow.
                warn!(
                    backend = %name,
                    cap_ms = cap.as_millis(),
                    "Replaced transport still held past the longest request this \
                     backend permits; closing it and treating the holder as hung"
                );
            }
            let _ = old.close().await;
        });
    }

    /// The longest a caller can legitimately hold this backend's transport.
    ///
    /// Derived, not chosen. One `ActivityGuard` can span an entire retry
    /// sequence: `with_retry` re-invokes its closure per attempt against the
    /// SAME transport `Arc` (`src/backend/ops.rs`), so the bound is every
    /// attempt's request timeout plus the backoff between them, not a single
    /// timeout. A fixed constant cannot express that - `timeout`,
    /// `max_attempts` and `max_backoff` are all per-backend configuration, so
    /// any constant is either wrong for a slow backend or needlessly long for
    /// a fast one.
    ///
    /// `max_backoff` upper-bounds each individual backoff, so using it for all
    /// of them is conservative in the safe direction: the cap can only be too
    /// generous, never too tight. `GRACE` covers the gap between a transport's
    /// own timeout firing and the caller actually dropping its `Arc`.
    fn max_legitimate_hold(&self, entry: &PooledEntry) -> Duration {
        /// Slack for teardown and scheduling after the last attempt's deadline.
        const GRACE: Duration = Duration::from_secs(1);

        let policy = &entry.failsafe.retry_policy;
        let attempts = if policy.enabled {
            policy.max_attempts.max(1)
        } else {
            1
        };

        self.config
            .timeout
            .saturating_mul(attempts)
            .saturating_add(
                policy
                    .max_backoff
                    .saturating_mul(attempts.saturating_sub(1)),
            )
            .saturating_add(GRACE)
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
        // Hold the transport for the whole probe WITHOUT claiming client activity.
        // Without this the reaper can close the transport between the health
        // loop's gate check and the probe's ping; the probe reads that as a fault
        // and calls force_restart(), so an idle backend is stopped and instantly
        // restarted. With a 10s health interval against a 60s sweep their ticks
        // coincide regularly, which would make the feature a periodic no-op - the
        // exact failure this change exists to correct.
        let _lease = self.begin_internal_activity();

        // A slot the reaper deliberately stopped is not a fault, and probing is
        // not a reason to wake it. `stop_if_idle` records this flag under the
        // same transport write guard that takes the transport, so by the time a
        // lease can be claimed the flag is already visible: either this lease
        // came first and the sweep declined, or the sweep completed and this
        // check sees it. Without the bail, the probe's ensure_started() below
        // would restart the process the sweep just released.
        if self
            .shared_entry()
            .stopped_when_idle
            .load(std::sync::atomic::Ordering::SeqCst)
        {
            return Ok(());
        }

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
}

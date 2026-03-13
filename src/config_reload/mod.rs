//! Config hot-reload with diff patching.
//!
//! This module watches `config.yaml` **and** any env files listed in
//! `config.env_files` (e.g. `~/.claude/secrets.env`) for changes.  When either
//! file type changes the full [`Config::load`] pipeline is re-run, env vars are
//! re-expanded, a structural diff is computed, and only the changed sections are
//! applied in-place.
//!
//! # Limitations
//!
//! Server address/port changes (`server.host`, `server.port`) cannot be applied
//! without restarting the TCP listener.  When such a change is detected a
//! `WARNING` is logged and the change is **not** applied; the process must be
//! restarted manually.
//!
//! # Example
//!
//! ```no_run
//! use std::{path::PathBuf, sync::Arc};
//! use tokio::sync::broadcast;
//! use mcp_gateway::{config::Config, config_reload::{ConfigWatcher, LiveConfig}};
//! use mcp_gateway::backend::BackendRegistry;
//!
//! # tokio_test::block_on(async {
//! let (shutdown_tx, _) = broadcast::channel(1);
//! let config = Config::default();
//! let live = Arc::new(LiveConfig::new(config.clone()));
//! let registry = Arc::new(BackendRegistry::new());
//!
//! let _watcher = ConfigWatcher::start(
//!     PathBuf::from("config.yaml"),
//!     live,
//!     registry,
//!     &config,
//!     shutdown_tx.subscribe(),
//! );
//! # });
//! ```

use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use notify::{
    Config as NotifyConfig, Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher,
};
use parking_lot::{Mutex, RwLock};
use tracing::{info, warn};

use crate::Result;
use crate::backend::{Backend, BackendRegistry};
use crate::config::{BackendConfig, Config, ServerConfig};

// ============================================================================
// Public types
// ============================================================================

/// Structural diff computed between two [`Config`] snapshots.
///
/// Only the `backends` and high-level flags that can be applied without a
/// restart are included.  Server address changes are flagged separately so the
/// caller can warn the operator.
#[derive(Debug, Default, Clone)]
pub struct ConfigPatch {
    /// Backends that exist in `new` but not in `old` (enabled flag respected).
    pub backends_added: Vec<(String, BackendConfig)>,
    /// Names of backends present in `old` but absent (or disabled) in `new`.
    pub backends_removed: Vec<String>,
    /// Backends whose config changed between `old` and `new`.
    pub backends_modified: Vec<(String, BackendConfig)>,
    /// `true` when `server.host` or `server.port` changed (requires restart).
    pub server_changed: bool,
    /// `true` when any field outside of `backends` / `server` changed.
    pub profiles_changed: bool,
}

impl ConfigPatch {
    /// Returns `true` when no changes were detected.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.backends_added.is_empty()
            && self.backends_removed.is_empty()
            && self.backends_modified.is_empty()
            && !self.server_changed
            && !self.profiles_changed
    }

    /// Human-readable summary of the patch (one line per change type).
    #[must_use]
    pub fn summary(&self) -> String {
        let mut parts = Vec::new();
        if !self.backends_added.is_empty() {
            parts.push(format!(
                "added backends: [{}]",
                self.backends_added
                    .iter()
                    .map(|(n, _)| n.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
        }
        if !self.backends_removed.is_empty() {
            parts.push(format!(
                "removed backends: [{}]",
                self.backends_removed.join(", ")
            ));
        }
        if !self.backends_modified.is_empty() {
            parts.push(format!(
                "modified backends: [{}]",
                self.backends_modified
                    .iter()
                    .map(|(n, _)| n.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
        }
        if self.server_changed {
            parts.push("server address changed (restart required)".to_string());
        }
        if self.profiles_changed {
            parts.push("profiles/meta config changed".to_string());
        }
        if parts.is_empty() {
            "no changes".to_string()
        } else {
            parts.join("; ")
        }
    }
}

/// Live, atomically-swappable config snapshot shared across the gateway.
///
/// Readers take a read-lock and clone the inner `Arc`; writers swap the whole
/// `Arc` under a write-lock, so readers are never blocked for more than a
/// pointer-width CAS.
pub struct LiveConfig {
    inner: RwLock<Arc<Config>>,
}

impl LiveConfig {
    /// Create a new `LiveConfig` seeded with the startup configuration.
    #[must_use]
    pub fn new(config: Config) -> Self {
        Self {
            inner: RwLock::new(Arc::new(config)),
        }
    }

    /// Clone the current active configuration snapshot.
    #[must_use]
    pub fn get(&self) -> Arc<Config> {
        Arc::clone(&self.inner.read())
    }

    /// Atomically replace the current config.
    pub fn set(&self, config: Config) {
        *self.inner.write() = Arc::new(config);
    }
}

// ============================================================================
// Diff computation (pure, synchronous)
// ============================================================================

/// Compute the structural diff between two config snapshots.
///
/// This is a pure function: it does not touch the registry or spawn any tasks.
/// The caller is responsible for applying the returned [`ConfigPatch`].
///
/// # Examples
///
/// ```
/// use mcp_gateway::config::Config;
/// use mcp_gateway::config_reload::compute_diff;
///
/// let old = Config::default();
/// let new = Config::default();
/// let patch = compute_diff(&old, &new);
/// assert!(patch.is_empty());
/// ```
#[must_use]
pub fn compute_diff(old: &Config, new: &Config) -> ConfigPatch {
    let mut patch = ConfigPatch {
        server_changed: server_address_changed(&old.server, &new.server),
        profiles_changed: profiles_changed(old, new),
        ..ConfigPatch::default()
    };

    classify_backends(old, new, &mut patch);

    patch
}

/// Returns `true` when the TCP-listener address differs.
fn server_address_changed(old: &ServerConfig, new: &ServerConfig) -> bool {
    old.host != new.host || old.port != new.port
}

/// Returns `true` when any non-backend, non-server field differs.
///
/// Uses YAML serialization as a cheap structural equality check so we don't
/// need to `PartialEq` every nested config type.
fn profiles_changed(old: &Config, new: &Config) -> bool {
    // Compare the sections that can be applied without backend restart.
    let fields_changed = |a: &Config, b: &Config| -> bool {
        // Avoid false positives from the backends map (handled separately).
        // We serialise and compare just the non-backends, non-server sections.
        let old_meta = MetaFields::from(a);
        let new_meta = MetaFields::from(b);
        old_meta != new_meta
    };
    fields_changed(old, new)
}

/// Comparable snapshot of everything except backends and server address.
#[derive(PartialEq)]
struct MetaFields {
    auth: String,
    meta_mcp: String,
    streaming: String,
    failsafe: String,
    capabilities: String,
    cache: String,
    playbooks: String,
    security: String,
    webhooks: String,
}

impl MetaFields {
    fn from(c: &Config) -> Self {
        Self {
            auth: serde_json::to_string(&c.auth).unwrap_or_default(),
            meta_mcp: serde_json::to_string(&c.meta_mcp).unwrap_or_default(),
            streaming: serde_json::to_string(&c.streaming).unwrap_or_default(),
            failsafe: serde_json::to_string(&c.failsafe).unwrap_or_default(),
            capabilities: serde_json::to_string(&c.capabilities).unwrap_or_default(),
            cache: serde_json::to_string(&c.cache).unwrap_or_default(),
            playbooks: serde_json::to_string(&c.playbooks).unwrap_or_default(),
            security: serde_json::to_string(&c.security).unwrap_or_default(),
            webhooks: serde_json::to_string(&c.webhooks).unwrap_or_default(),
        }
    }
}

/// Partition backends into added / removed / modified buckets.
fn classify_backends(old: &Config, new: &Config, patch: &mut ConfigPatch) {
    let old_enabled: std::collections::HashMap<&str, &BackendConfig> = old
        .backends
        .iter()
        .filter(|(_, c)| c.enabled)
        .map(|(k, v)| (k.as_str(), v))
        .collect();

    let new_enabled: std::collections::HashMap<&str, &BackendConfig> = new
        .backends
        .iter()
        .filter(|(_, c)| c.enabled)
        .map(|(k, v)| (k.as_str(), v))
        .collect();

    // Added: in new but not in old
    for (name, cfg) in &new_enabled {
        if !old_enabled.contains_key(name) {
            patch
                .backends_added
                .push(((*name).to_string(), (*cfg).clone()));
        }
    }

    // Removed: in old but not in new
    for name in old_enabled.keys() {
        if !new_enabled.contains_key(name) {
            patch.backends_removed.push((*name).to_string());
        }
    }

    // Modified: in both but config differs
    for (name, new_cfg) in &new_enabled {
        if let Some(old_cfg) = old_enabled.get(name)
            && backend_config_changed(old_cfg, new_cfg)
        {
            patch
                .backends_modified
                .push(((*name).to_string(), (*new_cfg).clone()));
        }
    }
}

/// Returns `true` when any observable field of a backend config differs.
///
/// Uses JSON serialization for a stable, deep equality check without requiring
/// `PartialEq` on all nested types.
fn backend_config_changed(old: &BackendConfig, new: &BackendConfig) -> bool {
    serde_json::to_string(old).ok() != serde_json::to_string(new).ok()
}

// ============================================================================
// Patch application
// ============================================================================

/// Apply a [`ConfigPatch`] against the live [`BackendRegistry`].
///
/// - **Added backends**: registered immediately (lazy-connect, identical to
///   startup behaviour).
/// - **Removed backends**: stopped (graceful drain via existing `stop()`) and
///   deregistered.
/// - **Modified backends**: the old backend is stopped and replaced with a
///   freshly created one.  In-flight requests finish on the old transport; new
///   requests pick up the replacement.
/// - **Server address changes**: a `WARN` is emitted and the change is
///   skipped.
/// - **Profile changes**: logged at `INFO`; the `LiveConfig` is updated by the
///   caller after this function returns.
pub async fn apply_patch(
    patch: &ConfigPatch,
    registry: &BackendRegistry,
    failsafe_config: &crate::config::FailsafeConfig,
    cache_ttl: Duration,
) {
    if patch.server_changed {
        warn!("Config reload: server host/port changed — restart required to apply this change");
    }

    for (name, cfg) in &patch.backends_added {
        let backend = Arc::new(Backend::new(name, cfg.clone(), failsafe_config, cache_ttl));
        registry.register(Arc::clone(&backend));
        info!(backend = %name, transport = %cfg.transport.transport_type(), "Config reload: backend added");
    }

    for name in &patch.backends_removed {
        if let Some(backend) = registry.get(name)
            && let Err(e) = backend.stop().await
        {
            warn!(backend = %name, error = %e, "Config reload: error stopping removed backend");
        }
        registry.remove(name);
        info!(backend = %name, "Config reload: backend removed");
    }

    for (name, cfg) in &patch.backends_modified {
        // Stop old instance (waits for transport close).
        if let Some(old) = registry.get(name)
            && let Err(e) = old.stop().await
        {
            warn!(backend = %name, error = %e, "Config reload: error stopping modified backend");
        }
        // Register replacement.
        let backend = Arc::new(Backend::new(name, cfg.clone(), failsafe_config, cache_ttl));
        registry.register(Arc::clone(&backend));
        info!(backend = %name, transport = %cfg.transport.transport_type(), "Config reload: backend updated");
    }

    if patch.profiles_changed {
        info!("Config reload: meta/profile config updated (in-place)");
    }
}

// ============================================================================
// File watcher — helpers
// ============================================================================

/// What caused a reload to be scheduled.
///
/// Carried through the debounce channel so the reload task can log a
/// context-specific message (config change vs. env-file change).
#[derive(Debug, Clone)]
enum ReloadTrigger {
    /// The main `config.yaml` was modified.
    ConfigFile,
    /// One of the watched env files was modified.
    EnvFile(PathBuf),
}

/// Expand a leading `~` to the current user's home directory.
///
/// Returns the path unchanged if it does not start with `~` or if the home
/// directory cannot be determined.
fn expand_tilde(path_str: &str) -> PathBuf {
    if path_str.starts_with('~')
        && let Some(home) = dirs::home_dir()
    {
        return PathBuf::from(path_str.replacen('~', &home.display().to_string(), 1));
    }
    PathBuf::from(path_str)
}

/// Resolve a list of raw env-file path strings (supports `~`) into
/// canonical [`PathBuf`]s, deduplicating by parent directory while
/// preserving the full path for event filtering.
fn resolve_env_file_paths(raw: &[String]) -> Vec<PathBuf> {
    raw.iter().map(|s| expand_tilde(s)).collect()
}

/// Returns `true` for create/modify events on the watched config file.
fn is_config_event(event: &Event, config_path: &std::path::Path) -> bool {
    matches!(event.kind, EventKind::Create(_) | EventKind::Modify(_))
        && event.paths.iter().any(|p| p == config_path)
}

/// Returns `Some(path)` when the event matches any of the watched env files,
/// `None` otherwise.
fn matching_env_file(event: &Event, env_paths: &[PathBuf]) -> Option<PathBuf> {
    if !matches!(event.kind, EventKind::Create(_) | EventKind::Modify(_)) {
        return None;
    }
    env_paths
        .iter()
        .find(|ep| event.paths.iter().any(|p| p == *ep))
        .cloned()
}

// ============================================================================
// File watcher
// ============================================================================

/// File watcher that triggers config hot-reload on `config.yaml` **and**
/// env-file changes (e.g. `~/.claude/secrets.env`).
///
/// Mirrors the structure of [`crate::capability::CapabilityWatcher`].
/// Holds the underlying `notify` watcher alive for the lifetime of the struct.
pub struct ConfigWatcher {
    /// Kept alive to prevent the OS watcher from being dropped.
    _watcher: Mutex<Option<RecommendedWatcher>>,
}

impl ConfigWatcher {
    /// Start watching `config_path` and any env files listed in the initial
    /// config for changes.
    ///
    /// Spawns a debounced background task that re-parses the file and calls
    /// [`apply_patch`] on each detected change.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying `notify` watcher cannot be created.
    pub fn start(
        config_path: PathBuf,
        live_config: Arc<LiveConfig>,
        registry: Arc<BackendRegistry>,
        initial_config: &Config,
        shutdown_rx: tokio::sync::broadcast::Receiver<()>,
    ) -> Result<Self> {
        let (event_tx, event_rx) = tokio::sync::mpsc::channel::<ReloadTrigger>(32);

        let env_file_paths = resolve_env_file_paths(&initial_config.env_files);

        let watcher = Self::create_notify_watcher(event_tx, &config_path, &env_file_paths)?;

        let failsafe_cfg = initial_config.failsafe.clone();
        let cache_ttl = initial_config.meta_mcp.cache_ttl;

        Self::spawn_reload_task(
            config_path,
            live_config,
            registry,
            failsafe_cfg,
            cache_ttl,
            event_rx,
            shutdown_rx,
        );

        Ok(Self {
            _watcher: Mutex::new(Some(watcher)),
        })
    }

    /// Create the low-level `notify` watcher and register all watch paths.
    ///
    /// The config file's parent directory and each env file's parent directory
    /// are registered with `NonRecursive` watching.  Duplicate parent
    /// directories are watched only once.
    fn create_notify_watcher(
        event_tx: tokio::sync::mpsc::Sender<ReloadTrigger>,
        config_path: &std::path::Path,
        env_file_paths: &[PathBuf],
    ) -> Result<RecommendedWatcher> {
        let config_path_owned = config_path.to_path_buf();
        let env_paths_owned: Vec<PathBuf> = env_file_paths.to_vec();

        let mut watcher = RecommendedWatcher::new(
            move |result: std::result::Result<Event, notify::Error>| {
                let Ok(event) = result else { return };

                if is_config_event(&event, &config_path_owned) {
                    let _ = event_tx.try_send(ReloadTrigger::ConfigFile);
                } else if let Some(path) = matching_env_file(&event, &env_paths_owned) {
                    let _ = event_tx.try_send(ReloadTrigger::EnvFile(path));
                }
            },
            NotifyConfig::default().with_poll_interval(Duration::from_secs(2)),
        )
        .map_err(|e| crate::Error::Internal(format!("Failed to create config watcher: {e}")))?;

        // Watch the config file's parent directory.
        let config_dir = config_path
            .parent()
            .unwrap_or_else(|| std::path::Path::new("."))
            .to_path_buf();
        watcher
            .watch(&config_dir, RecursiveMode::NonRecursive)
            .map_err(|e| crate::Error::Internal(format!("Failed to watch config path: {e}")))?;

        // Watch each env file's parent directory (skip duplicates and missing).
        let mut watched_dirs = std::collections::HashSet::new();
        watched_dirs.insert(config_dir);

        for env_path in env_file_paths {
            let dir = env_path
                .parent()
                .unwrap_or_else(|| std::path::Path::new("."))
                .to_path_buf();

            if watched_dirs.contains(&dir) {
                continue;
            }

            if dir.exists() {
                match watcher.watch(&dir, RecursiveMode::NonRecursive) {
                    Ok(()) => {
                        info!(
                            dir = %dir.display(),
                            "Config watcher: watching env-file directory"
                        );
                    }
                    Err(e) => {
                        warn!(
                            dir = %dir.display(),
                            error = %e,
                            "Config watcher: failed to watch env-file directory"
                        );
                    }
                }
            } else {
                warn!(
                    dir = %dir.display(),
                    "Config watcher: env-file directory does not exist, skipping"
                );
            }

            watched_dirs.insert(dir);
        }

        Ok(watcher)
    }

    /// Spawn the debounced reload task.
    #[allow(clippy::too_many_arguments)]
    fn spawn_reload_task(
        config_path: PathBuf,
        live_config: Arc<LiveConfig>,
        registry: Arc<BackendRegistry>,
        failsafe_cfg: crate::config::FailsafeConfig,
        cache_ttl: Duration,
        mut event_rx: tokio::sync::mpsc::Receiver<ReloadTrigger>,
        mut shutdown_rx: tokio::sync::broadcast::Receiver<()>,
    ) {
        tokio::spawn(async move {
            const DEBOUNCE: Duration = Duration::from_millis(500);
            let mut last_event: Option<Instant> = None;
            let mut pending_trigger: Option<ReloadTrigger> = None;
            let mut ticker = tokio::time::interval(Duration::from_millis(100));

            loop {
                tokio::select! {
                    Some(trigger) = event_rx.recv() => {
                        last_event = Some(Instant::now());
                        // Keep the first trigger reason for the log message;
                        // the reload re-reads everything anyway.
                        if pending_trigger.is_none() {
                            pending_trigger = Some(trigger);
                        }
                    }
                    _ = ticker.tick() => {
                        if pending_trigger.is_some()
                            && last_event.is_some_and(|t| t.elapsed() >= DEBOUNCE)
                        {
                            let trigger = pending_trigger.take().unwrap();
                            last_event = None;
                            log_reload_trigger(&trigger);
                            reload_once(
                                &config_path,
                                &live_config,
                                &registry,
                                &failsafe_cfg,
                                cache_ttl,
                            )
                            .await;
                        }
                    }
                    _ = shutdown_rx.recv() => {
                        info!("Config watcher shutting down");
                        break;
                    }
                }
            }
        });
    }
}

/// Emit an INFO log describing what triggered the pending reload.
fn log_reload_trigger(trigger: &ReloadTrigger) {
    match trigger {
        ReloadTrigger::ConfigFile => {
            info!("Config watcher: config file changed, triggering reload");
        }
        ReloadTrigger::EnvFile(path) => {
            info!(
                path = %path.display(),
                "Config watcher: env file changed, triggering reload"
            );
        }
    }
}

/// Parse the config file, compute the diff, and apply the patch.
async fn reload_once(
    config_path: &std::path::Path,
    live_config: &Arc<LiveConfig>,
    registry: &Arc<BackendRegistry>,
    failsafe_cfg: &crate::config::FailsafeConfig,
    cache_ttl: Duration,
) {
    let old_config = live_config.get();

    let new_config = match Config::load(Some(config_path)) {
        Ok(c) => c,
        Err(e) => {
            warn!(error = %e, "Config reload: failed to parse config file, keeping current config");
            return;
        }
    };

    let patch = compute_diff(&old_config, &new_config);

    if patch.is_empty() {
        tracing::debug!("Config reload: no changes detected");
        return;
    }

    info!(changes = %patch.summary(), "Config reload: applying patch");

    apply_patch(&patch, registry, failsafe_cfg, cache_ttl).await;

    // Swap live config after patch is applied so readers see a consistent view.
    live_config.set(new_config);

    info!("Config reload: complete");
}

// ============================================================================
// ReloadContext — imperative reload handle for the meta-tool
// ============================================================================

/// Shareable context required to trigger a config reload imperatively
/// (e.g. from the `gateway_reload_config` meta-tool).
///
/// Create one at server startup and store an `Arc<ReloadContext>` in `MetaMcp`
/// via `MetaMcp::set_reload_context`.
pub struct ReloadContext {
    /// Path to the config file on disk.
    pub config_path: PathBuf,
    /// Live config store shared with the gateway.
    pub live_config: Arc<LiveConfig>,
    /// Backend registry to mutate.
    pub registry: Arc<BackendRegistry>,
    /// Failsafe config (needed to construct replacement backends).
    pub failsafe_config: crate::config::FailsafeConfig,
    /// Cache TTL forwarded from startup config.
    pub cache_ttl: Duration,
}

impl ReloadContext {
    /// Create a new `ReloadContext`.
    #[must_use]
    pub fn new(
        config_path: PathBuf,
        live_config: Arc<LiveConfig>,
        registry: Arc<BackendRegistry>,
        failsafe_config: crate::config::FailsafeConfig,
        cache_ttl: Duration,
    ) -> Self {
        Self {
            config_path,
            live_config,
            registry,
            failsafe_config,
            cache_ttl,
        }
    }

    /// Reload the config file and apply the diff.
    ///
    /// Returns a human-readable description of what changed.
    ///
    /// # Errors
    ///
    /// Returns an error string if the config file cannot be read or parsed.
    pub async fn reload(&self) -> std::result::Result<String, String> {
        let old_config = self.live_config.get();

        let new_config = Config::load(Some(&self.config_path))
            .map_err(|e| format!("Failed to parse config: {e}"))?;

        let patch = compute_diff(&old_config, &new_config);

        if patch.is_empty() {
            return Ok("no changes detected".to_string());
        }

        let summary = patch.summary();
        apply_patch(
            &patch,
            &self.registry,
            &self.failsafe_config,
            self.cache_ttl,
        )
        .await;
        self.live_config.set(new_config);

        Ok(summary)
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests;

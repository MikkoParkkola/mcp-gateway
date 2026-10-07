// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Config hot-reload with diff patching.
//!
//! This module watches `config.yaml` **and** any env files listed in
//! `config.env_files` (e.g. `~/.config/mcp-gateway/secrets.env`) for changes.  When either
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
//! use mcp_gateway::{config::{Config, LiveEnv}, config_reload::{ConfigWatcher, LiveConfig}};
//! use mcp_gateway::backend::BackendRegistry;
//!
//! # tokio_test::block_on(async {
//! let (shutdown_tx, _) = broadcast::channel(1);
//! let config = Config::default();
//! let live = Arc::new(LiveConfig::new(config.clone()));
//! let registry = Arc::new(BackendRegistry::new());
//! // The overlay and the paths startup actually opened; `default` is the
//! // empty one, which is what a gateway started without env files carries.
//! let env = Arc::new(LiveEnv::default());
//!
//! let _watcher = ConfigWatcher::start(
//!     PathBuf::from("config.yaml"),
//!     live,
//!     registry,
//!     &config,
//!     env,
//!     None, // no identity-grant sink: grants are not reloaded
//!     shutdown_tx.subscribe(),
//! );
//! # });
//! ```

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use parking_lot::RwLock;
use serde::Serialize;

use tracing::{info, warn};

use crate::backend::{Backend, BackendRegistry, runtime_plan_for_backend};
use crate::config::{Config, RuntimeConfig};

// ============================================================================
// Public types
// ============================================================================

/// Summary text a reload reports when the file on disk matches the live config.
/// Shared so the file-watcher can recognise the no-op case without matching on a
/// literal that could drift away from the one `no_changes` writes.
const NO_CHANGES_SUMMARY: &str = "no changes detected";

/// Error text a reload returns when the registry refused a backend because the
/// gateway is shutting down. A shared constant because the file-watcher has to
/// tell this apart from a bad config file: one is a broken file an operator must
/// fix, the other is normal shutdown, and they must not share an alert. The
/// honest fix is a typed error, but `reload_outcome` returns `Result<_, String>`
/// to callers outside this crate, so changing its shape is a next-major job.
const SHUTDOWN_ABORTED_ERROR: &str = "config reload aborted: the gateway is shutting down and refused to register \
     one or more backends";

/// Prefix of the error a reload returns when applying the file would leave the
/// tool surface reachable without a credential — the state the gateway refuses
/// to START in (`gateway::server::support::network_bind_refusal`).
///
/// A bare LABEL, deliberately. It used to read "config reload refused, the
/// running gateway is unchanged:" — which is the very claim about what remains
/// in force that this message states two bounded facts instead of making. The
/// body was corrected and the prefix kept it, in compressed form, where a test
/// written against the old phrasings did not look.
///
/// A PREFIX, matched with [`is_posture_refusal`], not compared whole like
/// [`SHUTDOWN_ABORTED_ERROR`]: the refusal's own text names the exposure and
/// carries the remedy, and rides behind this. An arm written `==` would never
/// match, and the refusal would be logged as a broken config file — sending the
/// operator to hunt YAML instead of reverting the `public_url`.
const POSTURE_REFUSED_PREFIX: &str = "config reload refused:";

/// `true` when `error` is the refusal [`POSTURE_REFUSED_PREFIX`] describes.
///
/// One predicate rather than a bare `starts_with`, so the day a second consumer
/// needs to tell this apart there is one place that decides. The file watcher is
/// the only one today; the meta-tool and the admin API forward the message
/// whole, and it carries the prefix.
fn is_posture_refusal(error: &str) -> bool {
    error.starts_with(POSTURE_REFUSED_PREFIX)
}

/// How long a config write waits for the reload lock before reporting busy.
///
/// Long enough to sit out a normal reload — stopping and re-registering
/// backends — and short enough that a stuck one surfaces as a refusal the
/// caller can act on rather than a request that never returns.
const RELOAD_LOCK_WAIT: Duration = Duration::from_secs(5);

/// Structured reload outcome for callers that need more than a log line.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ReloadOutcome {
    /// Human-readable summary of what changed.
    pub changes: String,
    /// Whether part of the change set remains pending until restart.
    pub restart_required: bool,
    /// Stable machine-readable reason for `restart_required`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub restart_reason: Option<&'static str>,
    /// The fields still awaiting a restart, named rather than only summarised.
    ///
    /// `changes` already carries them in prose; a caller that has to parse a
    /// sentence to find out whether `HOME` moved is a caller that will stop
    /// checking.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub pending_restart_fields: Vec<String>,
}

impl ReloadOutcome {
    /// Outcome returned when the reload pipeline detects no effective change.
    #[must_use]
    pub fn no_changes() -> Self {
        Self {
            changes: NO_CHANGES_SUMMARY.to_string(),
            restart_required: false,
            restart_reason: None,
            pending_restart_fields: Vec::new(),
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
    /// What the running process actually applied, fixed at startup.
    ///
    /// Kept apart from `inner` because the diff compares the file against the
    /// published snapshot: publishing a restart-only edit into that snapshot
    /// makes the next reload see no difference, so the warning fires once and
    /// never again. Comparing against what is RUNNING keeps it true until a
    /// restart makes the two agree.
    running: Arc<Config>,
    /// Shared authorization-policy generation. `None` in isolated tests.
    policy_epoch: Option<Arc<AtomicU64>>,
}

impl LiveConfig {
    /// Create a new `LiveConfig` seeded with the startup configuration.
    #[must_use]
    pub fn new(config: Config) -> Self {
        let running = Arc::new(config);
        Self {
            inner: RwLock::new(Arc::clone(&running)),
            running,
            policy_epoch: None,
        }
    }

    /// Share the gateway policy epoch so a published reload can bump it.
    #[must_use]
    pub fn with_policy_epoch(mut self, epoch: Arc<AtomicU64>) -> Self {
        self.policy_epoch = Some(epoch);
        self
    }

    /// The configuration this process is actually running.
    #[must_use]
    pub fn running(&self) -> &Config {
        &self.running
    }

    /// `true` when the file asks for something only a restart can apply.
    ///
    /// Fail-closed: every tracked field counts unless it is on the allow-list of
    /// fields proven to be re-read on the request path. A field wrongly counted
    /// tells an operator to restart when they need not, which is the safe
    /// direction; the reverse tells them a change took effect when it did not.
    ///
    /// MIK-7249 is this fail-closed direction. Grep finds it here and nowhere
    /// else: the fix is a subtraction in `pending_restart_fields`, so there is
    /// no added symbol carrying the ticket, and it is otherwise findable only
    /// by reading the comparison.
    #[must_use]
    pub fn restart_required(&self) -> bool {
        !pending_restart_fields(&self.running, &self.get()).is_empty()
    }

    /// Which fields the file asks for that the running process has not applied.
    #[must_use]
    pub fn pending_restart_fields(&self) -> Vec<&'static str> {
        pending_restart_fields(&self.running, &self.get())
    }

    /// Clone the current active configuration snapshot.
    #[must_use]
    pub fn get(&self) -> Arc<Config> {
        Arc::clone(&self.inner.read())
    }

    /// Atomically replace the current config.
    pub fn set(&self, config: Config) {
        let mut lock = self.inner.write();
        *lock = Arc::new(config);
        if let Some(epoch) = &self.policy_epoch {
            let prev = epoch.fetch_add(1, Ordering::Release);
            debug_assert!(
                epoch.load(Ordering::Relaxed) > prev,
                "policy epoch must be monotonic"
            );
        }
    }
}

// ============================================================================
#[cfg(test)]
#[path = "account_reload_tests.rs"]
mod account_reload_tests;

#[cfg(test)]
#[path = "account_reload_guard_tests.rs"]
mod account_reload_guard_tests;

#[cfg(test)]
#[path = "replica_restart_tests.rs"]
mod replica_restart_tests;

#[cfg(test)]
mod restart_required_tests;

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
///
/// Returns `false` when the registry refused a registration because the gateway
/// is shutting down. The patch is then only partly applied, so the caller must
/// NOT publish the new config as live: doing so would describe backends that
/// are not registered and report a reload that did not happen.
///
/// Not transactional, and deliberately not: additions and removals already
/// applied stay applied, and a modified backend's old instance may already be
/// stopped. Keeping the previous `LiveConfig` therefore does not describe the
/// registry exactly either. That is acceptable only because a refusal happens
/// solely after the permanent shutdown latch, so the inconsistency is bounded
/// to a gateway that is terminating anyway. If registration ever becomes
/// refusable for another reason, this needs a rollback rather than a flag.
/// The caller must hold [`BackendRegistry::lock_reload`] across the whole
/// transaction that surrounds this call - reading the live config, diffing it,
/// applying the patch, and publishing the new config (#397). Taking the lock
/// inside this function is not enough: the patch is computed against the live
/// config beforehand, so two reloads can each compute a patch that adds the
/// same backend, queue here, and register two instances under one name. The
/// second registration discards the first without stopping it, and if traffic
/// started that first instance in the gap its child process is orphaned. Both
/// callers in this module take the lock before they read the config.
#[must_use = "a partly applied patch must not be published as the live config"]
pub async fn apply_patch(
    patch: &ConfigPatch,
    registry: &BackendRegistry,
    failsafe_config: &crate::config::FailsafeConfig,
    cache_ttl: Duration,
    runtime_config: &RuntimeConfig,
) -> bool {
    let mut fully_applied = true;

    if patch.restart_required() {
        warn!("Config reload: server host/port changed — restart required to apply this change");
    }

    for (name, cfg) in &patch.backends_added {
        let runtime_plan = runtime_plan_for_backend(name, cfg, runtime_config);
        let backend = Arc::new(Backend::new_with_runtime_plan(
            name,
            cfg.clone(),
            failsafe_config,
            cache_ttl,
            runtime_plan,
        ));
        if registry.register(Arc::clone(&backend)) {
            info!(backend = %name, transport = %cfg.transport.transport_type(), "Config reload: backend added");
        } else {
            // The registry refuses registrations once shutdown has begun,
            // because nothing would ever stop them. Reporting "added" here
            // would tell an operator a backend exists when it does not.
            warn!(backend = %name, "Config reload: backend not added, gateway is shutting down");
            fully_applied = false;
        }
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
        let runtime_plan = runtime_plan_for_backend(name, cfg, runtime_config);
        let backend = Arc::new(Backend::new_with_runtime_plan(
            name,
            cfg.clone(),
            failsafe_config,
            cache_ttl,
            runtime_plan,
        ));
        if registry.register(Arc::clone(&backend)) {
            info!(backend = %name, transport = %cfg.transport.transport_type(), "Config reload: backend updated");
        } else {
            // The old instance was stopped above and the replacement refused,
            // so depending on timing the map now holds a stopped backend or no
            // entry at all under this name. Neither is worth repairing:
            // refusal only happens after the permanent shutdown latch, so the
            // gateway is going away regardless. What matters is that the caller
            // does not treat this reload as applied.
            warn!(backend = %name, "Config reload: backend not updated, gateway is shutting down");
            fully_applied = false;
        }
    }

    if patch.profiles_changed {
        info!("Config reload: meta/profile config updated (in-place)");
    }

    fully_applied
}

mod diff;
mod reload_context;
mod watcher;
mod write;
use diff::pending_restart_fields;
#[cfg(test)]
use diff::tracked_sections;
pub use diff::{ConfigPatch, compute_diff};
pub use reload_context::ReloadContext;
#[cfg(test)]
use reload_context::{
    EvaluatedReload, changed_startup_env_keys, load_config_patch, with_pending_restart,
};
pub use watcher::ConfigWatcher;
use watcher::{ReloadTrigger, watch_dir_of};
#[cfg(test)]
use watcher::{absolute_watch_path, config_watch_paths, is_config_event, is_config_event_for};
pub(crate) use write::mutate_config_and_reload_with;
pub use write::{
    ConfigMutation, ConfigWriteError, mutate_config_and_reload, write_config_and_reload,
    write_config_and_reload_outcome,
};

mod env_poll;
// Linux-only (W-L9): the real-watcher rows run on inotify (see `watch_chain_tests.rs`).
#[cfg(all(test, target_os = "linux"))]
mod env_poll_e2e_tests;
pub(crate) mod grant_audit;
mod grant_audit_plan;
mod grant_delta;
mod grant_reload;
pub use grant_reload::IdentityGrantSink;
mod watch_chain;

#[cfg(test)]
mod c4_enable_tests;
#[cfg(test)]
mod c9_file_ref_tests;

#[cfg(test)]
mod grant_change_trigger_tests;

#[cfg(test)]
mod grant_reload_trigger_tests;

#[cfg(test)]
mod grant_audit_crash_tests;
#[cfg(test)]
mod grant_audit_journal_tests;
#[cfg(test)]
mod grant_audit_reload_tests;
#[cfg(test)]
pub(crate) mod grant_audit_tests;
#[cfg(test)]
mod principal_collision_tests;
#[cfg(test)]
mod reload_load_tests;

#[cfg(test)]
mod tests;

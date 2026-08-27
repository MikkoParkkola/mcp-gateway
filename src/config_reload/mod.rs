// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
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

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use notify::{
    Config as NotifyConfig, Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher,
};
use parking_lot::{Mutex, RwLock};
use serde::Serialize;
use serde_json::Value;
use tracing::{info, warn};

use crate::Result;
use crate::backend::{Backend, BackendRegistry, runtime_plan_for_backend};
use crate::config::{BackendConfig, Config, RuntimeConfig, ServerConfig};

// ============================================================================
// Public types
// ============================================================================

/// Structural diff computed between two [`Config`] snapshots.
///
/// Only the `backends` and other hot-reloadable config sections are included.
/// Server address changes are flagged separately so the caller can warn the
/// operator.
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
/// A PREFIX, matched with [`is_posture_refusal`], not compared whole like
/// [`SHUTDOWN_ABORTED_ERROR`]: the refusal's own text names the exposure and
/// carries the remedy, and rides behind this. An arm written `==` would never
/// match, and the refusal would be logged as a broken config file — sending the
/// operator to hunt YAML instead of reverting the `public_url`.
const POSTURE_REFUSED_PREFIX: &str = "config reload refused, the running gateway is unchanged:";

/// `true` when `error` is the refusal [`POSTURE_REFUSED_PREFIX`] describes.
///
/// One predicate rather than a bare `starts_with`, so the day a second consumer
/// needs to tell this apart there is one place that decides. The file watcher is
/// the only one today; the meta-tool and the admin API forward the message
/// whole, and it carries the prefix.
fn is_posture_refusal(error: &str) -> bool {
    error.starts_with(POSTURE_REFUSED_PREFIX)
}

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

    /// Returns `true` when some detected change requires a process restart.
    #[must_use]
    pub fn restart_required(&self) -> bool {
        self.server_changed
    }

    /// Stable machine-readable restart reason, if any.
    #[must_use]
    pub fn restart_reason(&self) -> Option<&'static str> {
        self.server_changed.then_some("server_address_changed")
    }

    /// Structured outcome derived from this patch.
    #[must_use]
    pub fn outcome(&self) -> ReloadOutcome {
        ReloadOutcome {
            changes: self.summary(),
            restart_required: self.restart_required(),
            restart_reason: self.restart_reason(),
        }
    }
}

impl ReloadOutcome {
    /// Outcome returned when the reload pipeline detects no effective change.
    #[must_use]
    pub fn no_changes() -> Self {
        Self {
            changes: NO_CHANGES_SUMMARY.to_string(),
            restart_required: false,
            restart_reason: None,
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
}

impl LiveConfig {
    /// Create a new `LiveConfig` seeded with the startup configuration.
    #[must_use]
    pub fn new(config: Config) -> Self {
        let running = Arc::new(config);
        Self {
            inner: RwLock::new(Arc::clone(&running)),
            running,
        }
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

#[cfg(test)]
mod restart_required_tests {
    use super::LiveConfig;
    use crate::config::Config;

    fn with_auth(enabled: bool) -> Config {
        let mut c = Config::default();
        c.auth.enabled = enabled;
        c
    }

    #[test]
    fn a_restart_only_change_keeps_reporting_until_a_restart() {
        // The diff compares the file against the published snapshot. Publishing
        // a restart-only edit into that snapshot makes the NEXT reload see no
        // difference, so the warning appears once and never again: an operator
        // who enables authentication, sees the warning, and later edits
        // something unrelated is told everything is fine while authentication
        // has never been on.
        let live = LiveConfig::new(with_auth(false));

        live.set(with_auth(true));
        assert!(
            live.restart_required(),
            "the first reload must report that a restart is needed"
        );

        // An unrelated later edit. Authentication is still not running.
        let mut later = with_auth(true);
        later.server.max_body_size = 1234;
        live.set(later);
        assert!(
            live.restart_required(),
            "it must keep reporting until a restart makes the running process agree"
        );
    }

    #[test]
    fn every_tracked_section_is_covered() {
        // The classifier used to name eight sections while the diff tracked
        // seventeen, so a change to one of the other nine reported as applied
        // while nothing read it — the hand-list this was meant to replace.
        let running = Config::default();
        let mut wanted = Config::default();
        wanted.meta_mcp.enabled = !wanted.meta_mcp.enabled;
        let pending = super::pending_restart_fields(&running, &wanted);
        assert!(
            pending.contains(&"meta_mcp"),
            "a tracked section outside the original list must be reported: {pending:?}"
        );

        // Every restart-only server field, not a hand-picked few: `ws_port`,
        // `request_timeout` and `shutdown_timeout` were all omitted before.
        for (label, changed) in [
            (
                "ws_port",
                Config {
                    server: crate::config::ServerConfig {
                        ws_port: Some(9),
                        ..Config::default().server
                    },
                    ..Config::default()
                },
            ),
            (
                "request_timeout",
                Config {
                    server: crate::config::ServerConfig {
                        request_timeout: std::time::Duration::from_secs(7),
                        ..Config::default().server
                    },
                    ..Config::default()
                },
            ),
            (
                "env_files",
                Config {
                    env_files: vec!["x.env".to_string()],
                    ..Config::default()
                },
            ),
        ] {
            let pending = super::pending_restart_fields(&running, &changed);
            assert!(
                !pending.is_empty(),
                "a change to {label} must be reported as needing a restart"
            );
        }

        // `public_url` is the one server field that IS re-read per request, so
        // changing it alone must NOT demand a restart.
        let public_url_only = Config {
            server: crate::config::ServerConfig {
                public_url: Some("https://mcp.example.com".to_string()),
                ..Config::default().server
            },
            ..Config::default()
        };
        assert!(
            super::pending_restart_fields(&running, &public_url_only).is_empty(),
            "a hot-reloadable field must not demand a restart"
        );

        // Top-level scalars too: they sit outside every section and were
        // reported as applied while nothing re-read them.
        let profile_change = Config {
            default_routing_profile: "research".to_string(),
            ..Config::default()
        };
        assert!(
            super::pending_restart_fields(&running, &profile_change)
                .contains(&"default_routing_profile"),
            "a top-level field must be reported too"
        );

        let names: Vec<&str> = super::tracked_sections(&running, &running)
            .into_iter()
            .map(|(n, _)| n)
            .collect();
        for expected in [
            "auth",
            "mtls",
            "key_server",
            "capabilities",
            "playbooks",
            "cache",
        ] {
            assert!(
                names.contains(&expected),
                "{expected} must be tracked: {names:?}"
            );
        }
    }

    #[test]
    fn no_pending_restart_when_the_file_matches_the_running_process() {
        let live = LiveConfig::new(with_auth(false));
        live.set(with_auth(false));
        assert!(!live.restart_required());
    }
}

/// Fields the file changes that only a restart can apply.
///
/// The allow-list below names every field proven to be re-read on the request
/// path; everything else is restart-required by default. Each entry carries the
/// consumer that reads it, so a reader can check the claim rather than trust it.
///
/// - `server.public_url` — `router/well_known.rs`, `router/origin_guard.rs`
/// - `control_plane.role_mapping` — `ui/control_plane.rs`
fn pending_restart_fields(running: &Config, wanted: &Config) -> Vec<&'static str> {
    let mut pending = Vec::new();

    // `server` wholesale, minus the one field that IS re-read per request.
    // Listing the restart-only fields by hand is how `ws_port`,
    // `request_timeout` and `shutdown_timeout` went unreported: subtracting the
    // single live field from the whole cannot drift as fields are added.
    let server_without_public_url = |c: &Config| {
        let mut server = c.server.clone();
        server.public_url = None;
        canonical_json(&server)
    };
    if server_without_public_url(running) != server_without_public_url(wanted) {
        pending.push("server");
    }
    // `control_plane` the same way as `server`: `role_mapping` IS re-read per
    // request (`ui::control_plane`), so comparing the section whole would tell
    // an operator to restart for a change that already took effect.
    let control_plane_without_role_mapping = |c: &Config| {
        let mut cp = c.control_plane.clone();
        cp.role_mapping = crate::control_plane::ControlPlaneRoleMappingConfig::default();
        canonical_json(&cp)
    };
    if control_plane_without_role_mapping(running) != control_plane_without_role_mapping(wanted) {
        pending.push("control_plane");
    }
    if canonical_json(&running.env_files) != canonical_json(&wanted.env_files) {
        pending.push("env_files");
    }
    if running.default_routing_profile != wanted.default_routing_profile {
        pending.push("default_routing_profile");
    }

    // Everything else is compared WHOLESALE and reported by name. An earlier
    // version listed the sections it knew about, which is the hand-list this
    // was supposed to replace: a section added later reported as applied while
    // nothing read it. Subtracting the live readers from the whole is the only
    // form that stays true as the config grows.
    for (name, differs) in tracked_sections(running, wanted) {
        if differs {
            pending.push(name);
        }
    }

    pending
}

/// Every tracked section, paired with whether the file differs from the running
/// process. Live-applied sections are excluded by name, and that list is short
/// enough to check: `backends` is applied by the reload itself,
/// `server.public_url` and `control_plane.role_mapping` are re-read per request
/// (see `router::well_known`, `router::origin_guard`, `ui::control_plane`).
fn tracked_sections(running: &Config, wanted: &Config) -> Vec<(&'static str, bool)> {
    // A macro rather than sixteen hand-written comparisons: the point is that
    // the list is exhaustive, and a shape that makes adding one a single line
    // is the shape that stays exhaustive.
    macro_rules! sections {
        ($($name:literal => $field:ident),* $(,)?) => {
            vec![$((
                $name,
                canonical_json(&running.$field) != canonical_json(&wanted.$field),
            )),*]
        };
    }

    sections![
        "auth" => auth,
        "mtls" => mtls,
        "key_server" => key_server,
        "agent_auth" => agent_auth,
        "security" => security,
        "webhooks" => webhooks,
        "meta_mcp" => meta_mcp,
        "capabilities" => capabilities,
        "playbooks" => playbooks,
        "routing_profiles" => routing_profiles,
        "code_mode" => code_mode,
        "marketplace" => marketplace,
        "streaming" => streaming,
        "failsafe" => failsafe,
        "cache" => cache,
        "runtime" => runtime,
        "cost_governance" => cost_governance,
    ]
}

/// Returns `true` when the TCP-listener address differs.
fn server_address_changed(old: &ServerConfig, new: &ServerConfig) -> bool {
    old.host != new.host || old.port != new.port
}

/// Returns `true` when any non-backend, non-server field differs.
///
/// Uses canonical JSON with sorted object keys as a cheap structural equality
/// check so we don't need to `PartialEq` every nested config type.
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

/// Serialize a value to canonical JSON with object keys sorted recursively.
///
/// This keeps diff detection stable across logically-equivalent `HashMap` and
/// JSON object instances that may iterate in a different order between reloads.
fn canonical_json<T: Serialize + ?Sized>(value: &T) -> String {
    fn sort_json_value(value: &mut Value) {
        match value {
            Value::Object(map) => {
                let mut entries: Vec<_> = std::mem::take(map).into_iter().collect();
                entries.sort_by(|(left, _), (right, _)| left.cmp(right));

                for (_, entry_value) in &mut entries {
                    sort_json_value(entry_value);
                }

                *map = entries.into_iter().collect();
            }
            Value::Array(values) => {
                for entry in values {
                    sort_json_value(entry);
                }
            }
            Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {}
        }
    }

    let mut json = serde_json::to_value(value).unwrap_or(Value::Null);
    sort_json_value(&mut json);
    serde_json::to_string(&json).unwrap_or_default()
}

/// Comparable snapshot of every top-level [`Config`] field **except**:
///
/// - `backends` — tracked individually via the `backends_added/removed/modified` buckets.
/// - `server.host` / `server.port` — tracked separately via `server_changed`
///   because they require a process restart to take effect.
/// - `env_files` — loaded once at process startup; changes only take effect
///   after a full process restart, so they are excluded from hot-reload detection.
#[derive(PartialEq)]
struct MetaFields {
    // ── Always-tracked feature sections ─────────────────────────────────────
    auth: String,
    meta_mcp: String,
    streaming: String,
    failsafe: String,
    capabilities: String,
    cache: String,
    playbooks: String,
    security: String,
    webhooks: String,
    // ── Additional top-level fields (previously missing from diff) ───────────
    routing_profiles: String,
    default_routing_profile: String,
    code_mode: String,
    mtls: String,
    key_server: String,
    agent_auth: String,
    runtime: String,
    marketplace: String,
    /// Control-plane section (RBAC role mapping). Tracked so a role-mapping-only
    /// edit is detected and triggers a reload — without this, removing an admin
    /// rule would not take effect until restart (MIK-6702 CP.RELOAD.2).
    control_plane: String,
    /// `server.public_url` only. The advertised RFC 9728 protected-resource
    /// origin is read from `live_config` at request time, so a `public_url`
    /// edit takes effect on reload without a restart — unlike `server.host` /
    /// `server.port`, which change the TCP listener and stay in
    /// `server_address_changed`. Tracked here so a public-url-only edit is not
    /// silently ignored until the next restart.
    server_public_url: String,
    #[cfg(feature = "cost-governance")]
    cost_governance: String,
}

impl MetaFields {
    fn from(c: &Config) -> Self {
        Self {
            auth: canonical_json(&c.auth),
            meta_mcp: canonical_json(&c.meta_mcp),
            streaming: canonical_json(&c.streaming),
            failsafe: canonical_json(&c.failsafe),
            capabilities: canonical_json(&c.capabilities),
            cache: canonical_json(&c.cache),
            playbooks: canonical_json(&c.playbooks),
            security: canonical_json(&c.security),
            webhooks: canonical_json(&c.webhooks),
            routing_profiles: canonical_json(&c.routing_profiles),
            default_routing_profile: c.default_routing_profile.clone(),
            code_mode: canonical_json(&c.code_mode),
            mtls: canonical_json(&c.mtls),
            key_server: canonical_json(&c.key_server),
            agent_auth: canonical_json(&c.agent_auth),
            runtime: canonical_json(&c.runtime),
            marketplace: canonical_json(&c.marketplace),
            control_plane: canonical_json(&c.control_plane),
            server_public_url: c.server.public_url.clone().unwrap_or_default(),
            #[cfg(feature = "cost-governance")]
            cost_governance: canonical_json(&c.cost_governance),
        }
    }
}

/// Partition backends into added / removed / modified buckets.
fn classify_backends(old: &Config, new: &Config, patch: &mut ConfigPatch) {
    let runtime_changed = canonical_json(&old.runtime) != canonical_json(&new.runtime);
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
            && (backend_config_changed(old_cfg, new_cfg)
                || (runtime_changed && new_cfg.runtime_profile.is_some()))
        {
            patch
                .backends_modified
                .push(((*name).to_string(), (*new_cfg).clone()));
        }
    }
}

/// Returns `true` when any observable field of a backend config differs.
///
/// Uses canonical JSON for a stable, deep equality check without requiring
/// `PartialEq` on all nested types.
fn backend_config_changed(old: &BackendConfig, new: &BackendConfig) -> bool {
    canonical_json(old) != canonical_json(new)
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
        .map_err(|e| {
            crate::Error::ConfigWatcher(format!("Failed to create config watcher: {e}"))
        })?;

        // Watch the config file's parent directory.
        let config_dir = config_path
            .parent()
            .unwrap_or_else(|| std::path::Path::new("."))
            .to_path_buf();
        watcher
            .watch(&config_dir, RecursiveMode::NonRecursive)
            .map_err(|e| {
                crate::Error::ConfigWatcher(format!("Failed to watch config path: {e}"))
            })?;

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

            // The watcher runs the same reload transaction as the meta-tool and
            // the admin UI, through the same function (#397). It used to have a
            // private copy of that transaction, which meant the regression test
            // covering the reload lock only ever exercised the other two entry
            // points: an edit that moved the lock here alone would not have
            // failed a single test.
            let ctx =
                ReloadContext::new(config_path, live_config, registry, failsafe_cfg, cache_ttl);

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
                            match ctx.reload_outcome().await {
                                Ok(outcome) if outcome.changes == NO_CHANGES_SUMMARY => {
                                    tracing::debug!("Config reload: no changes detected");
                                }
                                Ok(outcome) => {
                                    info!(
                                        changes = %outcome.changes,
                                        restart_required = outcome.restart_required,
                                        "Config reload: complete"
                                    );
                                }
                                Err(e) if is_posture_refusal(&e) => {
                                    // Its own arm, ahead of the generic one: a
                                    // posture refusal is a decision about this
                                    // config, not a file the operator must fix
                                    // the syntax of.
                                    warn!("Config reload: {e}");
                                }
                                Err(e) if e == SHUTDOWN_ABORTED_ERROR => {
                                    warn!(
                                        "Config reload: aborted, the gateway is \
                                         shutting down; keeping the previous live \
                                         config rather than publishing one that \
                                         describes backends which were never \
                                         registered"
                                    );
                                }
                                Err(e) => {
                                    // Every other error out of `reload_outcome`
                                    // comes from reading or parsing the file:
                                    // that call has exactly two failure sources
                                    // and the arm above catches the other one. A
                                    // third source added later lands here and
                                    // would be mislabelled, so give it its own
                                    // arm rather than widening this message.
                                    warn!(
                                        error = %e,
                                        "Config reload: failed to parse config file, keeping current config"
                                    );
                                }
                            }
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

fn load_config_patch(
    config_path: &std::path::Path,
    live_config: &Arc<LiveConfig>,
) -> std::result::Result<Option<(Config, ConfigPatch)>, String> {
    let old_config = live_config.get();
    let new_config =
        Config::load(Some(config_path)).map_err(|e| format!("Failed to parse config: {e}"))?;
    let patch = compute_diff(&old_config, &new_config);

    if patch.is_empty() {
        Ok(None)
    } else {
        Ok(Some((new_config, patch)))
    }
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
        self.reload_outcome().await.map(|outcome| outcome.changes)
    }

    /// Reload the config file and return a structured outcome for callers/UI.
    ///
    /// # Errors
    ///
    /// Returns an error string if the config file cannot be read or parsed.
    pub async fn reload_outcome(&self) -> std::result::Result<ReloadOutcome, String> {
        // Serializes the whole reload transaction (#397) - read, diff, apply,
        // publish. All four concurrent entry points land here: the
        // `gateway_reload_config` meta-tool, the admin UI reload, every admin UI
        // backend edit, and the config-file watcher. See `apply_patch` for why
        // the lock cannot live one level down.
        let _reload_guard = self.registry.lock_reload().await;
        self.reload_outcome_locked().await
    }

    /// Write `config` to `path`, then reload, with both steps under one lock.
    ///
    /// Waits [`RELOAD_LOCK_WAIT`] for the reload lock. See
    /// [`Self::write_and_reload_outcome_within`] for why the wait is bounded.
    ///
    /// # Errors
    ///
    /// [`ConfigWriteError::Busy`] when the lock did not come free in time, and
    /// [`ConfigWriteError::Failed`] on validation, serialization, write,
    /// rename, or reload failure.
    ///
    /// The write must be inside the same critical section as the reload. Two
    /// admin UI edits that write first and lock second can interleave so that
    /// one reload reads the other's file, and the caller is told its own edit
    /// was applied. Holding one guard across write-read-apply-publish is what
    /// makes an edit's own bytes the ones it reloads.
    pub async fn write_and_reload_outcome(
        &self,
        path: &std::path::Path,
        config: &Config,
    ) -> std::result::Result<ReloadOutcome, ConfigWriteError> {
        self.write_and_reload_outcome_within(path, RELOAD_LOCK_WAIT, config)
            .await
    }

    /// [`Self::write_and_reload_outcome`] with an explicit bound on the wait.
    ///
    /// The bound is a parameter so a test can prove the busy path without
    /// spending the production wait in wall-clock time.
    ///
    /// # Errors
    ///
    /// As [`Self::write_and_reload_outcome`].
    pub async fn write_and_reload_outcome_within(
        &self,
        path: &std::path::Path,
        wait: Duration,
        config: &Config,
    ) -> std::result::Result<ReloadOutcome, ConfigWriteError> {
        let _reload_guard = self.lock_reload_within(wait).await?;
        crate::config_persistence::write_config(path, config)?;
        self.reload_outcome_locked()
            .await
            .map_err(|e| ConfigWriteError::Failed(format!("Config written but reload failed: {e}")))
    }

    /// Read the config, apply `mutate`, write, and reload, all under one guard.
    ///
    /// The read belongs inside the guard. Two admin UI edits that each read the
    /// file before locking will each build their change on the same starting
    /// copy, and whichever writes second erases the other's change while
    /// telling its caller the edit was saved.
    ///
    /// Waits [`RELOAD_LOCK_WAIT`] for the reload lock. See
    /// [`Self::mutate_and_reload_outcome_within`] for why the wait is bounded.
    ///
    /// # Errors
    ///
    /// [`ConfigWriteError::Busy`] when the lock did not come free in time, and
    /// [`ConfigWriteError::Failed`] on write, rename, or reload failure. A
    /// refusal from `mutate` is not an error; it comes back as
    /// [`ConfigMutation::Rejected`].
    pub async fn mutate_and_reload_outcome<T, E, F>(
        &self,
        path: &std::path::Path,
        mutate: F,
    ) -> std::result::Result<ConfigMutation<T, E>, ConfigWriteError>
    where
        F: FnOnce(&mut Config) -> std::result::Result<T, E>,
    {
        self.mutate_and_reload_outcome_within(path, RELOAD_LOCK_WAIT, mutate)
            .await
    }

    /// [`Self::mutate_and_reload_outcome`] with an explicit bound on the wait.
    ///
    /// # Errors
    ///
    /// As [`Self::mutate_and_reload_outcome`].
    pub async fn mutate_and_reload_outcome_within<T, E, F>(
        &self,
        path: &std::path::Path,
        wait: Duration,
        mutate: F,
    ) -> std::result::Result<ConfigMutation<T, E>, ConfigWriteError>
    where
        F: FnOnce(&mut Config) -> std::result::Result<T, E>,
    {
        let _reload_guard = self.lock_reload_within(wait).await?;
        let mut config = crate::config_persistence::load_config_or_default(path);
        let value = match mutate(&mut config) {
            Ok(value) => value,
            Err(rejection) => return Ok(ConfigMutation::Rejected(rejection)),
        };
        crate::config_persistence::write_config(path, &config)?;
        let outcome = self.reload_outcome_locked().await.map_err(|e| {
            ConfigWriteError::Failed(format!("Config written but reload failed: {e}"))
        })?;
        Ok(ConfigMutation::Applied(value, Some(outcome)))
    }

    /// Take the reload lock, giving up after `wait`.
    ///
    /// The bound covers *acquiring* the lock, not holding it. A write that wins
    /// the lock then runs its reload to completion, however long that takes;
    /// what the bound prevents is every other write queueing behind that one
    /// forever.
    ///
    /// Only config *writes* are bounded at all. A reload triggered by the
    /// meta-tool, the admin UI reload button, or the file watcher still waits as
    /// long as it takes: refusing one of those would silently drop a config
    /// change the operator already made on disk, which trades a hang for a lost
    /// edit. A refused write, by contrast, has changed nothing and can be
    /// retried.
    async fn lock_reload_within(
        &self,
        wait: Duration,
    ) -> std::result::Result<tokio::sync::MutexGuard<'_, ()>, ConfigWriteError> {
        tokio::time::timeout(wait, self.registry.lock_reload())
            .await
            .map_err(|_| ConfigWriteError::Busy)
    }

    /// The reload transaction itself. The caller must already hold the reload
    /// lock; taking it here as well would deadlock on the non-reentrant mutex.
    async fn reload_outcome_locked(&self) -> std::result::Result<ReloadOutcome, String> {
        let Some((new_config, patch)) = load_config_patch(&self.config_path, &self.live_config)?
        else {
            // No difference from the published snapshot does not mean nothing is
            // outstanding: a restart-only edit was published on an earlier
            // reload and the running process still has not applied it.
            return Ok(with_pending_restart(
                ReloadOutcome::no_changes(),
                &self.live_config,
            ));
        };

        // Before `apply_patch`, which stops and starts backends: a refusal that
        // ran after it could not say nothing was applied. And before the
        // publish, which is what the origin gate would re-read.
        if let Some(refusal) =
            crate::gateway::reload_posture_refusal(self.live_config.running(), &new_config)
        {
            // What a restart does with this same file is the operator's next
            // decision, and it differs. A file that also enables authentication
            // is right on a restart and only wrong to apply live; a file that
            // just declares the name refuses at the next start, planned or not.
            let restart = if refusal.restart_would_also_refuse {
                "This configuration is on disk, so the next start — including an                  unplanned one — will refuse to serve. Revert it, or close the                  tool paths."
            } else {
                "A restart applies this file whole, including the parts a reload                  cannot, and starting on it is safe."
            };
            return Err(format!(
                "{POSTURE_REFUSED_PREFIX} {} Nothing was applied, backends in the \
                 same file included, and the gateway is still serving the \
                 configuration in force before this reload. {restart}",
                refusal.reason
            ));
        }

        let outcome = patch.outcome();
        let fully_applied = apply_patch(
            &patch,
            &self.registry,
            &self.failsafe_config,
            self.cache_ttl,
            &new_config.runtime,
        )
        .await;

        if !fully_applied {
            // Publishing here would describe backends the registry refused, and
            // report a reload that did not happen. The caller asked for an
            // outcome; the honest one is an error.
            return Err(SHUTDOWN_ABORTED_ERROR.to_string());
        }

        self.live_config.set(new_config);

        Ok(with_pending_restart(outcome, &self.live_config))
    }
}

/// Fold outstanding restart-only fields into a reload outcome.
///
/// Reported on every reload while they remain outstanding, not once. The diff
/// alone cannot carry this: publishing a restart-only edit into the snapshot
/// removes it from every later diff, so the operator who enables authentication
/// and is distracted would never be told again.
fn with_pending_restart(mut outcome: ReloadOutcome, live: &LiveConfig) -> ReloadOutcome {
    let pending = live.pending_restart_fields();
    if pending.is_empty() {
        return outcome;
    }
    outcome.restart_required = true;
    // Never overwrite an existing reason: it is documented as stable and
    // machine-readable, so a consumer keying on `server_address_changed` must
    // keep seeing it. Only fill it in when the patch had none.
    outcome.restart_reason = outcome
        .restart_reason
        .or(Some("config changed in fields that only a restart applies"));
    outcome.changes = format!(
        "{} — NOT YET APPLIED, restart required for: {}",
        outcome.changes,
        pending.join(", ")
    );
    outcome
}

/// How long a config write waits for the reload lock before reporting busy.
///
/// Long enough to sit out a normal reload — stopping and re-registering
/// backends — and short enough that a stuck one surfaces as a refusal the
/// caller can act on rather than a request that never returns.
const RELOAD_LOCK_WAIT: Duration = Duration::from_secs(5);

/// Why a config write did not happen.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfigWriteError {
    /// Another reload or write held the reload lock for longer than this write
    /// was willing to wait. Nothing was read, written, or reloaded, so the same
    /// request can simply be retried.
    Busy,
    /// The write itself failed. The message describes which step.
    Failed(String),
}

impl std::fmt::Display for ConfigWriteError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Busy => write!(
                f,
                "the gateway is applying another config change; nothing was written, retry shortly"
            ),
            Self::Failed(message) => write!(f, "{message}"),
        }
    }
}

impl std::error::Error for ConfigWriteError {}

impl From<String> for ConfigWriteError {
    fn from(message: String) -> Self {
        Self::Failed(message)
    }
}

/// Serialize `config`, write it atomically, then trigger hot-reload when a
/// reload context is available.
///
/// Persistence is always authoritative for the on-disk file. Hot-reload then
/// applies only the subset of changes supported by [`ReloadContext`] (for
/// example, backend changes); server listener changes remain on disk until the
/// process is restarted.
///
/// # Errors
///
/// [`ConfigWriteError::Busy`] when a reload held the lock too long, and
/// [`ConfigWriteError::Failed`] on serialization, write, rename, or reload failure.
pub async fn write_config_and_reload(
    path: &Path,
    config: &Config,
    reload_context: Option<&ReloadContext>,
) -> std::result::Result<(), ConfigWriteError> {
    write_config_and_reload_outcome(path, config, reload_context)
        .await
        .map(|_| ())
}

/// Serialize `config`, write it atomically, then return any hot-reload outcome.
///
/// # Errors
///
/// [`ConfigWriteError::Busy`] when a reload held the lock too long, and
/// [`ConfigWriteError::Failed`] on serialization, write, rename, or reload failure.
pub async fn write_config_and_reload_outcome(
    path: &Path,
    config: &Config,
    reload_context: Option<&ReloadContext>,
) -> std::result::Result<Option<ReloadOutcome>, ConfigWriteError> {
    if let Some(ctx) = reload_context {
        // Write and reload share one lock inside the context. Writing here
        // first would reopen the race the lock exists to close.
        return ctx.write_and_reload_outcome(path, config).await.map(Some);
    }

    crate::config_persistence::write_config(path, config)?;
    Ok(None)
}

/// What a guarded read-modify-write did: either the change was applied and
/// persisted, or the caller's own check rejected it and nothing was written.
pub enum ConfigMutation<T, E> {
    /// The change was applied, persisted, and (when a reload context exists)
    /// reloaded.
    Applied(T, Option<ReloadOutcome>),
    /// The caller's closure refused the change. The file is untouched.
    Rejected(E),
}

/// Read the config, apply `mutate` to it, and persist the result without
/// letting another writer slip in between the read and the write.
///
/// Reading outside the lock is what makes edits vanish: two requests each read
/// the same starting file, each apply their own change to that stale copy, and
/// the second write erases the first change while reporting success. Doing the
/// read inside the same critical section as the write is what stops it.
///
/// # Errors
///
/// [`ConfigWriteError::Busy`] when a reload held the lock too long, and
/// [`ConfigWriteError::Failed`] on validation, write, rename, or reload failure.
/// A refusal from `mutate` is not an error; it comes back as
/// [`ConfigMutation::Rejected`] with the file untouched.
pub async fn mutate_config_and_reload<T, E, F>(
    path: &Path,
    reload_context: Option<&ReloadContext>,
    mutate: F,
) -> std::result::Result<ConfigMutation<T, E>, ConfigWriteError>
where
    F: FnOnce(&mut Config) -> std::result::Result<T, E>,
{
    if let Some(ctx) = reload_context {
        return ctx.mutate_and_reload_outcome(path, mutate).await;
    }

    // No live gateway to reload, so no reload lock exists to hold. This path is
    // the CLI acting on a config file nothing else is serving.
    let mut config = crate::config_persistence::load_config_or_default(path);
    match mutate(&mut config) {
        Ok(value) => {
            crate::config_persistence::write_config(path, &config)?;
            Ok(ConfigMutation::Applied(value, None))
        }
        Err(rejection) => Ok(ConfigMutation::Rejected(rejection)),
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests;

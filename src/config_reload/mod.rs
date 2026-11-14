// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Config hot-reload with diff patching.
//!
//! This module watches `config.yaml` **and** any env files listed in
//! `config.env_files` (e.g. `~/.config/mcp-gateway/secrets.env`) for changes.  When either
//! file type changes the full [`Config::load`](crate::config::Config::load) pipeline is re-run, env vars are
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
//!     None, // no capability backend to announce listing changes for
//!     shutdown_tx.subscribe(),
//! );
//! # });
//! ```

// Only the test modules that glob-import this module still name these.
#[cfg(test)]
use std::sync::Arc;
#[cfg(test)]
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use serde::Serialize;

#[cfg(test)]
use crate::config::Config;

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

/// How every network-posture reason starts (`gateway::server`'s serve refusal:
/// a bind or a cleartext exposure). The restart-only refusals that share
/// [`POSTURE_REFUSED_PREFIX`] (signing, posture and hardened fields, an
/// account binding) say "restart" instead.
const NETWORK_POSTURE_REASON: &str = "refusing to serve HTTP";

/// Why a reload failed, for a caller that answers with a status (MIK-8058).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ReloadFailure {
    /// The network-posture policy refused the file: the operator's config,
    /// not a server fault.
    PostureRefused,
    /// Shutdown began: the reload was stopped by the shutdown signal, or the
    /// registry refused its backends.
    ShuttingDown,
    /// Anything else: an unreadable file, a failed apply, a change that needs
    /// a restart.
    Internal,
}

/// Classify a `reload_outcome` error. The error stays a `String` (a public
/// shape), so the class is read from the shared prefix, the posture reason
/// and the shutdown literals.
pub(crate) fn reload_failure(error: &str) -> ReloadFailure {
    let posture = error
        .strip_prefix(POSTURE_REFUSED_PREFIX)
        .is_some_and(|rest| rest.trim_start().starts_with(NETWORK_POSTURE_REASON));
    if posture {
        ReloadFailure::PostureRefused
    } else if error.starts_with(SHUTDOWN_ABORTED_ERROR)
        || error.starts_with(reload_context::STOPPED)
    {
        ReloadFailure::ShuttingDown
    } else {
        ReloadFailure::Internal
    }
}

/// How long a config write waits for the reload lock before reporting busy.
///
/// Long enough to sit out a normal reload — stopping and re-registering
/// backends — and short enough that a stuck one surfaces as a refusal the
/// caller can act on rather than a request that never returns.
pub(crate) const RELOAD_LOCK_WAIT: Duration = Duration::from_secs(5);

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

mod live_config;
pub use live_config::LiveConfig;

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

#[cfg(all(test, feature = "firewall"))]
mod live_collusion_tests;
#[cfg(test)]
mod live_keys_reload_tests;
#[cfg(test)]
mod live_sections_tests;
#[cfg(test)]
mod owner_reload_tests;

mod apply;
pub use apply::apply_patch;

mod diff;
mod generation;
/// The settings the web UI may change (U8).
#[path = "ui_fields.rs"]
pub(crate) mod ui_fields;
pub use generation::Generation;
#[cfg(all(test, feature = "webui"))]
pub(crate) use generation::refuse_hook;
#[cfg(feature = "webui")]
pub(crate) use generation::refuse_multi_user_flip;

/// `config` with both request-path security flags off: what the router test
/// fixtures set on `AppState` before the flags moved into the published
/// config (ADR-023).
#[cfg(test)]
pub(crate) fn flags_off(mut config: Config) -> Config {
    config.security.sanitize_input = false;
    config.security.ssrf_protection = false;
    config
}
pub(crate) mod override_audit;
#[cfg_attr(
    not(feature = "webui"),
    allow(
        dead_code,
        reason = "every build records refusals; only the web UI's refusals route reads them back"
    )
)]
pub(crate) mod refusals;
mod reload_context;
pub(crate) mod reload_tally;
mod reload_warm_hook;
pub(crate) mod revision;
// Linux and macOS, as the other real-watcher rows (MIK-8181).
#[cfg(all(test, any(target_os = "linux", target_os = "macos")))]
mod reload_warm_hook_tests;
pub(crate) use reload_warm_hook::{OnRegistered, RegisteredChange};
mod watcher;
mod write;
// The restart-required test modules call it through this module.
#[cfg(test)]
use diff::pending_restart_fields;

/// The `pending_restart` entry for startup environment values (env files,
/// secret files, process overrides) changed since start: one name, never the
/// variables themselves.
const ENV_RESTART: &str = "environment";

/// `pending` with [`ENV_RESTART`] present exactly while `env_restart` is not
/// empty.
fn with_env_restart(mut pending: Vec<&'static str>, env_restart: &[String]) -> Vec<&'static str> {
    pending.retain(|field| *field != ENV_RESTART);
    if !env_restart.is_empty() {
        pending.push(ENV_RESTART);
    }
    pending
}
#[cfg(test)]
use diff::tracked_sections;
pub use diff::{ConfigPatch, compute_diff};
pub use reload_context::ReloadContext;
pub(crate) use reload_context::SurfacedHook;
use reload_context::replace::startup_recovery_intent;

/// Recover a byte write a crash left behind, before a serving gateway first
/// loads `config`, recording the recovery in the audit log of the config it
/// leaves first (`config_persistence::recover_before_start` with the record
/// step). Here rather than in `config_persistence`, which must not
/// depend on this module. Exists for the bundled binary's serve paths; not a
/// stable API.
///
/// # Errors
///
/// As `config_persistence::recover_before_start`; the message says
/// what to do, and the gateway must not start.
pub fn recover_before_start(config: &std::path::Path) -> Result<(), String> {
    crate::config_persistence::recover_before_start(config, &startup_recovery_intent)
}
#[cfg(all(test, feature = "webui"))]
pub(crate) use reload_context::replace::order as write_order;
#[cfg(feature = "webui")]
pub(crate) use reload_context::replace::{
    AuditPosture, BackendOp, Expected, FileRevision, GatewayAuth, IntentKind, NO_AUDIT_LOG,
    RefusalClass, Replace, ReplaceError, ReplaceOutcome, Replaced, RevokeCheck, SecretStep,
    replace_audited, replace_audited_revoke,
};
// The settings routes' reach into the save core: these named items only, each
// already pub(crate) in its module; the rest of the two modules stays private.
#[cfg(feature = "webui")]
pub(crate) use reload_context::replace::ui_diff::{
    Patch, PatchStep, PreviewRefused, Shown, UiPreview, UiRefused, path_text, ui_diff,
};
#[cfg(feature = "webui")]
pub(crate) use reload_context::replace::ui_save::{SaveEdit, SaveValue, SecretTarget, ui_save};
#[cfg(test)]
use reload_context::{
    EvaluatedReload, changed_startup_env_keys, load_config_patch, with_pending_restart,
};
pub use watcher::ConfigWatcher;
use watcher::{ReloadTrigger, watch_dir_of};
#[cfg(test)]
use watcher::{absolute_watch_path, config_watch_paths, is_config_event, is_config_event_for};
pub use write::{ConfigMutation, ConfigWriteError, mutate_config_and_reload};
#[allow(deprecated)] // the deprecated writers stay reachable by name until 5.0
pub use write::{write_config_and_reload, write_config_and_reload_outcome};
// The writer-lock tests call the refusing writer directly.
#[cfg(test)]
use write::mutate_config_and_reload_with;

mod env_poll;
// Linux and macOS (MIK-8181), as the real-watcher rows (see `watch_chain_tests.rs`).
#[cfg(all(test, any(target_os = "linux", target_os = "macos")))]
mod env_poll_announce_tests;
#[cfg(all(test, any(target_os = "linux", target_os = "macos")))]
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
mod config_error_leak_tests;
#[cfg(test)]
mod empty_backends_reload_tests;
#[cfg(test)]
mod reload_pause;
/// For the admin audit layer's cancel rows, which pause a UI write between
/// writing the file and publishing its reload.
#[cfg(all(test, feature = "webui"))]
pub(crate) use reload_pause::arm as arm_reload_pause;
#[cfg(test)]
mod webhook_base_path_reload_tests;
#[cfg(test)]
mod writer_lock_tests;
#[cfg(all(test, unix))]
mod writer_symlink_tests;

#[cfg(test)]
mod flip_pin_tests;
#[cfg(all(test, feature = "webui"))]
mod replace_audit_key_tests;
#[cfg(test)]
mod replace_audit_tests;
#[cfg(test)]
mod replace_secret_tests;
#[cfg(test)]
mod replace_test_support;
#[cfg(test)]
mod replace_tests;
#[cfg(test)]
mod replace_validate_tests;

#[cfg(test)]
mod reader_lock_tests;

#[cfg(test)]
mod grant_change_trigger_tests;

#[cfg(test)]
mod grant_reload_trigger_tests;

/// A backend's configured `headers:`/`env:` credentials across a reload
/// that changes which of them are secret.
#[cfg(test)]
mod configured_secrets_reload_tests;
#[cfg(all(test, feature = "firewall"))]
mod firewall_shape_reload_tests;
#[cfg(test)]
mod grant_audit_crash_tests;
#[cfg(test)]
mod grant_audit_journal_tests;
#[cfg(test)]
mod grant_audit_plan_tests;
#[cfg(test)]
mod grant_audit_reload_tests;
#[cfg(test)]
pub(crate) mod grant_audit_tests;
#[cfg(test)]
mod pattern_grammar_reload_tests;
#[cfg(test)]
mod principal_collision_tests;
#[cfg(test)]
mod reload_load_tests;
#[cfg(test)]
mod runtime_name_clash_tests;

#[cfg(test)]
mod tests;

#[cfg(test)]
#[path = "refusal_class_tests.rs"]
mod refusal_class_tests;

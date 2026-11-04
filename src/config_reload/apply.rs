// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Applying a computed [`ConfigPatch`] to the live backend registry.

use std::sync::Arc;
use std::time::Duration;

use tracing::{info, warn};

use super::ConfigPatch;
use crate::backend::{Backend, BackendRegistry, runtime_plan_for_backend};
use crate::config::RuntimeConfig;

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
    // A backend registered here is seeded from the registry's load record:
    // the caller sets this load's record first (reload_transaction).
    debug_assert!(
        registry.take_load_record(),
        "apply_patch without its load's record: call set_load_record first"
    );
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
        #[allow(
            clippy::disallowed_methods,
            reason = "Lifecycle: config reload applies the operator's backend set; no caller request"
        )]
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
        #[allow(
            clippy::disallowed_methods,
            reason = "Lifecycle: config reload applies the operator's backend set; no caller request"
        )]
        if let Some(backend) = registry.get(name)
            && let Err(e) = backend.stop().await
        {
            warn!(backend = %name, error = %e, "Config reload: error stopping removed backend");
        }
        #[allow(
            clippy::disallowed_methods,
            reason = "Lifecycle: config reload applies the operator's backend set; no caller request"
        )]
        registry.remove(name);
        info!(backend = %name, "Config reload: backend removed");
    }

    for (name, cfg) in &patch.backends_modified {
        // Stop old instance (waits for transport close).
        #[allow(
            clippy::disallowed_methods,
            reason = "Lifecycle: config reload applies the operator's backend set; no caller request"
        )]
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
        #[allow(
            clippy::disallowed_methods,
            reason = "Lifecycle: config reload applies the operator's backend set; no caller request"
        )]
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

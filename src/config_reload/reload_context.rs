// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! `ReloadContext`: the imperative reload handle used by the meta-tool.

use std::path::PathBuf;
use std::sync::Arc;

use std::time::Duration;

use std::fmt::Write as _;

use crate::Result;
use crate::backend::BackendRegistry;
use crate::config::{Config, EnvOverlay, LiveEnv, ResolvedEnvFiles};
use crate::security::{posture, ssrf::DestinationPolicy};

use super::{IdentityGrantSink, LiveConfig, ReloadOutcome, SHUTDOWN_ABORTED_ERROR, apply_patch};

#[path = "reload_context_write.rs"]
mod write_api;

#[path = "reload_context_lock.rs"]
mod lock_api;

#[path = "replace.rs"]
pub(crate) mod replace;

#[path = "replace_refusal.rs"]
mod replace_refusal;

#[path = "reload_context_evaluate.rs"]
mod evaluate;

#[path = "reload_context_refusals.rs"]
mod refusals;

#[cfg(test)]
pub(super) use evaluate::IMPLICIT_STARTUP_ENV_KEYS;
use evaluate::nothing_published;
pub(super) use evaluate::{EvaluatedReload, changed_startup_env_keys, load_config_patch};
use lock_api::{ReloadRefusal, ReloadRefusalKind};
use refusals::BeforeApplyKind;

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
    /// The environment in force, and the env-file paths startup recorded.
    ///
    /// A reload re-reads those paths; it never resolves `config.env_files`
    /// again, because `~` resolved once, at startup, and resolving it a second
    /// time can silently open a different file.
    pub(super) env: Arc<LiveEnv>,
    /// The live grant store, its epoch, and the file they are reloaded from.
    ///
    /// `None` when no grants file is configured, which is every deployment
    /// that never wrote one — the reload step then reports nothing rather
    /// than inventing an empty store and revoking everything.
    pub(super) identity_grants: Option<Arc<IdentityGrantSink>>,
    /// The reload's file load: config parse plus env-file reads.
    pub(super) load: LoadPatch,
    /// Starts `load` on a thread of its own.
    pub(super) spawn: SpawnLoad,
    /// Cancelled when the gateway starts shutting down; every reload wait
    /// ends on it. Never cancelled unless the server wires one in.
    pub(super) stop: tokio_util::sync::CancellationToken,
    /// The capability backend whose listing the env overlay can change: a key
    /// set or removed in an env file turns a keyed capability on or off.
    pub(super) capabilities: Option<Arc<crate::capability::CapabilityBackend>>,
    /// Told which backends each applied reload registered (`MIK-8054`).
    pub(super) on_registered: Option<super::reload_warm_hook::OnRegistered>,
    /// The shared refusal ledger and override auditor (`GET /ui/api/refusals`).
    pub(super) reporting: super::refusals::ReloadReporting,
    /// Where an applied reload marks the web UI's charts.
    pub(super) markers: Option<Arc<crate::counters::CounterStore>>,
    /// Set when lock recovery put an earlier gateway.yaml back on disk: the
    /// running config is then on bytes that are gone, so the next holder of
    /// the reload lock reloads before its own work. Cleared only by an
    /// accepted reload, so a reload that fails is retried, never forgotten.
    pub(super) reload_owed: std::sync::atomic::AtomicBool,
    /// Where an audited gateway's recovery intents go, set once at start
    /// from the audit posture: every in-gateway holder of the config lock
    /// appends one before it recovers a crashed write or pays an owed
    /// reload.
    pub(super) recovery_audit: parking_lot::Mutex<Option<Box<dyn replace::IntentSink>>>,
    /// Test-only: parks an audited recovery inside its task, lock held.
    #[cfg(test)]
    pub(super) recovery_pause: std::sync::Arc<crate::test_pause::Slot>,
    /// gateway.yaml as this gateway resolved it at start, through any
    /// symlink. The byte writer writes only there: a link re-pointed since
    /// would send config bytes, secrets included, wherever it now leads.
    #[cfg_attr(
        not(any(test, feature = "webui")),
        expect(
            dead_code,
            reason = "read only by the byte writer, whose first caller lands next"
        )
    )]
    pub(super) trusted_config: PathBuf,
    /// Applies `meta_mcp.surfaced_tools` from each published config,
    /// set by the gateway when it attaches to this context.
    surfaced_hook: parking_lot::Mutex<Option<SurfacedHook>>,
}

/// Applies a published config's `meta_mcp.surfaced_tools` to the running
/// gateway, under `lock_reload`.
pub(crate) type SurfacedHook = Arc<dyn Fn(&Config) + Send + Sync>;

/// The refusal a reload returns when the gateway's shutdown ended its wait.
pub(super) const STOPPED: &str = "config reload stopped: the gateway is shutting down";

/// The reload's file load; a field so a test can stall or fail it.
pub(super) type LoadPatch = fn(
    &std::path::Path,
    &Arc<LiveConfig>,
    &LiveEnv,
) -> std::result::Result<EvaluatedReload, String>;

/// How a reload starts its load off the async workers.
pub(super) type SpawnLoad = fn(Box<dyn FnOnce() + Send>) -> std::io::Result<()>;

/// A detached thread, not `spawn_blocking`: dropping a Tokio runtime waits for
/// its blocking tasks, so a read stalled on NFS or FUSE would hold shutdown
/// for as long as the mount stalls (#1808).
pub(super) fn spawn_load_thread(load: Box<dyn FnOnce() + Send>) -> std::io::Result<()> {
    std::thread::Builder::new()
        .name("config-reload".into())
        .spawn(load)
        .map(drop)
}

impl ReloadContext {
    /// Create a new `ReloadContext`, pairing `registry` with the running
    /// config's destination policy.
    ///
    /// # Errors
    ///
    /// A hardened config is refused for a registry holding an HTTP or
    /// WebSocket backend that already connected under no policy (MIK-7700).
    pub fn new(
        config_path: PathBuf,
        live_config: Arc<LiveConfig>,
        registry: Arc<BackendRegistry>,
        failsafe_config: crate::config::FailsafeConfig,
        cache_ttl: Duration,
    ) -> Result<Self> {
        // A registry built by the caller still serves this config's posture.
        let running = live_config.running();
        #[allow(
            clippy::disallowed_methods,
            reason = "Lifecycle: config reload applies the operator's backend set; no caller request"
        )]
        registry.enforce_destinations(
            DestinationPolicy::for_posture(running.security.posture),
            &running.security.hardened.private_backends,
        )?;
        let trusted_config = crate::identity_grants::journal::resolved(&config_path);
        Ok(Self {
            config_path,
            trusted_config,
            reload_owed: std::sync::atomic::AtomicBool::new(false),
            recovery_audit: parking_lot::Mutex::new(None),
            #[cfg(test)]
            recovery_pause: std::sync::Arc::default(),
            live_config,
            registry,
            failsafe_config,
            cache_ttl,
            // No env files until told otherwise: every lookup then falls
            // through to the process environment, which is what a context
            // built without one has always done.
            env: Arc::new(LiveEnv::new(
                Arc::new(EnvOverlay::none()),
                ResolvedEnvFiles::default(),
            )),
            identity_grants: None,
            load: load_config_patch,
            spawn: spawn_load_thread,
            stop: tokio_util::sync::CancellationToken::new(),
            capabilities: None,
            on_registered: None,
            reporting: super::refusals::ReloadReporting::default(),
            markers: None,
            surfaced_hook: parking_lot::Mutex::new(None),
        })
    }

    /// Mark every applied reload on `markers`.
    #[must_use]
    pub(crate) fn with_markers(
        mut self,
        markers: Option<Arc<crate::counters::CounterStore>>,
    ) -> Self {
        self.markers = markers;
        self
    }

    /// Install the hook that applies `surfaced_tools` on every applied
    /// reload. The gateway calls it when it attaches to this context.
    pub(crate) fn set_surfaced_hook(&self, hook: SurfacedHook) {
        *self.surfaced_hook.lock() = Some(hook);
    }

    /// Announce `tools/list_changed` for `capabilities` when a reload's env
    /// overlay changes what it lists (a login or key edit).
    #[must_use]
    pub(crate) fn with_capabilities(
        mut self,
        capabilities: Option<Arc<crate::capability::CapabilityBackend>>,
    ) -> Self {
        self.capabilities = capabilities;
        self
    }

    /// Publish `overlay` and, when it changes what the capability backend
    /// lists, send the same tools-changed notice a registry change sends.
    fn publish_overlay(&self, overlay: Arc<crate::config::EnvOverlay>) {
        match &self.capabilities {
            // Under the backend's listing lock, which an expired login's
            // announcement takes too, so one change is announced once.
            Some(capabilities) => {
                capabilities.announce_listing_change(&self.registry, || self.env.set(overlay));
            }
            None => self.env.set(overlay),
        }
    }

    /// Stop this context's reload waits when `stop` is cancelled (#1808).
    #[must_use]
    pub(crate) fn with_stop(mut self, stop: tokio_util::sync::CancellationToken) -> Self {
        self.stop = stop;
        self
    }

    /// Replace the file load, so a test can stall, fail or observe it.
    #[cfg(test)]
    #[must_use]
    pub(super) fn with_load(mut self, load: LoadPatch) -> Self {
        self.load = load;
        self
    }

    /// Test-only: a context whose every reload after a write refuses the new
    /// bytes, so a route's answer to a refused reload can be driven end to end.
    /// Its only caller is the web UI's backend rows.
    #[cfg(all(test, feature = "webui"))]
    #[must_use]
    pub(crate) fn refusing_reloads_for_test(self) -> Self {
        fn refused(
            _: &std::path::Path,
            _: &Arc<LiveConfig>,
            _: &LiveEnv,
        ) -> std::result::Result<EvaluatedReload, String> {
            Err("the reload refused the new bytes (test)".to_owned())
        }
        self.with_load(refused)
    }

    /// Replace how the load thread starts, so a test can refuse it.
    #[cfg(test)]
    #[must_use]
    pub(super) fn with_spawn(mut self, spawn: SpawnLoad) -> Self {
        self.spawn = spawn;
        self
    }

    /// Attach the grant sink a reload publishes into.
    ///
    /// Without it `reload_identity_grants` is inert and says so; with it the
    /// same operator trigger that reloads config also makes a revocation live
    /// on the running process.
    #[must_use]
    pub fn with_identity_grant_sink(mut self, sink: Arc<IdentityGrantSink>) -> Self {
        self.identity_grants = Some(sink);
        self
    }

    /// [`Self::with_identity_grant_sink`] for a caller that may have none.
    ///
    /// `None` when grants are disabled: the reload step then reports nothing,
    /// rather than reading a file that does not exist, failing open on it, and
    /// printing a refusal on every reload of a gateway that never used grants.
    #[must_use]
    pub fn with_identity_grant_sink_opt(self, sink: Option<Arc<IdentityGrantSink>>) -> Self {
        match sink {
            Some(sink) => self.with_identity_grant_sink(sink),
            None => self,
        }
    }

    /// The env-file paths a reload re-reads.
    #[must_use]
    pub fn env_paths(&self) -> &ResolvedEnvFiles {
        self.env.env_paths()
    }

    /// The live environment, for callers resolving a value the way the gateway
    /// does.
    #[must_use]
    pub fn live_env(&self) -> &Arc<LiveEnv> {
        &self.env
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
        // Grants FIRST, and on their own lock. Two reasons, both settled in
        // review: a config refusal must not hold a revocation hostage, and a
        // revocation must not queue behind `backend.stop()` for an unrelated
        // config edit. Its result is folded into `changes` below rather than
        // short-circuiting, so neither step's refusal refuses the other.
        //
        // Every wait below also ends on shutdown (#1808): axum's graceful
        // shutdown waits for this handler, and a read stalled on NFS or FUSE
        // never returns. `biased` puts the stop first, so a reload that starts
        // after the signal reads nothing, not even the grants file.
        let grants = tokio::select! {
            biased;
            () = self.stop.cancelled() => return Err(STOPPED.to_owned()),
            grants = self.reload_identity_grants() => grants,
        };

        // Serializes the whole reload transaction (#397) - read, diff, apply,
        // publish. All four concurrent entry points land here: the
        // `gateway_reload_config` meta-tool, the admin UI reload, every admin UI
        // backend edit, and the config-file watcher. See `apply_patch` for why
        // the lock cannot live one level down.
        #[allow(
            clippy::disallowed_methods,
            reason = "Lifecycle: config reload applies the operator's backend set; no caller request"
        )]
        let lock = self.registry.lock_reload();
        let _reload_guard = tokio::select! {
            biased;
            () = self.stop.cancelled() => return Err(STOPPED.to_owned()),
            guard = lock => guard,
        };
        // Then the config sidecar, the order every holder takes them in: so
        // this load never reads bytes a refused write is about to roll back.
        let deadline = std::time::Instant::now() + super::RELOAD_LOCK_WAIT;
        // The lock resolves the config once, off the workers: lock, journal
        // checks and load are about that one file.
        let reader = tokio::select! {
            biased;
            () = self.stop.cancelled() => return Err(STOPPED.to_owned()),
            reader = self.reader_lock_for_reload(deadline) => reader,
        };
        let (_sidecar, target) = match reader {
            crate::config_persistence::lock::ReaderLock::Held(locked) => {
                // An audited gateway's lock recovered nothing yet: the
                // recovery intent comes first.
                let locked = match self.recover_for_reload(locked).await {
                    Ok(locked) => locked,
                    Err(why) => {
                        return Err(format!(
                            "config reload skipped: {why}; the next change retries"
                        ));
                    }
                };
                if locked.recovered == crate::config_persistence::journal::Recovered::RolledBack {
                    self.reload_owed
                        .store(true, std::sync::atomic::Ordering::SeqCst);
                }
                (Some(locked.held), locked.target)
            }
            crate::config_persistence::lock::ReaderLock::Unlocked(target) => (None, target),
            crate::config_persistence::lock::ReaderLock::Skip(why) => {
                self.note_refused_lock();
                let mut skipped = format!("config reload skipped: {why}; the next change retries");
                if let Some(Ok(line) | Err(line)) = grants {
                    write!(skipped, "; {line}").ok();
                }
                return Err(skipped);
            }
        };
        let mut outcome = match self.reload_outcome_locked_at(&target).await {
            Ok(outcome) => {
                // An applied reload marks the charts; a refused one
                // returns below and marks nothing.
                if let Some(markers) = &self.markers {
                    markers.mark_now(crate::counters::MarkerKind::ConfigReload, None);
                }
                outcome
            }
            // Both steps render on every path: a config refusal read alone
            // hides whether the revocation landed. Appended, so every consumer
            // keying on the refusal's prefix still matches.
            Err(refusal) => {
                let mut refusal = refusal.text;
                if let Some(Ok(line) | Err(line)) = grants {
                    write!(refusal, "; {line}").ok();
                }
                return Err(refusal);
            }
        };
        match grants {
            Some(Ok(line)) => write!(outcome.changes, "; {line}").ok(),
            // A refusal is reported, not swallowed: the config half succeeded,
            // and an operator who is told only that reads a lost revocation as
            // a success.
            Some(Err(reason)) => write!(outcome.changes, "; {reason}").ok(),
            None => None,
        };
        Ok(outcome)
    }

    async fn reload_transaction(
        &self,
        path: &std::path::Path,
    ) -> std::result::Result<ReloadOutcome, ReloadRefusal> {
        #[cfg(test)]
        super::reload_pause::pause_here(&self.config_path).await;
        let evaluated = self.load_off_worker(path.to_path_buf()).await?;
        // First: a posture change also changes what the posture forces (signing
        // among it), and the posture is the cause the operator must act on.
        if let Some(refusal) =
            posture::reload_refusal(self.live_config.running(), &evaluated.config)
        {
            return Err(refusal.into());
        }
        self.restart_only_refusal(&evaluated)?;
        // Measured against the overlay startup captured, so a requirement stays
        // reported on every reload until the process actually restarts.
        let env_restart_keys = changed_startup_env_keys(&self.env, &evaluated);
        let EvaluatedReload {
            config: new_config,
            mut patch,
            overlay,
            inputs,
            configured,
            ..
        } = evaluated;
        // A backend whose configured credentials changed (a value newly
        // written as a reference, or no longer) is modified: replacing its
        // instance clears what it cached and seeds the new one, and the
        // publish moves every cache key on.
        for name in self.registry.marking_changes(&configured) {
            let Some(cfg) = new_config
                .enabled_backends()
                .find(|(n, _)| **n == name)
                .map(|(_, c)| c)
            else {
                continue;
            };
            let mut listed = patch.backends_added.iter().chain(&patch.backends_modified);
            if !listed.any(|(n, _)| *n == name) {
                patch.backends_modified.push((name, cfg.clone()));
            }
        }

        if patch.is_empty() {
            // The env files can rotate under an unchanged config file, so the
            // overlay is published even here — a resolver reading the old one
            // would serve a value the operator has already replaced.
            self.publish_overlay(overlay);
            // The same rotation changes what the config was built from.
            self.live_config.set_inputs(inputs, &env_restart_keys);
            // No difference from the published snapshot does not mean nothing is
            // outstanding: a restart-only edit was published on an earlier
            // reload and the running process still has not applied it.
            return Ok(with_pending_restart(
                ReloadOutcome::no_changes(),
                &self.live_config,
                env_restart_keys,
            ));
        }

        if let Some(refusal) = self.before_apply_refusal(&new_config, &patch) {
            return Err(ReloadRefusal {
                kind: match refusal.kind {
                    BeforeApplyKind::NetworkPosture => ReloadRefusalKind::Posture,
                    BeforeApplyKind::AccountBinding | BeforeApplyKind::CapabilityClash => {
                        ReloadRefusalKind::Other
                    }
                },
                text: refusal.text,
            });
        }
        // Every view this config compiles to is built before `apply_patch`, so a
        // refused build starts and stops no backend.
        let prepared = self.live_config.prepare(new_config, &overlay);
        let generation = Arc::new(prepared.map_err(|reason| nothing_published(&reason))?);

        let outcome = patch.outcome();
        // After every refusal: a backend `apply_patch` registers is seeded
        // from this load's record.
        self.registry.set_load_record(configured);
        let fully_applied = apply_patch(
            &patch,
            &self.registry,
            &self.failsafe_config,
            self.cache_ttl,
            &generation.config().runtime,
        )
        .await;

        if !fully_applied {
            // Publishing here would describe backends the registry refused, and
            // report a reload that did not happen. The caller asked for an
            // outcome; the honest one is an error.
            return Err(SHUTDOWN_ABORTED_ERROR.to_string().into());
        }
        // Test seam: after the patch registered its backends, before the
        // publish, so a test can drop a reload between the two.
        #[cfg(test)]
        super::reload_pause::pause_here(&super::reload_pause::after_apply(&self.config_path)).await;

        // Published together: a resolver that read the new config against the
        // old overlay would resolve an `env:` reference the reload just changed.
        self.live_config
            .set_applied(Arc::clone(&generation), inputs, &env_restart_keys);
        self.publish_overlay(overlay);
        // Still under `lock_reload`, against the config just published.
        self.report_registered(&patch.registered_change(), &self.live_config.get());
        // `surfaced_tools` applies here too, under the same lock.
        let surfaced_hook = self.surfaced_hook.lock().clone();
        if let Some(hook) = surfaced_hook {
            hook(&self.live_config.get());
        }

        Ok(with_pending_restart(
            outcome,
            &self.live_config,
            env_restart_keys,
        ))
    }
}

/// Fold outstanding restart-only fields into a reload outcome.
///
/// Reported on every reload while they remain outstanding, not once. The diff
/// alone cannot carry this: publishing a restart-only edit into the snapshot
/// removes it from every later diff, so the operator who enables authentication
/// and is distracted would never be told again.
pub(super) fn with_pending_restart(
    mut outcome: ReloadOutcome,
    live: &LiveConfig,
    env_keys: Vec<String>,
) -> ReloadOutcome {
    let mut pending: Vec<String> = live
        .pending_restart_fields()
        .iter()
        .map(|field| (*field).to_string())
        .collect();
    pending.extend(env_keys);
    if pending.is_empty() {
        return outcome;
    }
    outcome.restart_required = true;
    outcome
        .pending_restart_fields
        .extend(pending.iter().cloned());
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
    // The advice above is "restart", so it has to be advice that works. A
    // restart-only edit is judged by the STARTUP check, not the reload overlay:
    // the file is already published, so what a restart boots is `live.get()`.
    // Telling an operator to restart into a refusal costs them the gateway,
    // and the refusal message arrives after the process they were serving with
    // is already gone (MIK-7255). Availability, not exposure — the edit that
    // would have removed authentication is exactly the one that never applies.
    if let Some(why) = crate::gateway::next_start_refusal(&live.get()) {
        outcome.changes = format!(
            "{outcome_changes} — WARNING: a restart would not start: {why}",
            outcome_changes = outcome.changes
        );
    }
    outcome
}

// Mounted here, not under `reload_tally`: they drive the lock-recovery and
// lock-skip paths, which are private to this module.
#[cfg(test)]
#[path = "reload_tally_tests.rs"]
mod tally_tests;

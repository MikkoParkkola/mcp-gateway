// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The file watcher that triggers a reload when `config.yaml` or an env file changes.

use std::path::PathBuf;
use std::sync::Arc;

use std::time::{Duration, Instant};

use notify::{Config as NotifyConfig, Event, EventKind, RecommendedWatcher, Watcher};

use tracing::{info, warn};

use crate::Result;
use crate::backend::BackendRegistry;
use crate::config::{Config, LiveEnv};
use crate::security::ssrf::DestinationPolicy;

use super::{
    IdentityGrantSink, LiveConfig, NO_CHANGES_SUMMARY, ReloadContext, SHUTDOWN_ABORTED_ERROR,
    env_poll, is_posture_refusal, watch_chain,
};

/// What caused a reload to be scheduled.
///
/// Carried through the debounce channel so the reload task can log a
/// context-specific message (config change vs. env-file change).
#[derive(Debug, Clone)]
pub(super) enum ReloadTrigger {
    /// The main `config.yaml` was modified.
    ConfigFile,
    /// A recorded env file's content differs from the live overlay (#1286).
    EnvFile(PathBuf),
    /// The last reload failed; retried each poll until one succeeds.
    Retry(PathBuf),
}

/// Returns `true` for create/modify events on the watched config file.
pub(super) fn is_config_event(event: &Event, config_paths: &[PathBuf]) -> bool {
    matches!(event.kind, EventKind::Create(_) | EventKind::Modify(_))
        && event
            .paths
            .iter()
            .any(|p| config_paths.iter().any(|watched| watched == p))
}

/// Returns `true` for create/modify events on the config the operator named,
/// resolving the link target on every call.
///
/// The paths a config can arrive as are not fixed for the life of the process:
/// a deployment can repoint the link at a new release and write that file. A
/// list captured at startup keeps naming the release the link left behind, so
/// the resolution happens per event instead.
pub(super) fn is_config_event_for(event: &Event, named_config_path: &std::path::Path) -> bool {
    is_config_event(event, &config_watch_paths(named_config_path.to_path_buf()))
}

// ============================================================================
// File watcher
// ============================================================================

/// File watcher that triggers config hot-reload on `config.yaml` **and**
/// env-file changes (e.g. `~/.config/mcp-gateway/secrets.env`).
///
/// Mirrors the structure of [`crate::capability::CapabilityWatcher`].
/// Holds the underlying `notify` watcher alive for the lifetime of the struct.
pub struct ConfigWatcher {
    /// Kept alive with the struct: the OS watcher and the config directories
    /// it watches. The rewatch task holds it too, and drops the watcher when
    /// the gateway shuts down.
    _chain: Arc<watch_chain::ChainWatch>,
    /// What the reload task did with `EnvFile` triggers.
    // Linux-only (W-L9): the real-watcher rows run on inotify (see `watch_chain_tests.rs`).
    #[cfg(all(test, target_os = "linux"))]
    env_reloads: Arc<env_poll::EnvReloadCounts>,
}

impl ConfigWatcher {
    /// The chain watch, for tests that wait on its ledger and counters.
    // Only the linux-gated real-watcher tests read it.
    #[cfg(all(test, target_os = "linux"))]
    #[expect(
        clippy::used_underscore_binding,
        reason = "the field is named for keeping the watch alive; only tests read it"
    )]
    pub(super) fn chain(&self) -> &Arc<watch_chain::ChainWatch> {
        &self._chain
    }

    /// What the reload task did with `EnvFile` triggers so far.
    // Linux-only (W-L9): the real-watcher rows run on inotify (see `watch_chain_tests.rs`).
    #[cfg(all(test, target_os = "linux"))]
    pub(super) fn env_reloads(&self) -> &env_poll::EnvReloadCounts {
        &self.env_reloads
    }

    /// Start watching `config_path`, and polling the env files startup
    /// recorded, for changes.
    ///
    /// Spawns a debounced background task that re-parses the file and calls
    /// [`super::apply_patch`] on each detected change.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying `notify` watcher cannot be created,
    /// or if the registry refuses the destination pairing: under the
    /// `hardened` posture, a backend that already connected over HTTP or
    /// WebSocket before any destination policy was stamped cannot be pinned in
    /// place (MIK-7700), and nothing is started.
    pub fn start(
        config_path: PathBuf,
        live_config: Arc<LiveConfig>,
        registry: Arc<BackendRegistry>,
        initial_config: &Config,
        env: Arc<LiveEnv>,
        identity_grants: Option<Arc<IdentityGrantSink>>,
        shutdown_rx: tokio::sync::broadcast::Receiver<()>,
    ) -> Result<Self> {
        // Pair first, so a refusal is returned before any watcher or task
        // exists; the reload task's own context then pairs as a no-op.
        {
            let running = live_config.running();
            registry.enforce_destinations(
                DestinationPolicy::for_posture(running.security.posture),
                &running.security.hardened.private_backends,
            )?;
        }
        let (event_tx, event_rx) = tokio::sync::mpsc::channel::<ReloadTrigger>(32);

        let config_path = watch_chain::named_config_path(config_path);

        let (wake_tx, mut wake_rx) = tokio::sync::watch::channel(());
        let chain = Self::create_notify_watcher(event_tx.clone(), wake_tx, &config_path)?;
        // One resolve as soon as the watches are live: a retarget that landed
        // between resolving the chain and installing them is followed.
        wake_rx.mark_changed();
        let env_reloads = Arc::new(env_poll::EnvReloadCounts::default());
        watch_chain::spawn_rewatch_task(
            config_path.clone(),
            Arc::clone(&chain),
            wake_rx,
            event_tx,
            shutdown_rx.resubscribe(),
            watch_chain::CHAIN_RETRY,
            env_poll::EnvPoller::new(
                Arc::clone(&env),
                Arc::clone(&env_reloads),
                config_path.clone(),
            ),
            env_poll::POLL_EVERY,
        );

        let failsafe_cfg = initial_config.failsafe.clone();
        let cache_ttl = initial_config.meta_mcp.cache_ttl;
        Self::spawn_reload_task(
            config_path,
            live_config,
            registry,
            failsafe_cfg,
            cache_ttl,
            env,
            identity_grants,
            event_rx,
            shutdown_rx,
            Arc::clone(&env_reloads),
        );

        Ok(Self {
            _chain: chain,
            // Linux-only (W-L9): the real-watcher rows run on inotify (see `watch_chain_tests.rs`).
            #[cfg(all(test, target_os = "linux"))]
            env_reloads,
        })
    }

    /// Create the low-level `notify` watcher and register all watch paths.
    ///
    /// The config's link chain is watched through [`watch_chain::ChainWatch`],
    /// which the rewatch task keeps following. Env files are not watched: the
    /// rewatch task polls them (#1286).
    pub(super) fn create_notify_watcher(
        event_tx: tokio::sync::mpsc::Sender<ReloadTrigger>,
        wake_tx: tokio::sync::watch::Sender<()>,
        config_path: &std::path::Path,
    ) -> Result<Arc<watch_chain::ChainWatch>> {
        let named_config_path = config_path.to_path_buf();
        let closure_config_path = named_config_path.clone();

        let watcher = RecommendedWatcher::new(
            move |result: std::result::Result<Event, notify::Error>| {
                let Ok(event) = result else { return };

                // Every event that changes a directory may have moved the
                // chain: a link unlinked and re-created is an event on the
                // named path itself. An access (open, read, close) cannot, and
                // the reload's own read must not wake the task again. The task decides;
                // this thread must not block or call `watch`.
                if !matches!(event.kind, EventKind::Access(_)) {
                    wake_tx.send_replace(());
                }
                if is_config_event_for(&event, &closure_config_path) {
                    let _ = event_tx.try_send(ReloadTrigger::ConfigFile);
                }
            },
            NotifyConfig::default().with_poll_interval(Duration::from_secs(2)),
        )
        .map_err(|e| {
            crate::Error::ConfigWatcher(format!("Failed to create config watcher: {e}"))
        })?;

        let wanted = watch_chain::startup_dirs(&named_config_path);
        let chain = watch_chain::ChainWatch::new(watcher);
        chain.reconcile(&wanted);
        let in_ledger = chain.watched_now();
        if let Some(missing) = wanted.iter().find(|dir| !in_ledger.contains(*dir)) {
            return Err(crate::Error::ConfigWatcher(format!(
                "Failed to watch config path: {}",
                missing.display()
            )));
        }
        Ok(chain)
    }

    /// Spawn the debounced reload task.
    #[allow(clippy::too_many_arguments)]
    pub(super) fn spawn_reload_task(
        config_path: PathBuf,
        live_config: Arc<LiveConfig>,
        registry: Arc<BackendRegistry>,
        failsafe_cfg: crate::config::FailsafeConfig,
        cache_ttl: Duration,
        env: Arc<LiveEnv>,
        identity_grants: Option<Arc<IdentityGrantSink>>,
        mut event_rx: tokio::sync::mpsc::Receiver<ReloadTrigger>,
        mut shutdown_rx: tokio::sync::broadcast::Receiver<()>,
        env_reloads: Arc<env_poll::EnvReloadCounts>,
    ) {
        use env_poll::{DEBOUNCE, RELOAD_TICK};
        tokio::spawn(async move {
            let mut last_event: Option<Instant> = None;
            let mut pending_trigger: Option<ReloadTrigger> = None;
            let mut ticker = tokio::time::interval(RELOAD_TICK);
            // The poll re-triggers a failing env file every tick; this keeps
            // its warning to one a minute unless the error changes.
            let mut env_warns = env_poll::WarnLimiter::default();

            // The watcher runs the same reload transaction as the meta-tool and
            // the admin UI, through the same function (#397). It used to have a
            // private copy of that transaction, which meant the regression test
            // covering the reload lock only ever exercised the other two entry
            // points: an edit that moved the lock here alone would not have
            // failed a single test.
            let ctx = match ReloadContext::new(
                config_path,
                live_config,
                registry,
                failsafe_cfg,
                cache_ttl,
            ) {
                Ok(ctx) => ctx
                    .with_env(env)
                    .with_identity_grant_sink_opt(identity_grants),
                Err(error) => {
                    tracing::error!(%error, "Config watcher not started");
                    return;
                }
            };

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
                            env_poll::log_trigger(&trigger);
                            env_reloads.count_attempt(&trigger);
                            let result = ctx.reload_outcome().await;
                            let error = result.as_ref().err().map(String::as_str);
                            env_reloads.settled(&mut env_warns, error, &trigger);
                            match (result, &trigger) {
                                (Ok(outcome), ReloadTrigger::EnvFile(path)) => {
                                    env_poll::report_reloaded(path, &outcome);
                                }
                                (Ok(outcome), _) if outcome.changes == NO_CHANGES_SUMMARY => {
                                    tracing::debug!("Config reload: no changes detected");
                                }
                                (Ok(outcome), _) => {
                                    info!(
                                        changes = %outcome.changes,
                                        restart_required = outcome.restart_required,
                                        "Config reload: complete"
                                    );
                                }
                                (Err(e), trigger)
                                    if !matches!(trigger, ReloadTrigger::ConfigFile)
                                        && !e.starts_with(SHUTDOWN_ABORTED_ERROR) =>
                                {
                                    env_reloads.report_failure(&mut env_warns, trigger, &e);
                                }
                                (Err(e), _) if is_posture_refusal(&e) => {
                                    // Its own arm, ahead of the generic one: a
                                    // posture refusal is a decision about this
                                    // config, not a file the operator must fix
                                    // the syntax of.
                                    warn!("Config reload: {e}");
                                }
                                (Err(e), _) if e.starts_with(SHUTDOWN_ABORTED_ERROR) => {
                                    warn!(
                                        "Config reload: aborted, the gateway is \
                                         shutting down; keeping the previous live \
                                         config rather than publishing one that \
                                         describes backends which were never \
                                         registered"
                                    );
                                }
                                (Err(e), _) => {
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

/// Resolve a watched path to the absolute form `notify` reports.
///
/// Events arrive with absolute, symlink-resolved paths, and they are matched
/// against the watched paths by equality. A relative `-c gateway.yaml` would
/// never match one, so hot-reload would go quiet without ever failing.
///
/// Absolutizing first and canonicalizing second is what keeps a path that does
/// not exist yet — an `env_file` the operator has still to write — out of the
/// relative form: `canonicalize` fails on a missing file, so on its own it
/// would hand that case straight back as the relative path that never matches.
pub(super) fn absolute_watch_path(path: PathBuf) -> PathBuf {
    let absolute = std::path::absolute(&path).unwrap_or(path);
    // Resolve symlinks in the parent chain only. The chain must be resolved
    // because macOS reports events under the real directory (`/private/var`,
    // not `/var`) and the watcher compares paths for equality. The final
    // component must not be, or a symlink-managed deployment aims the watcher
    // at the current target's directory and retargeting the symlink fires no
    // event the watcher can see.
    absolute
        .parent()
        .zip(absolute.file_name())
        .and_then(|(parent, name)| std::fs::canonicalize(parent).ok().map(|dir| dir.join(name)))
        .unwrap_or(absolute)
}

/// The directory to watch for changes to `path`.
///
/// Every absolute path a config-file event can legitimately arrive as.
///
/// A symlinked config has two, and watching either alone loses a real case:
/// matching only the operator-named link misses an in-place write to the
/// target (which is what editing the config through the link does), and
/// matching only the target misses a retarget of the link itself.
pub(super) fn config_watch_paths(path: PathBuf) -> Vec<PathBuf> {
    let named = absolute_watch_path(path);
    let mut paths = vec![named.clone()];
    if let Ok(target) = std::fs::canonicalize(&named)
        && target != named
    {
        paths.push(target);
    }
    paths
}

/// `Path::parent` returns an empty path for a bare relative filename such as
/// `gateway.yaml`, and an empty path cannot be watched. Both callers below
/// hand this a user-supplied path, so both need the same answer.
pub(super) fn watch_dir_of(path: &std::path::Path) -> PathBuf {
    match path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent.to_path_buf(),
        _ => PathBuf::from("."),
    }
}

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
use crate::config_persistence::CommentLoss;
use crate::security::{posture, ssrf::DestinationPolicy};

use super::{
    ConfigMutation, ConfigPatch, ConfigWriteError, IdentityGrantSink, LiveConfig,
    POSTURE_REFUSED_PREFIX, RELOAD_LOCK_WAIT, ReloadOutcome, SHUTDOWN_ABORTED_ERROR, apply_patch,
    compute_diff,
};

/// A candidate config, evaluated against the recorded env files.
pub(super) struct EvaluatedReload {
    pub(super) config: Config,
    /// May be empty: the env files can change while the config file does not.
    pub(super) patch: ConfigPatch,
    pub(super) overlay: Arc<EnvOverlay>,
    /// Every `env:NAME` the config references, resolved or not.
    pub(super) secret_refs: std::collections::BTreeSet<String>,
}

pub(super) fn load_config_patch(
    config_path: &std::path::Path,
    live_config: &Arc<LiveConfig>,
    env: &LiveEnv,
) -> std::result::Result<EvaluatedReload, String> {
    let old_config = live_config.get();
    // The recorded paths, never `new_config.env_files`: `~` resolved once at
    // startup, and resolving the spelling again could open a different file.
    // A malformed line is an error here rather than a warning, so a reload
    // against a half-read env file is refused instead of published.
    let evaluated = Config::load_with_overlay(Some(config_path), env.env_paths())
        .map_err(|e| format!("Failed to parse config: {e}"))?;
    let patch = compute_diff(&old_config, &evaluated.config);

    Ok(EvaluatedReload {
        config: evaluated.config,
        patch,
        overlay: evaluated.overlay,
        secret_refs: evaluated.secret_refs,
    })
}

/// Startup-only environment keys no config field names.
///
/// The attestation signer is built once, during startup, straight off the
/// overlay — these names appear in no config file, so a rotation is invisible
/// both to the config diff and to the config's own `env:` references.
pub(super) const IMPLICIT_STARTUP_ENV_KEYS: &[&str] = &[
    crate::attestation::wiring::ATTESTATION_MODE_ENV,
    crate::attestation::wiring::ATTESTATION_SIGNING_KEY_ENV,
    crate::attestation::wiring::ATTESTATION_KEY_ID_ENV,
    crate::attestation::wiring::ATTESTATION_AUDIENCE_ENV,
];

/// Startup-only environment keys a restart would read differently.
///
/// Two kinds, and neither is visible in the config diff:
///
/// * a rotated `env:NAME` secret. The holder that consumed it — a
///   `ResolvedAuthConfig`, an agent's HS256 key — is built once at startup and
///   nothing rebuilds it, so the running process keeps the old value.
/// * a `HOME` that no longer resolves where it did at startup, when an env-file
///   entry was spelled with `~`. A restart resolves that entry against the new
///   home and opens a different file.
///
/// The `HOME` rule is deliberately conservative: any assignment of `HOME` by
/// either run's env files, or any change in the value they leave standing, is
/// reported. The notice is never absent when a restart would read different
/// files, and it does not clear: a config whose env files assign `HOME` beside
/// a `~` entry reports `HOME` on every reload, and restarting does not settle
/// it, because the next startup's env files assign it again. It says a restart
/// *could* read different files, never that one is outstanding.
///
/// It has to be, because the question the rule is really answering — would a
/// restart open different files than startup did — cannot be answered from
/// values. `~` in entry N is expanded against the `HOME` in force at THAT point
/// in the sequence (`Config::evaluate`), so an env file can move where a later
/// entry is read while a file after it restores the final value, leaving both
/// runs equal on every value comparison. Answering exactly would mean expanding
/// `~` a second time, which the design forbids. Both runs' assignments count:
/// deleting the move leaves nothing to notice on the reload side, and the
/// restored value can equal the process environment's, so only startup's own
/// assignment records that the expansion base was ever moved.
///
/// The accepted cost is a notice that fires when nothing moved — re-stating an
/// unchanged `HOME` beside a `~` entry (ENVFILE.19g). Reordering is not this
/// rule's to catch: an edit to the `env_files` list is reported as `env_files`.
///
/// Names only. The values are secrets and a reload report is not a place to
/// print one.
pub(super) fn changed_startup_env_keys(env: &LiveEnv, evaluated: &EvaluatedReload) -> Vec<String> {
    let startup = env.startup();
    let keys: std::collections::BTreeSet<String> = evaluated
        .secret_refs
        .iter()
        .map(String::as_str)
        .chain(IMPLICIT_STARTUP_ENV_KEYS.iter().copied())
        .filter(|name| startup.resolve(name) != evaluated.overlay.resolve(name))
        .map(ToString::to_string)
        .collect();
    let mut keys: Vec<String> = keys.into_iter().collect();
    keys.extend(evaluated.overlay.rotated_secret_files(startup));
    // A `~` entry is expanded against the `HOME` in force AT THAT POINT in the
    // sequence (`Config::evaluate`), not the one left standing at the end, so
    // an env file can move where a LATER entry reads while the final value is
    // restored and compares equal (ENVFILE.19i). Comparing values alone cannot
    // see that, and neither can the reload overlay alone: deleting the move
    // leaves nothing there to notice, and the value it restored may be the
    // process environment's own (ENVFILE.19j). Either run's assignment counts,
    // so the notice never clears for such a config — see the fn doc.
    if env.env_paths().has_tilde_entry()
        && (startup.assigns("HOME")
            || evaluated.overlay.assigns("HOME")
            || startup.resolve("HOME") != evaluated.overlay.resolve("HOME"))
    {
        keys.push("HOME".to_string());
    }
    keys
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
}

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
        registry.enforce_destinations(
            DestinationPolicy::for_posture(running.security.posture),
            &running.security.hardened.private_backends,
        )?;
        Ok(Self {
            config_path,
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
        })
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
        let before = self.capabilities.as_ref().map(|c| c.listed_names());
        self.env.set(overlay);
        if let (Some(capabilities), Some(before)) = (&self.capabilities, before)
            && capabilities.listed_names() != before
        {
            self.registry.announce_change(&capabilities.name);
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

    /// Attach the environment startup published.
    ///
    /// Consuming builder rather than a constructor argument: every existing
    /// call site keeps working, and the one that has a `LiveEnv` says so.
    #[must_use]
    pub fn with_env(mut self, env: Arc<LiveEnv>) -> Self {
        self.env = env;
        self
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
        let _reload_guard = tokio::select! {
            biased;
            () = self.stop.cancelled() => return Err(STOPPED.to_owned()),
            guard = self.registry.lock_reload() => guard,
        };
        let mut outcome = match self.reload_outcome_locked().await {
            Ok(outcome) => outcome,
            // Both steps render on every path: a config refusal read alone
            // hides whether the revocation landed. Appended, so every consumer
            // keying on the refusal's prefix still matches.
            Err(mut refusal) => {
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
    /// [`ConfigWriteError::Failed`] on load, write, rename, or reload failure. A
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
        self.mutate_locked(path, wait, CommentLoss::Rewrite, mutate)
            .await
            .map_err(Into::into)
    }

    /// [`Self::mutate_and_reload_outcome_within`] in `mode` for a write that
    /// would drop comments. A write that changes nothing reloads nothing.
    pub(crate) async fn mutate_locked<T, E, F>(
        &self,
        path: &std::path::Path,
        wait: Duration,
        mode: CommentLoss,
        mutate: F,
    ) -> std::result::Result<ConfigMutation<T, E>, super::write::MutateError>
    where
        F: FnOnce(&mut Config) -> std::result::Result<T, E>,
    {
        let _reload_guard = self.lock_reload_within(wait).await?;
        let mut config = crate::config_persistence::load_existing_or_default(path)
            .map_err(|e| super::write::load_failure(path, &e, mode))?;
        let value = match mutate(&mut config) {
            Ok(value) => value,
            Err(rejection) => return Ok(ConfigMutation::Rejected(rejection)),
        };
        if !crate::config_persistence::write_config_with(path, &config, mode)? {
            return Ok(ConfigMutation::Applied(value, None));
        }
        let outcome = self
            .reload_outcome_locked()
            .await
            .map_err(|e| format!("Config written but reload failed: {e}"))?;
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

    /// Run the file load on its own thread and wait for it without holding a
    /// runtime worker (#1808).
    ///
    /// The load reads the config file and every env file; on a stalled NFS or
    /// FUSE mount that read blocks for as long as the mount does. Awaiting it
    /// here keeps the workers free and lets shutdown drop this future; nothing
    /// the thread computes is published unless this future is still waiting.
    /// Both failure arms refuse the reload, as a failed load always has. A
    /// panicking load is a refusal only where panics unwind: the release
    /// profile aborts on any panic, here as everywhere else.
    async fn load_off_worker(&self) -> std::result::Result<EvaluatedReload, String> {
        // The reload lock alone does not bound threads: a reload whose future
        // is dropped (a client that disconnects, a caller's timeout) releases
        // the lock while its read is still stalled. The permit travels into the
        // thread and is released only when that read returns.
        let slot = tokio::select! {
            biased;
            () = self.stop.cancelled() => return Err(STOPPED.to_owned()),
            slot = self.registry.reload_read_slot().acquire_owned() => {
                slot.map_err(|_| "config reload load slot closed".to_owned())?
            }
        };
        let (done, result) = tokio::sync::oneshot::channel();
        let (load, path, live, env) = (
            self.load,
            self.config_path.clone(),
            Arc::clone(&self.live_config),
            Arc::clone(&self.env),
        );
        (self.spawn)(Box::new(move || {
            // Released when the read returns, not when the reload that asked
            // for it gives up.
            let _slot = slot;
            drop(done.send(load(&path, &live, &env)));
        }))
        .map_err(|e| format!("config reload could not start its file read: {e}"))?;
        tokio::select! {
            biased;
            () = self.stop.cancelled() => Err(STOPPED.to_owned()),
            done = result => {
                done.map_err(|_| "config reload file read ended without a result".to_owned())?
            }
        }
    }

    /// The reload transaction itself. The caller must already hold the reload
    /// lock; taking it here as well would deadlock on the non-reentrant mutex.
    async fn reload_outcome_locked(&self) -> std::result::Result<ReloadOutcome, String> {
        let evaluated = self.load_off_worker().await?;
        // First: a posture change also changes what the posture forces (signing
        // among it), and the posture is the cause the operator must act on.
        if let Some(refusal) =
            posture::reload_refusal(self.live_config.running(), &evaluated.config)
        {
            return Err(refusal);
        }
        let (running, proposed) = (&self.live_config.running().security, &evaluated.config);
        let (env, overlay): (&crate::config::EnvOverlay, &crate::config::EnvOverlay) =
            (self.env.startup(), &evaluated.overlay);
        let signing = (running.message_signing)
            .restart_changed_field(&proposed.security.message_signing, env, overlay)
            .map_err(|error| error.to_string())?;
        let (was, now) = (&running.signature_chain, &proposed.security.signature_chain);
        let chain =
            crate::config::SignatureChainConfig::restart_changed_field(was.as_ref(), now.as_ref());
        if let Some(field) = (signing.map(|f| format!("message_signing.{f}")))
            .or_else(|| chain.map(|f| format!("signature_chain.{f}")))
        {
            return Err(format!(
                "config reload refused: security.{field} requires restart"
            ));
        }
        // Measured against the overlay startup captured, so a requirement stays
        // reported on every reload until the process actually restarts.
        let env_restart_keys = changed_startup_env_keys(&self.env, &evaluated);
        let EvaluatedReload {
            config: new_config,
            patch,
            overlay,
            ..
        } = evaluated;

        if patch.is_empty() {
            // The env files can rotate under an unchanged config file, so the
            // overlay is published even here — a resolver reading the old one
            // would serve a value the operator has already replaced.
            self.publish_overlay(overlay);
            // No difference from the published snapshot does not mean nothing is
            // outstanding: a restart-only edit was published on an earlier
            // reload and the running process still has not applied it.
            return Ok(with_pending_restart(
                ReloadOutcome::no_changes(),
                &self.live_config,
                env_restart_keys,
            ));
        }

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
                "This configuration is on disk, so the next start, including an \
                 unplanned one, will refuse to serve. Revert it, or close the \
                 tool paths."
            } else {
                // "accepts", not "is safe". The one file that reaches this
                // branch while still leaving the tools open is the one that
                // sets the escape hatch, and calling that safe would have the
                // gateway endorse a choice the operator made deliberately and
                // owns.
                // "would not refuse it for this reason", not "accepts it".
                // `network_bind_refusal` is the only question asked here; a
                // restart still reads the whole file and can fail on a missing
                // env: reference, an unreadable certificate, or anything else
                // validation catches. Promising acceptance is how an operator
                // restarts a working gateway into a different outage — the same
                // overclaiming that cost this message three earlier rewrites.
                "A restart would not refuse it for this reason, and applies the \
                 parts a reload cannot."
            };
            // Two bounded facts, and no summary of "what is still in force".
            //
            // The clause that kept being wrong went out with its cause. Env
            // files once reached the PROCESS environment inside `Config::load`
            // before it returned, so a refused candidate had already mutated
            // the process that refused it — that is the defect MIK-7256 names,
            // and it is closed: the candidate's env files build an `EnvOverlay`
            // that is published only on success (`self.env.set(overlay)`, below
            // and unreachable from this path), the overlay parses in memory
            // (`dotenvy::from_read_iter`, `src/config/env_overlay.rs:362`)
            // rather than through `dotenvy::dotenv`, and `rg set_var src/` is
            // empty.
            //
            // Say that, not "impossible". `#![deny(unsafe_code)]` is not
            // `forbid`, an `#[allow]` overrides it, and neither binds a
            // dependency. What holds this closed is the ABSENT call site plus
            // the parse path — a switch to `dotenvy::from_path` would reopen
            // it, and that is the line to watch.
            //
            // The summary is still not written, for a different reason: this
            // check asks `network_bind_refusal` and nothing else, while a
            // restart reads the whole file. Claiming more than the two facts
            // below is how a security message starts the next report.
            return Err(format!(
                "{POSTURE_REFUSED_PREFIX} {} No backend was started or stopped, \
                 and no configuration was published. {restart}",
                refusal.reason
            ));
        }

        // A changed account binding cannot reuse the credentials minted under
        // the descriptor it replaces: the descriptor's authority, resource,
        // issuer, client id and requested scopes define the account key and the
        // descriptor revision every existing lease carries. Eager replacement
        // of those is not implemented in this slice, so this refuses and
        // mutates nothing rather than pretending a live replacement happened.
        // Compared against what is RUNNING, so it stays true until a restart.
        if let Some(reason) = crate::config::account_bindings::reload_binding_refusal(
            self.live_config.running(),
            &new_config,
        ) {
            return Err(format!(
                "{POSTURE_REFUSED_PREFIX} {reason} No backend was started or stopped, and no \
                 configuration was published."
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

        // Published together: a resolver that read the new config against the
        // old overlay would resolve an `env:` reference the reload just changed.
        self.live_config.set(new_config);
        self.publish_overlay(overlay);

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

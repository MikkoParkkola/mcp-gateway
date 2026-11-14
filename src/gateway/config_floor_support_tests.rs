// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Shared fixtures of the config floor rows: temp config and fallback dirs,
//! gate and adapter builders, lock probes, bounded waits, and drivers that
//! call the real writer, reload and CLI entry points. A driver never admits or
//! records for production code: the gate calls belong to the production paths.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use sha2::{Digest, Sha256};

use super::{ConfigFloor, ConfigGate, ConfigSource};
use crate::backend::BackendRegistry;
use crate::config::Config;
use crate::fs_lock::ExclusiveFileLock;
use crate::gateway::test_helpers::write_owner_only;

/// Every bounded wait in a row: long enough for a loaded CI host, short
/// enough that a hung stub fails the row instead of stalling the run.
pub(crate) const BOUND: Duration = Duration::from_secs(30);

/// A minimal config that loads: one backend, nothing else.
pub(crate) const BASE: &str = "backends:\n  a:\n    http_url: \"http://127.0.0.1:9/mcp\"\n";

/// The lower-hex sha256 of literal `bytes`, as a certification carries it.
pub(crate) fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

/// A temp dir holding `gateway.yaml`, written owner-only from literal bytes.
pub(crate) struct ConfigDir {
    pub(crate) dir: tempfile::TempDir,
    pub(crate) path: PathBuf,
}

impl ConfigDir {
    /// A dir whose `gateway.yaml` holds exactly `text`.
    pub(crate) fn with(text: &str) -> Self {
        let dir = tempfile::tempdir().expect("config dir");
        let path = dir.path().join("gateway.yaml");
        write_owner_only(&path, text).expect("write gateway.yaml");
        Self { dir, path }
    }

    /// Replace the file's bytes in place, owner-only, as an outside edit.
    pub(crate) fn rewrite(&self, text: &str) {
        write_owner_only(&self.path, text).expect("outside edit");
    }

    /// The file's current bytes.
    pub(crate) fn bytes(&self) -> Vec<u8> {
        std::fs::read(&self.path).expect("read gateway.yaml")
    }

    /// The sidecar path of the journal or abandoned file named `suffix`
    /// (for example `.gateway.yaml.replace-journal`).
    pub(crate) fn beside(&self, name: &str) -> PathBuf {
        self.dir.path().join(name)
    }
}

/// Four candidate files in four temp dirs, none existing yet, in the order the
/// startup search reads them.
pub(crate) struct Candidates {
    _dirs: Vec<tempfile::TempDir>,
    pub(crate) paths: Vec<PathBuf>,
}

impl Candidates {
    pub(crate) fn new() -> Self {
        let dirs: Vec<_> = (0..4)
            .map(|_| tempfile::tempdir().expect("candidate dir"))
            .collect();
        let paths = dirs.iter().map(|d| d.path().join("gateway.yaml")).collect();
        Self { _dirs: dirs, paths }
    }

    /// Put `text` at candidate position `index` (0-based), owner-only.
    pub(crate) fn put(&self, index: usize, text: &str) {
        write_owner_only(&self.paths[index], text).expect("write candidate");
    }
}

/// Whether a lock answered a non-waiting take.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Probe {
    Free,
    Busy,
}

/// The config lock of `config`: Free when a non-waiting take succeeds (and is
/// released at once), Busy when it answers contention.
pub(crate) fn config_probe(config: &Path) -> Probe {
    let lock = crate::config_persistence::lock::lock_path(config);
    match ExclusiveFileLock::try_acquire(&lock) {
        Ok(_held) => Probe::Free,
        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => Probe::Busy,
        Err(e) => panic!("config lock probe failed for {}: {e}", lock.display()),
    }
}

/// The reload lock: Free when `try_lock` succeeds, Busy otherwise.
pub(crate) fn reload_probe(lock: &tokio::sync::Mutex<()>) -> Probe {
    if lock.try_lock().is_ok() {
        Probe::Free
    } else {
        Probe::Busy
    }
}

/// Poll `ready` until true or [`BOUND`] elapses, failing with `what` named.
/// Waits on a thread-yield, never a sleep window; for non-async hooks.
pub(crate) fn wait_until(what: &str, mut ready: impl FnMut() -> bool) {
    let end = std::time::Instant::now() + BOUND;
    while !ready() {
        assert!(std::time::Instant::now() < end, "never reached: {what}");
        std::thread::yield_now();
    }
}

/// A Booted floor over the config at `path`, on `gate` and the reload lock of
/// `registry`: the same lock its reload context and `reload_outcome` take.
pub(crate) fn booted_floor(
    gate: &ConfigGate,
    registry: &BackendRegistry,
    path: &Path,
) -> ConfigFloor {
    ConfigFloor::new(
        gate.clone(),
        registry.reload_lock_handle(),
        ConfigSource::Booted(path.to_path_buf()),
        Vec::new(),
    )
}

/// A Defaults floor whose fallback search reads the temp `candidates`, passed
/// through the candidate-path override a row owns.
pub(crate) fn defaults_floor(
    gate: &ConfigGate,
    registry: &BackendRegistry,
    candidates: &Candidates,
) -> ConfigFloor {
    let mut floor = ConfigFloor::new(
        gate.clone(),
        registry.reload_lock_handle(),
        ConfigSource::Defaults,
        Vec::new(),
    );
    floor.override_candidates(candidates.paths.clone());
    floor
}

/// Everything a row needs for a Booted config: the file, one gate, the reload
/// lock, a reload context over the file and a floor that shares them.
pub(crate) struct Booted {
    pub(crate) cfg: ConfigDir,
    pub(crate) gate: ConfigGate,
    pub(crate) registry: Arc<BackendRegistry>,
    pub(crate) ctx: Arc<crate::config_reload::ReloadContext>,
}

impl Booted {
    /// A booted config holding exactly `text`, running config loaded from it.
    pub(crate) fn new(text: &str) -> Self {
        let cfg = ConfigDir::with(text);
        let registry = Arc::new(BackendRegistry::new());
        let ctx = reload_context(&cfg.path, Arc::clone(&registry));
        Self {
            cfg,
            gate: ConfigGate::new(),
            registry,
            ctx,
        }
    }

    /// A floor for this config; each call builds a fresh adapter.
    pub(crate) fn floor(&self) -> ConfigFloor {
        booted_floor(&self.gate, &self.registry, &self.cfg.path)
    }

    pub(crate) fn config_probe(&self) -> Probe {
        config_probe(&self.cfg.path)
    }

    pub(crate) fn reload_probe(&self) -> Probe {
        reload_probe(&self.registry.reload_lock_handle())
    }

    /// The running config's `environment` key: the value a row edits and
    /// compares against a literal.
    pub(crate) fn running_environment(&self) -> Option<String> {
        self.ctx.live_config.get().environment.clone()
    }
}

/// A real reload context over the config at `path` on `registry`, as the
/// byte-writer and reload tests build one.
pub(crate) fn reload_context(
    path: &Path,
    registry: Arc<BackendRegistry>,
) -> Arc<crate::config_reload::ReloadContext> {
    let running = Config::load(Some(path)).expect("fixture config loads");
    let ctx = crate::config_reload::ReloadContext::new(
        path.to_path_buf(),
        Arc::new(crate::config_reload::LiveConfig::new(running)),
        registry,
        crate::config::FailsafeConfig::default(),
        Duration::from_secs(60),
    )
    .expect("the registry pairs with the config");
    Arc::new(ctx)
}

/// The reload log of `gate`: each completed reload's source and the running
/// value of the key the row edits, in order.
pub(crate) fn reload_log(gate: &ConfigGate) -> Vec<super::seams::ReloadEntry> {
    gate.reload_log()
}

/// The log's entries of one source, values only, in order.
pub(crate) fn reload_values(gate: &ConfigGate, source: super::seams::ReloadSource) -> Vec<String> {
    reload_log(gate)
        .into_iter()
        .filter(|e| e.source == source)
        .map(|e| e.value)
        .collect()
}

/// A Booted floor over an existing reload context (its own registry's reload
/// lock) and config `path`, for rows that reuse another fixture's context.
pub(crate) fn floor_over(
    gate: &ConfigGate,
    ctx: &crate::config_reload::ReloadContext,
    path: &Path,
) -> ConfigFloor {
    booted_floor(gate, &ctx.registry, path)
}

#[cfg(feature = "webui")]
/// The byte writer's real entry point, `replace_audited`, on an unaudited
/// gateway: replaces gateway.yaml with `text` under any revision.
pub(crate) async fn write_bytes(
    gate: &ConfigGate,
    ctx: Arc<crate::config_reload::ReloadContext>,
    text: &str,
) -> Result<crate::config_reload::ReplaceOutcome, crate::config_reload::ReplaceError> {
    use crate::config_reload::{
        AuditPosture, Expected, GatewayAuth, IntentKind, RELOAD_LOCK_WAIT, Replace, Replaced,
        replace_audited,
    };
    // The wiring stage passes the gate to the writer; the rows never change.
    let _ = gate;
    let bytes = text.as_bytes().to_vec();
    let replace = Replace {
        expected: Expected::Any,
        compute: Box::new(move |_| Ok(crate::config_persistence::keyedit::Template::plain(bytes))),
        replaced: Replaced::Discard,
        secrets: None,
    };
    let audit = AuditPosture::of(None, GatewayAuth::Off)
        .audit(IntentKind::Adopt)
        .expect("an unaudited gateway with auth off writes");
    replace_audited(ctx, replace, audit, RELOAD_LOCK_WAIT).await
}

/// A manual reload through `reload_outcome`, the entry the UI route and the
/// meta-tool both call.
pub(crate) async fn manual_reload(
    gate: &ConfigGate,
    ctx: &crate::config_reload::ReloadContext,
) -> Result<crate::config_reload::ReloadOutcome, String> {
    // The wiring stage passes the gate to the reload context.
    let _ = gate;
    ctx.reload_outcome().await
}

/// A CLI-style writer running on its own thread: the real
/// `edit_config` path the CLI writer wraps, setting `environment`.
pub(crate) struct CliWriter {
    pub(crate) join: std::thread::JoinHandle<Result<(), String>>,
    /// Told once when the writer starts waiting for the config lock.
    pub(crate) waiting: std::sync::mpsc::Receiver<()>,
}

/// Start a CLI-style writer for `path`. (`config_write::write` is the
/// binary's thin wrapper over the `edit_config` it calls.) The lock-wait signal is registered
/// before the thread starts, so it cannot be missed.
pub(crate) fn spawn_cli_writer(gate: &ConfigGate, path: &Path, environment: &str) -> CliWriter {
    // The wiring stage passes the gate; the CLI path stays gate-free by design.
    let _ = gate;
    let waiting = crate::gateway::test_helpers::when_waiting_for_config_lock(path);
    let (path, value) = (path.to_path_buf(), environment.to_owned());
    let join = std::thread::spawn(move || {
        crate::config_persistence::edit_config(
            &path,
            crate::config_persistence::CommentLoss::Refuse,
            move |config| {
                config.environment = Some(value);
                Ok(())
            },
        )
        .map(drop)
    });
    CliWriter { join, waiting }
}

/// Wait for a std channel message within [`BOUND`], naming `what` on failure.
pub(crate) fn recv_bounded<T>(rx: &std::sync::mpsc::Receiver<T>, what: &str) -> T {
    rx.recv_timeout(BOUND)
        .unwrap_or_else(|_| panic!("never received: {what}"))
}

/// Join a thread within [`BOUND`], naming `what` on failure.
pub(crate) fn join_bounded<T>(handle: std::thread::JoinHandle<T>, what: &str) -> T {
    wait_until(what, || handle.is_finished());
    handle.join().unwrap_or_else(|_| panic!("panicked: {what}"))
}

/// The watcher as a row drives it: its gate, reload context and config path.
/// The production loop has no hand-driven tick yet, so this holds only what the
/// wiring stage will pass to it.
pub(crate) struct WatcherFixture {
    pub(crate) gate: ConfigGate,
    pub(crate) ctx: Arc<crate::config_reload::ReloadContext>,
    pub(crate) path: PathBuf,
}

impl WatcherFixture {
    pub(crate) fn over(
        gate: &ConfigGate,
        ctx: &Arc<crate::config_reload::ReloadContext>,
        path: &Path,
    ) -> Self {
        Self {
            gate: gate.clone(),
            ctx: Arc::clone(ctx),
            path: path.to_path_buf(),
        }
    }

    pub(crate) fn new(booted: &Booted) -> Self {
        Self {
            gate: booted.gate.clone(),
            ctx: Arc::clone(&booted.ctx),
            path: booted.cfg.path.clone(),
        }
    }
}

/// One hand-driven watcher tick, run to completion.
pub(crate) async fn tick(watcher: &WatcherFixture) {
    // No hand-driven tick exists in production yet: this runs nothing, so a row
    // that needs a tick fails at its own assertion on the stub.
    let _ = (&watcher.gate, &watcher.ctx, &watcher.path);
}

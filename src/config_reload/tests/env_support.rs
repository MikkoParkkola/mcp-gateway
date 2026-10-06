// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Shared fixtures for the env-file reload tests: a recording home resolver and file builders.

use super::*;
use crate::config::{EnvOverlay, Evaluated, HomeResolver, LiveEnv};
use std::sync::{Mutex, atomic::AtomicBool};

/// A home resolver that answers exactly as production does — the overlay under
/// construction first, `crate::home_dir::home_dir()` otherwise — while recording what it
/// returned on each call and REFUSING to answer once startup has completed.
///
/// The refusal is the mechanism. An outcome assertion cannot tell a
/// single-resolution implementation from one that resolves a second time and
/// agrees with itself; a resolver that cannot be called at all can.
pub(super) struct RecordingHome {
    calls: Mutex<Vec<std::path::PathBuf>>,
    startup_done: AtomicBool,
    /// The home in force before any env file has been applied.
    ///
    /// A test that needs the FIRST `~` entry to land somewhere it controls has
    /// no other way to say so: assigning `HOME` in the process environment is
    /// unsafe in edition 2024 and the library forbids unsafe, and seeding the
    /// overlay would presuppose the very sequencing under test.
    base: Option<std::path::PathBuf>,
}

impl RecordingHome {
    pub(super) fn new() -> Self {
        Self {
            calls: Mutex::new(Vec::new()),
            startup_done: AtomicBool::new(false),
            base: None,
        }
    }

    /// A recorder whose pre-file home is `base`.
    pub(super) fn based_at(base: &std::path::Path) -> Self {
        Self {
            base: Some(base.to_path_buf()),
            ..Self::new()
        }
    }

    /// After this, any further call is a design violation and panics.
    pub(super) fn finish_startup(&self) {
        self.startup_done.store(true, Ordering::SeqCst);
    }

    /// The homes handed out, in the order they were handed out.
    pub(super) fn recorded(&self) -> Vec<std::path::PathBuf> {
        self.calls.lock().unwrap().clone()
    }
}

impl HomeResolver for RecordingHome {
    fn home_dir(&self, so_far: &EnvOverlay) -> Option<std::path::PathBuf> {
        assert!(
            !self.startup_done.load(Ordering::SeqCst),
            "the home resolver was called after startup completed: the design \
             resolves `~` exactly once, at startup"
        );
        // Same computation production performs, at the same point in the
        // sequence: the overlay built so far, then the platform's own answer.
        // `assigns` rather than `resolve`: the overlay falls back to the
        // process environment, which would hand back the real home and hide
        // the base this recorder was given.
        let home = so_far
            .assigns("HOME")
            .then(|| so_far.resolve("HOME"))
            .flatten()
            .filter(|h| !h.is_empty())
            .map(std::path::PathBuf::from)
            .or_else(|| self.base.clone())
            .or_else(crate::home_dir::home_dir);
        if let Some(ref h) = home {
            self.calls.lock().unwrap().push(h.clone());
        }
        home
    }
}

/// Writes `contents` to `dir/name` and returns the path.
pub(super) fn env_file(dir: &std::path::Path, name: &str, contents: &str) -> std::path::PathBuf {
    let path = dir.join(name);
    write_owner_only(&path, contents).unwrap();
    path
}

/// A config file naming `entries` as its `env_files`, verbatim.
pub(super) fn config_naming_env_files(
    dir: &std::path::Path,
    entries: &[&str],
) -> std::path::PathBuf {
    let mut yaml = String::from("env_files:\n");
    for e in entries {
        use std::fmt::Write as _;
        writeln!(yaml, "  - '{e}'").unwrap();
    }
    let path = dir.join("gateway.yaml");
    write_owner_only(&path, yaml).unwrap();
    path
}

/// Startup as the gateway performs it, through an injected home.
pub(super) fn startup_through(cfg: &std::path::Path, home: &dyn HomeResolver) -> Evaluated {
    Config::load_evaluated_with_home(Some(cfg), home).unwrap()
}

/// A reload context carrying the environment startup published — the shape the
/// design requires, so that a reload takes the recorded `ResolvedEnvFiles`
/// instead of resolving `config.env_files` itself.
pub(super) fn reload_context_with_env(cfg: &std::path::Path, startup: &Evaluated) -> ReloadContext {
    test_reload_context(cfg).with_env(Arc::new(LiveEnv::new(
        startup.overlay.clone(),
        startup.env_paths.clone(),
    )))
}

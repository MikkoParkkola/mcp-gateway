// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! In-memory environment overlay (MIK-7256).
//!
//! Env files used to be applied straight to the process environment, so a
//! config that was later rejected had already mutated the process it was
//! rejected by. Reading them into an overlay that is published only on a
//! successful load makes the mutation follow the decision instead of preceding
//! it.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};

use crate::{Error, Result};

/// The env-file paths a running process actually opened.
///
/// A wrapper rather than a bare `Vec<PathBuf>` because these are the paths a
/// reload must reuse: `~` resolves exactly once, at startup, and the recorded
/// sequence is the only record of what it resolved to.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ResolvedEnvFiles {
    paths: Vec<PathBuf>,
    /// Whether any entry was spelled with a leading `~`.
    ///
    /// Kept because the resolved path cannot be asked: `/home/a/x.env` is the
    /// same string whether it was written that way or expanded from `~/x.env`,
    /// and only the second is moved by a later `HOME` assignment.
    tilde: bool,
}

impl ResolvedEnvFiles {
    /// Records paths already resolved, in application order.
    pub(crate) fn new(paths: Vec<PathBuf>, tilde: bool) -> Self {
        Self { paths, tilde }
    }

    /// Whether a `HOME` assignment could move where a restart reads.
    #[must_use]
    pub fn has_tilde_entry(&self) -> bool {
        self.tilde
    }

    /// The recorded paths, in the order they were applied.
    #[must_use]
    pub fn as_paths(&self) -> &[PathBuf] {
        &self.paths
    }
}

/// Where `~` resolves to, injected so the resolution point is observable.
///
/// `so_far` is load-bearing: startup applies each env file before expanding the
/// next, so an entry's home is whatever the overlay under construction says at
/// that moment. A resolver blind to it cannot reproduce that ordering.
pub trait HomeResolver {
    /// The home directory to substitute for `~`, given the overlay built so far.
    fn home_dir(&self, so_far: &EnvOverlay) -> Option<PathBuf>;
}

/// The platform's own answer, consulting the overlay first exactly as the
/// expansion path does.
pub struct SystemHome;

impl HomeResolver for SystemHome {
    fn home_dir(&self, so_far: &EnvOverlay) -> Option<PathBuf> {
        so_far
            .resolve("HOME")
            .filter(|h| !h.is_empty())
            .map(PathBuf::from)
            .or_else(dirs::home_dir)
    }
}

/// Environment as the gateway sees it: env-file assignments layered over the
/// process environment, without touching the process environment.
#[derive(Debug, Clone, Default)]
pub struct EnvOverlay {
    /// Assignments made by this overlay's own env files.
    vars: HashMap<String, String>,
    /// Keys this overlay's files assign. Distinct from `vars`' key set only in
    /// intent, but the intent is what the restart notice is decided from.
    owned: BTreeSet<String>,
    /// Values inherited from the overlay in force when this one was built.
    inherited: HashMap<String, String>,
    /// The process-environment value of each owned key at construction, so a
    /// consumer can tell an override from a pass-through.
    baseline: HashMap<String, String>,
}

impl EnvOverlay {
    /// No env files: every lookup falls through to the process environment.
    #[must_use]
    pub fn none() -> Self {
        Self::default()
    }

    /// The single resolver. Env-file assignment first, then whatever the
    /// previous overlay carried, then the process environment.
    #[must_use]
    pub fn resolve(&self, name: &str) -> Option<String> {
        self.vars
            .get(name)
            .or_else(|| self.inherited.get(name))
            .cloned()
            .or_else(|| std::env::var(name).ok())
    }

    /// True when this overlay's own files assign `name`.
    ///
    /// Assignment, never value comparison: the value a restart would resolve
    /// against is not knowable from a reload, so a same-value assignment still
    /// counts.
    #[must_use]
    pub fn assigns(&self, name: &str) -> bool {
        self.owned.contains(name)
    }

    /// The keys this overlay's files assign.
    #[must_use]
    pub fn owned_keys(&self) -> &BTreeSet<String> {
        &self.owned
    }

    /// The process-environment value `name` had when this overlay was built.
    #[must_use]
    pub fn baseline(&self, name: &str) -> Option<&str> {
        self.baseline.get(name).map(String::as_str)
    }

    /// Everything the overlay contributes, for consumers that need a map rather
    /// than point lookups.
    #[must_use]
    pub fn effective_vars(&self) -> BTreeMap<String, String> {
        self.inherited
            .iter()
            .chain(self.vars.iter())
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect()
    }

    /// Overlay for already-resolved paths, layered over `previous`.
    ///
    /// Unreadable or malformed files are warned about and skipped, matching the
    /// tolerance the process-mutating loader had.
    #[must_use]
    pub fn from_paths(paths: &[PathBuf], previous: &EnvOverlay) -> Self {
        let mut overlay = Self::inheriting(previous);
        for path in paths {
            overlay.apply_file_tolerant(path);
        }
        overlay
    }

    /// As [`EnvOverlay::from_paths`], but a malformed file is an error.
    ///
    /// The diagnostic is rebuilt rather than forwarded: `dotenvy`'s own
    /// `Display` echoes the offending line, which would put a secret into a log
    /// line written because a secret was mistyped.
    pub fn from_paths_checked(paths: &[PathBuf], previous: &EnvOverlay) -> Result<Self> {
        let mut overlay = Self::inheriting(previous);
        for path in paths {
            overlay.apply_file(path)?;
        }
        Ok(overlay)
    }

    /// An empty overlay layered over `previous`, to be filled entry by entry.
    pub(crate) fn inheriting(previous: &EnvOverlay) -> Self {
        Self {
            vars: HashMap::new(),
            owned: BTreeSet::new(),
            inherited: previous.effective_vars().into_iter().collect(),
            baseline: HashMap::new(),
        }
    }

    /// Applies one env file, warning rather than failing on malformed content.
    pub(crate) fn apply_file_tolerant(&mut self, path: &Path) {
        if let Err(error) = self.apply_file(path) {
            tracing::warn!("Failed to load env file {}: {error}", path.display());
        }
    }

    /// Applies one env file. A missing file is not an error — the old loader
    /// skipped it silently and configs rely on that for optional files.
    pub(crate) fn apply_file(&mut self, path: &Path) -> Result<()> {
        if !path.exists() {
            tracing::debug!("Env file not found (skipped): {}", path.display());
            return Ok(());
        }
        let iter = dotenvy::from_path_iter(path).map_err(|e| Self::describe(path, &e))?;
        for entry in iter {
            let (key, value) = entry.map_err(|e| Self::describe(path, &e))?;
            self.insert(key, value);
        }
        tracing::info!("Loaded env file: {}", path.display());
        Ok(())
    }

    fn insert(&mut self, key: String, value: String) {
        if let Ok(existing) = std::env::var(&key) {
            self.baseline.entry(key.clone()).or_insert(existing);
        }
        self.owned.insert(key.clone());
        self.vars.insert(key, value);
    }

    /// File, line and category — never the line's content.
    fn describe(path: &Path, error: &dotenvy::Error) -> Error {
        let where_ = path.display();
        match error {
            dotenvy::Error::LineParse(_, index) => Error::Config(format!(
                "Failed to parse env file {where_} line {}: the line is not a KEY=value \
                 assignment. The offending text is withheld because env files carry \
                 secrets.",
                index + 1
            )),
            dotenvy::Error::Io(io) => {
                Error::Config(format!("Cannot read env file {where_}: {}", io.kind()))
            }
            _ => Error::Config(format!("Cannot load env file {where_}: malformed content.")),
        }
    }
}

/// The environment a running gateway resolves against.
///
/// A cell rather than a captured `Arc<EnvOverlay>`: a reload replaces the
/// overlay, and a holder that captured the `Arc` would keep answering from the
/// one it captured. `get` is on the request path, `set` only on reload.
#[derive(Debug)]
pub struct LiveEnv {
    overlay: RwLock<Arc<EnvOverlay>>,
    env_paths: ResolvedEnvFiles,
}

impl Default for LiveEnv {
    /// The process environment and nothing else: every lookup falls through,
    /// which is what a consumer built outside the gateway's startup path had
    /// before an overlay existed.
    fn default() -> Self {
        Self::new(Arc::new(EnvOverlay::none()), ResolvedEnvFiles::default())
    }
}

impl LiveEnv {
    #[must_use]
    /// The environment a successful load produced, ready to be published.
    pub fn new(overlay: Arc<EnvOverlay>, env_paths: ResolvedEnvFiles) -> Self {
        Self {
            overlay: RwLock::new(overlay),
            env_paths,
        }
    }

    /// The overlay in force. Cheap enough for the request path.
    #[must_use]
    pub fn get(&self) -> Arc<EnvOverlay> {
        self.overlay
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    /// Publishes a new overlay. Called only once a load has succeeded.
    pub fn set(&self, overlay: Arc<EnvOverlay>) {
        *self
            .overlay
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = overlay;
    }

    /// The paths startup recorded. A reload reuses these; it never resolves
    /// `env_files` again.
    #[must_use]
    pub fn env_paths(&self) -> &ResolvedEnvFiles {
        &self.env_paths
    }
}

/// A config plus the environment it was evaluated against.
///
/// One resolution, one result: startup and reload both produce this, so the
/// paths a reload opens are the paths startup recorded rather than a second
/// resolution that happens to agree.
#[derive(Debug, Clone)]
pub struct Evaluated {
    /// The configuration itself.
    pub config: super::Config,
    /// The environment it was evaluated against.
    pub overlay: Arc<EnvOverlay>,
    /// The env-file paths that were opened, in order.
    pub env_paths: ResolvedEnvFiles,
    /// Names the config referenced as `env:NAME`.
    ///
    /// Recorded before substitution, because after it the config holds the
    /// value and the reference is gone. A reload compares these names across
    /// overlays to report a rotation no running holder can take.
    pub secret_refs: std::collections::BTreeSet<String>,
}

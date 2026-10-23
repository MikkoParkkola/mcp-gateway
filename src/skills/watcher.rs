// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! Hot-reload skill regeneration watcher.
//!
//! Watches capability YAML directories and regenerates only the affected skill
//! bundle when a file changes, without triggering a full backend reload.
//!
//! # Design
//!
//! The [`SkillsWatcher`] is intentionally independent of [`CapabilityWatcher`]:
//! it owns its own file-system watcher and operates on the parsed
//! [`CapabilityDefinition`] directly from the changed file, regenerating the
//! single affected category bundle instead of all of them.
//!
//! [`CapabilityWatcher`]: crate::capability::CapabilityWatcher
//! [`CapabilityDefinition`]: crate::capability::CapabilityDefinition
//!
//! # Usage
//!
//! ```no_run
//! use std::path::PathBuf;
//! use mcp_gateway::skills::watcher::SkillsWatcher;
//!
//! # fn example() -> mcp_gateway::Result<()> {
//! let dirs = vec!["capabilities".to_string()];
//! let watcher = SkillsWatcher::start(
//!     &dirs,
//!     PathBuf::from("skills"),
//!     vec![],
//!     tokio::sync::broadcast::channel(1).1,
//! )?;
//! # Ok(())
//! # }
//! ```

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use notify::{Config, Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use parking_lot::Mutex;
use tracing::{debug, error, info, warn};

use super::regenerate_for_capability;
use crate::Result;
use crate::capability::parse_capability_file;

/// Changed capability paths waiting for the regen task: a set, so a burst or
/// an edit during a pass is kept, never dropped (MIK-8690). Two limits stay
/// as they were: paths still pending at shutdown are abandoned, and a steady
/// stream of edits keeps postponing the pass until it goes quiet for the
/// debounce.
struct ChangeSet {
    state: Mutex<Dirty>,
}

/// The pending paths and when the latest one arrived.
#[derive(Default)]
struct Dirty {
    paths: std::collections::HashSet<PathBuf>,
    last: Option<Instant>,
}

impl ChangeSet {
    /// Takes the lock for one insert; never drops a path and never waits on a
    /// regeneration pass.
    fn push(&self, path: PathBuf) {
        let mut state = self.state.lock();
        state.paths.insert(path);
        state.last = Some(Instant::now());
    }

    /// Take every pending path once none has arrived for `quiet`; empty
    /// means nothing is due.
    fn take_if_quiet(&self, quiet: Duration) -> Vec<PathBuf> {
        let taken = {
            let mut state = self.state.lock();
            if !state.paths.is_empty() && state.last.is_some_and(|t| t.elapsed() >= quiet) {
                let paths = std::mem::take(&mut state.paths);
                state.last = None;
                paths
            } else {
                std::collections::HashSet::new()
            }
        };
        let mut paths: Vec<PathBuf> = taken.into_iter().collect();
        paths.sort();
        paths
    }

    /// How many paths are still waiting for a pass.
    fn pending_count(&self) -> usize {
        self.state.lock().paths.len()
    }
}

/// The receiving side the regen task drains.
struct ChangeSource {
    changes: Arc<ChangeSet>,
    /// Pause point after a pass has regenerated its batch, before the loop
    /// looks for changes that arrived during it (tests only).
    #[cfg(test)]
    after_pass: crate::test_pause::Slot,
}

/// Both sides of the shared set: one for the file watcher, one for the regen task.
fn change_set() -> (Arc<ChangeSet>, ChangeSource) {
    let changes = Arc::new(ChangeSet {
        state: Mutex::new(Dirty::default()),
    });
    (
        Arc::clone(&changes),
        ChangeSource {
            changes,
            #[cfg(test)]
            after_pass: crate::test_pause::Slot::default(),
        },
    )
}

/// Hot-reload watcher that regenerates skill bundles on capability file changes.
pub struct SkillsWatcher {
    /// Keep the underlying notify watcher alive.
    _watcher: Mutex<Option<RecommendedWatcher>>,
}

impl SkillsWatcher {
    /// Start watching `directories` for YAML changes.
    ///
    /// On each change the affected capability is re-parsed from disk and its
    /// skill bundle regenerated in `out_dir`.  Changes are debounced by 500 ms
    /// to coalesce rapid saves.  Changed paths collect in a set, so a burst
    /// larger than any buffer, or an edit made during a regeneration pass, is
    /// regenerated on the next pass, and a pass which leaves changes behind
    /// warns once.  `agent_paths` follows the same semantics as
    /// [`install_bundle`](super::installer::install_bundle).
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying file watcher cannot be created.
    pub fn start(
        directories: &[String],
        out_dir: PathBuf,
        agent_paths: Vec<PathBuf>,
        shutdown_rx: tokio::sync::broadcast::Receiver<()>,
    ) -> Result<Self> {
        if directories.is_empty() {
            return Ok(Self {
                _watcher: Mutex::new(None),
            });
        }

        let (changes, source) = change_set();
        let watcher = Self::create_watcher(changes, directories)?;
        Self::spawn_regen_task(source, shutdown_rx, out_dir, agent_paths);

        Ok(Self {
            _watcher: Mutex::new(Some(watcher)),
        })
    }

    /// Create the notify watcher, forwarding changed YAML paths.
    fn create_watcher(
        changes: Arc<ChangeSet>,
        directories: &[String],
    ) -> Result<RecommendedWatcher> {
        let mut watcher = RecommendedWatcher::new(
            move |result: std::result::Result<Event, notify::Error>| {
                if let Ok(event) = result {
                    let is_relevant =
                        matches!(event.kind, EventKind::Create(_) | EventKind::Modify(_));
                    if is_relevant {
                        for path in event.paths {
                            if path.extension().is_some_and(|e| e == "yaml" || e == "yml") {
                                debug!(path = %path.display(), "Skill watcher: capability changed");
                                changes.push(path);
                            }
                        }
                    }
                }
            },
            Config::default().with_poll_interval(Duration::from_secs(2)),
        )
        .map_err(|e| crate::Error::ConfigWatcher(format!("Skills watcher: {e}")))?;

        for dir in directories {
            let path = Path::new(dir);
            if path.exists()
                && let Err(e) = watcher.watch(path, RecursiveMode::Recursive)
            {
                warn!(directory = %dir, error = %e, "Skills watcher: failed to watch dir");
            }
        }

        Ok(watcher)
    }

    /// Spawn the debounced regeneration task.
    fn spawn_regen_task(
        source: ChangeSource,
        mut shutdown_rx: tokio::sync::broadcast::Receiver<()>,
        out_dir: PathBuf,
        agent_paths: Vec<PathBuf>,
    ) {
        tokio::spawn(async move {
            const DEBOUNCE_MS: u64 = 500;
            let mut ticker = tokio::time::interval(Duration::from_millis(100));

            loop {
                tokio::select! {
                    _ = ticker.tick() => {
                        let paths = source
                            .changes
                            .take_if_quiet(Duration::from_millis(DEBOUNCE_MS));
                        if !paths.is_empty() {
                            regenerate_changed_files(&paths, &out_dir, &agent_paths).await;
                            #[cfg(test)]
                            source.after_pass.pause().await;
                            let deferred = source.changes.pending_count();
                            if deferred > 0 {
                                warn!(
                                    deferred,
                                    "Skills watcher: {deferred} skill changes arrived during regeneration; deferred to the next pass"
                                );
                            }
                        }
                    }
                    _ = shutdown_rx.recv() => {
                        info!("Skills watcher shutting down");
                        break;
                    }
                }
            }
        });
    }
}

/// Parse and regenerate skills for each changed file path.
async fn regenerate_changed_files(paths: &[PathBuf], out_dir: &Path, agent_paths: &[PathBuf]) {
    for path in paths {
        match parse_capability_file(path).await {
            Ok(cap) => {
                info!(
                    capability = %cap.name,
                    path = %path.display(),
                    "Skills watcher: regenerating bundle"
                );
                if let Err(e) = regenerate_for_capability(&cap, out_dir, agent_paths).await {
                    error!(
                        capability = %cap.name,
                        error = %e,
                        "Skills watcher: regeneration failed"
                    );
                }
            }
            Err(e) => {
                warn!(path = %path.display(), error = %e, "Skills watcher: parse failed");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn skills_watcher_start_with_no_directories_returns_ok() {
        // GIVEN: empty directory list
        let (_tx, rx) = tokio::sync::broadcast::channel(1);
        // WHEN
        let result = SkillsWatcher::start(&[], PathBuf::from("skills"), vec![], rx);
        // THEN: no error
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn regenerate_changed_files_logs_parse_error_gracefully() {
        // GIVEN: a non-existent path
        let tmp = tempfile::TempDir::new().unwrap();
        let bad_path = PathBuf::from("/nonexistent/cap.yaml");
        // WHEN: called with a bad path (should not panic)
        regenerate_changed_files(&[bad_path], tmp.path(), &[]).await;
        // THEN: no panic (error is logged and swallowed)
    }

    #[tokio::test]
    async fn regenerate_changed_files_regenerates_valid_capability() {
        // GIVEN: a valid capability YAML on disk
        let tmp = tempfile::TempDir::new().unwrap();
        let cap_yaml = r"
name: test_regen_cap
description: Regen test
providers:
  primary:
    service: rest
    config:
      base_url: https://example.com
metadata:
  category: test_hot
";
        let yaml_path = tmp.path().join("test_regen_cap.yaml");
        tokio::fs::write(&yaml_path, cap_yaml).await.unwrap();
        let out_dir = tmp.path().join("skills");
        // WHEN
        regenerate_changed_files(&[yaml_path], &out_dir, &[]).await;
        // THEN: skill bundle created
        assert!(
            out_dir
                .join("mcp-gateway-test_hot")
                .join("SKILL.md")
                .exists()
        );
    }
}

#[cfg(test)]
#[path = "watcher_burst_tests.rs"]
mod burst_tests;

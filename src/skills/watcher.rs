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
use std::time::{Duration, Instant};

use notify::{Config, Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use parking_lot::Mutex;
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

use super::regenerate_for_capability;
use crate::Result;
use crate::capability::parse_capability_file;

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
    /// to coalesce rapid saves.  `agent_paths` follows the same semantics as
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

        let (event_tx, event_rx) = mpsc::channel::<PathBuf>(100);
        let watcher = Self::create_watcher(event_tx, directories)?;
        Self::spawn_regen_task(event_rx, shutdown_rx, out_dir, agent_paths);

        Ok(Self {
            _watcher: Mutex::new(Some(watcher)),
        })
    }

    /// Create the notify watcher, forwarding changed YAML paths.
    fn create_watcher(
        event_tx: mpsc::Sender<PathBuf>,
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
                                let _ = event_tx.try_send(path);
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
        mut event_rx: mpsc::Receiver<PathBuf>,
        mut shutdown_rx: tokio::sync::broadcast::Receiver<()>,
        out_dir: PathBuf,
        agent_paths: Vec<PathBuf>,
    ) {
        tokio::spawn(async move {
            const DEBOUNCE_MS: u64 = 500;
            let mut pending: Vec<PathBuf> = Vec::new();
            let mut last_event: Option<Instant> = None;
            let mut ticker = tokio::time::interval(Duration::from_millis(100));

            loop {
                tokio::select! {
                    Some(path) = event_rx.recv() => {
                        if !pending.contains(&path) {
                            pending.push(path);
                        }
                        last_event = Some(Instant::now());
                    }
                    _ = ticker.tick() => {
                        if !pending.is_empty()
                            && last_event.is_some_and(|t| t.elapsed() >= Duration::from_millis(DEBOUNCE_MS))
                        {
                            let paths = std::mem::take(&mut pending);
                            last_event = None;
                            regenerate_changed_files(&paths, &out_dir, &agent_paths).await;
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

// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Shared helpers for mutating and persisting gateway config files.

use std::path::Path;
#[cfg(not(windows))]
use std::path::PathBuf;
#[cfg(not(windows))]
use std::sync::atomic::{AtomicU64, Ordering};

use crate::config::Config;
use crate::config_reload::{ReloadContext, ReloadOutcome};

/// Load config from `path`, returning `Config::default()` when the file is absent
/// or cannot be parsed.
#[must_use]
pub fn load_config_or_default(path: &Path) -> Config {
    if path.exists() {
        Config::load(Some(path)).unwrap_or_else(|e| {
            tracing::warn!(error = %e, "Could not load config, using defaults");
            Config::default()
        })
    } else {
        Config::default()
    }
}

/// Load config from `path`, returning `Config::default()` when the file is absent.
///
/// # Errors
///
/// Returns an error when the file exists but cannot be parsed.
pub fn load_existing_or_default(path: &Path) -> crate::Result<Config> {
    if path.exists() {
        Config::load(Some(path))
    } else {
        Ok(Config::default())
    }
}

/// Serialize `config` as YAML and write it to `path`.
///
/// # Errors
///
/// Returns `Err` on validation, serialisation, or I/O failure.
pub fn write_config(path: &Path, config: &Config) -> Result<(), String> {
    config
        .validate()
        .map_err(|e| format!("Failed to validate config: {e}"))?;
    let yaml =
        serde_yaml::to_string(config).map_err(|e| format!("Failed to serialize config: {e}"))?;
    write_yaml(path, &yaml)
}

/// Serialize `config`, write it atomically, then trigger hot-reload when a
/// reload context is available.
///
/// Persistence is always authoritative for the on-disk file. Hot-reload then
/// applies only the subset of changes supported by [`ReloadContext`] (for
/// example, backend changes); server listener changes remain on disk until the
/// process is restarted.
///
/// # Errors
///
/// Returns an error string on serialization, write, rename, or reload failure.
pub async fn write_config_and_reload(
    path: &Path,
    config: &Config,
    reload_context: Option<&ReloadContext>,
) -> Result<(), String> {
    write_config_and_reload_outcome(path, config, reload_context)
        .await
        .map(|_| ())
}

/// Serialize `config`, write it atomically, then return any hot-reload outcome.
///
/// # Errors
///
/// Returns an error string on serialization, write, rename, or reload failure.
pub async fn write_config_and_reload_outcome(
    path: &Path,
    config: &Config,
    reload_context: Option<&ReloadContext>,
) -> Result<Option<ReloadOutcome>, String> {
    if let Some(ctx) = reload_context {
        // Write and reload share one lock inside the context. Writing here
        // first would reopen the race the lock exists to close.
        return ctx.write_and_reload_outcome(path, config).await.map(Some);
    }

    write_config(path, config)?;
    Ok(None)
}

fn write_yaml(path: &Path, yaml: &str) -> Result<(), String> {
    #[cfg(windows)]
    {
        std::fs::write(path, yaml).map_err(|e| format!("Failed to write config: {e}"))
    }

    #[cfg(not(windows))]
    {
        let tmp_path = temp_config_path(path);
        // Leave no debris behind on either failure. The scratch name is unique
        // per call, so without cleanup each failure would strand one more file
        // next to the config instead of reusing a single stale one.
        std::fs::write(&tmp_path, yaml).map_err(|e| {
            let _ = std::fs::remove_file(&tmp_path);
            format!("Failed to write temp config: {e}")
        })?;
        std::fs::rename(&tmp_path, path).map_err(|e| {
            let _ = std::fs::remove_file(&tmp_path);
            format!("Failed to replace config file: {e}")
        })
    }
}

/// A temp path unique to this call, in the same directory as `path` so the
/// rename stays atomic.
///
/// Uniqueness is the point. A shared `<config>.tmp` lets two concurrent writers
/// collide: both write the same temp file, the first rename ships whichever
/// bytes landed last while reporting its own edit saved, and the second rename
/// fails because the file it wrote is already gone.
#[cfg(not(windows))]
fn temp_config_path(path: &Path) -> PathBuf {
    static COUNTER: AtomicU64 = AtomicU64::new(0);

    let mut tmp_path = path.as_os_str().to_os_string();
    tmp_path.push(format!(
        ".tmp.{}.{}",
        std::process::id(),
        COUNTER.fetch_add(1, Ordering::Relaxed)
    ));
    PathBuf::from(tmp_path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn load_existing_or_default_returns_default_when_missing() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("missing.yaml");

        let config = load_existing_or_default(&path).unwrap();

        assert!(config.backends.is_empty());
    }

    #[test]
    fn write_config_persists_yaml() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("gateway.yaml");
        let config = Config::default();

        write_config(&path, &config).unwrap();

        assert!(path.exists());
        let loaded = Config::load(Some(&path)).unwrap();
        assert_eq!(loaded.backends.len(), config.backends.len());
    }

    /// The temp file used by an atomic config write must be unique per call.
    /// A shared `<config>.tmp` lets two concurrent writers clobber each other:
    /// one renames the other's bytes into place and reports its own edit saved.
    #[cfg(not(windows))]
    #[test]
    fn each_config_write_gets_its_own_temp_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("gateway.yaml");

        let first = temp_config_path(&path);
        let second = temp_config_path(&path);

        assert_ne!(
            first, second,
            "two writers shared one temp path, so either can overwrite the other"
        );
        for tmp in [&first, &second] {
            assert_eq!(tmp.parent(), path.parent(), "temp file left its directory");
        }
    }

    /// Concurrent writers must each either persist their own bytes or fail
    /// honestly, and the file left behind must be exactly one writer's config.
    /// Against a shared scratch path one writer's rename finds the file already
    /// renamed away and fails with "Failed to replace config file", and the
    /// bytes that land can belong to a writer that reported success elsewhere.
    #[test]
    fn concurrent_config_writes_do_not_lose_the_temp_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("gateway.yaml");

        // Each writer's config is distinguishable, so the assertion below can
        // tell "one writer won" from "the file is a mix of two writers".
        let config_for = |writer: usize| {
            let mut config = Config::default();
            config.backends.insert(
                format!("writer-{writer}"),
                crate::config::BackendConfig {
                    transport: crate::config::TransportConfig::Http {
                        http_url: "http://127.0.0.1:9/mcp".to_string(),
                        streamable_http: false,
                        protocol_version: None,
                    },
                    ..crate::config::BackendConfig::default()
                },
            );
            config
        };

        for _ in 0..40 {
            let errors: Vec<String> = std::thread::scope(|scope| {
                let path = &path;
                let config_for = &config_for;
                let handles: Vec<_> = (0..8)
                    .map(|writer| scope.spawn(move || write_config(path, &config_for(writer))))
                    .collect();
                handles
                    .into_iter()
                    .filter_map(|h| h.join().unwrap().err())
                    .collect()
            });

            assert!(
                errors.is_empty(),
                "concurrent writers collided on the scratch file: {errors:?}"
            );

            let loaded = Config::load(Some(&path)).expect("config left unparseable");
            let names: Vec<&String> = loaded.backends.keys().collect();
            assert_eq!(
                names.len(),
                1,
                "persisted config is not any single writer's: {names:?}"
            );
            assert!(
                names[0].starts_with("writer-"),
                "persisted config is not any single writer's: {names:?}"
            );
        }

        let leftovers: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(|e| e.ok().map(|e| e.file_name()))
            .filter(|name| name != "gateway.yaml")
            .collect();
        assert!(
            leftovers.is_empty(),
            "scratch files were left next to the config: {leftovers:?}"
        );
    }

    #[test]
    fn write_config_rejects_invalid_config() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("gateway.yaml");
        let mut config = Config::default();
        config.backends.insert(
            "invalid_backend".to_string(),
            crate::config::BackendConfig {
                transport: crate::config::TransportConfig::Http {
                    http_url: "not a url".to_string(),
                    streamable_http: false,
                    protocol_version: None,
                },
                ..crate::config::BackendConfig::default()
            },
        );

        let result = write_config(&path, &config);

        assert!(matches!(result, Err(msg) if msg.contains("Failed to validate config")));
        assert!(!path.exists());
    }

    #[tokio::test]
    async fn write_config_and_reload_without_context_persists_yaml() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("gateway.yaml");
        let config = Config::default();

        write_config_and_reload(&path, &config, None).await.unwrap();

        assert!(path.exists());
        let loaded = Config::load(Some(&path)).unwrap();
        assert_eq!(loaded.backends.len(), config.backends.len());
    }

    #[tokio::test]
    async fn write_config_and_reload_outcome_without_context_returns_none() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("gateway.yaml");
        let config = Config::default();

        let outcome = write_config_and_reload_outcome(&path, &config, None)
            .await
            .unwrap();

        assert!(outcome.is_none());
    }
}

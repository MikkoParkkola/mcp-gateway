//! Shared helpers for mutating and persisting gateway config files.

use std::path::Path;
#[cfg(not(windows))]
use std::path::PathBuf;

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
    write_config(path, config)?;

    if let Some(ctx) = reload_context {
        let outcome = ctx
            .reload_outcome()
            .await
            .map_err(|e| format!("Config written but reload failed: {e}"))?;
        return Ok(Some(outcome));
    }

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
        std::fs::write(&tmp_path, yaml).map_err(|e| format!("Failed to write temp config: {e}"))?;
        std::fs::rename(&tmp_path, path).map_err(|e| format!("Failed to replace config file: {e}"))
    }
}

#[cfg(not(windows))]
fn temp_config_path(path: &Path) -> PathBuf {
    let mut tmp_path = path.as_os_str().to_os_string();
    tmp_path.push(".tmp");
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

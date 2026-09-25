// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Where the control-plane (governance) store lives, and opening it at startup.

use std::sync::Arc;

use tracing::{info, warn};

use super::expand_home_path;
use crate::config::Config;

/// Open the durable control-plane store (grants/policies plus a
/// governance-scoped audit log, separate from the invocation transparency log;
/// ADR-005, MIK-6685).
///
/// Returns `None` — disabling the governance mutation routes (they answer 503) —
/// when auth is disabled, since an auth-disabled gateway treats every caller as
/// an anonymous admin and a durable governance mutation surface must not be open
/// to unauthenticated callers. Also returns `None` if the data directory or the
/// audit log cannot be opened; never fatal to startup.
///
/// The store is rooted next to the config file when one is known
/// (`<config-dir>/control-plane`), so distinct gateway instances do not share
/// governance state; otherwise it falls back to `~/.mcp-gateway/control-plane`.
/// Governance audit entries reuse the transparency log's signing identity, so
/// they are signed iff the invocation log is.
/// Per-config control-plane base directory (governance store + audit log).
/// Shared by [`build_control_plane_store`] and the SIEM export wiring so both
/// resolve the identical `audit.jsonl` path (MIK-6703).
pub(super) fn control_plane_base(config_path: Option<&std::path::Path>) -> std::path::PathBuf {
    config_path.map_or_else(
        || expand_home_path("~/.mcp-gateway/control-plane"),
        |p| {
            let dir = p.parent().unwrap_or_else(|| std::path::Path::new("."));
            let stem = p.file_stem().and_then(|s| s.to_str()).unwrap_or("gateway");
            dir.join(format!("{stem}-control-plane"))
        },
    )
}

pub(super) fn build_control_plane_store(
    config: &Config,
    config_path: Option<&std::path::Path>,
) -> Option<Arc<dyn crate::control_plane::ControlPlaneStore>> {
    use crate::control_plane::FileControlPlaneStore;
    use crate::security::TransparencyLogger;
    use crate::security::transparency_log::TransparencyLogConfig;

    if !config.auth.enabled {
        info!(
            "control-plane governance mutations disabled: auth is off (would expose an anonymous-admin mutation surface)"
        );
        return None;
    }

    // Derive a per-config store directory so distinct gateway instances do not
    // share governance state (see control_plane_base).
    let base = control_plane_base(config_path);
    let audit_cfg = Arc::new(TransparencyLogConfig {
        enabled: true,
        path: base.join("audit.jsonl").to_string_lossy().into_owned(),
        key_id: config.security.transparency_log.key_id.clone(),
        shared_secret: config.security.transparency_log.shared_secret.clone(),
    });
    let audit = match TransparencyLogger::open(audit_cfg) {
        Ok(logger) => Arc::new(logger),
        Err(e) => {
            warn!(error = %e, "control-plane audit log unavailable; governance mutations disabled");
            return None;
        }
    };
    match FileControlPlaneStore::open(base.join("store"), audit) {
        Ok(store) => Some(Arc::new(store) as Arc<dyn crate::control_plane::ControlPlaneStore>),
        Err(e) => {
            warn!(error = %e, "control-plane store unavailable; governance mutations disabled");
            None
        }
    }
}

/// F6 (MIK 7570.GOVSTORE.1): where the governance store lives, and what a
/// start does when that place cannot be written. Failures are forced with
/// ENOTDIR (a regular file where a directory must be), never with chmod: CI
/// runs as root, and root writes through a 0555 directory.
#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};

    use crate::config::Config;

    /// The startup outcome a test observes: `Err` is a refusal to start,
    /// `Ok(true)` a gateway serving governance mutation, `Ok(false)` one
    /// serving read-only.
    fn start(config: &Config, config_path: &Path) -> Result<bool, String> {
        Ok(super::build_control_plane_store(config, Some(config_path)).is_some())
    }

    fn base(config: &Config, config_path: &Path) -> PathBuf {
        let _ = config;
        super::control_plane_base(Some(config_path))
    }

    /// Write `yaml` as `<dir>/gateway.yaml` and load it the way startup does.
    fn load(dir: &Path, yaml: &str) -> (Config, PathBuf) {
        let path = dir.join("gateway.yaml");
        std::fs::write(&path, yaml).expect("write config");
        (Config::load(Some(&path)).expect("config loads"), path)
    }

    fn auth_on_with_store_dir(store_dir: &str) -> String {
        format!(
            "auth:\n  enabled: true\n  bearer_token: f6-test-token\ncontrol_plane:\n  store_dir: \"{store_dir}\"\n"
        )
    }

    #[test]
    fn store_opens_at_explicit_store_dir() {
        let (cfg_dir, data) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
        let store_dir = data.path().join("cp");
        let (config, path) = load(
            cfg_dir.path(),
            &auth_on_with_store_dir(&store_dir.to_string_lossy()),
        );

        assert_eq!(start(&config, &path), Ok(true));
        assert!(
            store_dir.join("store").is_dir(),
            "store not under store_dir"
        );
        assert!(
            store_dir.join("audit.jsonl").is_file(),
            "audit log not under store_dir"
        );
        assert!(
            !cfg_dir.path().join("gateway-control-plane").exists(),
            "an explicit store_dir must not also create the default base"
        );
    }

    #[test]
    fn explicit_unopenable_store_dir_refuses_start() {
        let (cfg_dir, data) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
        std::fs::write(data.path().join("file"), b"not a directory").unwrap();
        let store_dir = data.path().join("file").join("cp");
        let (config, path) = load(
            cfg_dir.path(),
            &auth_on_with_store_dir(&store_dir.to_string_lossy()),
        );

        let err = start(&config, &path).expect_err("an unopenable store_dir must refuse start");
        assert!(
            err.contains(&*store_dir.to_string_lossy()),
            "the refusal must name the path: {err}"
        );
    }

    #[test]
    fn relative_store_dir_refuses_start() {
        let cfg_dir = tempfile::tempdir().unwrap();
        let (config, path) = load(cfg_dir.path(), &auth_on_with_store_dir("relative/cp"));

        let err = start(&config, &path).expect_err("a relative store_dir must refuse start");
        assert!(
            err.contains("relative/cp"),
            "the refusal must name the value: {err}"
        );
        assert!(
            err.contains("absolute"),
            "the refusal must state the rule: {err}"
        );
    }

    #[test]
    fn default_unwritable_store_degrades_without_refusing() {
        let cfg_dir = tempfile::tempdir().unwrap();
        std::fs::write(cfg_dir.path().join("gateway-control-plane"), b"file").unwrap();
        let (config, path) = load(
            cfg_dir.path(),
            "auth:\n  enabled: true\n  bearer_token: f6-test-token\n",
        );

        assert_eq!(start(&config, &path), Ok(false));
    }

    #[test]
    fn default_store_path_unchanged() {
        let config = Config::default();
        assert_eq!(
            base(&config, Path::new("/x/gw.yaml")),
            PathBuf::from("/x/gw-control-plane")
        );
    }

    #[test]
    fn store_dir_change_is_restart_required() {
        let cfg_dir = tempfile::tempdir().unwrap();
        let (running, _) = load(cfg_dir.path(), &auth_on_with_store_dir("/srv/a"));
        let (wanted, _) = load(cfg_dir.path(), &auth_on_with_store_dir("/srv/b"));
        let live = crate::config_reload::LiveConfig::new(running);
        live.set(wanted);

        assert!(
            live.pending_restart_fields().contains(&"control_plane"),
            "a store_dir change must be reported as restart-required"
        );
    }

    #[tokio::test]
    async fn export_reads_governance_log_from_store_dir() {
        let (cfg_dir, data) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
        let store_dir = data.path().join("cp");
        let yaml = format!(
            "{}  export:\n    enabled: true\n    sink_path: \"{sink}\"\nsecurity:\n  transparency_log:\n    path: \"{inv}\"\n",
            auth_on_with_store_dir(&store_dir.to_string_lossy()),
            sink = data.path().join("sink.ndjson").display(),
            inv = data.path().join("invocation.jsonl").display(),
        );
        let (config, path) = load(cfg_dir.path(), &yaml);
        // A corrupt cursor makes the governance exporter's open fail, which is
        // how a test sees which log path the exporter was handed.
        let corrupt = |base: &Path| {
            std::fs::create_dir_all(base).unwrap();
            std::fs::write(base.join("audit.export-cursor.json"), b"{corrupt").unwrap();
        };
        let spawn = || {
            let (tx, rx) = tokio::sync::broadcast::channel(1);
            let status = super::super::spawn_export_task(&config, Some(&path), rx);
            let _ = tx.send(());
            status.is_some()
        };

        corrupt(&cfg_dir.path().join("gateway-control-plane"));
        assert!(
            spawn(),
            "export must not read the default base when store_dir is set"
        );
        corrupt(&store_dir);
        assert!(
            !spawn(),
            "export must read the governance log under store_dir"
        );
    }
}

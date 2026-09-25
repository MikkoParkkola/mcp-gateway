// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Where the control-plane (governance) store lives, and opening it at startup.

use std::path::Path;
use std::sync::Arc;

use tracing::{info, warn};

use super::expand_home_path;
use crate::config::Config;
use crate::control_plane::ControlPlaneStore;
use crate::control_plane::role_mapping::{ControlPlaneBaseInfo, ControlPlaneBaseSource};
use crate::{Error, Result};

/// The control-plane base directory (governance store + audit log), and which
/// setting chose it.
///
/// `control_plane.store_dir` wins (`~`-expanded). Otherwise the base is
/// `<config dir>/<config stem>-control-plane`, so distinct gateway instances do
/// not share governance state, or `~/.mcp-gateway/control-plane` when no config
/// path is known. Resolved once at startup; the store, the SIEM export wiring
/// (MIK-6703) and the admin API (through `AppState`) all use that one value.
pub(super) fn control_plane_base(
    config: &Config,
    config_path: Option<&Path>,
) -> ControlPlaneBaseInfo {
    if let Some(dir) = &config.control_plane.store_dir {
        return ControlPlaneBaseInfo {
            path: expand_home_path(dir),
            source: ControlPlaneBaseSource::Explicit,
        };
    }
    let path = config_path.map_or_else(
        || expand_home_path("~/.mcp-gateway/control-plane"),
        |p| {
            let dir = p.parent().unwrap_or_else(|| Path::new("."));
            let stem = p.file_stem().and_then(|s| s.to_str()).unwrap_or("gateway");
            dir.join(format!("{stem}-control-plane"))
        },
    );
    ControlPlaneBaseInfo {
        path,
        source: ControlPlaneBaseSource::Default,
    }
}

/// Open the durable control-plane store (grants/policies plus a
/// governance-scoped audit log, separate from the invocation transparency log;
/// ADR-005, MIK-6685).
///
/// `Ok(None)` disables the governance mutation routes (they answer 503):
/// - auth is off, since an auth-disabled gateway treats every caller as an
///   anonymous admin and a durable mutation surface must not be open to it;
/// - the DEFAULT base cannot be opened. Installs whose config directory is
///   read-only kept starting before `store_dir` existed and still do; the
///   admin API reports `store_unavailable` with the path.
///
/// `Err` refuses start when `control_plane.store_dir` is relative, or is set
/// and cannot be written: the operator asked for governance, and serving
/// without it would hide that the request was not met.
///
/// Governance audit entries reuse the transparency log's signing identity, so
/// they are signed iff the invocation log is.
pub(super) fn build_control_plane_store(
    config: &Config,
    base_info: &ControlPlaneBaseInfo,
) -> Result<Option<Arc<dyn ControlPlaneStore>>> {
    let (base, source) = (&base_info.path, base_info.source);
    let path = base.display();
    if source == ControlPlaneBaseSource::Explicit && !base.is_absolute() {
        return Err(Error::Config(format!(
            "control_plane.store_dir '{path}' must be an absolute path"
        )));
    }
    if !config.auth.enabled {
        info!(
            %path, ?source,
            "control-plane governance mutations disabled: auth is off (would expose an anonymous-admin mutation surface)"
        );
        return Ok(None);
    }
    // An explicit directory is proven writable, not inferred from the audit
    // log's open as a side effect.
    let opened = match source {
        ControlPlaneBaseSource::Explicit => probe_writable(base)
            .map_err(|e| e.to_string())
            .and_then(|()| open_store(config, base)),
        ControlPlaneBaseSource::Default => open_store(config, base),
    };
    match (opened, source) {
        (Ok(store), _) => {
            info!(%path, ?source, "control-plane store opened");
            Ok(Some(store))
        }
        (Err(error), ControlPlaneBaseSource::Explicit) => Err(Error::Config(format!(
            "control_plane.store_dir '{path}' could not be opened: {error}"
        ))),
        (Err(error), ControlPlaneBaseSource::Default) => {
            warn!(
                %path, ?source, %error,
                "control-plane store unavailable; governance mutations disabled. Set control_plane.store_dir to a writable directory"
            );
            Ok(None)
        }
    }
}

/// Create, write, fsync and remove a marker file in `dir`.
///
/// Whatever already sits at the marker's name is unlinked first (unlink never
/// follows a symlink), and the marker is opened `create_new`, so a planted
/// symlink cannot turn the probe into a write elsewhere. The marker is removed
/// on every path, and any failure is returned.
fn probe_writable(dir: &Path) -> std::io::Result<()> {
    use std::io::Write;

    std::fs::create_dir_all(dir)?;
    let marker = dir.join(".write-probe");
    let _ = std::fs::remove_file(&marker);
    let written = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&marker)
        .and_then(|mut file| {
            file.write_all(b"probe")?;
            file.sync_all()
        });
    let removed = std::fs::remove_file(&marker);
    written.and(removed)
}

fn open_store(
    config: &Config,
    base: &Path,
) -> std::result::Result<Arc<dyn ControlPlaneStore>, String> {
    use crate::control_plane::FileControlPlaneStore;
    use crate::security::TransparencyLogger;
    use crate::security::transparency_log::TransparencyLogConfig;

    let audit_cfg = Arc::new(TransparencyLogConfig {
        enabled: true,
        path: base.join("audit.jsonl").to_string_lossy().into_owned(),
        key_id: config.security.transparency_log.key_id.clone(),
        shared_secret: config.security.transparency_log.shared_secret.clone(),
    });
    let audit = TransparencyLogger::open(audit_cfg).map_err(|e| format!("audit log: {e}"))?;
    let store = FileControlPlaneStore::open(base.join("store"), Arc::new(audit))
        .map_err(|e| format!("store: {e}"))?;
    Ok(Arc::new(store))
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
        super::build_control_plane_store(
            config,
            &super::control_plane_base(config, Some(config_path)),
        )
        .map(|store| store.is_some())
        .map_err(|e| e.to_string())
    }

    fn base(config: &Config, config_path: &Path) -> PathBuf {
        super::control_plane_base(config, Some(config_path)).path
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

    /// A `.write-probe` symlink planted in the store dir must not become a
    /// write through the gateway's privileges. Chosen outcome: the probe
    /// unlinks the link and succeeds, and the link's target keeps its bytes.
    #[cfg(unix)]
    #[test]
    fn write_probe_does_not_follow_a_planted_symlink() {
        let (cfg_dir, data, outside) = (
            tempfile::tempdir().unwrap(),
            tempfile::tempdir().unwrap(),
            tempfile::tempdir().unwrap(),
        );
        let store_dir = data.path().join("cp");
        std::fs::create_dir_all(&store_dir).unwrap();
        let target = outside.path().join("victim");
        std::fs::write(&target, b"known bytes").unwrap();
        std::os::unix::fs::symlink(&target, store_dir.join(".write-probe")).unwrap();
        let (config, path) = load(
            cfg_dir.path(),
            &auth_on_with_store_dir(&store_dir.to_string_lossy()),
        );

        assert_eq!(start(&config, &path), Ok(true));
        assert_eq!(std::fs::read(&target).unwrap(), b"known bytes");
        assert!(
            std::fs::symlink_metadata(store_dir.join(".write-probe")).is_err(),
            "the probe must leave no marker behind"
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
            let base = super::control_plane_base(&config, Some(&path));
            let status = super::super::spawn_export_task(&config, &base, rx);
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

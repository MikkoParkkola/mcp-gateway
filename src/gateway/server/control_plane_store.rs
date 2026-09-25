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

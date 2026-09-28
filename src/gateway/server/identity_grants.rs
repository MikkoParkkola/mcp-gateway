// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Identity-grant startup helpers, moved out of `mod.rs` unchanged; that file
//! is over the 800-line ceiling.

use std::path::PathBuf;
use std::sync::Arc;

use tracing::warn;

use super::expand_home_path;
use crate::{Error, Result};

/// The grant sink a reload publishes into, or `None` when grants are off.
///
/// Rebuilt from config at the `ReloadContext` sites rather than threaded out
/// of `build_meta_mcp`: the path is `config.security.identity_grants.path`
/// either way, and `expand_home_path` is the same resolution startup used.
pub(super) fn identity_grant_sink_for(
    config: &crate::config::IdentityGrantsConfig,
    meta_mcp: &crate::gateway::meta_mcp::MetaMcp,
) -> Option<Arc<crate::config_reload::IdentityGrantSink>> {
    if !config.enabled {
        return None;
    }
    let (store, epoch) = meta_mcp.identity_grant_sink();
    Some(Arc::new(crate::config_reload::IdentityGrantSink::new(
        store,
        epoch,
        expand_home_path(&config.path),
    )))
}

pub(super) async fn load_configured_identity_grants(
    config: &crate::config::IdentityGrantsConfig,
) -> Result<Option<(PathBuf, crate::identity_grants::LocalIdentityGrantStore)>> {
    if !config.enabled {
        return Ok(None);
    }

    let path = expand_home_path(&config.path);
    match crate::identity_grants::load_identity_grants_file(&path).await {
        Ok(grants) => Ok(Some((path, grants))),
        Err(e) if config.fail_on_error => Err(Error::Config(e)),
        Err(e) => {
            warn!(
                error = %e,
                path = %path.display(),
                "Failed to load local identity grants; personal capabilities without matching grants will fail closed"
            );
            Ok(None)
        }
    }
}

/// Startup grant audit (design section 6 steps 3-6): build the grant sink,
/// attach an auditor when a governance store is open, reconcile the grant
/// file and journal under the journal lock, publish what was read, and write
/// the startup snapshot. Runs before any listener binds or stdio line is read.
///
/// # Errors
///
/// None yet: every audit failure serves an empty grant set instead.
#[allow(dead_code, clippy::unused_async, reason = "red-first stub")]
pub(super) async fn start_identity_grant_audit(
    config: &crate::config::Config,
    meta_mcp: &crate::gateway::meta_mcp::MetaMcp,
    store: Option<&Arc<dyn crate::control_plane::ControlPlaneStore>>,
    store_dir: &std::path::Path,
) -> Result<Option<Arc<crate::config_reload::IdentityGrantSink>>> {
    let _ = (store, store_dir);
    Ok(identity_grant_sink_for(
        &config.security.identity_grants,
        meta_mcp,
    ))
}

/// The stdio half: stdio opens no governance store for anything else, so it
/// opens one here when grants are on, then runs the same startup audit.
///
/// # Errors
///
/// The store refusal of [`super::build_control_plane_store`].
#[allow(dead_code, reason = "red-first stub")]
pub(super) async fn stdio_identity_grants(
    config: &crate::config::Config,
    config_path: Option<&std::path::Path>,
    meta_mcp: &crate::gateway::meta_mcp::MetaMcp,
) -> Result<Option<Arc<crate::config_reload::IdentityGrantSink>>> {
    let base = super::control_plane_base(config, config_path);
    start_identity_grant_audit(config, meta_mcp, None, &base.path).await
}

#[cfg(test)]
#[path = "identity_grants_tests.rs"]
mod tests;

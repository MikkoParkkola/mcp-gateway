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

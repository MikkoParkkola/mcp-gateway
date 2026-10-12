// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Which capability directories the local commands (`tool list`, `inspect`,
//! `invoke`, `completions`, `skills generate`) read: the ones the gateway
//! serves, unless `-C` or `MCP_GATEWAY_CAPABILITIES` names one (MIK-8044).
//!
//! The list is the loaded config's `capabilities.directories`, the field the
//! gateway reads (`gateway::server::run_steps`), so the two cannot drift.

use std::path::{Path, PathBuf};

use mcp_gateway::cli::invoke::ToolCatalogue;
use mcp_gateway::config::Config;

/// Where the capabilities come from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum CapabilityDirs {
    /// `-C` or `MCP_GATEWAY_CAPABILITIES`: one directory, read as before.
    Override(PathBuf),
    /// The loaded config's `capabilities.directories`.
    Configured(Vec<String>),
}

/// The message when the configured directories hold no capability.
pub(crate) const NONE_FOUND: &str = "No capability files found in the configured directories";

/// Resolve the directories for `flag` (clap fills it from `-C` or the env
/// var) and the global `--config`. The config file is picked as the loader
/// picks it (the named one, else `Config::fallback_config_path`), so the
/// message names the file the loader read. A named file that is missing is
/// reported by its path; any other config that will not load (unreadable
/// included, or a bad environment overlay with no file) gets a pointer to
/// `doctor` instead of the load error, whose text can quote a value.
pub(crate) fn resolve(
    flag: Option<PathBuf>,
    config: Option<&Path>,
) -> Result<CapabilityDirs, String> {
    if let Some(dir) = flag {
        return Ok(CapabilityDirs::Override(dir));
    }
    let picked = match config {
        Some(named) if !named.exists() => {
            return Err(format!("Config file not found: {}", named.display()));
        }
        Some(named) => Some(named.to_path_buf()),
        None => Config::fallback_config_path(),
    };
    if let Ok(cfg) = Config::load(picked.as_deref()) {
        return Ok(CapabilityDirs::Configured(cfg.capabilities.directories));
    }
    // The load error itself is never printed: its text can quote a value.
    Err(match picked {
        Some(path) => format!(
            "could not load {}; run `{}` to see why",
            path.display(),
            super::check_config_command(&path)
        ),
        // No file: the environment overlay is what failed.
        None => "could not load the configuration from the environment; run \
                 `mcp-gateway doctor` to see why"
            .to_owned(),
    })
}

/// Load the capabilities `dirs` names. An override directory that does not
/// exist is an error, as before; configured directories load as the gateway
/// loads them (`ToolCatalogue::load`: missing ones skipped with a warning,
/// a later definition of a name replacing an earlier one).
pub(crate) async fn load(dirs: &CapabilityDirs) -> Result<ToolCatalogue, String> {
    let list: Vec<String> = match dirs {
        CapabilityDirs::Override(dir) => {
            let shown = dir.to_string_lossy().into_owned();
            if !dir.is_dir() {
                return Err(format!(
                    "Failed to load capabilities from '{shown}': no such directory"
                ));
            }
            vec![shown]
        }
        CapabilityDirs::Configured(list) => list.clone(),
    };
    let refs: Vec<&str> = list.iter().map(String::as_str).collect();
    ToolCatalogue::load(&refs).await.map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::{CapabilityDirs, resolve};

    /// E14 (lead): with no override, the commands resolve exactly the list
    /// the gateway serves for the same config and environment.
    #[test]
    fn the_commands_resolve_the_gateways_directory_list() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("gateway.yaml");
        mcp_gateway::gateway::test_helpers::write_owner_only(
            &path,
            "capabilities:\n  directories: [\"rel_caps\", \"/abs/caps\"]\n",
        )
        .expect("config");
        let gateway = mcp_gateway::config::Config::load(Some(&path))
            .expect("loads")
            .capabilities
            .directories;
        assert_eq!(
            resolve(None, Some(&path)),
            Ok(CapabilityDirs::Configured(gateway))
        );
    }
}

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
/// var) and the global `--config`. A config that is missing or unreadable is
/// reported as the loader words it, since that names only the path; any other
/// load error is replaced by a pointer to `doctor`, because its text can
/// quote a value from the file.
pub(crate) fn resolve(
    flag: Option<PathBuf>,
    config: Option<&Path>,
) -> Result<CapabilityDirs, String> {
    if let Some(dir) = flag {
        return Ok(CapabilityDirs::Override(dir));
    }
    match Config::load(config) {
        Ok(cfg) => Ok(CapabilityDirs::Configured(
            cfg.capabilities.directories.clone(),
        )),
        Err(e) => {
            let text = e.to_string();
            // Errors raised before the file is read (Config::prepare) quote
            // no file content.
            if text.contains("Config file not found") || text.contains("Cannot read config file") {
                return Err(text);
            }
            let path = config
                .map(Path::to_path_buf)
                .or_else(|| super::doctor::resolve_config_path(None))
                .unwrap_or_else(|| PathBuf::from("gateway.yaml"));
            Err(format!(
                "could not load {}; run `{}` to see why",
                path.display(),
                super::check_config_command(&path)
            ))
        }
    }
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

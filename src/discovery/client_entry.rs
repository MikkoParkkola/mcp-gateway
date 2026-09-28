// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! One MCP server entry from a client config file, in the `mcpServers` shape
//! Claude, Cursor, Windsurf, Codex and Zed share: `command`/`args`/`env`/`cwd`
//! for stdio, `url`/`headers` for HTTP.
//!
//! Everything the entry carries survives (#1876): each argument keeps its
//! boundaries through [`crate::transport::join_command`], and `env` and
//! `headers` travel as [`super::SecretMap`]s, whose values reach only the
//! written backend.

use std::path::{Path, PathBuf};

use serde_json::Value;
use tracing::warn;

use super::{DiscoveredServer, DiscoverySource, SecretMap, ServerMetadata};
use crate::config::TransportConfig;

/// The string-valued members of `config[key]`; a non-string value is skipped
/// with a warning that names the key, never the value.
fn string_map(name: &str, config: &Value, key: &str) -> SecretMap {
    let Some(object) = config.get(key).and_then(Value::as_object) else {
        return SecretMap::default();
    };
    object
        .iter()
        .filter_map(|(k, v)| {
            let value = v.as_str();
            if value.is_none() {
                warn!("server {name}: {key}.{k} is not a string; skipped");
            }
            value.map(|value| (k.clone(), value.to_string()))
        })
        .collect()
}

/// Parse one entry, or `None` for a shape that is neither stdio nor HTTP.
pub(super) fn parse(
    name: &str,
    config: &Value,
    source: &DiscoverySource,
    config_path: &Path,
) -> Option<DiscoveredServer> {
    let description = format!("MCP server from {source:?}");
    if let Some(program) = config.get("command").and_then(Value::as_str) {
        let mut argv = vec![program.to_string()];
        argv.extend(
            config
                .get("args")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .filter_map(|v| v.as_str().map(String::from)),
        );
        let Some(command) = crate::transport::join_command(&argv) else {
            warn!("server {name}: an argument cannot be quoted for the command line; skipped");
            return None;
        };
        let working_dir = config.get("cwd").and_then(Value::as_str).map(PathBuf::from);
        let mut server = DiscoveredServer::new(
            name.to_string(),
            description,
            source.clone(),
            TransportConfig::Stdio {
                command: command.clone(),
                cwd: working_dir
                    .as_ref()
                    .map(|p| p.to_string_lossy().into_owned()),
                protocol_version: None,
            },
            ServerMetadata {
                config_path: Some(config_path.to_path_buf()),
                pid: None,
                port: None,
                command: Some(command),
                working_dir,
            },
        );
        server.env = string_map(name, config, "env");
        return Some(server);
    }

    if let Some(url) = config.get("url").and_then(Value::as_str) {
        let mut server = DiscoveredServer::new(
            name.to_string(),
            description,
            source.clone(),
            TransportConfig::for_url(url),
            ServerMetadata {
                config_path: Some(config_path.to_path_buf()),
                pid: None,
                port: url::Url::parse(url).ok().and_then(|u| u.port()),
                command: None,
                working_dir: None,
            },
        );
        server.headers = string_map(name, config, "headers");
        return Some(server);
    }

    warn!("Unsupported server config format for {name}");
    None
}

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
use std::sync::LazyLock;

use regex::Regex;

use serde_json::Value;
use tracing::warn;

use super::{DiscoveredServer, DiscoverySource, SecretMap, ServerMetadata};
use crate::config::TransportConfig;

/// The string-valued members of `config[key]` in gateway syntax. A non-string
/// value, or one only the client can resolve, is skipped with a warning that
/// names the client, server and key, never the value.
fn string_map(source: &DiscoverySource, name: &str, config: &Value, key: &str) -> SecretMap {
    let Some(object) = config.get(key).and_then(Value::as_object) else {
        return SecretMap::default();
    };
    object
        .iter()
        .filter_map(|(k, v)| {
            let Some(value) = v.as_str() else {
                warn!("{source:?} server {name}: {key}.{k} is not a string; skipped");
                return None;
            };
            let Some(value) = gateway_value(value) else {
                warn!(
                    "{source:?} server {name}: {key}.{k} uses a variable the gateway cannot resolve; skipped"
                );
                return None;
            };
            Some((k.clone(), value))
        })
        .collect()
}

/// A client `env`/header value in gateway syntax: `${env:NAME}` becomes
/// `${NAME}`; `None` when a client-only variable (`${input:…}`,
/// `${workspaceFolder}`, …) is left that a gateway load would refuse.
pub(super) fn gateway_value(value: &str) -> Option<String> {
    static CLIENT_ENV: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"\$\{env:([^}]*)\}").expect("constant pattern"));
    let value = CLIENT_ENV.replace_all(value, |c: &regex::Captures<'_>| format!("${{{}}}", &c[1]));
    crate::config::is_template_syntax(&value).then(|| value.into_owned())
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
        server.env = string_map(source, name, config, "env");
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
        server.headers = string_map(source, name, config, "headers");
        if let Some(headers) = config.get("headers").and_then(Value::as_object) {
            // A string the gateway cannot resolve; a non-string sends nothing.
            server.unresolved_header_names = headers
                .iter()
                .filter(|(_, value)| value.as_str().is_some_and(|v| gateway_value(v).is_none()))
                .map(|(key, _)| key.clone())
                .collect();
        }
        return Some(server);
    }

    warn!("Unsupported server config format for {name}");
    None
}

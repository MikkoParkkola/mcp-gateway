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
use crate::cli_support::shown;
use crate::config::TransportConfig;

/// The string-valued members of `config[key]` in gateway syntax. A non-string
/// value, or one only the client can resolve, is skipped with a warning that
/// names the client, server and key (escaped for a terminal), never the
/// value, and its field name (`env.K`) goes to `uncarried`.
fn string_map(
    source: &DiscoverySource,
    name: &str,
    config: &Value,
    key: &str,
    uncarried: &mut Vec<String>,
) -> SecretMap {
    let Some(object) = config.get(key).and_then(Value::as_object) else {
        return SecretMap::default();
    };
    object
        .iter()
        .filter_map(|(k, v)| {
            let Some(value) = v.as_str() else {
                warn!(
                    "{source:?} server {}: {key}.{} is not a string; skipped",
                    shown(name),
                    shown(k)
                );
                uncarried.push(format!("{key}.{k}"));
                return None;
            };
            let Some(value) = gateway_value(value) else {
                warn!(
                    "{source:?} server {}: {key}.{} uses a variable the gateway cannot resolve; skipped",
                    shown(name),
                    shown(k)
                );
                uncarried.push(format!("{key}.{k}"));
                return None;
            };
            Some((k.clone(), value))
        })
        .collect()
}

/// The gateway expands `${...}` only in a backend's `env` and `headers`: in a
/// command, an argument, a `cwd` or a URL it stays as written, where the
/// client would have expanded it.
fn client_expands(text: &str) -> bool {
    text.contains("${")
}

/// Entry keys that describe the entry to its client and change nothing about
/// how the server runs or what it may reach, so leaving them behind loses
/// nothing. Any other key a branch does not carry (a client's sandbox,
/// `envFile`, `oauth`, extension `settings`, ...) is recorded as uncarried:
/// a key not listed here makes the find not adoptable.
const DESCRIPTIVE_KEYS: &[&str] = &[
    "type",
    "name",
    "description",
    "title",
    "autoApprove",
    "alwaysAllow",
    "source",
];

/// Whether a carried key's value has the shape the parser reads.
type ShapeCheck = fn(&Value) -> bool;

/// Records every key of `config` neither in `carried` nor descriptive, and
/// every carried key whose value fails its shape check.
fn record_dropped_keys(
    config: &Value,
    carried: &[(&str, ShapeCheck)],
    uncarried: &mut Vec<String>,
) {
    let Some(object) = config.as_object() else {
        return;
    };
    for (key, value) in object {
        // An entry the client keeps switched off would be adopted switched
        // on: only an explicit "on" leaves nothing behind.
        let active = match key.as_str() {
            "disabled" => Some(value == &Value::Bool(false)),
            "enabled" => Some(value == &Value::Bool(true)),
            _ => None,
        };
        if let Some(active) = active {
            if !active {
                uncarried.push(key.clone());
            }
            continue;
        }
        match carried.iter().find(|(name, _)| *name == key.as_str()) {
            // `null` for an optional field is the field left out.
            Some((_, shape_ok)) if !value.is_null() && !shape_ok(value) => {
                uncarried.push(key.clone());
            }
            Some(_) => {}
            None if DESCRIPTIVE_KEYS.contains(&key.as_str()) => {}
            None => uncarried.push(key.clone()),
        }
    }
}

/// The URL schemes a gateway backend connects to; a client's `unix://` or
/// `pipe://` endpoint is not one.
fn gateway_scheme(url: &str) -> bool {
    url::Url::parse(url).is_ok_and(|u| matches!(u.scheme(), "http" | "https" | "ws" | "wss"))
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

/// The program and its string arguments, recording each argument the
/// gateway would not run as the client does: a `${` it would not expand, or
/// a non-string one, which is skipped as before.
fn client_argv(program: &str, config: &Value, uncarried: &mut Vec<String>) -> Vec<String> {
    let mut argv = vec![program.to_string()];
    for (i, arg) in config
        .get("args")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .enumerate()
    {
        match arg.as_str() {
            Some(arg) => {
                if client_expands(arg) {
                    uncarried.push(format!("args[{i}]"));
                }
                argv.push(arg.to_string());
            }
            None => uncarried.push(format!("args[{i}]")),
        }
    }
    argv
}

/// Parse one entry, or `None` for a shape that is neither stdio nor HTTP.
pub(super) fn parse(
    name: &str,
    config: &Value,
    source: &DiscoverySource,
    config_path: &Path,
) -> Option<DiscoveredServer> {
    let description = format!("MCP server from {source:?}");
    let entry_digest = crate::hashing::canonical_json_sha256(&serde_json::json!([
        config_path.to_string_lossy(),
        name,
        config
    ]));
    if let Some(program) = config.get("command").and_then(Value::as_str) {
        let mut uncarried = Vec::new();
        if client_expands(program) {
            uncarried.push("command".to_string());
        }
        let argv = client_argv(program, config, &mut uncarried);
        let Some(command) = crate::transport::join_command(&argv) else {
            warn!(
                "server {}: an argument cannot be quoted for the command line; skipped",
                shown(name)
            );
            return None;
        };
        let working_dir = config.get("cwd").and_then(Value::as_str).map(PathBuf::from);
        // A relative one names a directory under the client's, not the
        // gateway's, working directory.
        if working_dir
            .as_ref()
            .is_some_and(|dir| client_expands(&dir.to_string_lossy()) || dir.is_relative())
        {
            uncarried.push("cwd".to_string());
        }
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
        server.env = string_map(source, name, config, "env", &mut uncarried);
        record_dropped_keys(
            config,
            &[
                ("command", Value::is_string),
                ("args", Value::is_array),
                ("env", Value::is_object),
                ("cwd", Value::is_string),
            ],
            &mut uncarried,
        );
        server.uncarried = uncarried;
        server.entry_digest = entry_digest;
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
        if client_expands(url) || !gateway_scheme(url) {
            server.uncarried.push("url".to_string());
        }
        server.headers = string_map(source, name, config, "headers", &mut server.uncarried);
        if let Some(headers) = config.get("headers").and_then(Value::as_object) {
            // A string the gateway cannot resolve; a non-string sends nothing.
            server.unresolved_header_names = headers
                .iter()
                .filter(|(_, value)| value.as_str().is_some_and(|v| gateway_value(v).is_none()))
                .map(|(key, _)| key.clone())
                .collect();
        }
        record_dropped_keys(
            config,
            &[("url", Value::is_string), ("headers", Value::is_object)],
            &mut server.uncarried,
        );
        server.entry_digest = entry_digest;
        return Some(server);
    }

    warn!("Unsupported server config format for {}", shown(name));
    None
}

#[cfg(test)]
#[path = "client_entry_tests.rs"]
mod tests;

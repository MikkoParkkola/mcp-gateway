// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The env-overlay provider: `MCP_GATEWAY_*` overrides read from the overlay, and the settings around it.

use figment::{
    Metadata, Profile, Provider,
    value::{Dict, Map, Tag, Value},
};
use serde::Deserialize;

use super::{EnvOverlay, backend_transport};

#[derive(Default, Deserialize)]
#[serde(default)]
pub(super) struct EnvFileConfig {
    pub(super) env_files: Vec<String>,
}

/// How a malformed env file is treated during evaluation.
///
/// An enum rather than a bool so the call site says which behaviour it wants
/// without the reader opening the signature.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Tolerance {
    /// Warn and carry on — what [`Config::load`] has always done.
    Warn,
    /// Refuse the load, for callers that can decline to start.
    Fail,
}

/// Figment provider reading `MCP_GATEWAY_*` from the overlay, then the process
/// environment.
///
/// Replaces `Env::prefixed(..)`, which reads the process environment only and
/// would therefore ignore every assignment made by an env file that is no
/// longer exported into the process.
pub(super) struct OverlayEnv<'a> {
    overlay: &'a EnvOverlay,
}

/// The `MCP_GATEWAY_*` names a CLI flag owns (clap `env = ...`). They are not
/// config overrides: `MCP_GATEWAY_CAPABILITIES` names a directory for the tool
/// subcommands, and read as the `capabilities` key it failed every config load.
/// A test walks `Cli::command()` and requires this list to equal
/// its env names, so a new flag's variable cannot reach the overlay unlisted.
pub(crate) const CLI_OWNED_ENV: &[&str] = &[
    "MCP_GATEWAY_CA_CERT",
    "MCP_GATEWAY_CAPABILITIES",
    "MCP_GATEWAY_CLIENT_CERT",
    "MCP_GATEWAY_CLIENT_KEY",
    "MCP_GATEWAY_CONFIG",
    "MCP_GATEWAY_CONFIG_DIR",
    "MCP_GATEWAY_DOCTOR_NO_REGISTRY_CHECK",
    "MCP_GATEWAY_HOST",
    "MCP_GATEWAY_LOG_FORMAT",
    "MCP_GATEWAY_LOG_LEVEL",
    "MCP_GATEWAY_PORT",
    "MCP_GATEWAY_PROTOCOL_REVISION_WINDOW",
    "MCP_GATEWAY_SKILLS_REGISTRY",
];

impl<'a> OverlayEnv<'a> {
    pub(super) const PREFIX: &'static str = "MCP_GATEWAY_";

    pub(super) fn new(overlay: &'a EnvOverlay) -> Self {
        Self { overlay }
    }

    /// The variables the provider sees: `base` overlaid with the env files.
    ///
    /// `base` is the process environment as `OsString` pairs, converted the way
    /// `Env` converts them. Reading it through `std::env::vars` instead would
    /// panic the process on a single non-UTF-8 variable belonging to someone
    /// else, which is a startup failure `Env` never had.
    pub(super) fn merged_vars<I>(&self, base: I) -> std::collections::BTreeMap<String, String>
    where
        I: Iterator<Item = (std::ffi::OsString, std::ffi::OsString)>,
    {
        let mut merged: std::collections::BTreeMap<String, String> = base
            .filter(|(key, _)| !key.is_empty())
            .map(|(key, value)| {
                (
                    key.to_string_lossy().into_owned(),
                    value.to_string_lossy().into_owned(),
                )
            })
            .collect();
        // Process environment first so an env-file assignment wins, which is
        // the precedence `EnvOverlay::resolve` states.
        merged.extend(self.overlay.effective_vars());
        merged
    }

    /// Places `value` at the path `parts` names, creating dictionaries on the
    /// way down — the nesting `__` in a key stands for.
    fn insert_nested(dict: &mut Dict, parts: &[String], value: String) {
        match parts {
            [] => {}
            [leaf] => {
                // Parsed, not stored as a string: `Env` reads `9090` as a
                // number and `[a, b]` as a list, and `Figment::extract` does
                // not coerce a string into either. Inserting the raw string
                // would fail every non-string field an operator can override.
                // invariant: figment's `Value` parses from any string (`Err = Infallible`).
                dict.insert(leaf.clone(), value.parse().expect("infallible"));
            }
            [head, tail @ ..] => {
                let entry = dict
                    .entry(head.clone())
                    .or_insert_with(|| Value::Dict(Tag::Default, Dict::new()));
                let mut inner = match entry {
                    Value::Dict(_, existing) => std::mem::take(existing),
                    _ => Dict::new(),
                };
                Self::insert_nested(&mut inner, tail, value);
                *entry = Value::Dict(Tag::Default, inner);
            }
        }
    }
}

impl OverlayEnv<'_> {
    /// The `MCP_GATEWAY_*` overrides applied from `base` and the env files:
    /// (name, nested path, value). The one filter both the provider and the
    /// revision capture read, so they cannot disagree on what was applied.
    pub(super) fn overrides<I>(&self, base: I) -> Vec<(String, Vec<String>, String)>
    where
        I: Iterator<Item = (std::ffi::OsString, std::ffi::OsString)>,
    {
        self.merged_vars(base)
            .into_iter()
            .filter_map(|(key, value)| {
                // Whole names only: `MCP_GATEWAY_CAPABILITIES__NAME` is still a
                // nested override of `capabilities.name`.
                if CLI_OWNED_ENV.contains(&key.as_str()) {
                    return None;
                }
                let rest = key.strip_prefix(Self::PREFIX)?;
                let parts: Vec<String> = rest.split("__").map(str::to_lowercase).collect();
                if parts.iter().any(String::is_empty) {
                    return None;
                }
                Some((key, parts, value))
            })
            .collect()
    }
}

impl Provider for OverlayEnv<'_> {
    fn metadata(&self) -> Metadata {
        Metadata::named("environment variable(s)")
    }

    fn data(&self) -> figment::Result<Map<Profile, Dict>> {
        let mut dict = Dict::new();
        for (_, parts, value) in self.overrides(std::env::vars_os()) {
            Self::insert_nested(&mut dict, &parts, value);
        }
        backend_transport::refuse_backend_url(&dict).map_err(figment::Error::from)?;
        Ok(Profile::Default.collect(dict))
    }
}

/// Whether a load substitutes the environment into the config it returns.
///
/// A config destined for a rewrite must stay [`Expansion::Literal`]: the write
/// path serialises the whole struct, so a substituted secret becomes a
/// plaintext secret on disk.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Expansion {
    /// Resolve `env:` references and expand `${VAR}` patterns.
    Resolve,
    /// Leave every reference exactly as the file spells it.
    Literal,
}

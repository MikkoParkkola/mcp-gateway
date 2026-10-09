// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Typed provider configuration for `service: cli` and `service: mcp` (MIK-7782).
//!
//! Both are parsed at load from the provider's `config` mapping with
//! `deny_unknown_fields`: a misspelled key is a load error, never a silently
//! ignored one. Every value here comes from the pinned capability file; caller
//! parameters only ever fill `{placeholder}` slots at call time.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// The typed configuration of a provider that runs a local process.
///
/// Built only by [`ProcessConfig::from_provider`], which knows the `service`;
/// serialized untagged so it round-trips under the provider's `config` key.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(untagged)]
pub enum ProcessConfig {
    /// `service: cli`
    Cli(Box<CliConfig>),
    /// `service: mcp`
    Mcp(Box<McpConfig>),
}

impl ProcessConfig {
    /// Parse `config` for a process-running `service`. `Ok(None)` for every
    /// other service, which keeps its existing (REST-shaped) parsing.
    ///
    /// # Errors
    ///
    /// The serde error, when `service` is `cli` or `mcp` and `config` does not
    /// match the typed schema (unknown key, wrong type, missing `command`).
    pub fn from_provider(
        service: &str,
        config: Option<Value>,
    ) -> Result<Option<Self>, serde_json::Error> {
        let config = config.unwrap_or_else(|| Value::Object(serde_json::Map::new()));
        match service {
            "cli" => Ok(Some(Self::Cli(Box::new(serde_json::from_value(config)?)))),
            "mcp" => Ok(Some(Self::Mcp(Box::new(serde_json::from_value(config)?)))),
            _ => Ok(None),
        }
    }

    /// The command the provider runs, exactly as the file spells it.
    #[must_use]
    pub fn command(&self) -> &str {
        match self {
            Self::Cli(c) => &c.command,
            Self::Mcp(m) => &m.command,
        }
    }

    /// The leading arguments that are fixed by the file (no placeholder), in
    /// order, up to the first element a caller parameter can influence. The
    /// invocation allowlist compares against this prefix.
    #[must_use]
    pub fn static_args_prefix(&self) -> Vec<&str> {
        match self {
            Self::Cli(c) => c
                .args
                .iter()
                .map_while(|arg| match arg {
                    CliArg::Literal(s) if !s.contains('{') => Some(s.as_str()),
                    _ => None,
                })
                .collect(),
            Self::Mcp(m) => m.args.iter().map(String::as_str).collect(),
        }
    }
}

/// `service: cli` configuration.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CliConfig {
    /// A bare program name looked up on PATH, or an absolute path. Never
    /// templated.
    pub command: String,
    /// One item is exactly one argv element; nothing is ever re-split.
    #[serde(default)]
    pub args: Vec<CliArg>,
    /// Template written to the child's stdin, then closed. The route for free
    /// text into tools that would read `@file` or a subcommand from argv.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stdin: Option<String>,
    /// Names of gateway environment variables copied into the child.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub env: Vec<String>,
    /// Variable that receives the credential resolved for `auth.key`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    // ci-allow-secret-debug: holds a variable NAME; the token itself is never stored here
    pub token_env: Option<String>,
    /// How stdout becomes the result.
    #[serde(default)]
    pub output: CliOutput,
    /// Cap for stdout and for stderr, each.
    #[serde(
        default = "default_max_output_bytes",
        skip_serializing_if = "is_default_max_output_bytes"
    )]
    pub max_output_bytes: usize,
}

/// Default cap on each output stream (1 MiB).
pub const DEFAULT_MAX_OUTPUT_BYTES: usize = 1024 * 1024;
/// Hard ceiling for `max_output_bytes` (8 MiB).
pub const MAX_OUTPUT_BYTES_CEILING: usize = 8 * 1024 * 1024;

fn default_max_output_bytes() -> usize {
    DEFAULT_MAX_OUTPUT_BYTES
}

#[allow(clippy::trivially_copy_pass_by_ref)] // serde's skip_serializing_if passes a reference
fn is_default_max_output_bytes(value: &usize) -> bool {
    *value == DEFAULT_MAX_OUTPUT_BYTES
}

/// How a CLI capability's stdout is returned.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CliOutput {
    /// stdout must parse as JSON; that value is the result.
    #[default]
    Json,
    /// stdout is returned as `{"text": ...}`.
    Text,
}

/// One `args` item.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum CliArg {
    /// A plain string, possibly holding one `{placeholder}`.
    Literal(String),
    /// One bound `--x={item}` element per item of an array parameter.
    Each(EachArg),
    /// An element emitted only when its parameter was supplied.
    Conditional(ConditionalArg),
    /// A JSON document serialized from a typed template, after a fixed prefix.
    Json(JsonArg),
}

/// `{ each: <array param>, arg: "--x={item}" }`
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EachArg {
    /// The array-of-strings input property.
    pub each: String,
    /// The element template; `{item}` is the only placeholder.
    pub arg: String,
}

/// `{ arg: "--cc={cc}", if: cc }`
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConditionalArg {
    /// The element template.
    pub arg: String,
    /// The input property whose presence emits the element.
    #[serde(rename = "if")]
    pub when: String,
}

/// `{ json: "--params=", value: { ... } }`
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JsonArg {
    /// Literal prefix of the element, for example `--params=`.
    pub json: String,
    /// Template whose leaves that are exactly `"{p}"` take p's typed value.
    pub value: Value,
}

/// `service: mcp` configuration (stdio only: a remote MCP server is a
/// configured backend already).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct McpConfig {
    /// Server program; static, never templated.
    pub command: String,
    /// Static server arguments; no placeholders.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub args: Vec<String>,
    /// Names of gateway environment variables copied into the server.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub env: Vec<String>,
    /// Accepted for older files; `stdio` is the only transport.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transport: Option<McpTransport>,
    /// Single-tool capability: the tool to call.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool: Option<String>,
    /// Single-tool capability: its argument template.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub arguments: Option<Value>,
    /// Several tools, selected by one input property.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool_selector: Option<ToolSelector>,
    /// Server environment variables set to a `capabilities.files` root, for a
    /// server that scopes its file access to one root: it then opens what a
    /// `path_root` parameter was confined to (MIK-7823). An unset root, or a
    /// name the gateway sets itself, sets nothing.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub root_env: BTreeMap<String, RootName>,
}

/// A `capabilities.files` root a definition may name.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RootName {
    /// `capabilities.files.uploads`
    Uploads,
    /// `capabilities.files.projects`
    Projects,
    /// `capabilities.files.downloads`
    Downloads,
}

impl RootName {
    /// The key under `capabilities.files`.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Uploads => "uploads",
            Self::Projects => "projects",
            Self::Downloads => "downloads",
        }
    }
}

/// The only MCP capability transport.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum McpTransport {
    /// A child process speaking MCP over stdin/stdout.
    Stdio,
}

/// Picks the tool from an input property; unknown values fail closed.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolSelector {
    /// The input property holding the operation name.
    pub param: String,
    /// Operation value to the call it makes.
    pub tools: BTreeMap<String, ToolCall>,
}

/// One MCP `tools/call`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolCall {
    /// The server's tool name.
    pub tool: String,
    /// Argument template (`json:` leaf rules).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub arguments: Option<Value>,
    /// A call made first on the same child, whose result feeds this one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prepare: Option<PrepareCall>,
    /// Input properties this operation needs. A missing or null one is refused
    /// before a child starts. The schema stays flat: the capability schemas may
    /// not compose subschemas, so per-operation requirements live here.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub requires: Vec<String>,
    /// Polled after the call until the work it started has finished.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wait: Option<WaitStep>,
}

/// The `wait` step of a [`ToolCall`]: poll a tool until a condition holds.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WaitStep {
    /// The server's tool name to poll.
    pub tool: String,
    /// Argument template (`json:` leaf rules).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub arguments: Option<Value>,
    /// When to stop polling.
    pub until: WaitUntil,
    /// Pause between polls, 200 to 5000 ms.
    #[serde(
        default = "default_wait_interval_ms",
        deserialize_with = "crate::duration_bound::millis"
    )]
    pub interval_ms: u64,
    /// Longest the wait may last, in seconds; at most the provider timeout
    /// minus 10 s.
    pub max_wait_s: u64,
}

fn default_wait_interval_ms() -> u64 {
    1000
}

/// Smallest and largest `interval_ms`.
pub const WAIT_INTERVAL_MS: std::ops::RangeInclusive<u64> = 200..=5000;

/// A poll result is ready when its `array` holds an element whose `match`
/// fields equal the given templates and whose `field` equals `equals`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WaitUntil {
    /// Result field holding the array to search.
    pub array: String,
    /// Element field to the template it must equal (`{param}` or a literal).
    #[serde(rename = "match")]
    pub matches: BTreeMap<String, String>,
    /// Element field to test once an element matches.
    pub field: String,
    /// The value that field must equal.
    pub equals: Value,
}

/// The `prepare` step of a [`ToolCall`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrepareCall {
    /// The server's tool name.
    pub tool: String,
    /// Argument template (`json:` leaf rules).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub arguments: Option<Value>,
    /// Main-call argument name to the prepare result field that fills it.
    pub bind: BTreeMap<String, String>,
}

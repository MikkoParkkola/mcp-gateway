// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! `service: cli` execution (MIK-7782): build, run, and turn the child's
//! answer into a result or a redacted error.

use std::ffi::OsString;
use std::sync::{Arc, LazyLock};
use std::time::Duration;

use serde_json::{Value, json};

use super::CapabilityExecutor;
use super::cli_argv::{CliInvocation, build_cli_invocation};
use super::cli_run::{CliOutcome, Workdir, child_env, resolve_command, run};
use crate::capability::CapabilityDefinition;
use crate::capability::definition::{CliConfig, CliOutput, MAX_OUTPUT_BYTES_CEILING};
use crate::security::firewall::redactor::Redactor;
use crate::{Error, Result};

/// Children one capability may run at once.
pub(crate) const MAX_CONCURRENT_PER_CAPABILITY: usize = 4;
/// How much of a failed child's diagnostics an error carries.
const EXCERPT_BYTES: usize = 2048;
/// Caller values shorter than this stay in diagnostics: replacing every `a`
/// or `1` would destroy the message, and secrets never travel as caller values.
const MIN_REDACTED_CALLER_VALUE: usize = 4;

static REDACTOR: LazyLock<Redactor> = LazyLock::new(Redactor::new);

impl CapabilityExecutor {
    pub(super) async fn execute_cli(
        &self,
        capability: &CapabilityDefinition,
        config: &CliConfig,
        params: &Value,
    ) -> Result<Value> {
        let invocation = build_cli_invocation(config, params, &capability.schema.input)?;
        if config.token_env.is_some() {
            return Err(Error::Config(format!(
                "capability '{}': credential injection for CLI capabilities is not available \
                 in this build",
                capability.name
            )));
        }
        let overlay = self.env.get();
        let lookup = |name: &str| {
            overlay
                .resolve(name)
                .map(OsString::from)
                .or_else(|| std::env::var_os(name))
        };
        let program = resolve_command(
            &invocation.command,
            lookup("PATH").as_deref(),
            lookup("PATHEXT").as_deref(),
        )?;
        let workdir = Workdir::create()
            .map_err(|e| Error::Protocol(format!("no private work directory: {}", e.kind())))?;
        let env = child_env(workdir.path(), &config.env, &lookup, None);
        let secrets: Vec<String> = config
            .env
            .iter()
            .filter_map(|name| lookup(name))
            .map(|v| v.to_string_lossy().into_owned())
            .collect();

        let slots = Arc::clone(
            self.process_slots
                .entry(capability.name.clone())
                .or_insert_with(|| {
                    Arc::new(tokio::sync::Semaphore::new(MAX_CONCURRENT_PER_CAPABILITY))
                })
                .value(),
        );
        let _slot = slots
            .acquire_owned()
            .await
            .map_err(|_| Error::Internal("process slots closed".into()))?;

        let timeout = Duration::from_secs(
            capability
                .primary_provider()
                .map_or(30, |provider| provider.timeout),
        );
        let max_output = config.max_output_bytes.min(MAX_OUTPUT_BYTES_CEILING);
        let outcome = run(&program, &invocation, &workdir, env, timeout, max_output).await?;
        interpret(&invocation, config.output, &outcome, &secrets, params)
    }
}

/// The child's answer as a result, or a redacted error.
fn interpret(
    invocation: &CliInvocation,
    output: CliOutput,
    outcome: &CliOutcome,
    secrets: &[String],
    params: &Value,
) -> Result<Value> {
    if outcome.status.success() {
        return match output {
            CliOutput::Json => serde_json::from_slice(&outcome.stdout).map_err(|_| {
                Error::Protocol(format!(
                    "'{}' succeeded but its output is not JSON",
                    invocation.command
                ))
            }),
            CliOutput::Text => Ok(json!({ "text": String::from_utf8_lossy(&outcome.stdout) })),
        };
    }
    let code = outcome
        .status
        .code()
        .map_or_else(|| "a signal".to_owned(), |c| format!("status {c}"));
    let excerpt = redact(&diagnostic(outcome), secrets, &caller_values(params));
    Err(Error::Protocol(format!(
        "'{}' exited with {code}: {excerpt}",
        invocation.command
    )))
}

/// The most useful text a failed child left: a JSON `error.message` on stdout
/// (gws), else the tail of stderr.
fn diagnostic(outcome: &CliOutcome) -> String {
    if let Ok(body) = serde_json::from_slice::<Value>(&outcome.stdout)
        && let Some(error) = body.get("error")
    {
        return error
            .get("message")
            .and_then(Value::as_str)
            .map_or_else(|| error.to_string(), str::to_owned);
    }
    let tail = &outcome.stderr[outcome.stderr.len().saturating_sub(EXCERPT_BYTES)..];
    String::from_utf8_lossy(tail).trim().to_owned()
}

/// Every string, number and boolean the caller supplied.
fn caller_values(params: &Value) -> Vec<String> {
    let mut out = Vec::new();
    let mut stack = vec![params];
    while let Some(value) = stack.pop() {
        match value {
            Value::String(s) => out.push(s.clone()),
            Value::Number(n) => out.push(n.to_string()),
            Value::Array(items) => stack.extend(items),
            Value::Object(map) => stack.extend(map.values()),
            _ => {}
        }
    }
    out
}

/// Remove injected secrets (any length) and caller values (from 4 bytes)
/// literally, then run the firewall's credential scanner, then truncate.
pub(crate) fn redact(text: &str, secrets: &[String], caller: &[String]) -> String {
    let mut text = text.to_owned();
    let mut needles: Vec<&str> = secrets
        .iter()
        .map(String::as_str)
        .filter(|s| !s.is_empty())
        .chain(
            caller
                .iter()
                .map(String::as_str)
                .filter(|s| s.len() >= MIN_REDACTED_CALLER_VALUE),
        )
        .collect();
    // Longest first, so a value containing another is removed whole.
    needles.sort_by_key(|s| std::cmp::Reverse(s.len()));
    for needle in needles {
        text = text.replace(needle, "[redacted]");
    }
    let mut value = Value::String(text);
    REDACTOR.scan_and_redact(&mut value);
    let text = value.as_str().unwrap_or_default();
    if text.len() <= EXCERPT_BYTES {
        return text.to_owned();
    }
    let mut cut = text.len() - EXCERPT_BYTES;
    while !text.is_char_boundary(cut) {
        cut += 1;
    }
    text[cut..].to_owned()
}

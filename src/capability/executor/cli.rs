// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! `service: cli` execution (MIK-7782): build, run, and turn the child's
//! answer into a result or a redacted error.

use std::ffi::OsString;
use std::sync::Arc;
use std::time::Duration;

use serde_json::{Value, json};

use super::CapabilityExecutor;
use super::cli_argv::{CliInvocation, build_cli_invocation};
use super::cli_run::{CliOutcome, Workdir, child_env, is_reserved, resolve_command, run};
use crate::capability::definition::{CliConfig, CliOutput, MAX_OUTPUT_BYTES_CEILING};
use crate::capability::{CapabilityDefinition, CapabilityExecutionContext};
use crate::{Error, Result};

/// Children one capability may run at once.
pub(crate) const MAX_CONCURRENT_PER_CAPABILITY: usize = 4;
/// How much of a failed child's diagnostics an error carries.
const EXCERPT_BYTES: usize = 2048;

pub(crate) use crate::security::secret_redaction::{redact_untruncated, redact_value};

impl CapabilityExecutor {
    pub(super) async fn execute_cli(
        &self,
        capability: &CapabilityDefinition,
        config: &CliConfig,
        params: &Value,
        context: &CapabilityExecutionContext,
    ) -> Result<Value> {
        refuse_egress(capability)?;
        let params = confine_paths(capability, params, &self.process_policy.files)?;
        let invocation = build_cli_invocation(config, &params, &capability.schema.input)?;
        // The slot first: no credential is fetched and no directory made for a
        // call that would then wait behind the capability's busy children.
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

        let token = match &config.token_env {
            Some(name) => Some((name.as_str(), self.cli_token(capability, context).await?)),
            None => None,
        };
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
        let env = child_env(
            workdir.path(),
            &config.env,
            &lookup,
            token.as_ref().map(|(name, value)| (*name, value.as_str())),
        );
        // The gateway sets a reserved name for the child itself (`child_env`),
        // never from this list, so its value is no injected secret.
        let secrets: Vec<String> = config
            .env
            .iter()
            .filter(|name| !is_reserved(name))
            .filter_map(|name| lookup(name))
            .map(|v| v.to_string_lossy().into_owned())
            .chain(token.map(|(_, value)| value))
            .collect();

        let timeout = Duration::from_secs(
            capability
                .primary_provider()
                .map_or(30, |provider| provider.timeout),
        );
        let max_output = config.max_output_bytes.min(MAX_OUTPUT_BYTES_CEILING);
        let outcome = run(&program, &invocation, &workdir, env, timeout, max_output).await?;
        interpret(&invocation, config.output, &outcome, &secrets, &params)
    }

    /// The access token for `auth.key`, resolved exactly as the REST path
    /// resolves it: a caller's account credential when the capability names
    /// an `auth.account`, else the gateway-held credential (which
    /// `validate_oauth_isolation` has already admitted for this caller).
    async fn cli_token(
        &self,
        capability: &CapabilityDefinition,
        context: &CapabilityExecutionContext,
    ) -> Result<String> {
        if let Some(headers) = self
            .resolve_account_headers(&capability.auth, context)
            .await?
        {
            return headers
                .iter()
                .find(|(name, _)| name.eq_ignore_ascii_case("authorization"))
                .and_then(|(_, value)| value.strip_prefix("Bearer "))
                .map(str::to_owned)
                .ok_or_else(|| {
                    Error::Config(format!(
                        "capability '{}': the account credential is not a bearer token",
                        capability.name
                    ))
                });
        }
        self.fetch_credential(&capability.auth, context).await
    }
}

/// Refuse a capability with a parameter that names a network destination.
///
/// The gateway cannot stop a child from following a redirect or a DNS rebind
/// to a private address, and no shipped tool refuses those at dial time yet
/// (MIK-7788), so no such capability runs on a pre-check alone.
pub(super) fn refuse_egress(capability: &CapabilityDefinition) -> Result<()> {
    let egress = capability
        .schema
        .input
        .get("properties")
        .and_then(Value::as_object)
        .and_then(|props| {
            props
                .iter()
                .find(|(_, prop)| prop.get("egress").and_then(Value::as_bool) == Some(true))
        });
    match egress {
        Some((name, _)) => Err(Error::Config(format!(
            "capability '{}' is not executable: its parameter '{name}' is a network destination \
             that this gateway cannot confine at connect time (MIK-7788)",
            capability.name
        ))),
        None => Ok(()),
    }
}

/// Resolve every parameter whose schema declares `path_root` to a canonical
/// path inside that configured root, and hand the child that canonical path.
pub(crate) fn confine_paths(
    capability: &CapabilityDefinition,
    params: &Value,
    roots: &crate::config::FileRoots,
) -> Result<Value> {
    let mut params = params.clone();
    let Some(props) = capability
        .schema
        .input
        .get("properties")
        .and_then(Value::as_object)
    else {
        return Ok(params);
    };
    for (name, prop) in props {
        let Some(root_name) = prop.get("path_root").and_then(Value::as_str) else {
            continue;
        };
        let Some(value) = params.get(name).and_then(Value::as_str) else {
            continue;
        };
        let confined = confine(value, root_name, roots).map_err(|why| {
            Error::json_rpc(
                crate::error::rpc_codes::INVALID_PARAMS,
                format!("parameter '{name}' {why}"),
            )
        })?;
        params[name.as_str()] = Value::String(confined.display().to_string());
    }
    Ok(params)
}

/// `path` canonicalized (symlinks followed), spelled as a program writes it.
pub(crate) fn canonical(path: &std::path::Path) -> std::io::Result<std::path::PathBuf> {
    std::fs::canonicalize(path).map(spelled)
}

/// A canonical path in its plain spelling where one names the same file.
/// On Windows `canonicalize` returns the verbatim form (`\\?\C:\x`); a server
/// that resolves only one side of a prefix check reads that as another path
/// (MIK-7911). The plain form is used only when it resolves back to exactly
/// this path, so a name the plain form reads differently (a device name such
/// as `con.txt`, a trailing dot or space) keeps the verbatim form. Elsewhere
/// the path is returned unchanged.
fn spelled(resolved: std::path::PathBuf) -> std::path::PathBuf {
    match resolved
        .to_str()
        .and_then(plain)
        .map(std::path::PathBuf::from)
    {
        Some(spelling) if std::fs::canonicalize(&spelling).is_ok_and(|again| again == resolved) => {
            spelling
        }
        _ => resolved,
    }
}

/// The plain spelling of a verbatim drive path (`\\?\C:\x` to `C:\x`), or
/// `None` for any other verbatim path (UNC, volume, device) and for a path
/// that is not verbatim. Whether it names the same file is [`spelled`]'s
/// check. Length is not limited: root and path take the same form, and
/// long-path handling stays with the server.
fn plain(verbatim: &str) -> Option<&str> {
    let rest = verbatim.strip_prefix(r"\\?\")?;
    let drive =
        rest.starts_with(|c: char| c.is_ascii_alphabetic()) && rest.get(1..3) == Some(r":\");
    drive.then_some(rest)
}

/// `value` canonicalized (symlinks followed) and checked to lie inside the
/// root, component by component, so `/srv/uploads_evil` is not inside
/// `/srv/uploads`.
pub(crate) fn confine(
    value: &str,
    root_name: &str,
    roots: &crate::config::FileRoots,
) -> std::result::Result<std::path::PathBuf, String> {
    let root = roots
        .get(root_name)
        .ok_or_else(|| format!("needs capabilities.files.{root_name}, which is not configured"))?;
    let root = std::fs::canonicalize(root)
        .map_err(|_| format!("needs capabilities.files.{root_name}, which does not exist"))?;
    let candidate = std::path::Path::new(value);
    let joined = if candidate.is_absolute() {
        candidate.to_path_buf()
    } else {
        root.join(candidate)
    };
    let resolved =
        std::fs::canonicalize(&joined).map_err(|_| "does not name an existing path".to_owned())?;
    if resolved.strip_prefix(&root).is_err() {
        return Err(format!("is outside capabilities.files.{root_name}"));
    }
    // Checked in the verbatim form, handed on in the form the root takes.
    Ok(spelled(resolved))
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
        // The child may echo a credential it was given (MIK-7882): the answer
        // loses the injected secrets like an error does, but is returned whole.
        // Caller values stay: a tool legitimately returns what it was asked to
        // store, send or look up.
        return match output {
            CliOutput::Json => serde_json::from_slice::<Value>(&outcome.stdout)
                .map(|mut value| {
                    redact_value(&mut value, secrets);
                    value
                })
                .map_err(|_| {
                    Error::Protocol(format!(
                        "'{}' succeeded but its output is not JSON",
                        invocation.command
                    ))
                }),
            CliOutput::Text => Ok(json!({
                "text": redact_untruncated(
                    &String::from_utf8_lossy(&outcome.stdout),
                    secrets,
                    &[],
                )
            })),
        };
    }
    if unauthorized(outcome) {
        return Err(Error::CliCredentialRefused {
            message: format!("'{}' refused its credential", invocation.command),
        });
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

/// A JSON error with code 401 on stdout: the tool refused its credential.
fn unauthorized(outcome: &CliOutcome) -> bool {
    serde_json::from_slice::<Value>(&outcome.stdout)
        .ok()
        .and_then(|body| body.pointer("/error/code").and_then(Value::as_i64))
        == Some(401)
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
    // The whole (capped) stream: `redact` removes secrets first and only then
    // keeps the tail, so a secret cannot straddle the cut.
    String::from_utf8_lossy(&outcome.stderr).trim().to_owned()
}

/// Every string, number and boolean the caller supplied.
pub(super) fn caller_values(params: &Value) -> Vec<String> {
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
/// literally, then keep the last [`EXCERPT_BYTES`]. A credential the cut would
/// split is dropped whole: its tail alone is recognised by no scanner, so the
/// firewall could neither find nor redact it. A credential wholly inside the
/// excerpt stays for the firewall (see [`redact_untruncated`]).
pub(crate) fn redact(text: &str, secrets: &[String], caller: &[String]) -> String {
    let text = redact_untruncated(text, secrets, caller);
    let text = text.as_str();
    if text.len() <= EXCERPT_BYTES {
        return text.to_owned();
    }
    // Not `crate::truncate`: the excerpt keeps the tail (MIK-8667).
    let mut cut = text.len() - EXCERPT_BYTES;
    // Spans are merged, so at most one contains the cut.
    #[cfg(feature = "firewall")]
    if let Some(&(_, end)) = (crate::security::secret_redaction::credential_spans(text).iter())
        .find(|&&(start, end)| start < cut && cut < end)
    {
        cut = end;
    }
    cut = text.ceil_char_boundary(cut);
    text[cut..].to_owned()
}

#[cfg(test)]
#[path = "cli_tests.rs"]
mod tests;

#[cfg(all(test, feature = "firewall"))]
#[path = "cli_firewall_tests.rs"]
mod firewall_tests;

#[cfg(test)]
#[path = "cli_literal_tests.rs"]
mod literal_tests;

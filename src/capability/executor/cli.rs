// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! `service: cli` execution (MIK-7782): build, run, and turn the child's
//! answer into a result or a redacted error.

use std::ffi::OsString;
use std::sync::Arc;
#[cfg(feature = "firewall")]
use std::sync::LazyLock;
use std::time::Duration;

use serde_json::{Value, json};

use super::CapabilityExecutor;
use super::cli_argv::{CliInvocation, build_cli_invocation};
use super::cli_run::{CliOutcome, Workdir, child_env, resolve_command, run};
use crate::capability::definition::{CliConfig, CliOutput, MAX_OUTPUT_BYTES_CEILING};
use crate::capability::{CapabilityDefinition, CapabilityExecutionContext};
#[cfg(feature = "firewall")]
use crate::security::firewall::redactor::Redactor;
use crate::{Error, Result};

/// Children one capability may run at once.
pub(crate) const MAX_CONCURRENT_PER_CAPABILITY: usize = 4;
/// How much of a failed child's diagnostics an error carries.
const EXCERPT_BYTES: usize = 2048;
/// Caller values shorter than this stay in diagnostics: replacing every `a`
/// or `1` would destroy the message, and secrets never travel as caller values.
const MIN_REDACTED_CALLER_VALUE: usize = 4;

#[cfg(feature = "firewall")]
static REDACTOR: LazyLock<Redactor> = LazyLock::new(Redactor::new);

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
        let secrets: Vec<String> = config
            .env
            .iter()
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
    Ok(resolved)
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
        return Err(Error::JsonRpc {
            code: crate::security::http_diagnostics::CLI_UNAUTHORIZED,
            message: format!("'{}' refused its credential", invocation.command),
            data: None,
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

/// Injected secrets (any length) and caller values (from 4 bytes), longest
/// first so a value containing another is removed whole.
fn needles<'a>(secrets: &'a [String], caller: &'a [String]) -> Vec<&'a str> {
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
    needles.sort_by_key(|s| std::cmp::Reverse(s.len()));
    needles
}

/// Replace every occurrence of every needle with a marker. All matches are
/// located in the ORIGINAL text and overlapping ones merge into one marker, so
/// two credentials that overlap leave no fragment of either behind.
///
/// Memory is one flag per byte of `text`, whatever the number of matches (a
/// one-character needle in a long text matches at every position); each needle
/// costs one linear pass, however much its matches overlap.
///
/// A credential the scanner would find in the ORIGINAL text and that a
/// literal overlaps is removed with it: removing the literal alone (an
/// injected value equal to `Bearer`) would leave the rest of that credential
/// where the scanner no longer recognises it.
fn scrub(text: &str, needles: &[&str]) -> String {
    let mut covered: Vec<bool> = Vec::new();
    let mut seen: Vec<&str> = Vec::new();
    for needle in needles {
        if needle.is_empty() || seen.contains(needle) || !text.contains(needle) {
            continue;
        }
        seen.push(needle);
        if covered.is_empty() {
            covered = vec![false; text.len()];
        }
        // Matches arrive in order of their end, so each marks only what the
        // previous one did not and the marking is linear in the text.
        let mut marked_to = 0;
        match_starts(text.as_bytes(), needle.as_bytes(), |start| {
            let end = start + needle.len();
            covered[start.max(marked_to)..end].fill(true);
            marked_to = end;
        });
    }
    if covered.is_empty() {
        return text.to_owned();
    }
    #[cfg(feature = "firewall")]
    for (start, end) in REDACTOR.credential_spans(text) {
        if covered[start..end].contains(&true) {
            covered[start..end].fill(true);
        }
    }
    let mut out = String::with_capacity(text.len());
    let mut at = 0;
    while at < text.len() {
        if covered[at] {
            while at < text.len() && covered[at] {
                at += 1;
            }
            out.push_str("[redacted]");
        } else {
            let start = at;
            while at < text.len() && !covered[at] {
                at += 1;
            }
            out.push_str(&text[start..at]);
        }
    }
    out
}

/// Every start of `needle` in `text`, overlapping ones included, in
/// O(text + needle) (Knuth-Morris-Pratt). A byte match of a UTF-8 needle in
/// UTF-8 text starts and ends on character boundaries.
fn match_starts(text: &[u8], needle: &[u8], mut each: impl FnMut(usize)) {
    let mut fail = vec![0usize; needle.len()];
    let mut k = 0;
    for i in 1..needle.len() {
        while k > 0 && needle[i] != needle[k] {
            k = fail[k - 1];
        }
        if needle[i] == needle[k] {
            k += 1;
        }
        fail[i] = k;
    }
    k = 0;
    for (i, &byte) in text.iter().enumerate() {
        while k > 0 && byte != needle[k] {
            k = fail[k - 1];
        }
        if byte == needle[k] {
            k += 1;
        }
        if k == needle.len() {
            each(i + 1 - k);
            k = fail[k - 1];
        }
    }
}

/// [`redact`] without the truncation: for a result the caller receives whole.
/// Removes the literals only; a credential a literal overlaps goes with it
/// (see [`scrub`]).
///
/// A credential-shaped value the gateway did not inject is left for the
/// response firewall, which inspects every result and error the caller
/// receives: replacing it here would hand the firewall only a marker, so its
/// rules, its Block and its audit finding would never see the credential.
pub(crate) fn redact_untruncated(text: &str, secrets: &[String], caller: &[String]) -> String {
    scrub(text, &needles(secrets, caller))
}

/// Redact a successful JSON result in place: every string value and object key,
/// never the structure, so the document still parses and a redacted string
/// stays a string. No truncation. Injected literals only, as
/// [`redact_untruncated`]: the credential scanner is the response firewall's.
pub(crate) fn redact_value(value: &mut Value, secrets: &[String]) {
    let needles = needles(secrets, &[]);
    if !needles.is_empty() {
        scrub_value(value, &needles);
    }
}

fn scrub_value(value: &mut Value, needles: &[&str]) {
    match value {
        Value::String(s) => *s = scrub(s, needles),
        // A credential that is all digits can come back as a JSON number. A
        // short needle would hit every number, so only one a caller could not
        // guess by chance (the same floor as caller values) is looked for.
        // An all-digit needle is also compared by value: printed as a number,
        // it loses its leading zeros ("012345" comes back as 12345), and past
        // u64 it parses as a float and prints in exponent form. The floor is
        // on the needle as injected, so "0007" redacts the number 7 but never
        // the 7 inside 1771. The sign is ignored on both paths: a needle has
        // none, so -12345, -12345.0 and -0.0 are the same value as one.
        Value::Number(n) => {
            let digits = n.to_string();
            let float = n.as_f64().filter(|_| n.is_f64()).map(f64::abs);
            let same_value = |needle: &str| {
                if !needle.bytes().all(|b| b.is_ascii_digit()) {
                    return false;
                }
                let value = needle.trim_start_matches('0');
                let value = if value.is_empty() { "0" } else { value };
                // Parsed by serde_json, the parser that read the result, so
                // both sides round the same way whatever its float features.
                if let Some(f) = float {
                    return serde_json::from_str::<f64>(value)
                        .is_ok_and(|p| p.to_bits() == f.to_bits());
                }
                digits.trim_start_matches('-') == value
            };
            if needles.iter().any(|needle| {
                needle.len() >= MIN_REDACTED_CALLER_VALUE
                    && (digits.contains(needle) || same_value(needle))
            }) {
                *value = Value::String("[redacted]".to_owned());
            }
        }
        Value::Array(items) => items.iter_mut().for_each(|v| scrub_value(v, needles)),
        Value::Object(map) => {
            let old = std::mem::take(map);
            let mut renamed = Vec::new();
            // Keys that survive keep their names whole: a renamed key never
            // takes one of them.
            for (key, mut item) in old {
                scrub_value(&mut item, needles);
                let new = scrub(&key, needles);
                if new == key {
                    map.insert(key, item);
                } else {
                    renamed.push((new, item));
                }
            }
            // Keys that collapse to the same marker all survive, `#2`, `#3`, ...
            let mut next: std::collections::HashMap<String, usize> =
                std::collections::HashMap::new();
            for (base, item) in renamed {
                let mut key = base.clone();
                while map.contains_key(&key) {
                    let n = next.entry(base.clone()).or_insert(1);
                    *n += 1;
                    key = format!("{base}#{n}");
                }
                map.insert(key, item);
            }
        }
        _ => {}
    }
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
    let mut cut = text.len() - EXCERPT_BYTES;
    // Spans are merged, so at most one contains the cut.
    #[cfg(feature = "firewall")]
    if let Some(&(_, end)) =
        (REDACTOR.credential_spans(text).iter()).find(|&&(start, end)| start < cut && cut < end)
    {
        cut = end;
    }
    while !text.is_char_boundary(cut) {
        cut += 1;
    }
    text[cut..].to_owned()
}

#[cfg(test)]
#[path = "cli_tests.rs"]
mod tests;

#[cfg(all(test, feature = "firewall"))]
#[path = "cli_firewall_tests.rs"]
mod firewall_tests;

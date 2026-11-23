// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! `mcp-gateway audit lookup-email`: ask a running gateway for the key
//! server's retained issuance rows for one email.
//!
//! The email (first page) or the page token (every later page, from
//! `--cursor-stdin`) comes from stdin, bounded, and goes only into the request
//! body built in memory: never an argument, never a file, never an error
//! message of this command. (A value typed as an argument anyway is refused,
//! and the binary's parse entry, `src/parse_errors.rs`, never repeats it.)
//! The answer is decoded strictly and printed as the typed answer; any HTTP,
//! authentication, read or decode failure is a nonzero exit.

use std::process::ExitCode;

use mcp_gateway::cli::audit_lookup::LookupEmailArgs;
use serde::{Deserialize, Serialize};

use super::cli_exit::{
    CliError, CliExit, CliOutcome, PROTOCOL_MESSAGE, PROTOCOL_REMEDY, Request, StdoutRule,
    UNSAFE_BODY_MESSAGE, UNSAFE_BODY_REMEDY, emit,
};
use super::dashboard_link::{LinkTls, Remedies, refusal, transport};

/// The most bytes read from stdin: an email is at most 320 bytes.
pub(crate) const MAX_EMAIL_INPUT: usize = 1024;

/// The longest page token accepted, in bytes, its line end not counted: the
/// gateway's own limit on one (2048 characters of URL-safe base64).
pub(crate) const MAX_CURSOR_INPUT: usize = 2048;

/// What the lookup asks with: the email (first page) or a page token (every
/// later page). Never both, so a token never travels beside an email.
#[derive(Clone, PartialEq, Eq)]
pub(crate) enum LookupInput {
    Email(String),
    Cursor(String),
}

/// Names the kind only: neither the email nor the token is for a log line.
impl std::fmt::Debug for LookupInput {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Email(_) => "Email(<hidden>)",
            Self::Cursor(_) => "Cursor(<hidden>)",
        })
    }
}

/// The one line of stdin that is a page token, trimmed at its ends.
///
/// # Errors
///
/// A fixed message (never the input) when stdin is empty, unreadable, not
/// UTF-8, holds more than one line, the token is too long, or the line holds a
/// space or control character: a token is URL-safe base64.
pub(crate) fn read_cursor(input: impl std::io::Read) -> Result<String, String> {
    use std::io::Read as _;
    const TOO_LONG: &str = "the page token on stdin is too long";
    // The bound is on the token: room for a `\r\n` after it, and one byte
    // more proves "too long" without reading the rest.
    let line_bound = MAX_CURSOR_INPUT + 2;
    let mut raw = Vec::new();
    input
        .take(line_bound as u64 + 1)
        .read_to_end(&mut raw)
        .map_err(|_| UNREADABLE_CURSOR.to_string())?;
    if raw.len() > line_bound {
        return Err(TOO_LONG.to_string());
    }
    let text =
        String::from_utf8(raw).map_err(|_| "the page token on stdin is not UTF-8".to_string())?;
    let line = text.strip_suffix('\n').unwrap_or(&text);
    let line = line.strip_suffix('\r').unwrap_or(line);
    if line.contains('\n') {
        return Err("stdin must hold one line: the page token".to_string());
    }
    let token = line.trim();
    if token.is_empty() {
        return Err("stdin held no page token".to_string());
    }
    if token.len() > MAX_CURSOR_INPUT {
        return Err(TOO_LONG.to_string());
    }
    if token.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return Err("the page token on stdin is not valid".to_string());
    }
    Ok(token.to_owned())
}

/// One retained issuance row, as the gateway answers it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct LookupRow {
    pub(crate) timestamp: Option<String>,
    pub(crate) token_jti: Option<String>,
    pub(crate) subject: Option<String>,
    pub(crate) issuer: Option<String>,
    pub(crate) backends: Option<serde_json::Value>,
    pub(crate) tools: Option<serde_json::Value>,
    pub(crate) segment: u64,
}

/// One page of the answer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct LookupAnswer {
    pub(crate) rows: Vec<LookupRow>,
    pub(crate) next_cursor: Option<String>,
    pub(crate) scan_exhausted: bool,
    pub(crate) cursor_reset: bool,
    pub(crate) unreadable: u64,
    pub(crate) scope: String,
}

/// Stdin could not be read (exit 1); every other input refusal is a usage error (2, design D4).
const UNREADABLE_EMAIL: &str = "could not read the email from stdin";
const UNREADABLE_CURSOR: &str = "could not read the page token from stdin";

/// The longest email accepted, as the gateway's own limit (RFC 5321).
const MAX_EMAIL: usize = 320;

/// The one line of stdin, trimmed of its line end.
///
/// # Errors
///
/// A fixed message when stdin is empty, too long, unreadable, not UTF-8, or
/// holds anything but one email-sized line.
pub(crate) fn read_email(input: impl std::io::Read) -> Result<String, String> {
    use std::io::Read as _;
    let mut raw = Vec::new();
    // One byte over the bound proves "too long" without reading the rest.
    input
        .take(MAX_EMAIL_INPUT as u64 + 1)
        .read_to_end(&mut raw)
        .map_err(|_| UNREADABLE_EMAIL.to_string())?;
    if raw.len() > MAX_EMAIL_INPUT {
        return Err("the email on stdin is too long".to_string());
    }
    let text = String::from_utf8(raw).map_err(|_| "the email on stdin is not UTF-8".to_string())?;
    let line = text.strip_suffix('\n').unwrap_or(&text);
    let line = line.strip_suffix('\r').unwrap_or(line);
    if line.contains('\n') {
        return Err("stdin must hold one line: the email".to_string());
    }
    let email = line.trim();
    if email.is_empty() {
        return Err("stdin held no email".to_string());
    }
    if email.len() > MAX_EMAIL || email.chars().any(char::is_control) {
        return Err("the email on stdin is not valid".to_string());
    }
    Ok(email.to_owned())
}

/// The request body, built in memory.
pub(crate) fn request_body(input: &LookupInput, args: &LookupEmailArgs) -> serde_json::Value {
    let mut body = serde_json::Map::new();
    match input {
        // The first page: the email and the window. A token never rides with it.
        LookupInput::Email(email) => {
            body.insert("email".into(), email.as_str().into());
            for (key, value) in [("from", &args.from), ("to", &args.to)] {
                if let Some(value) = value {
                    body.insert(key.into(), value.clone().into());
                }
            }
        }
        // A later page: the token alone (it carries its own window) and the size.
        LookupInput::Cursor(token) => {
            body.insert("cursor".into(), token.as_str().into());
        }
    }
    if let Some(limit) = args.limit {
        body.insert("limit".into(), limit.into());
    }
    serde_json::Value::Object(body)
}

/// `--from` and `--to` must be RFC 3339 times, in order: refused here, since
/// the gateway charges a lookup before it rejects a typo.
///
/// # Errors
///
/// A fixed message naming the flags.
pub(crate) fn check_window(args: &LookupEmailArgs) -> Result<(), String> {
    let parse = |t: &Option<String>| match t {
        None => Ok(None),
        Some(t) => chrono::DateTime::parse_from_rfc3339(t)
            .map(Some)
            .map_err(|_| "--from and --to must be RFC 3339 times".to_string()),
    };
    if let (Some(from), Some(to)) = (parse(&args.from)?, parse(&args.to)?)
        && from > to
    {
        return Err("--from must not be after --to".to_string());
    }
    Ok(())
}

/// The answer as printed: the typed answer, so a field the gateway adds is
/// never echoed.
///
/// # Errors
///
/// A fixed message when the answer cannot be serialised.
pub(crate) fn render(answer: &LookupAnswer) -> Result<String, String> {
    serde_json::to_string_pretty(answer).map_err(|_| "could not print the answer".to_string())
}

/// Ask the gateway at `base` and decode its answer strictly. The shared
/// admin client refuses a cleartext non-loopback target before it connects.
/// It stays on `admin_call_url`, which carries the email or cursor body, and
/// shares the transport and refusal mapping with the other commands (design D2).
///
/// # Errors
///
/// The failure on the shared table; the caller prints it through
/// `CliError::outcome` with the token and the email or cursor as secrets.
pub(crate) async fn lookup(
    base: &str,
    tls: &LinkTls,
    token: &str,
    input: &LookupInput,
    args: &LookupEmailArgs,
) -> Result<LookupAnswer, CliError> {
    const PATH: &str = "/ui/api/key-server/audit/lookup-email";
    let endpoint =
        reqwest::Url::parse(&format!("{}{PATH}", base.trim_end_matches('/'))).map_err(|_| {
            CliError::new(
                CliExit::Usage,
                "the gateway URL is not valid",
                "Check the gateway settings, then retry.",
            )
        })?;
    check_window(args).map_err(|message| {
        CliError::new(
            CliExit::Usage,
            message,
            "Use RFC 3339 times with --from not after --to.",
        )
    })?;
    let body = super::dashboard_link::AdminBody::Json(request_body(input, args));
    let remedies = Remedies::read(base);
    let response = super::dashboard_link::admin_call_url(
        reqwest::Method::POST,
        endpoint,
        token,
        tls,
        Some(&body),
        None,
    )
    .await
    .map_err(|error| transport(error, Request::Read, token, &remedies, tls))?;
    if let Some(refused) = refusal(&response, Request::Read, &remedies) {
        return Err(refused);
    }
    serde_json::from_slice::<LookupAnswer>(&response.body)
        .map_err(|_| CliError::new(CliExit::Gateway, PROTOCOL_MESSAGE, PROTOCOL_REMEDY))
}

/// The token redacted from every text and JSON field of `answer`, in place, as the other commands redact a success
/// body (design D2); `false` when a JSON field lost an entry to it. The email or cursor stays: it may be data.
fn redact_answer(answer: &mut LookupAnswer, token: &str) -> bool {
    let secrets = [token.to_string()];
    let text = |value: &mut String| *value = mcp_gateway::cli::redact::text(value, &secrets);
    let mut kept = true;
    for row in &mut answer.rows {
        for field in [
            &mut row.timestamp,
            &mut row.token_jti,
            &mut row.subject,
            &mut row.issuer,
        ]
        .into_iter()
        .flatten()
        {
            text(field);
        }
        for value in [&mut row.backends, &mut row.tools].into_iter().flatten() {
            kept &= super::dashboard_link::redact_body(value, token);
        }
    }
    if let Some(cursor) = &mut answer.next_cursor {
        text(cursor);
    }
    text(&mut answer.scope);
    kept
}

/// Resolve the gateway, read the credential and the email, look up, print.
pub(crate) async fn run_with(
    args: LookupEmailArgs,
    load: impl FnOnce() -> Result<mcp_gateway::config::Config, String>,
    port_override: Option<u16>,
    host_override: Option<&str>,
    input: impl std::io::Read,
    token: impl Fn(&str) -> Option<String>,
) -> ExitCode {
    let (outcome, secrets) =
        lookup_run(args, load, port_override, host_override, input, token).await;
    // emit's own write-failure report is gated on every secret the run read (design D5).
    let secrets: Vec<&str> = secrets.iter().map(String::as_str).collect();
    emit(&outcome, false, &secrets)
}

/// What `audit lookup-email` prints and exits with. Checks in order (design D4): resolve the gateway, the token,
/// stdin, the window, the request. Every failure prints through `CliError::outcome` with every secret known at
/// that point: the token, then the email or cursor too (design D5).
// Rows only: production enters through `lookup_run`, which also returns the run's secrets for `emit`.
#[cfg(test)]
pub(crate) async fn lookup_outcome(
    args: LookupEmailArgs,
    load: impl FnOnce() -> Result<mcp_gateway::config::Config, String>,
    port_override: Option<u16>,
    host_override: Option<&str>,
    input: impl std::io::Read,
    token: impl Fn(&str) -> Option<String>,
) -> CliOutcome {
    lookup_run(args, load, port_override, host_override, input, token)
        .await
        .0
}

/// [`lookup_outcome`] with every secret the run read: the token once read, then the email or cursor.
pub(crate) async fn lookup_run(
    args: LookupEmailArgs,
    load: impl FnOnce() -> Result<mcp_gateway::config::Config, String>,
    port_override: Option<u16>,
    host_override: Option<&str>,
    input: impl std::io::Read,
    token: impl Fn(&str) -> Option<String>,
) -> (CliOutcome, Vec<String>) {
    let token = super::dashboard_link::read_token(token);
    let mut secrets: Vec<String> = token.iter().cloned().collect();
    let (base, tls, token) = match super::dashboard_link::resolved(
        args.gateway.url.clone(),
        args.tls.clone(),
        load,
        port_override,
        host_override,
        token,
        crate::cli::output::Render::Text,
    ) {
        Ok(resolved) => resolved,
        Err(out) => return (out, secrets),
    };
    let asked = if args.cursor_stdin {
        read_cursor(input).map(LookupInput::Cursor)
    } else {
        read_email(input).map(LookupInput::Email)
    };
    let asked = match asked {
        Ok(asked) => asked,
        Err(message) => {
            let failure = if message == UNREADABLE_EMAIL || message == UNREADABLE_CURSOR {
                CliError::new(CliExit::LocalFailure, message, "Check stdin and retry.")
            } else {
                CliError::new(
                    CliExit::Usage,
                    message,
                    "Pass one email (or the page token from the previous page) on stdin.",
                )
            };
            return (failure.outcome(false, &[&token]), secrets);
        }
    };
    let (LookupInput::Email(secret) | LookupInput::Cursor(secret)) = &asked;
    secrets.push(secret.clone());
    let both = [token.as_str(), secret.as_str()];
    let out = match lookup(&base, &tls, &token, &asked, &args).await {
        Ok(mut answer) => {
            if redact_answer(&mut answer, &token) {
                match render(&answer) {
                    // The email or cursor may be data in the answer; only the token is refused (design D6).
                    Ok(text) => CliOutcome::success(
                        format!("{text}\n").into_bytes(),
                        "",
                        false,
                        &both,
                        StdoutRule::RefuseToken,
                    ),
                    Err(message) => CliError::new(
                        CliExit::LocalFailure,
                        message,
                        "Retry; report the failure if it repeats.",
                    )
                    .outcome(false, &both),
                }
            } else {
                CliError::new(
                    CliExit::LocalFailure,
                    UNSAFE_BODY_MESSAGE,
                    UNSAFE_BODY_REMEDY,
                )
                .outcome(false, &both)
            }
        }
        Err(error) => error.outcome(false, &both),
    };
    (out, secrets)
}

/// `mcp-gateway audit lookup-email`.
pub async fn run_audit_lookup_command(
    args: LookupEmailArgs,
    load: impl FnOnce() -> Result<mcp_gateway::config::Config, String>,
    port_override: Option<u16>,
    host_override: Option<&str>,
) -> ExitCode {
    run_with(
        args,
        load,
        port_override,
        host_override,
        std::io::stdin(),
        |name| std::env::var(name).ok(),
    )
    .await
}

#[cfg(tp2)]
#[cfg(test)]
#[path = "audit_lookup_tests.rs"]
mod tests;

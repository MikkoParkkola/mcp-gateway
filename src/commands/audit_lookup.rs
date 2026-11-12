// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! `mcp-gateway audit lookup-email`: ask a running gateway for the key
//! server's retained issuance rows for one email.
//!
//! The email comes from stdin, bounded, and goes only into the request body
//! built in memory: never an argument, never a file, never an error message.
//! The answer is decoded strictly and printed as the typed answer; any HTTP,
//! authentication, read or decode failure is a nonzero exit.

use crate::cli::stdout::println;

use std::process::ExitCode;

use mcp_gateway::cli::audit_lookup::LookupEmailArgs;
use serde::{Deserialize, Serialize};

use super::dashboard_link::LinkTls;

/// The most bytes read from stdin: an email is at most 320 bytes.
pub(crate) const MAX_EMAIL_INPUT: usize = 1024;

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
        .map_err(|_| "could not read the email from stdin".to_string())?;
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
pub(crate) fn request_body(email: &str, args: &LookupEmailArgs) -> serde_json::Value {
    let mut body = serde_json::Map::new();
    body.insert("email".into(), email.into());
    if let Some(limit) = args.limit {
        body.insert("limit".into(), limit.into());
    }
    for (key, value) in [
        ("cursor", &args.cursor),
        ("from", &args.from),
        ("to", &args.to),
    ] {
        if let Some(value) = value {
            body.insert(key.into(), value.clone().into());
        }
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
///
/// # Errors
///
/// A message naming the status or the failure, never the email or the token.
pub(crate) async fn lookup(
    base: &str,
    tls: &LinkTls,
    token: &str,
    email: &str,
    args: &LookupEmailArgs,
) -> Result<LookupAnswer, String> {
    const PATH: &str = "/ui/api/key-server/audit/lookup-email";
    let hide =
        |text: &str| mcp_gateway::cli::redact::text(text, &[token.to_string(), email.to_string()]);
    let endpoint = reqwest::Url::parse(&format!("{}{PATH}", base.trim_end_matches('/')))
        .map_err(|_| "the gateway URL is not valid".to_string())?;
    check_window(args)?;
    let body = request_body(email, args);
    let response = super::dashboard_link::admin_call_url(
        reqwest::Method::POST,
        endpoint,
        token,
        tls,
        Some(&body),
        None,
    )
    .await
    .map_err(|error| hide(&error.to_string()))?;
    if !response.status.is_success() {
        let parsed: serde_json::Value = serde_json::from_slice(&response.body).unwrap_or_default();
        let reason = super::dashboard_link::gateway_reason(&parsed).unwrap_or("no reason given");
        let wait = response
            .headers
            .get(reqwest::header::RETRY_AFTER)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.trim().parse::<u64>().ok())
            .map(|secs| format!(" (retry after {secs} s)"))
            .unwrap_or_default();
        return Err(format!(
            "the gateway answered {}: {}{wait}",
            response.status,
            hide(reason)
        ));
    }
    serde_json::from_slice::<LookupAnswer>(&response.body)
        .map_err(|_| "the gateway's answer is not a lookup answer".to_string())
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
    let fail = |message: String| {
        eprintln!("audit lookup-email: {message}");
        ExitCode::FAILURE
    };
    let token = match super::dashboard_link::read_token(token) {
        Ok(token) => token,
        Err(error) => return fail(error.to_string()),
    };
    let (base, tls) = match super::dashboard_link::dashboard_link_base(
        args.url.clone(),
        args.tls.clone(),
        load,
        port_override,
        host_override,
    ) {
        Ok(resolved) => resolved,
        Err(message) => return fail(message),
    };
    let email = match read_email(input) {
        Ok(email) => email,
        Err(message) => return fail(message),
    };
    match lookup(&base, &tls, &token, &email, &args).await {
        Ok(answer) => match render(&answer) {
            Ok(text) => {
                println!("{text}");
                ExitCode::SUCCESS
            }
            Err(message) => fail(message),
        },
        Err(message) => fail(message),
    }
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

#[cfg(test)]
#[path = "audit_lookup_tests.rs"]
mod tests;

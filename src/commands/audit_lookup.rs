// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! `mcp-gateway audit lookup-email`: ask a running gateway for the key
//! server's retained issuance rows for one email.
//!
//! The email comes from stdin, bounded, and goes only into the request body
//! built in memory: never an argument, never a file, never an error message.
//! The answer is decoded strictly and printed as the typed answer; any HTTP,
//! authentication, read or decode failure is a nonzero exit.

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

/// The one line of stdin, trimmed of its line end.
///
/// # Errors
///
/// A fixed message when stdin is empty, too long, unreadable, not UTF-8, or
/// holds anything but one email-sized line.
pub(crate) fn read_email(_input: impl std::io::Read) -> Result<String, String> {
    Err("not built".to_string())
}

/// The request body, built in memory.
pub(crate) fn request_body(_email: &str, _args: &LookupEmailArgs) -> serde_json::Value {
    serde_json::Value::Null
}

/// Ask the gateway at `base` and decode its answer strictly.
///
/// # Errors
///
/// A message naming the status or the failure, never the email or the token.
pub(crate) async fn lookup(
    _base: &str,
    _tls: &LinkTls,
    _token: &str,
    _email: &str,
    _args: &LookupEmailArgs,
) -> Result<LookupAnswer, String> {
    Err("not built".to_string())
}

/// Resolve the gateway, read the email and the credential, look up, print.
pub(crate) async fn run_with(
    _args: LookupEmailArgs,
    _load: impl FnOnce() -> Result<mcp_gateway::config::Config, String>,
    _port_override: Option<u16>,
    _host_override: Option<&str>,
    _input: impl std::io::Read,
    _token: impl Fn(&str) -> Option<String>,
) -> ExitCode {
    ExitCode::FAILURE
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

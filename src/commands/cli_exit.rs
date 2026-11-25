// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The CLI's shared exit table and error shape (design D1), from the api command.
//!
//! The output rules: data on stdout; messages, progress and errors on stderr. A JSON document the CLI composes (an
//! error with `--json`) carries `schema_version`; JSON the CLI passes through unchanged (a gateway body) keeps its
//! own shape. Every buffered outcome is built by [`CliError::outcome`] or [`CliOutcome::success`], both gated
//! against the run's secrets, and printed by [`emit`].

use mcp_gateway::cli::redact;
// The transport half below serves the remote commands, which exist only with the web UI; the local half (the exit
// table, the error shape and the three exits) builds in every configuration.
#[cfg(feature = "webui")]
use serde_json::Value;

#[cfg(feature = "webui")]
use super::dashboard_link::{AdminCallError, AdminFailureKind, TokenError};

/// Exit table E. Each kind has one process code, independent of HTTP status.
/// What an error becomes when its rendering would still contain the token.
const UNPRINTABLE_ERROR: &str =
    "error: The error report could not be printed without exposing the credential.\n";

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize)]
pub(crate) enum CliExit {
    Ok,
    LocalFailure,
    Usage,
    #[cfg_attr(
        not(feature = "webui"),
        allow(dead_code, reason = "raised by the remote commands only")
    )]
    AuthRefused,
    #[cfg_attr(
        not(feature = "webui"),
        allow(dead_code, reason = "raised by the remote commands only")
    )]
    NotFound,
    #[cfg_attr(
        not(feature = "webui"),
        allow(dead_code, reason = "raised by the remote commands only")
    )]
    Network,
    #[cfg_attr(
        not(feature = "webui"),
        allow(dead_code, reason = "raised by the remote commands only")
    )]
    Gateway,
    #[allow(dead_code, reason = "reserved by the shared exit table")]
    Declined,
    #[cfg_attr(
        not(feature = "webui"),
        allow(dead_code, reason = "raised by the remote commands only")
    )]
    UncertainOutcome,
    #[allow(dead_code, reason = "reserved by the shared exit table")]
    Interrupted,
}

impl CliExit {
    pub(crate) const fn code(self) -> u8 {
        match self {
            Self::Ok => 0,
            Self::LocalFailure => 1,
            Self::Usage => 2,
            Self::AuthRefused => 3,
            Self::NotFound => 4,
            Self::Network => 5,
            Self::Gateway => 6,
            Self::Declined => 7,
            Self::UncertainOutcome => 8,
            Self::Interrupted => 130,
        }
    }
}

/// Output is captured before printing, so tests need no process globals.
/// The fields are private: an outcome is built only by [`CliError::outcome`] or [`CliOutcome::success`], both
/// gated, so no command can print an ungated one (design D1).
pub(crate) struct CliOutcome {
    stdout: Vec<u8>,
    stderr: String,
    exit: CliExit,
}

/// What a success's stdout must satisfy before it prints (design D1).
#[cfg(feature = "webui")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum StdoutRule {
    /// The converted commands: refused when stdout still holds a secret after redaction (D6).
    RefuseToken,
    /// api: the body already passed its own entry-loss check, so stdout is printed as given.
    RedactedJsonBody,
}

impl CliOutcome {
    /// The gated success: under [`StdoutRule::RefuseToken`], stdout still holding the token (the first secret) is
    /// refused as api refuses an unsafe body (design D6; the email or cursor may be data); the stderr `note` is
    /// redacted against every secret and gated as an error is.
    #[cfg(feature = "webui")]
    pub(crate) fn success(
        stdout: Vec<u8>,
        note: &str,
        json: bool,
        secrets: &[&str],
        rule: StdoutRule,
    ) -> Self {
        let token = secrets.first().copied().unwrap_or_default();
        if rule == StdoutRule::RefuseToken
            && !token.is_empty()
            && (stdout
                .windows(token.len())
                .any(|window| window == token.as_bytes())
                || (json && decoded_holds(&stdout, token)))
        {
            return CliError::new(
                CliExit::LocalFailure,
                UNSAFE_BODY_MESSAGE,
                UNSAFE_BODY_REMEDY,
            )
            .outcome(json, secrets);
        }
        let secrets = owned(secrets);
        Self {
            stdout,
            stderr: gated(redact::text(note, &secrets), &secrets),
            exit: CliExit::Ok,
        }
    }

    /// An outcome as given, for the emitter's rows: they stage what a write failure meets.
    #[cfg(all(test, feature = "webui"))]
    pub(crate) fn raw(stdout: Vec<u8>, stderr: String, exit: CliExit) -> Self {
        Self {
            stdout,
            stderr,
            exit,
        }
    }

    /// Read-only views for the rows; production prints an outcome only through [`emit`].
    #[cfg(test)]
    pub(crate) fn exit(&self) -> CliExit {
        self.exit
    }

    #[cfg(test)]
    pub(crate) fn stdout(&self) -> &[u8] {
        &self.stdout
    }

    #[cfg(test)]
    pub(crate) fn stderr(&self) -> &str {
        &self.stderr
    }
}

pub(crate) struct CliError {
    pub(crate) kind: CliExit,
    pub(crate) message: String,
    pub(crate) remedy: String,
    pub(crate) http_status: Option<u16>,
    pub(crate) request_id: Option<String>,
}

impl CliError {
    pub(crate) fn new(
        kind: CliExit,
        message: impl Into<String>,
        remedy: impl Into<String>,
    ) -> Self {
        Self {
            kind,
            message: message.into(),
            remedy: remedy.into(),
            http_status: None,
            request_id: None,
        }
    }

    /// The gated failure: each field redacted against every secret; if the printed text still holds one, the
    /// fixed sentence, or nothing if even that holds one.
    pub(crate) fn outcome(self, json: bool, secrets: &[&str]) -> CliOutcome {
        let secrets = owned(secrets);
        // Redact values before serialization: a secret resembling JSON
        // punctuation must never replace JSON syntax.
        let message = redact::text(&self.message, &secrets);
        let remedy = redact::text(&self.remedy, &secrets);
        let request_id = self.request_id.map(|id| redact::text(&id, &secrets));
        let stderr = if json {
            let error = serde_json::json!({
                "schema_version": 1,
                "error": {
                    "kind": self.kind,
                    "message": message,
                    "remedy": remedy,
                    "http_status": self.http_status,
                    "request_id": request_id,
                },
            });
            format!("{error}\n")
        } else {
            format!("error: {message}\n{remedy}\n")
        };
        // Fixed fields (kind, schema_version, http_status) and the "error: "
        // prefix are never redacted, so a secret equal to one of them would
        // still show: the gate decides on the text as printed.
        let stderr = gated(stderr, &secrets);
        CliOutcome {
            stdout: Vec::new(),
            stderr,
            exit: self.kind,
        }
    }
}

/// api's uncertain-outcome, unsafe-body and protocol sentences, shared by every converted command (design D2, D4).
#[cfg(feature = "webui")]
pub(crate) const UNCERTAIN_MESSAGE: &str = "The gateway may have applied this change.";
#[cfg(feature = "webui")]
pub(crate) const UNCERTAIN_REMEDY: &str =
    "Inspect the gateway state before retrying; this command did not retry.";
#[cfg(feature = "webui")]
pub(crate) const UNSAFE_BODY_MESSAGE: &str = "The response could not be printed safely.";
#[cfg(feature = "webui")]
pub(crate) const UNSAFE_BODY_REMEDY: &str = "The response was received but could not be printed safely; inspect the gateway state before sending the request again.";
#[cfg(feature = "webui")]
pub(crate) const PROTOCOL_MESSAGE: &str = "The gateway returned an invalid response.";
#[cfg(feature = "webui")]
pub(crate) const PROTOCOL_REMEDY: &str = "Check the gateway response against UI API 1.";

/// Whether `stdout`, read as one JSON document, holds `token` in any string or object key once decoded: JSON
/// escaping turns a `"` or `\` in a token into two bytes, so the byte search alone can miss it (MIK-9764.JSONF.1,
/// design D9). A stdout that is not JSON decodes to nothing; the byte search still covers it.
#[cfg(feature = "webui")]
fn decoded_holds(stdout: &[u8], token: &str) -> bool {
    fn walk(value: &serde_json::Value, token: &str) -> bool {
        match value {
            serde_json::Value::String(text) => text.contains(token),
            serde_json::Value::Array(items) => items.iter().any(|item| walk(item, token)),
            serde_json::Value::Object(map) => map
                .iter()
                .any(|(key, item)| key.contains(token) || walk(item, token)),
            _ => false,
        }
    }
    serde_json::from_slice::<serde_json::Value>(stdout).is_ok_and(|value| walk(&value, token))
}

/// The secrets that can be printed against: an empty value hides nothing.
fn owned(secrets: &[&str]) -> Vec<String> {
    secrets
        .iter()
        .filter(|secret| !secret.is_empty())
        .map(|secret| (*secret).to_owned())
        .collect()
}

/// `text` as printed when it holds no secret; else the fixed sentence, or nothing if even that holds one.
fn gated(text: String, secrets: &[String]) -> String {
    let holds = |text: &str| secrets.iter().any(|secret| text.contains(secret.as_str()));
    if !holds(&text) {
        text
    } else if holds(UNPRINTABLE_ERROR) {
        String::new()
    } else {
        UNPRINTABLE_ERROR.to_string()
    }
}

/// Whether a request changes gateway state, which decides what a lost or failed answer means (design D3).
#[cfg(feature = "webui")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Request {
    Read,
    Mutation,
}

/// The exit for a transport failure (api's decisions, moved; design D1): a bad target or settings 2, local I/O 1,
/// DNS, connect and TLS 5; a lost or oversized answer 8 on a mutation (it may have run), else 5.
#[cfg(feature = "webui")]
pub(crate) fn transport_kind(kind: AdminFailureKind, request: Request) -> CliExit {
    match kind {
        AdminFailureKind::Target | AdminFailureKind::Settings => CliExit::Usage,
        AdminFailureKind::LocalIo => CliExit::LocalFailure,
        AdminFailureKind::Dns | AdminFailureKind::Connect | AdminFailureKind::Tls => {
            CliExit::Network
        }
        AdminFailureKind::ResponseLost | AdminFailureKind::ResponseTooLarge => match request {
            Request::Mutation => CliExit::UncertainOutcome,
            Request::Read => CliExit::Network,
        },
    }
}

/// The exit for a gateway answer, `None` for a success (api's order, moved; design D1): an explicit uncertainty
/// 8; a mutation's 5xx not known not to have run 8; an unsupported API version 6; a success known not to have run
/// 6; any other success none; 401 and 403 3; 404 4; any other status 6.
#[cfg(feature = "webui")]
pub(crate) fn status_kind(
    status: reqwest::StatusCode,
    body: &serde_json::Value,
    request: Request,
) -> Option<CliExit> {
    let code = gateway_code(body);
    let explicit = body["disposition"].as_str() == Some("may_have_run")
        || matches!(code.as_deref(), Some("state_uncertain" | "may_have_run"));
    let not_run = known_not_run(status, body) && !explicit;
    Some(
        if explicit || (request == Request::Mutation && status.is_server_error() && !not_run) {
            CliExit::UncertainOutcome
        } else if code.as_deref() == Some("unsupported_version") || (status.is_success() && not_run)
        {
            CliExit::Gateway
        } else if status.is_success() {
            return None;
        } else if matches!(
            status,
            reqwest::StatusCode::UNAUTHORIZED | reqwest::StatusCode::FORBIDDEN
        ) {
            CliExit::AuthRefused
        } else if status == reqwest::StatusCode::NOT_FOUND {
            CliExit::NotFound
        } else {
            CliExit::Gateway
        },
    )
}

#[cfg(feature = "webui")]
pub(crate) fn unsafe_target() -> CliError {
    CliError::new(
        CliExit::Usage,
        "Gateway URL must use HTTPS or loopback HTTP.",
        "Use an HTTPS gateway URL or a loopback HTTP URL.",
    )
}

/// api's transport messages for a failure before an answer was read, with the kind [`transport_kind`] decides.
#[cfg(feature = "webui")]
pub(crate) fn transport_failure(error: AdminCallError, request: Request, token: &str) -> CliError {
    let kind = transport_kind(error.kind, request);
    let mut failure = match error.kind {
        AdminFailureKind::Target => unsafe_target(),
        AdminFailureKind::LocalIo | AdminFailureKind::Settings => CliError::new(
            kind,
            error.detail,
            "Check the gateway hostname, CA and client identity files, then retry.",
        ),
        AdminFailureKind::Dns => CliError::new(
            kind,
            "Gateway host could not be resolved.",
            "Check the gateway hostname and DNS settings, then retry.",
        ),
        AdminFailureKind::Connect => CliError::new(
            kind,
            "Could not connect to the gateway.",
            "Check the gateway address and listener, then retry.",
        ),
        AdminFailureKind::Tls => CliError::new(
            kind,
            "Gateway TLS verification failed.",
            "Check the gateway hostname, CA and client identity files, then retry.",
        ),
        AdminFailureKind::ResponseTooLarge => CliError::new(
            kind,
            "Gateway response exceeded 16 MiB.",
            "Narrow the request or read the data in smaller pages.",
        ),
        AdminFailureKind::ResponseLost if request == Request::Mutation => {
            CliError::new(kind, UNCERTAIN_MESSAGE, UNCERTAIN_REMEDY)
        }
        AdminFailureKind::ResponseLost => CliError::new(
            kind,
            "Gateway response was interrupted.",
            "Repeat the read request.",
        ),
    };
    failure.http_status = error.status.map(|s| s.as_u16());
    failure.request_id = error.request_id.and_then(|id| safe_text(&id, token));
    failure
}

/// Only bounded, single-line diagnostic values from known fields are shown.
#[cfg(feature = "webui")]
pub(crate) fn safe_text(text: &str, token: &str) -> Option<String> {
    let text = redact::text(text, &[token.to_string()]);
    (!text.is_empty() && text.len() <= 4096 && !text.chars().any(char::is_control)).then_some(text)
}

#[cfg(feature = "webui")]
pub(crate) fn gateway_code(body: &Value) -> Option<String> {
    let value = body
        .get("error")
        .and_then(|error| error.get("code"))
        .or_else(|| body.get("error").filter(|error| error.is_string()));
    match value {
        Some(Value::Number(code)) => Some(code.to_string()),
        Some(Value::String(code))
            if !code.is_empty()
                && code.len() <= 128
                && code
                    .bytes()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'_' | b'-' | b'.')) =>
        {
            Some(code.clone())
        }
        _ => None,
    }
}

#[cfg(feature = "webui")]
pub(crate) fn known_not_run(status: reqwest::StatusCode, body: &Value) -> bool {
    body["disposition"].as_str() == Some("not_run")
        || (status == reqwest::StatusCode::SERVICE_UNAVAILABLE
            && body["jsonrpc"].as_str() == Some("2.0")
            && body["error"]["code"].as_i64() == Some(-32003)
            && body["error"]["message"].is_string()
            && body.get("id") == Some(&Value::Null))
}

/// The credential to send, or the refusal that ends the command before any
/// request: none, empty, or holding a control character (a credential travels
/// in a header line, so it can never hold CR or LF).
#[cfg(feature = "webui")]
pub(crate) fn resolve_token(
    credential: Result<String, TokenError>,
    origin: &str,
) -> Result<String, CliError> {
    match credential {
        Ok(token) if token.chars().any(char::is_control) => Err(CliError::new(
            CliExit::Usage,
            "MCP_GATEWAY_TOKEN holds a control character.",
            "Unset or replace MCP_GATEWAY_TOKEN, then retry.",
        )),
        Ok(token) => Ok(token),
        Err(TokenError::Missing) => Err(CliError::new(
            CliExit::AuthRefused,
            "No gateway credential is available.",
            token_remedy(origin),
        )),
        Err(TokenError::Blank) => Err(CliError::new(
            CliExit::Usage,
            "MCP_GATEWAY_TOKEN is empty.",
            "Unset or replace MCP_GATEWAY_TOKEN, then retry.",
        )),
    }
}

/// The remedy for a missing or refused token (design D4).
#[cfg(feature = "webui")]
pub(crate) fn token_remedy(origin: &str) -> String {
    format!("Set MCP_GATEWAY_TOKEN to a valid token for {origin}, then retry.")
}

/// Prints a buffered outcome through `stdout` and `stderr`: a broken pipe on stdout ends with exit 0; any other
/// stdout write failure becomes the gated `Could not write command output.` error, exit 1; a stderr write failure
/// is exit 1 (api's `write_outcome`, moved).
pub(crate) fn emit_to(
    outcome: &CliOutcome,
    json: bool,
    secrets: &[&str],
    stdout: &mut impl std::io::Write,
    stderr: &mut impl std::io::Write,
) -> CliExit {
    // Nothing to print touches no stdout: after a streamed deadline, the
    // printing thread may still be parked in a write holding stdout's lock.
    let written = if outcome.stdout.is_empty() {
        Ok(())
    } else {
        stdout.write_all(&outcome.stdout)
    };
    if let Err(error) = written {
        if error.kind() == std::io::ErrorKind::BrokenPipe {
            return CliExit::Ok;
        }
        let failure = CliError::new(
            CliExit::LocalFailure,
            "Could not write command output.",
            "Check the output destination before repeating the command.",
        )
        .outcome(json, secrets);
        let _ = stderr.write_all(failure.stderr.as_bytes());
        return failure.exit;
    }
    if stderr.write_all(outcome.stderr.as_bytes()).is_err() {
        return CliExit::LocalFailure;
    }
    outcome.exit
}

/// [`emit_to`] on the process's stdout and stderr, as the process exit.
pub(crate) fn emit(outcome: &CliOutcome, json: bool, secrets: &[&str]) -> std::process::ExitCode {
    // Not locked up front: a streamed run's printing thread may hold stdout past its deadline, and an empty answer
    // must not wait.
    std::process::ExitCode::from(
        emit_to(
            outcome,
            json,
            secrets,
            &mut std::io::stdout(),
            &mut std::io::stderr().lock(),
        )
        .code(),
    )
}

// The three ways command code leaves with a non-zero code.

/// `text` with each line break (LF, CR LF or a lone CR) written as one space, so a path or an OS error cannot split
/// the two-line error shape.
fn one_line(text: &str) -> String {
    text.replace("\r\n", " ").replace(['\n', '\r'], " ")
}

/// The remedy line of a usage error: the command's own `--help`.
fn usage_remedy(command: &str) -> String {
    format!("Run 'mcp-gateway {command} --help' for usage.")
}

/// The two-line outcome `fail` prints: `error: <message>` and the remedy, each on one line.
fn error_outcome(kind: CliExit, message: &str, remedy: &str) -> CliOutcome {
    debug_assert!(!remedy.is_empty(), "a local error needs a remedy line");
    CliError::new(kind, one_line(message), one_line(remedy)).outcome(false, &[])
}

/// The outcome `usage` prints: exit 2, the remedy naming `command`'s help.
fn usage_outcome(command: &str, message: &str) -> CliOutcome {
    error_outcome(CliExit::Usage, message, &usage_remedy(command))
}

/// A local failure: prints `error: <message>` and the remedy on stderr and returns `kind`'s code. The remedy must
/// not be empty.
pub(crate) fn fail(kind: CliExit, message: &str, remedy: &str) -> std::process::ExitCode {
    emit(&error_outcome(kind, message, remedy), false, &[])
}

/// A wrong invocation of `command` (its leaf path, e.g. `tls issue-server`): exit 2, the remedy its `--help`.
pub(crate) fn usage(command: &str, message: &str) -> std::process::ExitCode {
    emit(&usage_outcome(command, message), false, &[])
}

/// A command that ran and whose answer is negative (a check failed, a file has findings): prints nothing, returns
/// `code`. The command has already printed its result.
pub(crate) fn verdict(code: u8) -> std::process::ExitCode {
    mutant!("K36", { eprintln!("verdict {code}"); std::process::ExitCode::from(code) }, std::process::ExitCode::from(code))
}

#[cfg(tp2)]
#[cfg(test)]
#[path = "cli_exit_tests.rs"]
mod tests;

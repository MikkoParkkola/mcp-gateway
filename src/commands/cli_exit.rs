// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The CLI's shared exit table and error shape (design D1), moved unchanged from the api command.

use mcp_gateway::cli::redact;

/// Exit table E. Each kind has one process code, independent of HTTP status.
/// What an error becomes when its rendering would still contain the token.
const UNPRINTABLE_ERROR: &str =
    "error: The error report could not be printed without exposing the credential.\n";

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize)]
pub(crate) enum CliExit {
    Ok,
    LocalFailure,
    Usage,
    AuthRefused,
    NotFound,
    Network,
    Gateway,
    #[allow(dead_code, reason = "reserved by the shared exit table")]
    Declined,
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
pub(crate) struct CliOutcome {
    pub(crate) stdout: Vec<u8>,
    pub(crate) stderr: String,
    pub(crate) exit: CliExit,
}

/// What a success's stdout must satisfy before it prints (design D1).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum StdoutRule {
    /// The converted commands: refused when stdout still holds a secret after redaction (D6).
    RefuseToken,
    /// api: the body already passed its own entry-loss check, so stdout is printed as given.
    RedactedJsonBody,
}

impl CliOutcome {
    /// The gated success: stdout under `rule`, the stderr `note` redacted and gated as an error is.
    ///
    /// Red scaffold: prints both as given, as the commands did before the move.
    pub(crate) fn success(
        stdout: Vec<u8>,
        note: String,
        json: bool,
        secrets: &[&str],
        rule: StdoutRule,
    ) -> Self {
        let _ = (json, secrets, rule);
        Self {
            stdout,
            stderr: note,
            exit: CliExit::Ok,
        }
    }

    pub(crate) fn exit(&self) -> CliExit {
        self.exit
    }

    pub(crate) fn stdout(&self) -> &[u8] {
        &self.stdout
    }

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
    ///
    /// Red scaffold: gates on the first secret only, api's behaviour before the move.
    pub(crate) fn outcome(self, json: bool, secrets: &[&str]) -> CliOutcome {
        let token = secrets.first().copied().unwrap_or_default();
        // Redact values before serialization: a token resembling JSON
        // punctuation must never replace JSON syntax.
        let message = redact::text(&self.message, &[token.to_string()]);
        let remedy = redact::text(&self.remedy, &[token.to_string()]);
        let request_id = self
            .request_id
            .map(|id| redact::text(&id, &[token.to_string()]));
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
        // Fixed fields (kind, schema_version, http_status) are never
        // redacted, so a token equal to one of them would still show. Then
        // print one fixed token-free sentence instead of the report, or
        // nothing if even that sentence contains the token.
        let stderr = if !token.is_empty() && stderr.contains(token) {
            if UNPRINTABLE_ERROR.contains(token) {
                String::new()
            } else {
                UNPRINTABLE_ERROR.to_string()
            }
        } else {
            stderr
        };
        CliOutcome {
            stdout: Vec::new(),
            stderr,
            exit: self.kind,
        }
    }
}

/// Prints a buffered outcome through `stdout` and `stderr`: a broken pipe on stdout ends with exit 0; any other
/// stdout write failure becomes the gated `Could not write command output.` error, exit 1; a stderr write failure
/// is exit 1 (api's `write_outcome`, moved).
///
/// Red scaffold: gates on the first secret only, api's behaviour before the move.
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

#[cfg(test)]
#[path = "cli_exit_tests.rs"]
mod tests;

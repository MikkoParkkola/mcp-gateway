// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Shared diagnostic helpers that must not echo credentials.
//!
//! MIK-7222: HTTP transport grew `safe_request_error` / `safe_http_status_error`
//! for PR #439. Other modules still interpolated reqwest Display, OAuth bodies,
//! and raw stdio command lines. One definition, many callers.

use reqwest::StatusCode;

use crate::Error;
use crate::security::sanitize::redact_url_for_diagnostics;

/// Marker `is_session_expired_error` reads. Writer and reader must stay a pair.
pub const SESSION_EXPIRED_MARKER: &str = "session expired";

/// Classify a reqwest failure without keeping its Display (which embeds URLs).
#[must_use]
pub fn request_error_category(error: &reqwest::Error) -> &'static str {
    if error.is_timeout() {
        "timeout"
    } else if error.is_connect() {
        "connection failed"
    } else if error.is_redirect() {
        "redirect rejected"
    } else if error.is_decode() {
        "response parse failed"
    } else {
        "request failed"
    }
}

/// Context + category, never `reqwest::Error` Display (that embeds the URL).
#[must_use]
pub fn safe_reqwest_message(context: &str, error: &reqwest::Error) -> String {
    format!("{context}: {}", request_error_category(error))
}

/// Transport-layer reqwest failure: context + category, never `{e}`.
#[must_use]
pub fn safe_request_error(context: &str, error: &reqwest::Error) -> Error {
    Error::Transport(safe_reqwest_message(context, error))
}

/// HTTP status without an untrusted body, except the session-expiry signal.
#[must_use]
pub fn safe_http_status_error(status: StatusCode, body: &str) -> Error {
    Error::Transport(safe_status_text(status, body))
}

/// OAuth token-endpoint / registration failure. Status stays; body does not.
#[must_use]
pub fn safe_oauth_http_error(context: &str, status: StatusCode, body: &str) -> String {
    format!("{context}: {}", safe_status_text(status, body))
}

fn safe_status_text(status: StatusCode, body: &str) -> String {
    let lower = body.to_ascii_lowercase();
    if body.contains("-32015") || lower.contains("session not found") {
        format!("HTTP {status}: {SESSION_EXPIRED_MARKER}")
    } else {
        format!("HTTP {status}")
    }
}

/// Stdio command for diagnostics: executable name + argument count, never argv.
#[must_use]
pub fn summarize_stdio_command(command: &str) -> String {
    match shlex::split(command) {
        Some(parts) if !parts.is_empty() => {
            let n = parts.len().saturating_sub(1);
            format!("{} ({n} argument(s) redacted)", parts[0])
        }
        Some(_) => "empty command".to_string(),
        None => "invalid quoting (command redacted)".to_string(),
    }
}

/// Origin-only URL for logs and doctor hints.
#[must_use]
pub fn diagnostic_url(raw: &str) -> String {
    redact_url_for_diagnostics(raw)
}

#[cfg(test)]
mod tests {
    use super::*;

    const CANARY: &str = "SENTINEL_SWEEP_7222";

    #[test]
    fn oauth_and_status_drop_body_canary() {
        let body = format!("{{\"access_token\":\"{CANARY}\",\"client_secret\":\"{CANARY}\"}}");
        let redacted =
            safe_oauth_http_error("Client credentials failed", StatusCode::UNAUTHORIZED, &body);
        assert!(!redacted.contains(CANARY));
        assert!(redacted.contains("HTTP 401"));
        let err = safe_http_status_error(StatusCode::BAD_REQUEST, &body);
        assert!(!err.to_string().contains(CANARY), "{err}");
    }

    #[test]
    fn session_expiry_marker_survives() {
        let body = format!("{{\"code\":-32015,\"message\":\"Session not found {CANARY}\"}}");
        let err = safe_http_status_error(StatusCode::BAD_REQUEST, &body);
        assert!(err.to_string().contains(SESSION_EXPIRED_MARKER));
        assert!(!err.to_string().contains(CANARY));
    }

    #[test]
    fn stdio_summary_never_echoes_argv() {
        let cmd = format!("npx --api-key {CANARY} -y server");
        let out = summarize_stdio_command(&cmd);
        assert!(!out.contains(CANARY), "{out}");
        assert!(out.contains("npx"), "{out}");
        assert!(out.contains("argument(s) redacted"), "{out}");
        let bad = summarize_stdio_command(&format!("\"unclosed {CANARY}"));
        assert!(!bad.contains(CANARY), "{bad}");
        assert_eq!(bad, "invalid quoting (command redacted)");
    }
}

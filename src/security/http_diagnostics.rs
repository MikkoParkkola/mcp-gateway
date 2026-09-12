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
///
/// Returns the coarse [`Error::Transport`], which ADR-012 settles as terminal.
/// Use [`safe_request_error_for`] at a site that dispatches a side-effecting
/// request and can name the URL it posted to.
#[must_use]
pub fn safe_request_error(context: &str, error: &reqwest::Error) -> Error {
    Error::Transport(safe_reqwest_message(context, error))
}

/// Whether the caller can prove its request never followed a redirect.
///
/// A bare `bool` here selects behaviour on the one argument whose two values
/// mean "a retry is safe" and "a retry may re-execute a side effect", and it
/// reads identically at a call site whichever way round it is passed. Naming
/// both states makes a transposition a compile error rather than a silent
/// downgrade -- or, worse, a silent upgrade.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RedirectEvidence {
    /// The caller sampled a redirect counter either side of the send and it
    /// did not move, so the request stayed at the origin it was addressed to.
    NoRedirectFollowed,
    /// The caller cannot prove that. Either a hop was taken, or the caller has
    /// no counter to consult; both settle terminally.
    MayHaveRedirected,
}

/// As [`safe_request_error`], but proves a connect failure is pre-dispatch.
///
/// `redirect_evidence` is the caller's evidence that the request never left
/// the origin it was addressed to: the dispatch site samples the transport's
/// redirect counter either side of `send()` and reports whether it moved. Only
/// a connect failure on a request that followed no redirect is upgraded to
/// [`Error::TransportConnect`], which `Error::is_pre_dispatch` admits and the
/// idempotency layer therefore releases rather than settling as terminal.
///
/// Every other shape -- a timeout, a decode failure, a connect failure after a
/// redirect -- returns [`Error::Transport`] unchanged. A 307 re-submits the
/// request body, so a connect failure to a redirect target says nothing about
/// whether the origin that redirected had already executed the call.
///
/// The counter, not `reqwest::Error::url()`, carries this signal. The URL
/// comparison an earlier revision used cannot see a redirect at all: reqwest
/// back-fills the error's URL with the *original* request URL
/// (`if_no_url` on the error path) and only rewrites it to the current hop on
/// the success path, so the two URLs are equal whether or not a hop was taken.
/// The transport-level row `a_connect_failure_after_a_followed_redirect_is_not_pre_dispatch`
/// is what holds this apart; the rows below only pin the classifier itself.
#[must_use]
pub fn safe_request_error_for(
    context: &str,
    error: &reqwest::Error,
    redirect_evidence: RedirectEvidence,
) -> Error {
    let message = safe_reqwest_message(context, error);
    if error.is_connect() && redirect_evidence == RedirectEvidence::NoRedirectFollowed {
        Error::TransportConnect(message)
    } else {
        Error::Transport(message)
    }
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

    /// A dead port: bind to learn a free address, then give it up.
    async fn closed_port() -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind ephemeral port");
        let address = listener.local_addr().expect("local addr");
        drop(listener);
        format!("http://{address}/mcp")
    }

    /// An unredirected connect failure is provably pre-dispatch: nothing was
    /// written, so the idempotency key must be released rather than settled.
    #[tokio::test]
    async fn an_unredirected_connect_failure_is_pre_dispatch() {
        let url = closed_port().await;
        let error = reqwest::Client::new()
            .post(&url)
            .send()
            .await
            .expect_err("a dead port must refuse the connection");
        assert!(error.is_connect(), "precondition: {error}");

        let classified = safe_request_error_for(
            "Request failed",
            &error,
            RedirectEvidence::NoRedirectFollowed,
        );
        assert!(
            classified.is_pre_dispatch(),
            "a refused connection wrote no bytes, so the key must be released: {classified}"
        );
        assert!(matches!(classified, Error::TransportConnect(_)));
        assert_eq!(
            classified.to_rpc_code(),
            -32000,
            "the wire contract is unchanged"
        );
    }

    /// A connect failure the caller cannot vouch for stays coarse. The
    /// caller's evidence is a redirect counter it sampled around the send;
    /// when that moved, the body may already have been delivered to the origin
    /// that redirected, so the failure keeps today's terminal settlement.
    /// The end-to-end proof that the counter actually moves on a followed
    /// redirect is
    /// `a_connect_failure_after_a_followed_redirect_is_not_pre_dispatch` in
    /// `src/transport/http/tests.rs` -- this row only pins the classifier.
    #[tokio::test]
    async fn a_connect_failure_the_caller_cannot_vouch_for_stays_coarse() {
        let url = closed_port().await;
        let error = reqwest::Client::new()
            .post(&url)
            .send()
            .await
            .expect_err("a dead port must refuse the connection");
        assert!(error.is_connect(), "precondition: {error}");

        let classified = safe_request_error_for(
            "Request failed",
            &error,
            RedirectEvidence::MayHaveRedirected,
        );
        assert!(
            !classified.is_pre_dispatch(),
            "is_connect() alone must never upgrade: {classified}"
        );
        assert!(matches!(classified, Error::Transport(_)));
    }

    /// A non-connect failure is never upgraded, whatever URL it carries.
    #[tokio::test]
    async fn a_timeout_is_not_pre_dispatch() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind ephemeral port");
        let address = listener.local_addr().expect("local addr");
        // Accept and never answer, so the client times out with the connection
        // established -- the request WAS written.
        tokio::spawn(async move {
            // Hold the accepted connection open forever. Binding it rather than
            // dropping it is the point: the client must see an established
            // connection that never answers, which is a timeout, not a connect
            // failure.
            let _held = listener.accept().await;
            std::future::pending::<()>().await;
        });
        let url = format!("http://{address}/mcp");
        let error = reqwest::Client::new()
            .post(&url)
            .timeout(std::time::Duration::from_millis(250))
            .send()
            .await
            .expect_err("the server never answers");

        let classified = safe_request_error_for(
            "Request failed",
            &error,
            RedirectEvidence::NoRedirectFollowed,
        );
        assert!(
            !classified.is_pre_dispatch(),
            "the connection was established, so the request may have been read: {classified}"
        );
    }

    /// The coarse constructor keeps its old behaviour for the five call sites
    /// that stay on it -- the SSE reads and the notification send, all of which
    /// are post-dispatch by construction.
    #[tokio::test]
    async fn the_coarse_constructor_never_returns_the_narrow_variant() {
        let url = closed_port().await;
        let error = reqwest::Client::new()
            .post(&url)
            .send()
            .await
            .expect_err("a dead port must refuse the connection");

        let classified = safe_request_error("SSE connection failed", &error);
        assert!(matches!(classified, Error::Transport(_)));
        assert!(!classified.is_pre_dispatch());
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

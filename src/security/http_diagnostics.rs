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
/// Returns the coarse [`Error::Transport`], which ADR-012 settles as terminal,
/// except for a destination the SSRF pin refused, which is `Error::Protocol`
/// (`-32600 SSRF blocked`).
/// Use [`safe_request_error_for`] at a site that dispatches a side-effecting
/// request and can name the URL it posted to.
#[must_use]
pub fn safe_request_error(context: &str, error: &reqwest::Error) -> Error {
    ssrf_refusal(error).unwrap_or_else(|| Error::Transport(safe_reqwest_message(context, error)))
}

/// A destination the SSRF pin refused, typed `-32600 SSRF blocked` in every
/// posture: a policy answer, never a connect failure to retry.
pub(crate) fn ssrf_refusal(error: &reqwest::Error) -> Option<Error> {
    crate::security::ssrf::ssrf_denial(error).map(|denied| Error::Protocol(denied.to_string()))
}

/// An OAuth request's failed send: a destination-policy refusal stays
/// `-32600 SSRF blocked` (MIK-7701); anything else is an OAuth failure naming
/// `context` and the error's category, never its Display (that embeds the URL).
pub(crate) fn oauth_request_error(context: &str, error: &reqwest::Error) -> Error {
    ssrf_refusal(error).unwrap_or_else(|| Error::OAuth(safe_reqwest_message(context, error)))
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
/// A destination the SSRF pin refused is `Error::Protocol`, as in
/// [`safe_request_error`]. Every other shape -- a timeout, a decode failure, a
/// connect failure after a redirect -- returns [`Error::Transport`] unchanged. A 307 re-submits the
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
    if let Some(refused) = ssrf_refusal(error) {
        return refused;
    }
    let message = safe_reqwest_message(context, error);
    if error.is_connect() && redirect_evidence == RedirectEvidence::NoRedirectFollowed {
        Error::TransportConnect(message)
    } else {
        Error::Transport(message)
    }
}

/// HTTP status without an untrusted body, except the session-expiry signal.
///
/// MIK-7979: a 4xx the server answered with is `TransportPermanent`, so a
/// same-key retry is served that answer rather than told the outcome is
/// undetermined, and nothing retries a refusal. The exceptions stay
/// `Transport`: 400 and 404 (with or without a marker) and any status whose
/// body carries the session-expiry marker, because the HTTP transport reads an
/// expired session from `Transport` text and re-initializes (#247); 401, 403
/// and 407 (credential refusals, typed or re-initialized elsewhere); 408 and
/// 429 (transient: retrying is the right answer). A 5xx does not prove the work
/// did not run, so it stays `Transport` too.
///
/// This list is not `refused_as_wrong_transport`'s and must not be aligned
/// with it: that one asks "is this the wrong transport?", and a 400 or 404 can
/// mean so while still having to stay re-initializable here.
#[must_use]
pub fn safe_http_status_error(status: StatusCode, body: &str) -> Error {
    let text = safe_status_text(status, body);
    let answered = status.is_client_error()
        && !matches!(status.as_u16(), 400 | 401 | 403 | 404 | 407 | 408 | 429)
        && !carries_session_expiry(body);
    if answered {
        Error::TransportPermanent(text)
    } else {
        Error::Transport(text)
    }
}

/// A11-g: a credential refusal the backend answers the same way however often
/// it is asked, so it is typed and never retried. Not 400 or 404: the HTTP
/// transport reads an expired MCP session from their `Error::Transport` text
/// (`transport::http::is_session_expired_error`), and typing them would stop
/// the session from being re-initialized.
pub(crate) const fn is_deterministic_refusal(status: StatusCode) -> bool {
    matches!(status, StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN)
}

/// A non-2xx the HTTP transport answers with. A credential refusal keeps its
/// typed status (A11-b), URL stripped; anything else keeps today's safe
/// transport text, which MCP session-expiry detection reads.
pub(crate) fn status_refusal(
    typed: Option<reqwest::Error>,
    status: StatusCode,
    body: &str,
) -> Error {
    match typed {
        // A 401/403 whose body says the session expired keeps the marker, so
        // the transport re-initializes the session instead (as for 400/404).
        Some(e) if is_deterministic_refusal(status) && !carries_session_expiry(body) => {
            Error::Http(e.without_url())
        }
        _ => safe_http_status_error(status, body),
    }
}

/// A11-b: the backend refused the presented credential. Read from the typed
/// status only, never from body text, or from the CLI executor's own refusal
/// (`personal_accounts/refusal.rs`; MIK-7926.FIX.4).
pub(crate) fn is_upstream_unauthorized(error: &Error) -> bool {
    matches!(error, Error::Http(e) if e.status() == Some(StatusCode::UNAUTHORIZED))
        || matches!(error, Error::CliCredentialRefused { .. })
}

/// The code a CLI capability's refusal of its credential
/// ([`Error::CliCredentialRefused`]) is reported to the caller with (gws exits
/// 2 with a JSON error whose code is 401, MIK-7782).
pub(crate) const CLI_UNAUTHORIZED: i32 = 401;

/// OAuth token-endpoint / registration failure. Status stays; body does not.
#[must_use]
pub fn safe_oauth_http_error(context: &str, status: StatusCode, body: &str) -> String {
    format!("{context}: {}", safe_status_text(status, body))
}

/// Whether a non-2xx body says the MCP session expired (JSON-RPC `-32015`,
/// "session not found" or "session expired"), which the transport answers by
/// re-initializing. The phrases are the ones the transport's classifier reads
/// from a parsed refusal (`transport::http::is_session_expired_error`), so a
/// peer's expiry is recovered whether or not its body parsed (MIK-7717).
fn carries_session_expiry(body: &str) -> bool {
    let lower = body.to_ascii_lowercase();
    body.contains("-32015")
        || lower.contains("session not found")
        || lower.contains(SESSION_EXPIRED_MARKER)
}

fn safe_status_text(status: StatusCode, body: &str) -> String {
    if carries_session_expiry(body) {
        format!("HTTP {status}: {SESSION_EXPIRED_MARKER}")
    } else {
        format!("HTTP {status}")
    }
}

/// Stdio command for diagnostics: executable name + argument count, never argv.
#[must_use]
pub fn summarize_stdio_command(command: &str) -> String {
    match crate::transport::split_command(command) {
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

    /// A typed `reqwest::Error` for `status`, as the transport captures it.
    fn typed(status: u16) -> Option<reqwest::Error> {
        let response = axum::http::Response::builder()
            .status(status)
            .body(String::new())
            .expect("fixture response builds");
        reqwest::Response::from(response).error_for_status().err()
    }

    /// A11 T19: a 401 or 403 is typed only when its body does NOT signal an
    /// expired MCP session. With the signal it keeps the untyped marker form
    /// the transport re-initializes on, as 400 and 404 always do.
    #[test]
    fn a_session_expiry_body_keeps_the_reinit_marker_on_401_and_403() {
        for status in [401_u16, 403] {
            let code = StatusCode::from_u16(status).expect("valid status");
            for body in ["session not found", r#"{"error":{"code":-32015}}"#] {
                match status_refusal(typed(status), code, body) {
                    Error::Transport(text) => assert!(
                        text.contains(SESSION_EXPIRED_MARKER),
                        "{status} {body}: {text}"
                    ),
                    other => panic!("{status} {body} must stay re-initializable: {other:?}"),
                }
            }
            assert!(
                matches!(
                    status_refusal(typed(status), code, "denied"),
                    Error::Http(_)
                ),
                "{status} with no session-expiry signal is a typed credential refusal"
            );
        }
        for status in [400_u16, 404] {
            let code = StatusCode::from_u16(status).expect("valid status");
            for body in ["denied", "session not found"] {
                assert!(
                    matches!(
                        status_refusal(typed(status), code, body),
                        Error::Transport(_)
                    ),
                    "{status} is never typed, with or without a session-expiry body"
                );
            }
        }
    }

    /// MIK-7979: a 4xx the server answered (other than the session-expiry,
    /// timeout and rate-limit codes) is `TransportPermanent`, so its
    /// settlement replays the answer; a 5xx and the transient or overloaded
    /// codes stay `Transport`.
    #[test]
    fn a_4xx_answer_is_typed_as_answered() {
        for status in [405_u16, 409, 410, 413, 415, 422] {
            let code = StatusCode::from_u16(status).expect("valid status");
            let error = status_refusal(typed(status), code, "refused");
            assert!(
                matches!(error, Error::TransportPermanent(_)),
                "{status}: {error:?}"
            );
            let expired = status_refusal(typed(status), code, "session not found");
            assert!(
                matches!(expired, Error::Transport(_)),
                "{status} with a session-expiry body stays re-initializable: {expired:?}"
            );
        }
        for status in [400_u16, 404, 407, 408, 429, 500, 502, 503] {
            let code = StatusCode::from_u16(status).expect("valid status");
            let error = status_refusal(typed(status), code, "refused");
            assert!(matches!(error, Error::Transport(_)), "{status}: {error:?}");
        }
    }

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

    /// A dead port, and the connection that keeps it dead (#1754): the
    /// client end of a live loopback connection owns the port without
    /// listening, so a connect to it is refused on every platform and no
    /// other process can bind the port and answer it, the way it could a
    /// dropped listener's port. The client is bound explicitly, without
    /// address reuse: a port `connect()` picks for itself can be handed to a
    /// later connect, which then reaches itself. (A bound socket that never
    /// connects is refused on Linux but times out on macOS.) Hold the pair
    /// until the request is done; it drops server end first, so the `TIME_WAIT`
    /// lands on the listener's port, not the explicitly bound one.
    async fn closed_port() -> (String, (tokio::net::TcpStream, tokio::net::TcpStream)) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind ephemeral port");
        let socket = tokio::net::TcpSocket::new_v4().expect("socket");
        socket.set_reuseaddr(false).expect("no address reuse");
        socket
            .bind("127.0.0.1:0".parse().expect("loopback"))
            .expect("bind client port");
        let client = socket
            .connect(listener.local_addr().expect("local addr"))
            .await
            .expect("connect");
        let (server, _) = listener.accept().await.expect("accept");
        let address = client.local_addr().expect("client addr");
        (format!("http://{address}/mcp"), (server, client))
    }

    /// An unredirected connect failure is provably pre-dispatch: nothing was
    /// written, so the idempotency key must be released rather than settled.
    #[tokio::test]
    async fn an_unredirected_connect_failure_is_pre_dispatch() {
        let (url, _held) = closed_port().await;
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
        let (url, _held) = closed_port().await;
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
        let (url, _held) = closed_port().await;
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

    /// MIK-7926.FIX.4: a peer's own JSON-RPC error that happens to use code
    /// 401 is not a credential refusal. Only the typed status, or the CLI
    /// executor's own refusal, is (A11-b).
    #[test]
    fn a_peers_json_rpc_code_401_is_not_an_upstream_refusal() {
        for data in [None, Some(serde_json::json!({"anything": true}))] {
            let peer = Error::JsonRpc {
                code: 401,
                message: "unauthorized".into(),
                data,
            };
            assert!(!is_upstream_unauthorized(&peer), "{peer:?}");
        }
    }
}

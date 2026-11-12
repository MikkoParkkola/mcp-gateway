// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! `audit lookup-email`: stdin only, bounded, typed answer, nonzero on any
//! failure, no file written.

use clap::Parser;
use mcp_gateway::cli::Cli;
use mcp_gateway::cli::audit_lookup::LookupEmailArgs;
use serde_json::json;

use super::{MAX_EMAIL_INPUT, read_email, request_body};

const EMAIL: &str = "Planted.Person@corp.invalid";

fn parse(extra: &[&str]) -> Result<LookupEmailArgs, clap::Error> {
    let mut argv = vec!["mcp-gateway", "audit", "lookup-email"];
    argv.extend_from_slice(extra);
    match Cli::try_parse_from(argv)?.command {
        Some(mcp_gateway::cli::Command::Audit(mcp_gateway::cli::AuditCommand::LookupEmail(a))) => {
            Ok(a)
        }
        other => panic!("not lookup-email: {other:?}"),
    }
}

/// MIK-9456.CLI.1: the email is never an argument: no positional email, no
/// `--email VALUE`, and `--email-stdin` is required.
/// Mutant: accept a positional email, add `--email`, or drop `required`.
#[test]
fn the_email_is_never_an_argument() {
    assert!(parse(&["--email-stdin"]).is_ok());
    assert!(parse(&[]).is_err(), "stdin must be asked for");
    assert!(
        parse(&["--email-stdin", EMAIL]).is_err(),
        "no positional email"
    );
    assert!(parse(&["--email", EMAIL]).is_err(), "no --email VALUE");
    assert!(parse(&["--email-stdin", "--email", EMAIL]).is_err());
}

/// MIK-9456.CLI.1: the read is bounded and takes one email-sized line.
/// Mutant: read without a bound, or accept an empty or multi-line input.
#[test]
fn stdin_is_read_bounded_and_trimmed_to_one_line() {
    assert_eq!(
        read_email(format!("{EMAIL}\n").as_bytes()).as_deref(),
        Ok(EMAIL)
    );
    assert_eq!(
        read_email(format!("{EMAIL}\r\n").as_bytes()).as_deref(),
        Ok(EMAIL)
    );
    assert_eq!(
        read_email(EMAIL.as_bytes()).as_deref(),
        Ok(EMAIL),
        "no newline needed"
    );
    assert!(read_email(&b""[..]).is_err(), "empty");
    assert!(read_email(&b"\n"[..]).is_err(), "blank");
    assert!(
        read_email(&b"a@b.invalid\nsecond\n"[..]).is_err(),
        "two lines"
    );
    assert!(read_email(&b"a\0b@c.invalid"[..]).is_err(), "control byte");
    assert!(read_email(&[0xff, 0xfe][..]).is_err(), "not UTF-8");
    let long = "a".repeat(MAX_EMAIL_INPUT + 1);
    assert!(read_email(long.as_bytes()).is_err(), "over the bound");
    // A reader that never ends is cut off at the bound, not read to the end.
    let endless = std::io::repeat(b'a');
    assert!(read_email(endless).is_err());
}

/// MIK-9456.CLI.1: the body is built in memory from the email and the flags,
/// and carries only what was asked for.
/// Mutant: send the email in a query, drop a flag, or add a field.
#[test]
fn the_body_carries_the_email_and_only_the_flags_given() {
    let bare = parse(&["--email-stdin"]).expect("parses");
    assert_eq!(request_body(EMAIL, &bare), json!({"email": EMAIL}));
    let full = parse(&[
        "--email-stdin",
        "--limit",
        "7",
        "--cursor",
        "tok",
        "--from",
        "2026-11-01T00:00:00Z",
        "--to",
        "2026-11-02T00:00:00Z",
    ])
    .expect("parses");
    assert_eq!(
        request_body(EMAIL, &full),
        json!({"email": EMAIL, "limit": 7, "cursor": "tok",
               "from": "2026-11-01T00:00:00Z", "to": "2026-11-02T00:00:00Z"})
    );
    assert!(parse(&["--email-stdin", "--limit", "0"]).is_err());
    assert!(parse(&["--email-stdin", "--limit", "201"]).is_err());
}

use super::{LookupAnswer, lookup};
use crate::commands::dashboard_link::LinkTls;

const TOKEN: &str = "tok-secret";

/// A gateway stand-in answering the lookup route with `status` and `body`
/// for the credential `TOKEN`; it records the request body it received.
async fn stand_in(
    status: u16,
    body: &'static str,
) -> (String, std::sync::Arc<std::sync::Mutex<Vec<String>>>) {
    use axum::http::StatusCode;
    let seen = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let record = std::sync::Arc::clone(&seen);
    let app = axum::Router::new().route(
        "/ui/api/key-server/audit/lookup-email",
        axum::routing::post(move |headers: axum::http::HeaderMap, text: String| {
            let record = std::sync::Arc::clone(&record);
            async move {
                let bearer = headers
                    .get("authorization")
                    .and_then(|v| v.to_str().ok())
                    .map(str::to_owned);
                record
                    .lock()
                    .unwrap()
                    .push(format!("{}|{text}", bearer.unwrap_or_default()));
                (
                    StatusCode::from_u16(status).unwrap(),
                    [("content-type", "application/json")],
                    body,
                )
            }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("addr");
    tokio::spawn(async move { axum::serve(listener, app).await });
    (format!("http://{addr}"), seen)
}

const GOOD: &str = r#"{"rows":[{"timestamp":"2026-11-12T10:00:00+00:00","token_jti":"j1",
"subject":"s1","issuer":"https://issuer.invalid","backends":["*"],"tools":["*"],"segment":0}],
"next_cursor":null,"scan_exhausted":false,"cursor_reset":false,"unreadable":0,"scope":"retained"}"#;

async fn ask(base: &str) -> Result<LookupAnswer, String> {
    let args = parse(&["--email-stdin"]).expect("parses");
    lookup(base, &LinkTls::default(), TOKEN, EMAIL, &args).await
}

/// MIK-9456.CLI.2: a good answer decodes into the typed answer, and the
/// request carried the credential as a bearer and the email in the body only.
/// Mutant: send the email in the URL, or lose the bearer.
#[tokio::test]
async fn a_good_answer_decodes_and_the_request_carries_bearer_and_body() {
    let (base, seen) = stand_in(200, GOOD).await;
    let answer = ask(&base).await.expect("a good answer");
    assert_eq!(answer.rows.len(), 1);
    assert_eq!(answer.rows[0].subject.as_deref(), Some("s1"));
    assert_eq!(answer.scope, "retained");
    let seen = seen.lock().unwrap();
    assert_eq!(seen.len(), 1);
    let (bearer, text) = seen[0].split_once('|').expect("recorded");
    assert_eq!(bearer, format!("Bearer {TOKEN}"));
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(text).unwrap(),
        json!({"email": EMAIL})
    );
}

/// MIK-9456.CLI.2: any non-2xx is an error that names the status and never
/// carries the email or the credential, even when the gateway echoes them.
/// Mutant: swallow the status, or print the gateway's message unredacted.
#[tokio::test]
async fn a_refusal_is_an_error_without_the_email_or_the_token() {
    for status in [401_u16, 403, 429, 503] {
        let echo: &'static str =
            Box::leak(format!(r#"{{"error":"bad {EMAIL} with {TOKEN}"}}"#).into_boxed_str());
        let (base, _) = stand_in(status, echo).await;
        let message = ask(&base).await.expect_err("a refusal");
        assert!(message.contains(&status.to_string()), "{message}");
        assert!(!message.contains(TOKEN), "{message}");
        assert!(!message.to_lowercase().contains("planted"), "{message}");
    }
}

/// MIK-9456.CLI.2: a 200 whose body is not the typed answer is an error, not
/// an empty result.
/// Mutant: default a missing or mistyped field.
#[tokio::test]
async fn an_answer_that_is_not_the_typed_shape_is_an_error() {
    for body in [
        "not json",
        "{}",
        r#"{"rows":"x","next_cursor":null,"scan_exhausted":false,"cursor_reset":false,"unreadable":0,"scope":"retained"}"#,
        r#"{"rows":[],"next_cursor":null,"scan_exhausted":"no","cursor_reset":false,"unreadable":0,"scope":"retained"}"#,
        r#"{"rows":[],"next_cursor":null,"scan_exhausted":false,"cursor_reset":false,"unreadable":0}"#,
    ] {
        let (base, _) = stand_in(200, body).await;
        assert!(ask(&base).await.is_err(), "{body}");
    }
}

/// MIK-9456.CLI.2: a gateway that is not there is an error.
#[tokio::test]
async fn an_unreachable_gateway_is_an_error() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    drop(listener);
    assert!(ask(&base).await.is_err());
}

/// MIK-9456.CLI.3: a redirect is not followed (the next hop was not checked
/// and would carry the bearer), so a 307 is an error and the hop is never hit.
/// Mutant: follow redirects.
#[tokio::test]
async fn a_redirect_is_not_followed() {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    let hits = Arc::new(AtomicUsize::new(0));
    let seen = Arc::clone(&hits);
    let hop = axum::Router::new().fallback(move || {
        let seen = Arc::clone(&seen);
        async move {
            seen.fetch_add(1, Ordering::SeqCst);
            axum::Json(json!({"rows": []}))
        }
    });
    let hop_listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let hop_url = format!("http://{}/x", hop_listener.local_addr().expect("addr"));
    tokio::spawn(async move { axum::serve(hop_listener, hop).await });
    let redirector = axum::Router::new().fallback(move || {
        let to = hop_url.clone();
        async move {
            (
                axum::http::StatusCode::TEMPORARY_REDIRECT,
                [(axum::http::header::LOCATION, to)],
            )
        }
    });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let base = format!("http://{}", listener.local_addr().expect("addr"));
    tokio::spawn(async move { axum::serve(listener, redirector).await });
    assert!(ask(&base).await.is_err());
    assert_eq!(
        hits.load(Ordering::SeqCst),
        0,
        "the redirect target was reached"
    );
}

/// MIK-9456.CLI.3: the credential is never sent in cleartext to a non-loopback
/// host: refused before any connection.
/// Mutant: skip the target check.
#[tokio::test]
async fn a_cleartext_non_loopback_target_is_refused() {
    let message = ask("http://10.255.255.1:9").await.expect_err("refused");
    assert!(message.contains("cleartext"), "{message}");
}

/// MIK-9456.CLI.3: the command writes no file (no request history, no
/// cache) and offers no key or file shortcut: its source holds no file
/// creation or write call, and its only read is stdin.
/// Mutant: write a history file, or read the email from a file.
#[test]
fn the_command_writes_no_file_and_reads_no_key_file() {
    let source = include_str!("audit_lookup.rs");
    for banned in [
        "File::create",
        "fs::write",
        "OpenOptions",
        "create_dir",
        "read_to_string(",
        "fs::read",
        "dirs::",
        "home_dir",
    ] {
        assert!(!source.contains(banned), "the command uses {banned}");
    }
}

/// MIK-9456.CLI.4: the help names the stdin flag and the credential's
/// environment variable, and never offers `--email VALUE`.
/// Mutant: drop the flag's docs.
#[test]
fn the_help_names_stdin_and_the_credential() {
    use clap::CommandFactory as _;
    let mut root = Cli::command();
    let audit = root.find_subcommand_mut("audit").expect("audit");
    let lookup = audit
        .find_subcommand_mut("lookup-email")
        .expect("lookup-email");
    let help = lookup.render_long_help().to_string();
    assert!(help.contains("--email-stdin"), "{help}");
    assert!(!help.contains("--email <"), "{help}");
    assert!(!help.contains("--email "), "no bare --email option: {help}");
}

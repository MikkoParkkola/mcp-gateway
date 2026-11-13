// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! `audit lookup-email`: stdin only, bounded, typed answer, nonzero on any
//! failure, no file written.

use clap::Parser;
use mcp_gateway::cli::Cli;
use mcp_gateway::cli::audit_lookup::LookupEmailArgs;
use serde_json::json;

use super::{
    LookupInput, MAX_CURSOR_INPUT, MAX_EMAIL_INPUT, read_cursor, read_email, request_body,
};

const EMAIL: &str = "Planted.Person@corp.invalid";
/// A sealed page token as the gateway prints it: URL-safe base64, no spaces.
const PAGE: &str = "AQEBsealedPageTokenAbCdEf-_0123456789";

fn by_email() -> LookupInput {
    LookupInput::Email(EMAIL.to_owned())
}

fn by_cursor() -> LookupInput {
    LookupInput::Cursor(PAGE.to_owned())
}

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

/// A reader of `.1` bytes that counts what was taken from it.
struct Counting<'a>(&'a std::cell::Cell<usize>, usize);

impl std::io::Read for Counting<'_> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = buf.len().min(self.1);
        buf[..n].fill(b'a');
        self.1 -= n;
        self.0.set(self.0.get() + n);
        Ok(n)
    }
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
    // A long input is cut off at the bound, not read to the end.
    let read = std::cell::Cell::new(0);
    assert!(read_email(Counting(&read, 1 << 20)).is_err());
    assert!(
        read.get() <= MAX_EMAIL_INPUT + 1,
        "read {} bytes",
        read.get()
    );
}

/// MIK-9456.CLI.1: the body is built in memory from the email and the flags,
/// and carries only what was asked for.
/// Mutant: send the email in a query, drop a flag, or add a field.
#[test]
fn the_body_carries_the_email_and_only_the_flags_given() {
    let bare = parse(&["--email-stdin"]).expect("parses");
    assert_eq!(request_body(&by_email(), &bare), json!({"email": EMAIL}));
    let full = parse(&[
        "--email-stdin",
        "--limit",
        "7",
        "--from",
        "2026-11-01T00:00:00Z",
        "--to",
        "2026-11-02T00:00:00Z",
    ])
    .expect("parses");
    assert_eq!(
        request_body(&by_email(), &full),
        json!({"email": EMAIL, "limit": 7,
               "from": "2026-11-01T00:00:00Z", "to": "2026-11-02T00:00:00Z"})
    );
    assert!(parse(&["--email-stdin", "--limit", "0"]).is_err());
    assert!(parse(&["--email-stdin", "--limit", "201"]).is_err());
}

/// MIK-9456.CLI.1: the page token is never an argument either: no
/// `--cursor VALUE`, no positional token; the next page asks for stdin.
/// Mutant: keep the argv `--cursor`, or accept a positional token.
#[test]
fn a_page_token_is_never_an_argument() {
    assert!(parse(&["--cursor-stdin"]).is_ok());
    assert!(
        parse(&["--email-stdin", "--cursor", PAGE]).is_err(),
        "no --cursor VALUE"
    );
    assert!(parse(&["--cursor", PAGE]).is_err(), "no --cursor VALUE");
    assert!(
        parse(&["--cursor-stdin", PAGE]).is_err(),
        "no positional token"
    );
    assert!(parse(&["--cursor-stdin", "--cursor", PAGE]).is_err());
}

/// MIK-9456.CLI.1: exactly one of the two stdin sources; a page token
/// carries its own window, so a window flag beside it is refused here, before
/// the gateway charges a lookup for the 400 it would answer.
/// Mutant: drop the group, or drop a conflict.
#[test]
fn exactly_one_stdin_source_and_no_window_beside_a_token() {
    assert!(parse(&["--email-stdin"]).is_ok());
    assert!(parse(&["--cursor-stdin"]).is_ok());
    assert!(parse(&[]).is_err(), "one source is required");
    assert!(
        parse(&["--email-stdin", "--cursor-stdin"]).is_err(),
        "both sources"
    );
    assert!(parse(&["--cursor-stdin", "--from", "2026-11-01T00:00:00Z"]).is_err());
    assert!(parse(&["--cursor-stdin", "--to", "2026-11-02T00:00:00Z"]).is_err());
    assert!(
        parse(&["--cursor-stdin", "--limit", "7"]).is_ok(),
        "a page size may change"
    );
    assert!(
        parse(&[
            "--email-stdin",
            "--from",
            "2026-11-01T00:00:00Z",
            "--to",
            "2026-11-02T00:00:00Z"
        ])
        .is_ok()
    );
}

/// MIK-9456.CLI.1: the token line is read bounded, one line, no spaces or
/// control bytes, and every refusal is a fixed message that never echoes it.
/// Mutant: read without a bound, accept a second line or inner space, echo the
/// input in the message, or move the bound.
#[test]
fn the_token_line_is_read_bounded_and_never_echoed() {
    assert_eq!(
        read_cursor(format!("{PAGE}\n").as_bytes()).as_deref(),
        Ok(PAGE)
    );
    assert_eq!(
        read_cursor(format!("{PAGE}\r\n").as_bytes()).as_deref(),
        Ok(PAGE)
    );
    assert_eq!(
        read_cursor(PAGE.as_bytes()).as_deref(),
        Ok(PAGE),
        "no newline needed"
    );
    assert_eq!(
        read_cursor(format!("  {PAGE} \n").as_bytes()).as_deref(),
        Ok(PAGE),
        "ends are trimmed"
    );
    for (name, bad) in [
        ("empty", Vec::new()),
        ("blank", b"\n".to_vec()),
        ("two lines", format!("{PAGE}\nsecond\n").into_bytes()),
        ("inner space", format!("{PAGE} {PAGE}").into_bytes()),
        ("control byte", format!("{PAGE}\0").into_bytes()),
        ("not UTF-8", vec![0xff, 0xfe]),
        (
            "over the bound",
            "a".repeat(MAX_CURSOR_INPUT + 1).into_bytes(),
        ),
    ] {
        let message = read_cursor(bad.as_slice()).expect_err(name);
        assert!(
            !message.contains(PAGE) && !message.contains("second"),
            "{name}: {message}"
        );
        assert!(!message.contains(&"a".repeat(8)), "{name}: {message}");
    }
    assert_eq!(
        MAX_CURSOR_INPUT, 2048,
        "the gateway's own limit on a page token"
    );
    let at_limit = "a".repeat(MAX_CURSOR_INPUT);
    assert_eq!(
        read_cursor(at_limit.as_bytes()).as_deref(),
        Ok(at_limit.as_str())
    );
    // A long input is cut off one byte past the bound, not read to the end.
    let read = std::cell::Cell::new(0);
    assert!(read_cursor(Counting(&read, 1 << 20)).is_err());
    assert!(
        read.get() <= MAX_CURSOR_INPUT + 1,
        "read {} bytes",
        read.get()
    );
}

/// MIK-9456.CLI.1: a next-page body is exactly the token and the page size;
/// a first-page body never carries a token.
/// Mutant: add the email or a window beside the token, or send a token in a
/// first-page body.
#[test]
fn the_cursor_body_is_the_token_and_only_the_limit() {
    let bare = parse(&["--cursor-stdin"]).expect("parses");
    assert_eq!(request_body(&by_cursor(), &bare), json!({"cursor": PAGE}));
    let sized = parse(&["--cursor-stdin", "--limit", "7"]).expect("parses");
    assert_eq!(
        request_body(&by_cursor(), &sized),
        json!({"cursor": PAGE, "limit": 7})
    );
    let first = parse(&["--email-stdin", "--limit", "7"]).expect("parses");
    assert_eq!(
        request_body(&by_email(), &first),
        json!({"email": EMAIL, "limit": 7})
    );
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
    lookup(base, &LinkTls::default(), TOKEN, &by_email(), &args).await
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

/// MIK-9456.CLI.1/2: a next-page request sends the token in the body only
/// (never the email, a window or the URL), and an error never carries the
/// token even when the gateway echoes it.
/// Mutant: put the token in the URL or a header, or print the gateway's
/// message with the token in it.
#[tokio::test]
async fn a_next_page_request_sends_the_token_in_the_body_and_hides_it_in_errors() {
    let args = parse(&["--cursor-stdin", "--limit", "7"]).expect("parses");
    let (base, seen) = stand_in(200, GOOD).await;
    lookup(&base, &LinkTls::default(), TOKEN, &by_cursor(), &args)
        .await
        .expect("a good answer");
    {
        let seen = seen.lock().unwrap();
        assert_eq!(seen.len(), 1);
        let (bearer, text) = seen[0].split_once('|').expect("recorded");
        assert_eq!(bearer, format!("Bearer {TOKEN}"));
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(text).unwrap(),
            json!({"cursor": PAGE, "limit": 7})
        );
    }
    for status in [400_u16, 401, 429] {
        let echo: &'static str =
            Box::leak(format!(r#"{{"error":"bad {PAGE} with {TOKEN}"}}"#).into_boxed_str());
        let (base, _) = stand_in(status, echo).await;
        let message = lookup(&base, &LinkTls::default(), TOKEN, &by_cursor(), &args)
            .await
            .expect_err("a refusal");
        assert!(message.contains(&status.to_string()), "{message}");
        assert!(!message.contains(PAGE), "{message}");
        assert!(!message.contains(TOKEN), "{message}");
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
    assert!(help.contains("--cursor-stdin"), "{help}");
    assert!(
        !help.contains("--cursor <"),
        "no --cursor VALUE option: {help}"
    );
    assert!(help.contains("MCP_GATEWAY_TOKEN"), "{help}");
    assert!(!help.contains("--email <"), "{help}");
    assert!(!help.contains("--email "), "no bare --email option: {help}");
}

/// MIK-9456.CLI.1: the email-length rule is its own bound, in bytes, so a
/// multibyte address is counted by what it takes on the wire.
/// Mutant: drop the 320-byte rule, or count characters.
#[test]
fn the_email_length_rule_is_in_bytes() {
    let at_limit = format!("{}@b.invalid", "a".repeat(320 - "@b.invalid".len()));
    assert_eq!(at_limit.len(), 320);
    assert_eq!(
        read_email(at_limit.as_bytes()).as_deref(),
        Ok(at_limit.as_str())
    );
    let over = format!("{}@b.invalid", "a".repeat(321 - "@b.invalid".len()));
    assert!(read_email(over.as_bytes()).is_err(), "321 bytes");
    let wide_ok = "é".repeat(160);
    assert_eq!(wide_ok.len(), 320);
    assert!(
        read_email(wide_ok.as_bytes()).is_ok(),
        "160 two-byte characters"
    );
    let wide_over = "é".repeat(161);
    assert!(read_email(wide_over.as_bytes()).is_err(), "322 bytes");
}

use super::run_with;

fn code(exit: std::process::ExitCode) -> String {
    format!("{exit:?}")
}

async fn run(base: &str, input: &[u8], token: Option<&'static str>) -> std::process::ExitCode {
    let args = parse(&["--email-stdin", "--url", base]).expect("parses");
    run_with(
        args,
        || Err("no config in this row".to_string()),
        None,
        None,
        input,
        move |name| {
            (name == "MCP_GATEWAY_TOKEN")
                .then(|| token.map(str::to_owned))
                .flatten()
        },
    )
    .await
}

/// MIK-9456.CLI.2: the composed command exits 0 on a good answer and nonzero
/// on each failure class: no credential, no email on stdin, a refusal, an
/// answer of the wrong shape, an unreachable gateway.
/// Mutant: any failure class exits 0.
#[tokio::test]
async fn the_composed_command_exits_nonzero_on_every_failure_class() {
    let ok = code(std::process::ExitCode::SUCCESS);
    let fail = code(std::process::ExitCode::FAILURE);
    let (good, seen) = stand_in(200, GOOD).await;
    assert_eq!(code(run(&good, EMAIL.as_bytes(), Some(TOKEN)).await), ok);
    assert_eq!(seen.lock().unwrap().len(), 1);
    assert_eq!(
        code(run(&good, EMAIL.as_bytes(), None).await),
        fail,
        "no credential"
    );
    assert_eq!(code(run(&good, b"", Some(TOKEN)).await), fail, "no email");
    assert_eq!(
        seen.lock().unwrap().len(),
        1,
        "neither failure sent a request"
    );
    let (refused, _) = stand_in(403, r#"{"error":"no"}"#).await;
    assert_eq!(
        code(run(&refused, EMAIL.as_bytes(), Some(TOKEN)).await),
        fail,
        "a refusal"
    );
    let (odd, _) = stand_in(200, "{}").await;
    assert_eq!(
        code(run(&odd, EMAIL.as_bytes(), Some(TOKEN)).await),
        fail,
        "wrong shape"
    );
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let dead = format!("http://{}", listener.local_addr().unwrap());
    drop(listener);
    assert_eq!(
        code(run(&dead, EMAIL.as_bytes(), Some(TOKEN)).await),
        fail,
        "unreachable"
    );
}

async fn run_page(base: &str, input: &[u8]) -> std::process::ExitCode {
    let args = parse(&["--cursor-stdin", "--url", base]).expect("parses");
    run_with(
        args,
        || Err("no config in this row".to_string()),
        None,
        None,
        input,
        |name| (name == "MCP_GATEWAY_TOKEN").then(|| TOKEN.to_owned()),
    )
    .await
}

/// MIK-9456.CLI.2: the composed next-page command exits 0 on a good answer
/// and nonzero when stdin holds no usable token (and then sends nothing).
/// Mutant: read the email in cursor mode, or send a request for a bad token
/// line.
#[tokio::test]
async fn the_composed_next_page_command_reads_the_token_from_stdin() {
    let ok = code(std::process::ExitCode::SUCCESS);
    let fail = code(std::process::ExitCode::FAILURE);
    let (good, seen) = stand_in(200, GOOD).await;
    assert_eq!(
        code(run_page(&good, format!("{PAGE}\n").as_bytes()).await),
        ok
    );
    assert_eq!(seen.lock().unwrap().len(), 1);
    let body = seen.lock().unwrap()[0]
        .split_once('|')
        .unwrap()
        .1
        .to_owned();
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&body).unwrap(),
        json!({"cursor": PAGE})
    );
    for (name, bad) in [
        ("empty", &b""[..]),
        ("two lines", &b"a\nb\n"[..]),
        ("a space", &b"a b"[..]),
    ] {
        assert_eq!(code(run_page(&good, bad).await), fail, "{name}");
    }
    assert_eq!(
        seen.lock().unwrap().len(),
        1,
        "no bad token line sent a request"
    );
}

/// A refusal that carries Retry-After says how long to wait.
/// Mutant: drop the header from the message.
#[tokio::test]
async fn a_throttled_answer_names_how_long_to_wait() {
    let app = axum::Router::new().fallback(|| async {
        (
            axum::http::StatusCode::TOO_MANY_REQUESTS,
            [("retry-after", "6")],
            axum::Json(json!({"error": "slow down"})),
        )
    });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let base = format!("http://{}", listener.local_addr().expect("addr"));
    tokio::spawn(async move { axum::serve(listener, app).await });
    let message = ask(&base).await.expect_err("throttled");
    assert!(
        message.contains("429") && message.contains("retry after 6 s"),
        "{message}"
    );
}

/// A typo in --from or --to is refused before any request is sent.
/// Mutant: send it and let the gateway charge for it.
#[tokio::test]
async fn a_bad_window_is_refused_before_a_request_is_sent() {
    let (base, seen) = stand_in(200, GOOD).await;
    for flags in [
        vec!["--from", "yesterday"],
        vec!["--to", "2026-13-45T00:00:00Z"],
        vec![
            "--from",
            "2026-11-02T00:00:00Z",
            "--to",
            "2026-11-01T00:00:00Z",
        ],
    ] {
        let mut argv = vec!["--email-stdin"];
        argv.extend(flags);
        let parsed = parse(&argv).expect("parses");
        let message = lookup(&base, &LinkTls::default(), TOKEN, &by_email(), &parsed)
            .await
            .expect_err("a bad window");
        assert!(
            message.contains("--from") || message.contains("--to"),
            "{message}"
        );
    }
    assert!(seen.lock().unwrap().is_empty(), "no request was sent");
}

/// A field the gateway adds (even an email) is not echoed: the printed form
/// is the typed answer.
/// Mutant: print the raw body.
#[test]
fn the_printed_answer_drops_fields_it_does_not_know() {
    let body = GOOD.replace(
        r#""scope":"retained""#,
        r#""scope":"retained","email":"leak@x.invalid""#,
    );
    let answer: LookupAnswer = serde_json::from_str(&body).expect("decodes");
    let printed = super::render(&answer).expect("prints");
    assert!(
        !printed.contains("leak@x.invalid") && !printed.contains("email"),
        "{printed}"
    );
    assert!(printed.contains("retained"));
}

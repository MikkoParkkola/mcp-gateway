// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Rows for MIK-9680.CLIUX.19 (test plan T5-T7): every reachable failure site of dashboard-link, events
//! dead-letters and audit lookup-email exits with its code from the shared table and prints `error: <what>` then
//! what to do, with nothing on stdout; successes keep their stdout. Expected text is written out from design D4.

use std::fmt::Write as _;
use std::sync::{Arc, Mutex};

use clap::Parser as _;
use mcp_gateway::cli::{AuditCommand, Cli, Command};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

use super::cli_exit::{CliExit, CliOutcome};

std::thread_local! {
    /// The current row's mismatches: each case is checked and recorded, and the row fails once at its end with
    /// all of them, so one run shows every case's failure reason (rows run on a current-thread runtime).
    static MISSES: std::cell::RefCell<Vec<String>> = const { std::cell::RefCell::new(Vec::new()) };
}

/// Records `left != right` for the row's verdict instead of stopping at the first mismatch.
macro_rules! check_eq {
    ($left:expr, $right:expr, $($case:tt)+) => {{
        // A match, as assert_eq! uses, keeps temporaries in the operands alive for the comparison.
        match (&$left, &$right) {
            (left, right) => {
                if left != right {
                    let case = format!($($case)+);
                    MISSES.with(|m| m.borrow_mut().push(format!("{case}\n  left: {left:?}\n right: {right:?}")));
                }
            }
        }
    }};
}

/// Records a false condition for the row's verdict.
macro_rules! check {
    ($cond:expr, $($case:tt)+) => {{
        if !$cond {
            let case = format!($($case)+);
            MISSES.with(|m| m.borrow_mut().push(case));
        }
    }};
}

/// Fails the row with every recorded mismatch; each row ends with it.
fn finish() {
    let misses = MISSES.take();
    assert!(
        misses.is_empty(),
        "{} mismatch(es):\n{}",
        misses.len(),
        misses.join("\n")
    );
}

const TOKEN: &str = "tok-9680-valid";
const EMAIL: &str = "person@corp.test";
const CURSOR: &str = "AQEBsealedPageTokenAbCdEf-_0123456789";

/// What the stand-in gateway does with each request.
#[derive(Clone)]
enum Reply {
    /// Answer with this status, extra headers and body.
    Http {
        status: u16,
        headers: Vec<(&'static str, String)>,
        body: Vec<u8>,
    },
    /// Read the request, then close without answering.
    Close,
}

fn json(status: u16, body: &str) -> Reply {
    Reply::Http {
        status,
        headers: vec![("content-type", "application/json".to_string())],
        body: body.as_bytes().to_vec(),
    }
}

/// One request as the stand-in received it.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Seen {
    method: String,
    path: String,
    body: String,
}

struct Gateway {
    base: String,
    seen: Arc<Mutex<Vec<Seen>>>,
}

impl Gateway {
    fn requests(&self) -> Vec<Seen> {
        self.seen.lock().expect("lock").clone()
    }
}

/// A plain-HTTP loopback gateway that records every request and answers each with `reply`.
async fn gateway(reply: Reply) -> Gateway {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let base = format!("http://{}", listener.local_addr().expect("addr"));
    let seen = Arc::new(Mutex::new(Vec::new()));
    let log = seen.clone();
    tokio::spawn(async move {
        while let Ok((mut socket, _)) = listener.accept().await {
            let reply = reply.clone();
            let log = log.clone();
            tokio::spawn(async move {
                let request = read_request(&mut socket).await;
                log.lock().expect("lock").push(request);
                if let Reply::Http {
                    status,
                    headers,
                    body,
                } = reply
                {
                    let mut head = format!(
                        "HTTP/1.1 {status} Stand-in\r\ncontent-length: {}\r\nconnection: close\r\n",
                        body.len()
                    );
                    for (name, value) in headers {
                        let _ = write!(head, "{name}: {value}\r\n");
                    }
                    head.push_str("\r\n");
                    let _ = socket.write_all(head.as_bytes()).await;
                    let _ = socket.write_all(&body).await;
                }
            });
        }
    });
    Gateway { base, seen }
}

async fn read_request(socket: &mut tokio::net::TcpStream) -> Seen {
    let mut buf = Vec::new();
    let mut chunk = [0_u8; 8192];
    let (head_end, length) = loop {
        let n = socket.read(&mut chunk).await.unwrap_or(0);
        if n == 0 {
            return Seen {
                method: String::new(),
                path: String::new(),
                body: String::new(),
            };
        }
        buf.extend_from_slice(&chunk[..n]);
        if let Some(end) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            let head = String::from_utf8_lossy(&buf[..end]).to_ascii_lowercase();
            let length = head
                .lines()
                .find_map(|line| line.strip_prefix("content-length:"))
                .and_then(|v| v.trim().parse::<usize>().ok())
                .unwrap_or(0);
            break (end, length);
        }
    };
    while buf.len() < head_end + 4 + length {
        let n = socket.read(&mut chunk).await.unwrap_or(0);
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&chunk[..n]);
    }
    let head = String::from_utf8_lossy(&buf[..head_end]).to_string();
    let mut first = head.lines().next().unwrap_or("").split(' ');
    Seen {
        method: first.next().unwrap_or("").to_string(),
        path: first.next().unwrap_or("").to_string(),
        body: String::from_utf8_lossy(&buf[head_end + 4..]).to_string(),
    }
}

fn parse(argv: &[&str]) -> Command {
    let mut full = vec!["mcp-gateway"];
    full.extend_from_slice(argv);
    Cli::try_parse_from(full)
        .expect("the arguments parse")
        .command
        .expect("a command")
}

#[expect(
    clippy::unnecessary_wraps,
    reason = "the config loader parameter takes this type"
)]
fn loaded() -> Result<mcp_gateway::config::Config, String> {
    Ok(mcp_gateway::config::Config::default())
}

/// `dashboard-link` with `flags` after its name, through the rows' entry.
async fn link(
    flags: &[&str],
    token: Result<String, super::dashboard_link::TokenError>,
) -> CliOutcome {
    let mut full = vec!["dashboard-link"];
    full.extend_from_slice(flags);
    let Command::DashboardLink(args) = parse(&full) else {
        panic!("not dashboard-link")
    };
    super::dashboard_link::dashboard_link_outcome(args, loaded, None, None, token).await
}

/// `events dead-letters` with `flags` after its name.
async fn events(
    flags: &[&str],
    token: Result<String, super::dashboard_link::TokenError>,
) -> CliOutcome {
    let mut full = vec!["events", "dead-letters"];
    full.extend_from_slice(flags);
    let Command::Events(args) = parse(&full) else {
        panic!("not events")
    };
    let mcp_gateway::cli::events::EventsCommand::DeadLetters(args) = args.command;
    super::dashboard_link::events_outcome(&args, loaded, None, None, token).await
}

/// `audit lookup-email` with `flags` after its name, `stdin` and the token variable's value. The source flag
/// `--email-stdin` is added unless `flags` names `--cursor-stdin` (clap requires exactly one).
async fn lookup(flags: &[&str], stdin: &[u8], token: Option<&str>) -> CliOutcome {
    let mut full = vec!["audit", "lookup-email"];
    if !flags.contains(&"--cursor-stdin") {
        full.push("--email-stdin");
    }
    full.extend_from_slice(flags);
    let Command::Audit(AuditCommand::LookupEmail(args)) = parse(&full) else {
        panic!("not lookup-email")
    };
    let token = token.map(str::to_string);
    super::audit_lookup::lookup_outcome(args, loaded, None, None, stdin, move |name| {
        (name == "MCP_GATEWAY_TOKEN")
            .then(|| token.clone())
            .flatten()
    })
    .await
}

#[expect(
    clippy::unnecessary_wraps,
    reason = "the token parameter takes this type"
)]
fn ok_token() -> Result<String, super::dashboard_link::TokenError> {
    Ok(TOKEN.to_string())
}

/// Asserts a whole failure: the exit, stderr exactly `error: <what>` then `<remedy>`, and empty stdout.
fn failed(out: &CliOutcome, exit: CliExit, what: &str, remedy: &str, case: &str) {
    check_eq!(
        (out.exit(), out.stderr(), out.stdout()),
        (
            exit,
            format!("error: {what}\n{remedy}\n").as_str(),
            &b""[..]
        ),
        "{case}"
    );
}

const TOKEN_REMEDY_PREFIX: &str = "Set MCP_GATEWAY_TOKEN to a valid token for ";
const SETTINGS_REMEDY: &str = "Check the gateway settings, then retry.";
const REPLACE_TOKEN: &str = "Unset or replace MCP_GATEWAY_TOKEN, then retry.";

/// T5-T7, the token sites: unset 3, empty 2, a control character 2; no request is sent.
#[tokio::test]
async fn token_faults_exit_by_the_table_and_send_nothing() {
    use super::dashboard_link::TokenError;
    let gw = gateway(json(200, r#"{"link":"https://gw/x"}"#)).await;
    let url = ["--url", gw.base.as_str()];
    let unset_remedy = format!("{TOKEN_REMEDY_PREFIX}{}, then retry.", gw.base);
    for (case, out) in [
        (
            "dashboard-link unset",
            link(&url, Err(TokenError::Missing)).await,
        ),
        (
            "events unset",
            events(&["list", "--url", &gw.base], Err(TokenError::Missing)).await,
        ),
        ("lookup unset", lookup(&url, EMAIL.as_bytes(), None).await),
    ] {
        failed(
            &out,
            CliExit::AuthRefused,
            "No gateway credential is available.",
            &unset_remedy,
            case,
        );
    }
    for (case, out) in [
        (
            "dashboard-link empty",
            link(&url, Err(TokenError::Blank)).await,
        ),
        (
            "events empty",
            events(&["list", "--url", &gw.base], Err(TokenError::Blank)).await,
        ),
        (
            "lookup empty",
            lookup(&url, EMAIL.as_bytes(), Some("")).await,
        ),
    ] {
        failed(
            &out,
            CliExit::Usage,
            "MCP_GATEWAY_TOKEN is empty.",
            REPLACE_TOKEN,
            case,
        );
    }
    for (case, out) in [
        (
            "dashboard-link control",
            link(&url, Ok("tok\u{7}".to_string())).await,
        ),
        (
            "events control",
            events(&["list", "--url", &gw.base], Ok("tok\u{7}".to_string())).await,
        ),
        (
            "lookup control",
            lookup(&url, EMAIL.as_bytes(), Some("tok\u{7}")).await,
        ),
    ] {
        failed(
            &out,
            CliExit::Usage,
            "MCP_GATEWAY_TOKEN holds a control character.",
            REPLACE_TOKEN,
            case,
        );
    }
    check_eq!(
        gw.requests(),
        Vec::<Seen>::new(),
        "no request on a token fault"
    );
    finish();
}

/// T5-T7, resolution: a config that cannot load, with no --gateway, is a usage error (2).
#[tokio::test]
async fn an_unloadable_config_is_a_usage_error() {
    let broken = || -> Result<mcp_gateway::config::Config, String> { Err("planted".to_string()) };
    let what = "could not load the config (planted); pass --gateway";
    let Command::DashboardLink(args) = parse(&["dashboard-link"]) else {
        panic!()
    };
    let out =
        super::dashboard_link::dashboard_link_outcome(args, broken, None, None, ok_token()).await;
    failed(
        &out,
        CliExit::Usage,
        what,
        SETTINGS_REMEDY,
        "dashboard-link",
    );
    let Command::Events(args) = parse(&["events", "dead-letters", "list"]) else {
        panic!()
    };
    let mcp_gateway::cli::events::EventsCommand::DeadLetters(args) = args.command;
    let out = super::dashboard_link::events_outcome(&args, broken, None, None, ok_token()).await;
    failed(&out, CliExit::Usage, what, SETTINGS_REMEDY, "events");
    let Command::Audit(AuditCommand::LookupEmail(args)) =
        parse(&["audit", "lookup-email", "--email-stdin"])
    else {
        panic!()
    };
    let out =
        super::audit_lookup::lookup_outcome(args, broken, None, None, EMAIL.as_bytes(), |_| {
            Some(TOKEN.to_string())
        })
        .await;
    failed(&out, CliExit::Usage, what, SETTINGS_REMEDY, "lookup");
    finish();
}

/// T5-T7, the URL policy and the network: plain http off loopback is 2 (sent nowhere); a port with no
/// listener is 5.
#[tokio::test]
async fn url_policy_and_network_failures_exit_2_and_5() {
    let off = ["--url", "http://10.1.2.3:8080"];
    for (case, out) in [
        ("dashboard-link", link(&off, ok_token()).await),
        (
            "events",
            events(&["list", "--url", "http://10.1.2.3:8080"], ok_token()).await,
        ),
        ("lookup", lookup(&off, EMAIL.as_bytes(), Some(TOKEN)).await),
    ] {
        failed(
            &out,
            CliExit::Usage,
            "Gateway URL must use HTTPS or loopback HTTP.",
            "Use an HTTPS gateway URL or a loopback HTTP URL.",
            case,
        );
    }
    let closed = {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        format!("http://{}", listener.local_addr().expect("addr"))
    };
    let url = ["--url", closed.as_str()];
    for (case, out) in [
        ("dashboard-link", link(&url, ok_token()).await),
        (
            "events",
            events(&["list", "--url", &closed], ok_token()).await,
        ),
        ("lookup", lookup(&url, EMAIL.as_bytes(), Some(TOKEN)).await),
    ] {
        failed(
            &out,
            CliExit::Network,
            "Could not connect to the gateway.",
            "Check the gateway address and listener, then retry.",
            case,
        );
    }
    finish();
}

const RESOLVE: &str = "Resolve the gateway error, then retry.";
const UNCERTAIN: &str = "Inspect the gateway state before retrying; this command did not retry.";

/// Runs the three commands (events as a list) against one stand-in answering `reply`.
async fn all_three(reply: Reply) -> (Gateway, Vec<(&'static str, CliOutcome)>) {
    let gw = gateway(reply).await;
    let url = ["--url", gw.base.as_str()];
    let outs = vec![
        ("dashboard-link", link(&url, ok_token()).await),
        (
            "events list",
            events(&["list", "--url", &gw.base], ok_token()).await,
        ),
        ("lookup", lookup(&url, EMAIL.as_bytes(), Some(TOKEN)).await),
    ];
    (gw, outs)
}

/// The refusal cases: each status and body, the exit `status_kind`'s order gives it, and the message tail.
fn refusal_cases() -> Vec<(&'static str, Reply, CliExit, &'static str)> {
    let headers_30 = vec![
        ("content-type", "application/json".to_string()),
        ("retry-after", "30".to_string()),
    ];
    vec![
        (
            "401",
            json(401, r#"{"message":"denied"}"#),
            CliExit::AuthRefused,
            "401: denied",
        ),
        (
            "403",
            json(403, r#"{"message":"denied"}"#),
            CliExit::AuthRefused,
            "403: denied",
        ),
        (
            "404",
            json(404, r#"{"message":"gone"}"#),
            CliExit::NotFound,
            "404: gone",
        ),
        (
            "429",
            Reply::Http {
                status: 429,
                headers: headers_30,
                body: br#"{"message":"slow"}"#.to_vec(),
            },
            CliExit::Gateway,
            "429: slow; retry after 30 s",
        ),
        (
            "500",
            json(500, r#"{"message":"broke"}"#),
            CliExit::Gateway,
            "500: broke",
        ),
        (
            "503 not_run",
            json(503, r#"{"message":"down","disposition":"not_run"}"#),
            CliExit::Gateway,
            "503: down",
        ),
        (
            "500 may_have_run",
            json(500, r#"{"message":"maybe","disposition":"may_have_run"}"#),
            CliExit::UncertainOutcome,
            "500: maybe",
        ),
        (
            "409 state_uncertain",
            json(
                409,
                r#"{"message":"unsure","error":{"code":"state_uncertain"}}"#,
            ),
            CliExit::UncertainOutcome,
            "409: unsure",
        ),
        (
            "401 unsupported_version",
            json(
                401,
                r#"{"message":"old","error":{"code":"unsupported_version"}}"#,
            ),
            CliExit::Gateway,
            "401: old",
        ),
        (
            "200 may_have_run",
            json(200, r#"{"message":"maybe","disposition":"may_have_run"}"#),
            CliExit::UncertainOutcome,
            "200: maybe",
        ),
        (
            "200 not_run",
            json(200, r#"{"message":"skipped","disposition":"not_run"}"#),
            CliExit::Gateway,
            "200: skipped",
        ),
    ]
}

/// T5-T7, refusals: each status and body maps through `status_kind`'s order (design D1) to its code, with the
/// HTTP number and reason in the message and D4's remedy; the request reached the gateway.
#[tokio::test]
async fn refusals_map_through_the_shared_order() {
    let cases = refusal_cases();
    for (case, reply, exit, tail) in cases {
        let (gw, outs) = all_three(reply).await;
        let remedy = match exit {
            CliExit::AuthRefused if case == "403" => {
                format!("Use a token permitted to perform this operation for {}, then retry.", gw.base)
            }
            CliExit::AuthRefused => format!("{TOKEN_REMEDY_PREFIX}{}, then retry.", gw.base),
            CliExit::NotFound => {
                "Check that the gateway supports this command (update the gateway or the CLI), then retry.".to_string()
            }
            CliExit::UncertainOutcome => UNCERTAIN.to_string(),
            _ => RESOLVE.to_string(),
        };
        for (command, out) in &outs {
            failed(
                out,
                exit,
                &format!("The gateway answered HTTP {tail}"),
                &remedy,
                &format!("{command} {case}"),
            );
        }
        check_eq!(
            gw.requests().len(),
            3,
            "{case}: each command's request reached the gateway"
        );
    }
    finish();
}

/// T6, replay is a mutation: a 500 and a lost answer are 8; a 503 with `not_run` is 6; a 404 names the ID or the
/// subscription to check.
#[tokio::test]
async fn replay_uses_the_mutation_rules() {
    let gw = gateway(json(500, r#"{"message":"broke"}"#)).await;
    let out = events(&["replay", "dl-1", "--url", &gw.base], ok_token()).await;
    failed(
        &out,
        CliExit::UncertainOutcome,
        "The gateway answered HTTP 500: broke",
        UNCERTAIN,
        "replay 500",
    );
    let gw = gateway(json(503, r#"{"message":"down","disposition":"not_run"}"#)).await;
    let out = events(&["replay", "dl-1", "--url", &gw.base], ok_token()).await;
    failed(
        &out,
        CliExit::Gateway,
        "The gateway answered HTTP 503: down",
        RESOLVE,
        "replay 503 not_run",
    );
    let gw = gateway(Reply::Close).await;
    let out = events(&["replay", "dl-1", "--url", &gw.base], ok_token()).await;
    failed(
        &out,
        CliExit::UncertainOutcome,
        "The gateway may have applied this change.",
        UNCERTAIN,
        "replay lost",
    );
    let gw = gateway(json(404, r#"{"message":"gone"}"#)).await;
    let out = events(&["replay", "dl-1", "--url", &gw.base], ok_token()).await;
    failed(
        &out,
        CliExit::NotFound,
        "The gateway answered HTTP 404: gone",
        "Check the dead-letter ID with events dead-letters list, then retry.",
        "replay ID 404",
    );
    let out = events(
        &[
            "replay",
            "--all",
            "--subscription",
            "subs-1",
            "--url",
            &gw.base,
        ],
        ok_token(),
    )
    .await;
    failed(
        &out,
        CliExit::NotFound,
        "The gateway answered HTTP 404: gone",
        "Check the subscription with events dead-letters list --subscription subs-1, then retry.",
        "replay --all 404",
    );
    check_eq!(
        gw.requests()
            .iter()
            .map(|s| (s.method.clone(), s.path.clone()))
            .collect::<Vec<_>>(),
        vec![
            (
                "POST".to_string(),
                "/ui/api/events/dead-letters/dl-1/replay".to_string()
            ),
            (
                "POST".to_string(),
                "/ui/api/events/dead-letters/replay?all=1&subscription=subs-1".to_string()
            ),
        ],
        "the replays reached the gateway as built by dead_letters_request"
    );
    finish();
}

const LOOKUP_ANSWER: &str = r#"{"rows":[],"next_cursor":null,"scan_exhausted":true,"cursor_reset":false,"unreadable":0,"scope":"all"}"#;
const LOOKUP_PRINTED: &str = "{\n  \"rows\": [],\n  \"next_cursor\": null,\n  \"scan_exhausted\": true,\n  \"cursor_reset\": false,\n  \"unreadable\": 0,\n  \"scope\": \"all\"\n}\n";

/// T5-T7, successes keep today's bytes (A1: the permitted side of every failure row).
#[tokio::test]
async fn successes_print_as_today() {
    let gw = gateway(json(200, r#"{"link":"https://gw.test/once"}"#)).await;
    let out = link(&["--url", &gw.base], ok_token()).await;
    check_eq!(
        (out.exit(), out.stdout(), out.stderr()),
        (
            CliExit::Ok,
            &b"https://gw.test/once\n"[..],
            "Opens once, from this machine only.\n"
        ),
        "dashboard-link"
    );
    let gw = gateway(json(200, r#"{"items":[]}"#)).await;
    let out = events(&["list", "--url", &gw.base], ok_token()).await;
    check_eq!(
        (out.exit(), out.stdout(), out.stderr()),
        (CliExit::Ok, &b"{\n  \"items\": []\n}\n"[..], ""),
        "events list"
    );
    let gw = gateway(json(200, LOOKUP_ANSWER)).await;
    for (mode, argv, stdin, body) in [
        (
            "email",
            vec!["--url", gw.base.as_str()],
            EMAIL,
            format!("\"email\":\"{EMAIL}\""),
        ),
        (
            "cursor",
            vec!["--cursor-stdin", "--url", gw.base.as_str()],
            CURSOR,
            format!("\"cursor\":\"{CURSOR}\""),
        ),
    ] {
        let out = lookup(&argv, stdin.as_bytes(), Some(TOKEN)).await;
        check_eq!(
            (out.exit(), out.stdout(), out.stderr()),
            (CliExit::Ok, LOOKUP_PRINTED.as_bytes(), ""),
            "lookup {mode}"
        );
        let last = gw.requests().last().cloned().expect("a request");
        check!(
            last.body.contains(&body),
            "lookup {mode}: the request body carries the input: {last:?}"
        );
    }
    finish();
}

/// T5-T7, a lost answer and an oversized answer to a read are 5; a 2xx without JSON is 6.
#[tokio::test]
async fn lost_oversized_and_unparsable_answers() {
    let (_, outs) = all_three(Reply::Close).await;
    for (command, out) in &outs {
        let remedy = if *command == "dashboard-link" {
            "Repeat the request; each run mints a new one-time link."
        } else {
            "Repeat the read request."
        };
        failed(
            out,
            CliExit::Network,
            "Gateway response was interrupted.",
            remedy,
            command,
        );
    }
    let big = Reply::Http {
        status: 200,
        headers: vec![("content-type", "application/json".to_string())],
        body: vec![b' '; 16 * 1024 * 1024 + 1],
    };
    let (_, outs) = all_three(big).await;
    for (command, out) in &outs {
        failed(
            out,
            CliExit::Network,
            "Gateway response exceeded 16 MiB.",
            "Narrow the request or read the data in smaller pages.",
            command,
        );
    }
    let text = Reply::Http {
        status: 200,
        headers: vec![],
        body: b"not json".to_vec(),
    };
    let (_, outs) = all_three(text).await;
    for (command, out) in &outs {
        failed(
            out,
            CliExit::Gateway,
            "The gateway returned an invalid response.",
            "Check the gateway response against UI API 1.",
            command,
        );
    }
    finish();
}

// The T6-T7 stdout-safety row (`answers::stdout_safety_has_three_separate_outcomes`) lives in
// remote_answer_tests.rs, moved there for the file-size ceiling.

#[path = "remote_input_tests.rs"]
mod input;

#[path = "remote_secret_tests.rs"]
mod secrets;

#[path = "remote_answer_tests.rs"]
mod answers;

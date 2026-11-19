// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Exit-table rows that need the built binary (test plan T13, and the lead's 2026-11-17 rule for free-text formats):
//! each remote command's real entry point returns the shared table's code as the process exit with the same text
//! the in-process rows check; and `cap discover --format json` (src/cli/subcommands.rs:101, a free-text `format`)
//! is classed JSON-capable only because this row runs it and parses its stdout. H3 (MIK-9681.CLIUX.18): a mistyped
//! command suggests only visible commands, read from the real binary's stderr.
#![cfg(all(unix, feature = "webui"))]

#[path = "common/gateway_bin.rs"]
mod gateway_bin;

use std::io::{Read as _, Write as _};
use std::net::TcpListener;
use std::process::Stdio;

const TOKEN: &str = "tok-9680-valid";
const LOOKUP_ANSWER: &str = r#"{"rows":[],"next_cursor":null,"scan_exhausted":true,"cursor_reset":false,"unreadable":0,"scope":"all"}"#;
const LOOKUP_PRINTED: &str = "{\n  \"rows\": [],\n  \"next_cursor\": null,\n  \"scan_exhausted\": true,\n  \"cursor_reset\": false,\n  \"unreadable\": 0,\n  \"scope\": \"all\"\n}\n";

/// A loopback stand-in answering every request with `status` and the JSON `body`.
fn stand_in(status: u16, body: &'static str) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let base = format!("http://{}", listener.local_addr().expect("addr"));
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { return };
            let mut request = vec![0_u8; 65536];
            let _ = stream.read(&mut request);
            let head = format!(
                "HTTP/1.1 {status} Stand-in\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
                body.len()
            );
            let _ = stream.write_all(head.as_bytes());
            let _ = stream.write_all(body.as_bytes());
        }
    });
    base
}

/// The binary with `args`, an empty home, `token` as `MCP_GATEWAY_TOKEN` when given, and `stdin`.
fn run(args: &[&str], token: Option<&str>, stdin: &[u8]) -> (Option<i32>, String, String) {
    let home = tempfile::tempdir().expect("home");
    run_in(home.path(), args, token, stdin)
}

/// As [`run`], in the given home.
fn run_in(
    home: &std::path::Path,
    args: &[&str],
    token: Option<&str>,
    stdin: &[u8],
) -> (Option<i32>, String, String) {
    let mut command = gateway_bin::command(home, gateway_bin::Inherit::Nothing);
    command
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if let Some(token) = token {
        command.env("MCP_GATEWAY_TOKEN", token);
    }
    let mut child = command.spawn().expect("spawn"); // spawn-check: waits for exit: one-shot CLI, reaped by wait_with_output
    child
        .stdin
        .take()
        .expect("stdin")
        .write_all(stdin)
        .expect("write stdin");
    let out = child.wait_with_output().expect("wait");
    (
        out.status.code(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

/// The lead's rule: `cap discover`'s free-text format is proven by running it. The run reads only local files and
/// the local process list (src/commands/cap/server_scan.rs:27-32, src/discovery/mod.rs:235-256; ports are parsed
/// from command lines, src/discovery/process_scanner.rs:237-250): no network call, no port probe. One client config
/// is planted in the home, so the document must hold its entry; an empty `[]`, which other formats could also
/// print, does not pass.
#[test]
fn cap_discover_format_json_prints_one_json_document() {
    let home = tempfile::tempdir().expect("home");
    std::fs::write(
        home.path().join(".claude.json"),
        r#"{"mcpServers":{"planted-9680":{"command":"planted-9680-server"}}}"#,
    )
    .expect("plant a client config");
    // Never print what the command wrote, not even on failure: on a shared runner the process scan reads other
    // processes' command lines, which can carry keys (the lead, 2026-11-17). Only counts and the planted name show.
    let (code, stdout, _stderr) = run_in(
        home.path(),
        &["cap", "discover", "--format", "json"],
        None,
        b"",
    );
    let parsed = serde_json::from_str::<serde_json::Value>(&stdout).ok();
    let entries = parsed.as_ref().and_then(serde_json::Value::as_array);
    let planted = entries.map_or(0, |entries| {
        entries
            .iter()
            .filter(|entry| {
                entry.get("name").and_then(serde_json::Value::as_str) == Some("planted-9680")
            })
            .count()
    });
    assert_eq!(
        (code, parsed.is_some(), entries.is_some(), planted),
        (Some(0), true, true, 1),
        "exit; stdout is one JSON document; it is an array; entries named planted-9680"
    );
}

/// Records `left != right` in `misses` instead of stopping at the first mismatch, so one run shows every case.
macro_rules! check_eq {
    ($misses:ident, $left:expr, $right:expr, $($case:tt)+) => {{
        // A match, as assert_eq! uses, keeps temporaries in the operands alive for the comparison.
        match (&$left, &$right) {
            (left, right) => {
                if left != right {
                    let case = format!($($case)+);
                    $misses.push(format!("{case}\n  left: {left:?}\n right: {right:?}"));
                }
            }
        }
    }};
}

/// T13: each remote command through its real entry point succeeds as the process sees it.
#[test]
fn remote_commands_succeed_through_the_binary() {
    let mut misses: Vec<String> = Vec::new();
    let ok_link = stand_in(200, r#"{"link":"https://gw.test/once"}"#);
    check_eq!(
        misses,
        run(&["dashboard-link", "--url", &ok_link], Some(TOKEN), b""),
        (
            Some(0),
            "https://gw.test/once\n".to_string(),
            "Opens once, from this machine only.\n".to_string()
        ),
        "dashboard-link success"
    );
    let ok_list = stand_in(200, r#"{"items":[]}"#);
    check_eq!(
        misses,
        run(
            &["events", "dead-letters", "list", "--url", &ok_list],
            Some(TOKEN),
            b""
        ),
        (
            Some(0),
            "{\n  \"items\": []\n}\n".to_string(),
            String::new()
        ),
        "events success"
    );
    let ok_lookup = stand_in(200, LOOKUP_ANSWER);
    check_eq!(
        misses,
        run(
            &[
                "audit",
                "lookup-email",
                "--email-stdin",
                "--url",
                &ok_lookup
            ],
            Some(TOKEN),
            b"person@corp.test\n"
        ),
        (Some(0), LOOKUP_PRINTED.to_string(), String::new()),
        "lookup success"
    );
    let ok_api = stand_in(200, r#"{"a":1}"#);
    let (code, stdout, stderr) = run(
        &["api", "get", "/ui/api/x", "--url", &ok_api],
        Some(TOKEN),
        b"",
    );
    check_eq!(
        misses,
        (code, stderr.as_str()),
        (Some(0), ""),
        "api success"
    );
    check_eq!(
        misses,
        serde_json::from_str::<serde_json::Value>(&stdout).ok(),
        Some(serde_json::json!({"a": 1})),
        "api stdout"
    );

    assert!(
        misses.is_empty(),
        "{} mismatch(es):\n{}",
        misses.len(),
        misses.join("\n")
    );
}

/// T13: each remote command through its real entry point refuses (401) with the shared exit and text.
#[test]
fn remote_commands_refuse_with_the_table_through_the_binary() {
    let mut misses: Vec<String> = Vec::new();
    let refused = stand_in(401, r#"{"message":"denied"}"#);
    let remedy = format!("Set MCP_GATEWAY_TOKEN to a valid token for {refused}, then retry.");
    let want = (
        Some(3),
        String::new(),
        format!("error: The gateway answered HTTP 401: denied\n{remedy}\n"),
    );
    check_eq!(
        misses,
        run(&["dashboard-link", "--url", &refused], Some(TOKEN), b""),
        want,
        "dashboard-link 401"
    );
    check_eq!(
        misses,
        run(
            &["events", "dead-letters", "list", "--url", &refused],
            Some(TOKEN),
            b""
        ),
        want,
        "events 401"
    );
    check_eq!(
        misses,
        run(
            &["audit", "lookup-email", "--email-stdin", "--url", &refused],
            Some(TOKEN),
            b"person@corp.test\n"
        ),
        want,
        "lookup 401"
    );
    check_eq!(
        misses,
        run(
            &["api", "get", "/ui/api/x", "--url", &refused],
            Some(TOKEN),
            b""
        ),
        (Some(3), String::new(), format!("error: denied\n{remedy}\n")),
        "api 401"
    );
    assert!(
        misses.is_empty(),
        "{} mismatch(es):\n{}",
        misses.len(),
        misses.join("\n")
    );
}

// ── H3: a typo never names a hidden command (MIK-9681.CLIUX.18; design addendum H3) ─────────────────────────────

/// The hidden top-level commands, written out (A8); H3a checks the tree agrees.
const HIDDEN: [&str; 4] = ["kubernetes", "ranking", "runtime", "trust"];

/// clap's own suggestions for `argv`, before the binary rewrites the error: the premise that a hidden name is offered.
fn clap_suggests(argv: &[&str]) -> Vec<String> {
    use clap::error::{ContextKind, ContextValue};
    let err = <mcp_gateway::cli::Cli as clap::CommandFactory>::command()
        .try_get_matches_from(argv)
        .expect_err("a typo is refused");
    match err.get(ContextKind::SuggestedSubcommand) {
        Some(ContextValue::Strings(list)) => list.clone(),
        other => panic!("{argv:?}: clap suggests nothing: {other:?}"),
    }
}

fn names_no_hidden_command(stderr: &str) {
    for name in HIDDEN {
        assert!(
            !stderr.contains(&format!("'{name}'")),
            "{name} is named: {stderr}"
        );
    }
}

/// H3a: `stast` is close to the visible `stats` and the hidden `trust`; only `stats` is suggested.
#[test]
fn a_typo_suggests_only_the_visible_command() {
    let tree = <mcp_gateway::cli::Cli as clap::CommandFactory>::command();
    for name in HIDDEN {
        assert!(
            tree.find_subcommand(name).is_some_and(|c| c.is_hide_set()),
            "{name} is a hidden top-level command"
        );
    }
    assert_eq!(clap_suggests(&["mcp-gateway", "stast"]), ["trust", "stats"]);
    let (code, stdout, stderr) = run(&["stast"], None, b"");
    assert_eq!(code, Some(2), "{stderr}");
    assert_eq!(stdout, "");
    assert!(
        stderr.contains("unrecognized subcommand 'stast'"),
        "{stderr}"
    );
    assert!(
        stderr
            .lines()
            .any(|l| l == "  tip: a similar subcommand exists: 'stats'"),
        "{stderr}"
    );
    names_no_hidden_command(&stderr);
}

/// H3b: `rankng` is close only to the hidden `ranking` (clap's own list is exactly that), so no suggestion tip is
/// printed at all.
#[test]
fn a_typo_close_only_to_a_hidden_command_gets_no_tip() {
    assert_eq!(clap_suggests(&["mcp-gateway", "rankng"]), ["ranking"]);
    let (code, stdout, stderr) = run(&["rankng"], None, b"");
    assert_eq!(code, Some(2), "{stderr}");
    assert_eq!(stdout, "");
    assert!(
        stderr.contains("unrecognized subcommand 'rankng'"),
        "{stderr}"
    );
    assert!(!stderr.contains("similar subcommand"), "{stderr}");
    names_no_hidden_command(&stderr);
}

/// H3c: a typo at a nested level gets that level's visible suggestion (`listt` is close only to `list`).
#[test]
fn a_nested_typo_suggests_the_visible_command_there() {
    let (code, stdout, stderr) = run(&["cap", "listt"], None, b"");
    assert_eq!(code, Some(2), "{stderr}");
    assert_eq!(stdout, "");
    assert!(
        stderr
            .lines()
            .any(|l| l == "  tip: a similar subcommand exists: 'list'"),
        "{stderr}"
    );
}

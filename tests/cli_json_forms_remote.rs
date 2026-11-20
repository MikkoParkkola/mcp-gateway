// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! JSON forms of `stats` and `dashboard-link`, through the built binary against loopback stand-ins (test plan
//! r2: J1, J12, T1, T2, F). `dashboard-link` is on the shared error layer, so its `--json` errors are the shared
//! JSON error on stderr.

#[path = "common/gateway_bin.rs"]
mod gateway_bin;

use std::io::{Read as _, Write as _};
use std::net::TcpListener;

use serde_json::{Value, json};

/// What one run printed.
struct Out {
    code: Option<i32>,
    stdout: String,
    stderr: String,
}

/// A loopback stand-in answering every request with `status` and `body`.
fn stand_in(status: u16, body: String) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let base = format!("http://{}", listener.local_addr().expect("addr"));
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { return };
            let mut request = vec![0_u8; 65536];
            let _ = stream.read(&mut request);
            let head = format!(
                "HTTP/1.1 {status} Stand-in\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\
                 connection: close\r\n\r\n",
                body.len()
            );
            let _ = stream.write_all(head.as_bytes());
            let _ = stream.write_all(body.as_bytes());
        }
    });
    base
}

/// The binary with `args` in a fresh home, `token` as `MCP_GATEWAY_TOKEN` when given.
fn run(args: &[&str], token: Option<&str>) -> Out {
    let env: Vec<(&str, &str)> = token
        .map(|t| ("MCP_GATEWAY_TOKEN", t))
        .into_iter()
        .collect();
    let out = gateway_bin::run_cli(args, &env, None);
    Out {
        code: out.status.code(),
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
    }
}

/// The one document a `--json` run printed: exit 0, exactly one line ending in one newline.
fn document(out: &Out) -> Value {
    assert_eq!(out.code, Some(0), "stderr: {}", out.stderr);
    let line = out
        .stdout
        .strip_suffix('\n')
        .unwrap_or_else(|| panic!("no single trailing newline: {:?}", out.stdout));
    assert!(!line.contains('\n'), "more than one line: {:?}", out.stdout);
    serde_json::from_str(line).unwrap_or_else(|e| panic!("not one JSON document ({e}): {line:?}"))
}

// ── stats (J1, F) ───────────────────────────────────────────────────────────

/// A stats stand-in whose MCP answer carries `stats` as its text content.
fn stats_gateway(stats: &Value) -> String {
    let body = json!({
        "jsonrpc": "2.0", "id": 1,
        "result": {"content": [{"type": "text", "text": stats.to_string()}]}
    });
    stand_in(200, body.to_string())
}

#[test]
fn stats_prints_one_document_and_keeps_its_text() {
    let full = stats_gateway(&json!({
        "invocations": 7, "cache_hits": 3, "cache_hit_rate": 0.43, "tools_discovered": 12, "tools_available": 9,
        "top_tools": [{"server": "alpha", "tool": "search", "count": 5}, {"server": "beta", "tool": "fetch", "count": 2}]
    }));
    let plain = run(&["stats", "--url", &full], None);
    assert_eq!(
        (plain.code, plain.stdout.as_str(), plain.stderr.as_str()),
        (
            Some(0),
            "📊 Gateway Statistics\n\nInvocations:       7\nCache Hits:        3\nCache Hit Rate:    0.43\n\
             Tools Discovered:  12\nTools Available:   9\n\n🏆 Top Tools:\n  • alpha:search - 5 calls\n  \
             • beta:fetch - 2 calls\n",
            ""
        )
    );
    let json = run(&["stats", "--url", &full, "--json"], None);
    assert_eq!(
        document(&json),
        json!({
            "schema_version": 1, "invocations": 7, "cache_hits": 3, "cache_hit_rate": 0.43,
            "tools_discovered": 12, "tools_available": 9,
            "top_tools": [{"server": "alpha", "tool": "search", "count": 5},
                          {"server": "beta", "tool": "fetch", "count": 2}]
        })
    );
    assert_eq!(json.stderr, "");
}

/// The null rule from both sides: a counter present gives its value, absent gives null; absent `top_tools` is `[]`.
#[test]
fn stats_omitted_fields_are_null() {
    let partial = stats_gateway(&json!({
        "invocations": 7, "cache_hits": 3, "cache_hit_rate": 0.43, "tools_discovered": 12
    }));
    assert_eq!(
        document(&run(&["stats", "--url", &partial, "--json"], None)),
        json!({
            "schema_version": 1, "invocations": 7, "cache_hits": 3, "cache_hit_rate": 0.43,
            "tools_discovered": 12, "tools_available": null, "top_tools": []
        })
    );
    let bare = stats_gateway(&json!({}));
    assert_eq!(
        document(&run(&["stats", "--url", &bare, "--json"], None)),
        json!({
            "schema_version": 1, "invocations": null, "cache_hits": null, "cache_hit_rate": null,
            "tools_discovered": null, "tools_available": null, "top_tools": []
        })
    );
}

/// F: a refusing gateway under `--json` prints nothing on stdout; stderr and exit are the text form's.
#[test]
fn stats_json_failure_prints_no_document() {
    let refusing = stand_in(500, "{}".to_owned());
    let plain = run(&["stats", "--url", &refusing], None);
    let json = run(&["stats", "--url", &refusing, "--json"], None);
    assert_eq!(plain.code, Some(1), "{}", plain.stderr);
    assert_eq!(
        (json.code, json.stdout.as_str(), json.stderr.as_str()),
        (plain.code, "", plain.stderr.as_str())
    );
}

// ── dashboard-link (J12, T1, T2) ────────────────────────────────────────────

const TOKEN: &str = "tok-json-forms-0123456789abcdef";
const NOTE: &str = "Opens once, from this machine only.\n";

#[test]
fn dashboard_link_prints_one_document_and_keeps_its_text() {
    let gateway = stand_in(
        200,
        r#"{"link":"https://gw.example.test/ui/#k=abc123"}"#.to_owned(),
    );
    let plain = run(&["dashboard-link", "--url", &gateway], Some(TOKEN));
    assert_eq!(
        (plain.code, plain.stdout.as_str(), plain.stderr.as_str()),
        (Some(0), "https://gw.example.test/ui/#k=abc123\n", NOTE)
    );
    let json = run(
        &["dashboard-link", "--url", &gateway, "--json"],
        Some(TOKEN),
    );
    assert!(
        json.stdout.starts_with("{\"schema_version\":1,"),
        "field order: {:?}",
        json.stdout
    );
    assert_eq!(
        document(&json),
        json!({"schema_version": 1, "url": "https://gw.example.test/ui/#k=abc123"})
    );
    assert_eq!(json.stderr, NOTE);
}

/// T1: a token holding `"` or `\`, planted in the link the gateway returns, never reaches stdout in either form:
/// the command redacts it in the link (the text form prints `[redacted]` today), and the document carries the same
/// redacted link. The token appears neither raw nor JSON-escaped.
#[test]
fn dashboard_link_never_prints_a_token_planted_in_the_link() {
    for (token, escaped) in [
        (
            "tok\"quoted-0123456789abcdef",
            "tok\\\"quoted-0123456789abcdef",
        ),
        (
            "tok\\slashed-0123456789abcdef",
            "tok\\\\slashed-0123456789abcdef",
        ),
    ] {
        let link = format!("https://gw.example.test/ui/#k={token}");
        let gateway = stand_in(200, json!({"link": link}).to_string());
        let plain = run(&["dashboard-link", "--url", &gateway], Some(token));
        assert_eq!(
            (plain.code, plain.stdout.as_str(), plain.stderr.as_str()),
            (Some(0), "https://gw.example.test/ui/#k=[redacted]\n", NOTE),
            "{token}"
        );
        let json = run(
            &["dashboard-link", "--url", &gateway, "--json"],
            Some(token),
        );
        assert_eq!(
            document(&json),
            json!({"schema_version": 1, "url": "https://gw.example.test/ui/#k=[redacted]"}),
            "{token}"
        );
        for out in [&plain, &json] {
            assert!(
                !out.stdout.contains(token) && !out.stdout.contains(escaped),
                "{token}: {}",
                out.stdout
            );
            assert!(!out.stderr.contains(token), "{token}: {}", out.stderr);
        }
    }
}

/// T2: each failure of `dashboard-link --json` is the shared JSON error on stderr, stdout empty, with the plain
/// form's exit, message and remedy.
#[test]
fn dashboard_link_json_errors_are_the_shared_shape() {
    let dir = tempfile::tempdir().expect("dir");
    let broken = dir.path().join("gateway.yaml");
    mcp_gateway::gateway::test_helpers::write_owner_only(&broken, "server: [this is: not, valid\n")
        .expect("config");
    let broken = broken.to_str().expect("utf-8").to_owned();
    let refusing = stand_in(403, r#"{"error":"no"}"#.to_owned());
    let reachable = stand_in(
        200,
        r#"{"link":"https://gw.example.test/ui/#k=abc123"}"#.to_owned(),
    );
    // (args, token, kind, exit)
    let cases: [(Vec<&str>, Option<&str>, &str, i32); 3] = [
        (
            vec!["--config", broken.as_str(), "dashboard-link"],
            Some(TOKEN),
            "Usage",
            2,
        ),
        (
            vec!["dashboard-link", "--url", reachable.as_str()],
            None,
            "AuthRefused",
            3,
        ),
        (
            vec!["dashboard-link", "--url", refusing.as_str()],
            Some(TOKEN),
            "AuthRefused",
            3,
        ),
    ];
    for (args, token, kind, exit) in cases {
        let plain = run(&args, token);
        assert_eq!(
            (plain.code, plain.stdout.as_str()),
            (Some(exit), ""),
            "{args:?}: {}",
            plain.stderr
        );
        let (message, remedy) = plain
            .stderr
            .strip_prefix("error: ")
            .and_then(|rest| rest.strip_suffix('\n'))
            .and_then(|rest| rest.split_once('\n'))
            .unwrap_or_else(|| panic!("{args:?}: not the shared text error: {:?}", plain.stderr));
        let mut flagged = args.clone();
        flagged.push("--json");
        let json = run(&flagged, token);
        assert_eq!(
            (json.code, json.stdout.as_str()),
            (Some(exit), ""),
            "{args:?}: {}",
            json.stderr
        );
        let error: Value =
            serde_json::from_str(json.stderr.trim_end()).expect("one JSON error document");
        assert_eq!(
            (
                &error["schema_version"],
                &error["error"]["kind"],
                &error["error"]["message"],
                &error["error"]["remedy"]
            ),
            (&json!(1), &json!(kind), &json!(message), &json!(remedy)),
            "{args:?}"
        );
        let mut keys: Vec<&str> = error["error"]
            .as_object()
            .expect("object")
            .keys()
            .map(String::as_str)
            .collect();
        keys.sort_unstable();
        assert_eq!(
            keys,
            ["http_status", "kind", "message", "remedy", "request_id"],
            "{args:?}"
        );
    }
}

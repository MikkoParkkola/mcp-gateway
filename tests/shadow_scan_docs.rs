// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The shadow-scan docs and the shipped CLI must agree.

#[path = "common/gateway_bin.rs"]
mod gateway_bin;

use std::io::Write;
use std::process::{Command, Stdio};

#[test]
fn mik_5843_shadow_scope_anchors() {
    let docs = std::fs::read_to_string("docs/SHADOW_SCAN.md").expect("read SHADOW_SCAN.md");
    for needle in ["unmanaged MCP", "SIEM", "discover --shadow"] {
        assert!(
            docs.contains(needle),
            "shadow scope anchor missing from SHADOW_SCAN.md: {needle}"
        );
    }
}

#[test]
fn mik_5843_shipped_shadow_cli_matches_the_documented_scope() {
    let home = tempfile::tempdir().expect("an isolated home");
    let gateway = || gateway_bin::command(home.path(), gateway_bin::Inherit::Environment);
    let discover_help = gateway()
        .args(["cap", "discover", "--help"])
        .output()
        .expect("run cap discover --help");
    assert!(discover_help.status.success());
    assert!(String::from_utf8_lossy(&discover_help.stdout).contains("--shadow"));

    let doctor = gateway()
        .args(["doctor", "--shadow", "--shadow-format", "nginx"])
        .output()
        .expect("run doctor --shadow");
    assert!(doctor.status.success());
    let output = String::from_utf8_lossy(&doctor.stdout);
    assert!(output.contains("nginx log-phase map snippet"));
    assert!(output.contains("$request_body"));
    assert!(output.contains("\"~*("));
    assert!(output.contains("\\\"method\\\"[[:space:]]{0,5}"));
    assert!(output.contains("map directive belongs in the nginx http context"));
    assert!(output.contains("client_max_body_size 1m"));
    assert!(output.contains("client_body_buffer_size 1m"));
    assert!(output.contains("proxy_request_buffering on"));
    assert!(!output.contains("if ($request_body"));
    assert!(!output.contains("httpHost"));
    assert!(!output.contains("httpRequestURI"));

    let grep = gateway()
        .args(["doctor", "--shadow", "--shadow-format", "grep"])
        .output()
        .expect("run portable grep export");
    assert!(grep.status.success());
    let grep_output = String::from_utf8_lossy(&grep.stdout);
    assert!(grep_output.contains("grep -E"));
    assert!(grep_output.contains("[[:space:]]{0,5}"));
    assert!(!grep_output.contains("grep -P"));
    assert!(!grep_output.contains("\\s{0,5}"));

    let tools_call_pattern = grep_output
        .lines()
        .find(|line| line.contains("tools/call"))
        .and_then(|line| line.strip_prefix("grep -E '"))
        .and_then(|line| line.strip_suffix('\''))
        .expect("tools/call grep pattern");
    let mut system_grep = Command::new("grep")
        .args(["-E", tools_call_pattern])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .spawn()
        .expect("run system grep -E");
    system_grep
        .stdin
        .take()
        .expect("grep stdin")
        .write_all(br#"{"method": "tools/call"}"#)
        .expect("write MCP request sample");
    assert!(system_grep.wait().expect("wait for system grep").success());
}

#[test]
fn mik_5843_shadow_docs_are_linked_from_the_project_readme() {
    // The README names features, not competitors, so it links the shadow
    // documentation and not the comparison page.
    let readme = std::fs::read_to_string("README.md").expect("read README.md");
    assert!(
        readme.contains("[ShadowRadar](docs/SHADOW_SCAN.md)"),
        "project README does not link the operator-facing shadow documentation"
    );
}

#[test]
fn mik_5843_shadow_docs_expose_static_rule_export_without_enterprise_overclaim() {
    let docs = std::fs::read_to_string("docs/SHADOW_SCAN.md").expect("read SHADOW_SCAN.md");
    for format in ["grep", "nginx", "yaml"] {
        assert!(docs.contains(&format!(
            "mcp-gateway doctor --shadow --shadow-format {format}"
        )));
    }
    assert!(docs.contains("does not inspect traffic or publish findings to a SIEM"));
    assert!(docs.contains("remain enterprise workflow capabilities"));
    assert!(docs.contains("system grep on macOS and Linux"));
    assert!(docs.contains("`grep -E`"));
    assert!(docs.contains("not a commercial-use grant"));
    assert!(docs.contains("[`COMMERCIAL.md`](../COMMERCIAL.md)"));
}

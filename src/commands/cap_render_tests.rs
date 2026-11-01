// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The listing and the shadow report print every client-reachable value
//! escaped, keep their own layout, and never print a runnable command that
//! escaping would alter.

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use mcp_gateway::cli_support::is_hidden_char;
use mcp_gateway::config::TransportConfig;
use mcp_gateway::discovery::shadow::ShadowScanReport;
use mcp_gateway::discovery::{DiscoveredServer, DiscoverySource, ServerMetadata};
use mcp_gateway::security::summarize_stdio_command;

use super::{render_server_entry, render_shadow_report};

/// Recolours, reverses and breaks a terminal line.
const PAYLOAD: &str = "\u{1b}[31m\u{202e}\u{2028}";
/// The same without the line separator, for a field cut at whitespace
/// (U+2028 is whitespace), so the cut keeps it.
const TOKEN: &str = "\u{1b}[31m\u{202e}";

/// A stdio find whose command is also on record, as a process find's is:
/// the shadow report's executable comes from it.
fn with_command(name: &str, command: &str) -> DiscoveredServer {
    let mut server = stdio(name, command);
    server.metadata.command = Some(command.to_string());
    server
}

fn stdio(name: &str, command: &str) -> DiscoveredServer {
    DiscoveredServer::new(
        name.to_string(),
        "MCP server from ClaudeDesktop".to_string(),
        DiscoverySource::ClaudeDesktop,
        TransportConfig::Stdio {
            command: command.to_string(),
            cwd: None,
            protocol_version: None,
        },
        ServerMetadata::default(),
    )
}

fn http(name: &str, url: &str) -> DiscoveredServer {
    let mut server = stdio(name, "unused");
    server.transport = TransportConfig::Http {
        http_url: url.to_string(),
        streamable_http: None,
        protocol_version: None,
    };
    server
}

/// The layout's own line breaks are allowed; nothing else hidden is.
fn assert_clean(what: &str, text: &str) {
    let hidden: Vec<char> = text
        .chars()
        .filter(|&c| c != '\n' && is_hidden_char(c))
        .collect();
    assert!(hidden.is_empty(), "{what}: raw {hidden:?} in {text:?}");
}

/// The listing's text for a plain find is what the old printer wrote.
#[test]
fn a_plain_find_renders_as_before() {
    let command = "npx -y server-filesystem /data";
    let mut server = stdio("tool", command);
    server.metadata.config_path = Some(PathBuf::from("/home/me/.cursor/mcp.json"));
    server.metadata.pid = Some(42);
    let expected = format!(
        "📦 tool\n   Description: MCP server from ClaudeDesktop\n   Source: ClaudeDesktop\n   \
         Transport: stdio\n   Command: {}\n   Config: /home/me/.cursor/mcp.json\n   PID: 42\n\n",
        summarize_stdio_command(command)
    );
    assert_eq!(render_server_entry(&server), expected);
}

/// One row per client-reachable field of the listing, the payload in that
/// field only: no raw hidden character, and no extra line.
#[test]
fn every_listing_field_is_escaped() {
    let mut path = stdio("tool", "npx tool");
    path.metadata.config_path = Some(PathBuf::from(format!("/home/me{PAYLOAD}/mcp.json")));
    let mut plain_path = stdio("tool", "npx tool");
    plain_path.metadata.config_path = Some(PathBuf::from("/home/me/mcp.json"));
    let rows = [
        (
            "name",
            stdio(&format!("tool{PAYLOAD}"), "npx tool"),
            stdio("tool", "npx tool"),
        ),
        (
            "command",
            stdio("tool", &format!("np{PAYLOAD}x tool")),
            stdio("tool", "npx tool"),
        ),
        ("config path", path, plain_path),
    ];
    for (field, hostile, plain) in rows {
        let text = render_server_entry(&hostile);
        assert_clean(field, &text);
        assert_eq!(
            text.lines().count(),
            render_server_entry(&plain).lines().count(),
            "{field}: a line was forged: {text:?}"
        );
    }
    assert!(
        render_server_entry(&stdio(&format!("tool{PAYLOAD}"), "npx tool")).contains("\\u{1b}"),
        "the escape is shown"
    );
}

fn report(servers: &[DiscoveredServer], config: &Path) -> ShadowScanReport {
    ShadowScanReport::from_discovered(servers, &HashSet::new(), Some(config))
}

/// The shadow report escapes the name, endpoint and executable, and keeps
/// its layout.
#[test]
fn every_shadow_field_is_escaped() {
    let config = Path::new("/home/me/gateway.yaml");
    let rows = [
        (
            "name",
            stdio(&format!("tool{PAYLOAD}"), "npx tool"),
            stdio("tool", "npx tool"),
        ),
        (
            "executable",
            with_command("tool", &format!("np{TOKEN}x tool")),
            with_command("tool", "npx tool"),
        ),
        (
            "endpoint",
            // Unparseable, so redaction's fallback echoes it: the row can
            // go red.
            http("tool", &format!("{PAYLOAD}not-a-url")),
            http("tool", "not-a-url"),
        ),
    ];
    for (field, hostile, plain) in rows {
        let text = render_shadow_report(&report(&[hostile], config));
        assert_clean(field, &text);
        assert!(
            text.contains("\\u{1b}"),
            "{field}: the escape is not shown: {text}"
        );
        assert_eq!(
            text.lines().count(),
            render_shadow_report(&report(&[plain], config))
                .lines()
                .count(),
            "{field}: a line was forged: {text:?}"
        );
    }
}

/// A command holding a hidden character is withheld, never printed
/// altered: an altered command could end its own shell quoting early.
#[test]
fn a_command_escaping_would_alter_is_withheld() {
    let server = stdio("tool", "npx tool");
    let plain = render_shadow_report(&report(
        std::slice::from_ref(&server),
        Path::new("/home/me/gw.yaml"),
    ));
    assert!(plain.contains("Apply after review: "), "{plain}");
    assert!(!plain.contains("withheld"), "{plain}");
    let hostile = render_shadow_report(&report(
        &[server],
        Path::new(&format!("/home/me{PAYLOAD}'x/gw.yaml")),
    ));
    assert_clean("apply command", &hostile);
    assert!(hostile.contains("withheld"), "{hostile}");
    assert!(!hostile.contains("'x/gw.yaml"), "{hostile}");
}

/// A listed URL is reduced to its origin before it is shown, so a path
/// carrying hidden characters never reaches the terminal at all: this pins
/// the redaction, which is what protects this field.
#[test]
fn a_listed_url_shows_only_its_origin() {
    let text = render_server_entry(&http("tool", &format!("https://example.test/mcp{PAYLOAD}")));
    assert!(text.contains("   URL: https://example.test"), "{text}");
    assert!(!text.contains("/mcp"), "{text}");
    assert_clean("url", &text);
}

/// Machine output keeps the data: `--format json` and `--format yaml` carry a
/// hostile name exactly, and parse back to it (lead ruling: escaping is for
/// the human text only).
#[test]
fn json_and_yaml_carry_a_hostile_name_unchanged() {
    let name = format!("tool{PAYLOAD}\n\\u{{1b}}");
    let listed = vec![stdio(&name, "npx tool").redacted_for_diagnostics()];

    let json = serde_json::to_string_pretty(&listed).expect("json");
    let back: serde_json::Value = serde_json::from_str(&json).expect("parses");
    assert_eq!(back[0]["name"], serde_json::Value::String(name.clone()));
    assert!(
        !json.contains('\u{1b}'),
        "serde_json escapes C0 controls: {json:?}"
    );

    let yaml = crate::yaml::to_string(&listed).expect("yaml");
    let back: Vec<serde_json::Value> = crate::yaml::from_str(&yaml).expect("parses");
    assert_eq!(back[0]["name"], serde_json::Value::String(name));
}

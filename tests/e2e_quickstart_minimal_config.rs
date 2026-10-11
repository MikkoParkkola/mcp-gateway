// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8044 SURF.7 and P2f(d): a fresh home serves a tool call from the
//! minimal config QUICKSTART documents, and a 3.x config with keys 4.0
//! removed is refused with the way out, then serves the same call after
//! `mcp-gateway upgrade`.
//!
//! The config is read from the page itself (between its markers), so the
//! docs and this test cannot drift. Its one backend `command` is pointed at a
//! local stdio peer, so nothing leaves the machine; the documented launcher
//! itself runs only in the opt-in `--ignored` smoke row.

#![cfg(unix)]

#[path = "common/gateway_bin.rs"]
mod gateway_bin;
#[path = "common/journey.rs"]
#[allow(dead_code, reason = "shared harness; each journey uses a subset")]
mod journey;

use std::path::Path;
use std::process::Output;
use std::time::Duration;

use journey::{Gateway, MARKER, PEER, SEARCH_BOUND, Session, TOOL, Workspace, payload, show};
use serde_json::{Value, json};

const OPEN: &str = "<!-- quickstart-minimal-config -->";
const CLOSE: &str = "<!-- /quickstart-minimal-config -->";
/// A 3.x API key in plaintext, which `upgrade` rewrites to its digest.
const PLAINTEXT: &str = "surf7-plaintext-key-0123456789";
/// How long a `serve` expected to refuse its config may run.
const REFUSE_BOUND: Duration = Duration::from_secs(60);

/// The minimal config exactly as QUICKSTART shows it, fences stripped.
fn documented_minimal_config() -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("docs/QUICKSTART.md");
    let page = std::fs::read_to_string(&path).expect("docs/QUICKSTART.md");
    let start = page
        .find(OPEN)
        .unwrap_or_else(|| panic!("QUICKSTART marks no minimal config ({OPEN})"))
        + OPEN.len();
    let end = page[start..]
        .find(CLOSE)
        .unwrap_or_else(|| panic!("the minimal config is not closed ({CLOSE})"))
        + start;
    let fenced = page[start..end].trim();
    fenced
        .strip_prefix("```yaml")
        .and_then(|b| b.strip_suffix("```"))
        .unwrap_or_else(|| panic!("the marked block is not one ```yaml fence:\n{fenced}"))
        .trim_matches('\n')
        .to_string()
}

/// The documented config's one backend: its name and its `command` line.
fn documented_backend(yaml: &str) -> (String, usize) {
    let lines: Vec<&str> = yaml.lines().collect();
    let commands: Vec<usize> = (0..lines.len())
        .filter(|&i| lines[i].trim_start().starts_with("command:"))
        .collect();
    assert_eq!(commands.len(), 1, "one backend `command` line:\n{yaml}");
    let at = commands[0];
    let name = lines[at - 1]
        .trim()
        .strip_suffix(':')
        .unwrap_or_else(|| panic!("the line above `command:` names the backend:\n{yaml}"));
    (name.to_string(), at)
}

/// The documented config with its one backend `command` pointed at `peer`;
/// every other line as the page shows it.
fn with_peer(yaml: &str, peer: &Path) -> String {
    let (_, at) = documented_backend(yaml);
    let command = json!(format!("/bin/sh {}", peer.display())).to_string();
    let mut lines: Vec<String> = yaml.lines().map(str::to_string).collect();
    let indent = lines[at].len() - lines[at].trim_start().len();
    lines[at] = format!("{}command: {command}", " ".repeat(indent));
    lines.join("\n") + "\n"
}

/// P2f(d): the minimal config fits one screen and names one backend.
#[test]
fn the_documented_minimal_config_fits_one_screen_and_names_one_backend() {
    let yaml = documented_minimal_config();
    let lines = yaml.lines().count();
    assert!(lines <= 15, "{lines} lines, more than 15:\n{yaml}");
    let (name, _) = documented_backend(&yaml);
    assert!(!name.is_empty(), "{yaml}");
}

/// Write the documented config, its backend pointed at the local peer, into
/// the empty project directory. The backend's name, as documented.
fn write_served_config(ws: &Workspace, yaml: &str) -> String {
    let peer = ws.root.join("peer.sh");
    std::fs::write(&peer, PEER).expect("write the peer");
    std::fs::write(ws.root.join("gateway.yaml"), with_peer(yaml, &peer)).expect("write the config");
    documented_backend(yaml).0
}

/// `gateway_search_tools` until the peer's tool is found (bounded), then
/// `gateway_invoke` on it: the peer's answer comes back.
async fn search_then_invoke(session: &mut Session, gateway: &Gateway, backend: &str) {
    let deadline = tokio::time::Instant::now() + SEARCH_BOUND;
    loop {
        let answer = session
            .call("gateway_search_tools", json!({ "query": "tide harbour" }))
            .await;
        let found = answer["result"]["structuredContent"]["matches"]
            .as_array()
            .is_some_and(|m| {
                m.iter()
                    .any(|m| m["server"] == backend && m["tool"] == TOOL)
            });
        if found {
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "search never found {backend}/{TOOL} within {SEARCH_BOUND:?}: {answer}\n{}",
            gateway.logs()
        );
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    let answer = session
        .call(
            "gateway_invoke",
            json!({ "server": backend, "tool": TOOL, "arguments": { "harbour": "Oslo" } }),
        )
        .await;
    let result: Value = payload(&answer);
    assert_eq!(
        result["content"][0]["text"],
        MARKER,
        "invoke did not return the backend's answer: {answer}\n{}",
        gateway.logs()
    );
    assert_ne!(answer["result"]["isError"], true, "{answer}");
}

/// SURF.7, first half: a fresh HOME and an empty directory, the documented
/// minimal config (its backend pointed at a local peer), `serve`, and one
/// tool call through that backend. No token: a loopback `/mcp` with no
/// `auth` block serves tool calls, as QUICKSTART says.
#[tokio::test]
async fn a_fresh_home_serves_a_tool_call_from_the_documented_minimal_config() {
    let ws = Workspace::new();
    let backend = write_served_config(&ws, &documented_minimal_config());
    let gateway = Gateway::start(&ws).await;
    let mut session = Session::open(&format!("{}/mcp", gateway.url), None).await;
    search_then_invoke(&mut session, &gateway, &backend).await;
}

/// Every key 4.0 removed, as a 3.x config set them; each refuses the load but
/// `meta_mcp.cache_tools`, which only warns (`src/config/strict_keys.rs`).
const REFUSING: [&str; 6] = [
    "server.ws_port",
    "server.request_timeout",
    "marketplace",
    "cost_governance.currency",
    "idle_timeout",
    "circuit_breaker",
];

/// `config` (one backend `command` line) as a 3.x user had it: every removed
/// key set, and a plaintext API key.
fn three_x(config: &str) -> String {
    let mut out = Vec::new();
    let (mut server, mut backend) = (0, 0);
    for line in config.lines() {
        out.push(line.to_string());
        if line == "server:" {
            server += 1;
            out.push("  ws_port: 39401".into());
            out.push("  request_timeout: 30s".into());
        }
        if line.trim_start().starts_with("command:") {
            backend += 1;
            let pad = " ".repeat(line.len() - line.trim_start().len());
            out.push(format!("{pad}idle_timeout: 5m"));
            out.push(format!("{pad}circuit_breaker:"));
            out.push(format!("{pad}  enabled: false"));
        }
    }
    assert_eq!(
        (server, backend),
        (1, 1),
        "one `server:` and one backend:\n{config}"
    );
    out.push(format!(
        "meta_mcp:\n  cache_tools: true\nmarketplace:\n  marketplace_url: https://plugins.invalid\n\
         cost_governance:\n  currency: EUR\nauth:\n  enabled: true\n  api_keys:\n    - name: surf7\n      \
         key: \"{PLAINTEXT}\"\n      backends: [\"*\"]"
    ));
    out.join("\n") + "\n"
}

/// `serve` on a config it must refuse: it exits, within a bound, and its
/// output is returned. A `serve` that starts instead fails the row.
async fn refused_serve(ws: &Workspace) -> Output {
    let mut command = tokio::process::Command::from(ws.command());
    command
        .args(["-c", "gateway.yaml", "-p", "0", "serve"])
        .kill_on_drop(true);
    tokio::time::timeout(REFUSE_BOUND, command.output())
        .await
        .unwrap_or_else(|_| panic!("serve ran {REFUSE_BOUND:?} on a config it must refuse"))
        .expect("serve runs")
}

/// SURF.7, second half: a 3.x config with the removed keys is refused with
/// the way out; `mcp-gateway upgrade` rewrites it; the gateway then serves
/// the same tool call, authenticated by the same (now hashed) key.
#[tokio::test]
async fn a_three_x_config_is_refused_then_serves_after_upgrade() {
    use std::os::unix::fs::PermissionsExt;
    let ws = Workspace::new();
    let backend = write_served_config(&ws, &documented_minimal_config());
    let config = ws.root.join("gateway.yaml");
    let current = std::fs::read_to_string(&config).expect("config");
    std::fs::write(&config, three_x(&current)).expect("write the 3.x config");
    std::fs::set_permissions(&config, std::fs::Permissions::from_mode(0o600)).expect("0600");

    // The migration message: every refusing key, and the command that fixes them.
    let refused = refused_serve(&ws).await;
    let said = show(&refused);
    assert!(!refused.status.success(), "a 3.x config was served\n{said}");
    for key in REFUSING {
        assert!(
            said.contains(key),
            "the refusal does not name {key}\n{said}"
        );
    }
    assert!(
        said.contains("mcp-gateway upgrade"),
        "the refusal names no way out\n{said}"
    );

    // One upgrade.
    let state = ws.root.join("gateway-state");
    std::fs::create_dir_all(&state).expect("state dir");
    let state = state.display().to_string();
    ws.run_ok(&["-c", "gateway.yaml", "upgrade", "--data-dir", &state]);
    let upgraded = std::fs::read_to_string(&config).expect("config");
    assert_upgraded(&upgraded, &backend);

    // The same call, served, with the same key as the bearer.
    let gateway = Gateway::start(&ws).await;
    let mut session =
        Session::open(&format!("{}/mcp", gateway.url), Some(PLAINTEXT.to_string())).await;
    search_then_invoke(&mut session, &gateway, &backend).await;
    let log = gateway.logs();
    for said in ["Removed config key", "cache_tools"] {
        assert!(
            !log.contains(said),
            "the upgraded config still warns `{said}`:\n{log}"
        );
    }

    // The key still guards `/mcp`: no bearer, or a wrong one, is refused.
    let mcp = format!("{}/mcp", gateway.url);
    for bearer in [None, Some("surf7-a-wrong-key")] {
        let status = initialize_status(&mcp, bearer).await;
        assert_eq!(status, 401, "bearer {bearer:?} was not refused");
    }
}

/// The upgraded file, read as YAML: no removed path is left, `auth` is still
/// on, and the plaintext key became its digest (#3824).
fn assert_upgraded(upgraded: &str, backend: &str) {
    let yaml: serde_yaml::Value =
        serde_yaml::from_str(upgraded).expect("the upgraded file is YAML");
    let at = |path: &[&str]| path.iter().try_fold(&yaml, |v, k| v.get(*k));
    for path in [
        &["server", "ws_port"][..],
        &["server", "request_timeout"],
        &["marketplace"],
        &["cost_governance", "currency"],
        &["meta_mcp", "cache_tools"],
        &["backends", backend, "idle_timeout"],
        &["backends", backend, "circuit_breaker"],
    ] {
        assert!(at(path).is_none(), "upgrade left {path:?}:\n{upgraded}");
    }
    assert_eq!(
        at(&["auth", "enabled"]),
        Some(&serde_yaml::Value::Bool(true)),
        "{upgraded}"
    );
    let key = &at(&["auth", "api_keys"]).expect("api_keys")[0];
    assert!(
        key.get("key").is_none(),
        "the plaintext key stayed:\n{upgraded}"
    );
    assert!(
        key.get("key_sha256")
            .and_then(serde_yaml::Value::as_str)
            .is_some_and(|d| d.starts_with("sha256:")),
        "no digest:\n{upgraded}"
    );
    assert!(
        !upgraded.contains(PLAINTEXT),
        "the plaintext is still in the file"
    );
}

/// The HTTP status `/mcp` answers an `initialize` sent with `bearer`, or none.
async fn initialize_status(mcp: &str, bearer: Option<&str>) -> u16 {
    let body = json!({ "jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
        "protocolVersion": "2025-06-18", "capabilities": {},
        "clientInfo": { "name": "surf7", "version": "1" } } });
    let mut request = journey::http_client()
        .post(mcp)
        .header("content-type", "application/json")
        .header("accept", "application/json")
        .json(&body);
    if let Some(bearer) = bearer {
        request = request.bearer_auth(bearer);
    }
    request
        .send()
        .await
        .expect("the gateway answers")
        .status()
        .as_u16()
}

/// The documented launcher itself, unchanged: the reference server's `echo`
/// tool answers through the documented config. Opt-in, because it downloads
/// an npm package: `cargo test --test e2e_quickstart_minimal_config -- --ignored`.
#[tokio::test]
#[ignore = "network: the documented command downloads an npm package"]
async fn the_documented_launcher_serves_a_tool_call() {
    let ws = Workspace::new();
    let yaml = documented_minimal_config();
    std::fs::write(ws.root.join("gateway.yaml"), format!("{yaml}\n")).expect("write the config");
    let (backend, _) = documented_backend(&yaml);
    let gateway = Gateway::start(&ws).await;
    let mut session = Session::open(&format!("{}/mcp", gateway.url), None).await;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(180);
    let answer = loop {
        let answer = session
            .call(
                "gateway_invoke",
                json!({ "server": backend, "tool": "echo", "arguments": { "message": "surf7" } }),
            )
            .await;
        if answer["result"]["isError"] != true {
            break answer;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "the documented backend never answered: {answer}\n{}",
            gateway.logs()
        );
        tokio::time::sleep(Duration::from_secs(2)).await;
    };
    assert!(answer.to_string().contains("surf7"), "{answer}");
}

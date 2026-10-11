// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! First-run journey, driven through the built binary the way a new user
//! meets it: `init` in an empty directory, `list --available`, `add` a server,
//! start the gateway, then over HTTP list the meta-tools, find the added tool
//! with `gateway_search_tools` and call it with `gateway_invoke`.
//!
//! Every assertion is on what the user sees: exit codes, printed text, files
//! written, JSON-RPC answers. Nothing leaves the machine: `init` runs with an
//! empty `PATH` so no `npx`/`uvx` starter is written, the HTTP starters it
//! does write are removed with `remove`, and the added server is a local
//! stdio peer.

#![cfg(unix)]

#[path = "common/gateway_bin.rs"]
mod gateway_bin;
#[path = "common/journey.rs"]
#[allow(dead_code, reason = "shared harness; each journey uses a subset")]
mod journey;

use std::path::Path;
use std::time::Duration;

use journey::{
    BACKEND, Gateway, MARKER, PEER, SEARCH_BOUND, Session, TOOL, Workspace, payload, show,
};
use serde_json::{Value, json};

/// The documented admin meta-tool count (README, `public_claims.json`).
fn documented_meta_tools() -> usize {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("benchmarks/public_claims.json");
    let claims: Value =
        serde_json::from_str(&std::fs::read_to_string(path).expect("claims file")).expect("JSON");
    let count = claims["meta_tools"]["readme_benchmark"]
        .as_u64()
        .expect("meta_tools.readme_benchmark");
    usize::try_from(count).expect("small count")
}

/// `init`, `list --available`, `remove` the network starters, `add` the peer.
fn configure(ws: &Workspace) {
    init(ws);
    browse_and_add(ws);
}

/// `init` in the empty directory, then a second `init` that must refuse.
fn init(ws: &Workspace) {
    // init, with no npx/uvx on PATH: stdio starters are skipped, said why.
    let init = ws
        .command()
        .arg("init")
        .env("PATH", ws.root.join("empty-path"))
        .output()
        .expect("init runs");
    assert!(init.status.success(), "init failed\n{}", show(&init));
    let stdout = String::from_utf8_lossy(&init.stdout);
    for line in [
        "Created gateway.yaml",
        "Profile: local",
        "Created zero-key sample capabilities under ./capabilities/",
        "An admin credential was generated and written into that file,",
    ] {
        assert!(
            stdout.contains(line),
            "init did not print {line:?}\n{}",
            show(&init)
        );
    }
    let stderr = String::from_utf8_lossy(&init.stderr);
    assert!(
        stderr.contains("Skipped '"),
        "with no launcher on PATH, init must say which starters it skipped\n{}",
        show(&init)
    );
    for line in stderr.lines().filter(|l| !l.trim().is_empty()) {
        assert!(
            line.starts_with("Skipped '") && line.contains("is not on PATH"),
            "unexpected init stderr line {line:?}\n{}",
            show(&init)
        );
    }

    let config = ws.root.join("gateway.yaml");
    let written = std::fs::read_to_string(&config).expect("init wrote gateway.yaml");
    assert!(written.contains("bearer_token: \"mcpgw_"), "{written}");
    let mode = std::os::unix::fs::PermissionsExt::mode(
        &std::fs::metadata(&config)
            .expect("config metadata")
            .permissions(),
    );
    assert_eq!(mode & 0o777, 0o600, "gateway.yaml holds a credential");
    let samples = std::fs::read_dir(ws.root.join("capabilities")).expect("capabilities/");
    assert!(samples.count() > 0, "no sample capabilities written");

    // A second init refuses rather than overwriting the credential.
    let before = std::fs::read(&config).expect("config bytes");
    let again = ws.run(&["init"]);
    assert_eq!(
        std::fs::read(&config).expect("config bytes"),
        before,
        "a refused init must leave gateway.yaml as it was"
    );
    assert!(
        !again.status.success(),
        "second init must refuse\n{}",
        show(&again)
    );
    assert!(
        String::from_utf8_lossy(&again.stderr).contains("gateway.yaml already exists"),
        "{}",
        show(&again)
    );
}

/// `list --available`, then swap the starters for one local server.
fn browse_and_add(ws: &Workspace) {
    // The built-in library: the header's count matches the entries listed.
    let available = ws.run_ok(&["list", "--available"]);
    let header = available.lines().next().expect("a header line");
    let count: usize = header
        .split_whitespace()
        .next()
        .and_then(|n| n.parse().ok())
        .unwrap_or_else(|| panic!("no count in {header:?}"));
    assert!(
        header.ends_with(
            "servers in the built-in library. Turn one on with `mcp-gateway add <name>`."
        ),
        "{header:?}"
    );
    let listed = available
        .lines()
        .filter(|l| l.starts_with("    login: "))
        .count();
    assert_eq!(listed, count, "{available}");

    // Remove the starters init wrote (they reach the network).
    let starters: Value =
        serde_json::from_str(&ws.run_ok(&["list", "--json"])).expect("list --json is JSON");
    for name in starters.as_array().expect("a JSON array") {
        let name = name["name"].as_str().expect("a backend name");
        assert_eq!(
            ws.run_ok(&["remove", name]).trim(),
            format!("Removed '{name}'.")
        );
    }
    assert_eq!(
        ws.run_ok(&["list"]).trim(),
        "No backends configured in gateway.yaml."
    );

    // Add a local stdio server.
    let peer = ws.root.join("tidebook.sh");
    std::fs::write(&peer, PEER).expect("write the peer");
    let peer = peer.display().to_string();
    let added = ws.run_ok(&[
        "add",
        "--description",
        "Tide tables for harbours",
        BACKEND,
        "--",
        "/bin/sh",
        &peer,
    ]);
    assert!(
        added.starts_with(&format!("Added '{BACKEND}' (stdio).")),
        "{added}"
    );
    let list = ws.run_ok(&["list"]);
    assert!(list.contains(&format!("  {BACKEND} (stdio)")), "{list}");
    assert!(list.contains("    Tide tables for harbours"), "{list}");
}

fn admin_token(ws: &Workspace) -> String {
    let config = std::fs::read_to_string(ws.root.join("gateway.yaml")).expect("config");
    config
        .lines()
        .find_map(|l| l.trim().strip_prefix("bearer_token:"))
        .map(|t| t.trim().trim_matches('"').to_string())
        .expect("a bearer_token line")
}

#[tokio::test]
async fn first_run_journey_init_add_serve_search_invoke() {
    let ws = Workspace::new();
    configure(&ws);
    let gateway = Gateway::start(&ws).await;
    let mcp = format!("{}/mcp", gateway.url);

    // tools/list: the documented compact surface for the admin, and five
    // fewer for a caller without admin standing (README, "Meta-MCP").
    let documented = documented_meta_tools();
    let mut admin = Session::open(&mcp, Some(admin_token(&ws))).await;
    let admin_tools = admin.tool_names().await;
    assert_eq!(admin_tools.len(), documented, "admin sees {admin_tools:?}");
    let mut anon = Session::open(&mcp, None).await;
    let anon_tools = anon.tool_names().await;
    assert_eq!(
        anon_tools.len(),
        documented - 5,
        "anonymous sees {anon_tools:?}"
    );
    for core in [
        "gateway_list_servers",
        "gateway_list_tools",
        "gateway_search_tools",
        "gateway_invoke",
    ] {
        assert!(
            anon_tools.iter().any(|t| t == core),
            "{core} missing: {anon_tools:?}"
        );
    }

    // gateway_search_tools finds the added server's tool once it has warmed.
    let deadline = tokio::time::Instant::now() + SEARCH_BOUND;
    loop {
        let answer = anon
            .call("gateway_search_tools", json!({ "query": "tide harbour" }))
            .await;
        let found = answer["result"]["structuredContent"]["matches"]
            .as_array()
            .is_some_and(|m| {
                m.iter()
                    .any(|m| m["server"] == BACKEND && m["tool"] == TOOL)
            });
        if found {
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "search never found {BACKEND}/{TOOL} within {SEARCH_BOUND:?}: {answer}\n{}",
            gateway.logs()
        );
        tokio::time::sleep(Duration::from_millis(500)).await;
    }

    // gateway_invoke reaches the server and returns its answer.
    let answer = anon
        .call(
            "gateway_invoke",
            json!({ "server": BACKEND, "tool": TOOL, "arguments": { "harbour": "Oslo" } }),
        )
        .await;
    let result = payload(&answer);
    assert_eq!(
        result["content"][0]["text"],
        MARKER,
        "invoke did not return the server's answer: {answer}\n{}",
        gateway.logs()
    );
    assert_ne!(result["isError"], true, "{answer}");
    assert_ne!(answer["result"]["isError"], true, "{answer}");
}

/// MIK-8044.SURF.2 P2f(e), a guard: the config `init` writes keeps its auth
/// posture. Tools stay open to a tokenless client on loopback, the dashboard
/// API needs the generated token, and the solo OAuth principal is granted.
#[tokio::test]
async fn init_keeps_its_auth_posture() {
    let ws = Workspace::new();
    configure(&ws);
    let config = mcp_gateway::config::Config::load(Some(&ws.root.join("gateway.yaml")))
        .expect("the init config loads");
    assert!(
        config.auth.grants_single_user_principal(false),
        "init must keep single_user on"
    );

    let gateway = Gateway::start(&ws).await;
    let mut anon = Session::open(&format!("{}/mcp", gateway.url), None).await;
    let tools = anon.tool_names().await;
    assert!(
        tools.iter().any(|t| t == "gateway_invoke"),
        "a tokenless loopback client lists the tools: {tools:?}"
    );

    let status = format!("{}/ui/api/status", gateway.url);
    let http = http_client();
    let without = http.get(&status).send().await.expect("the gateway answers");
    assert_eq!(
        without.status(),
        reqwest::StatusCode::UNAUTHORIZED,
        "the dashboard API answered without the token"
    );
    let with = http
        .get(&status)
        .bearer_auth(admin_token(&ws))
        .send()
        .await
        .expect("the gateway answers");
    assert_eq!(
        with.status(),
        reqwest::StatusCode::OK,
        "the dashboard API refused the token init generated"
    );
}

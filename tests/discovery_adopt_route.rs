// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! `POST /ui/api/discovery/adopt` end to end: the real binary, the real
//! scanner, a client config file in the child's own home and the files
//! secret store. An adopted server becomes a disabled backend whose literal
//! values live in the store; the answers never carry a value.
//!
//! The child has its own home (`gateway_bin`), so neither the scan nor the
//! store touches the test runner's home or keychain.

#[path = "common/gateway_bin.rs"]
mod gateway_bin;
#[path = "common/mcp_http_servers.rs"]
#[allow(dead_code, reason = "shared fixtures; each binary uses a subset")]
mod mcp_http_servers;

use std::path::Path;
use std::process::Stdio;
use std::time::{Duration, Instant};

use serde_json::{Value, json};
use tokio::process::{Child, Command};

use gateway_bin::{ANY_PORT, reported_port};

const STARTUP: Duration = Duration::from_secs(60);
const BEARER: &str = "discovery-adopt-admin-token";
const SECRET: &str = "zq-adopt-env-secret";
const HEADER_SECRET: &str = "zq-adopt-header-secret";

fn write_owner_only(path: &Path, text: &str) {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).expect("dir");
    }
    mcp_gateway::gateway::test_helpers::write_owner_only(path, text).expect("write owner-only");
}

struct Gateway {
    child: Child,
    port: u16,
    log: std::path::PathBuf,
}

impl Gateway {
    async fn spawn(home: &Path, config: &Path) -> Self {
        let log = home.join("gateway.log");
        let out = std::fs::File::create(&log).expect("log file");
        let err = out.try_clone().expect("log handle");
        let child = Command::from(gateway_bin::command(
            home,
            gateway_bin::Inherit::Environment,
        ))
        .current_dir(home)
        .env("MCP_GATEWAY_CONFIG_DIR", home.join("state"))
        .env("RUST_LOG", "info")
        .kill_on_drop(true)
        .arg("serve")
        .arg("--config")
        .arg(config)
        .stdin(Stdio::null())
        .stdout(Stdio::from(out))
        .stderr(Stdio::from(err))
        .spawn()
        .expect("the built mcp-gateway binary spawns");
        let mut gateway = Self {
            child,
            port: ANY_PORT,
            log,
        };
        let deadline = Instant::now() + STARTUP;
        let probe = reqwest::Client::new();
        loop {
            if gateway.port == ANY_PORT {
                gateway.port = reported_port(&gateway.logs()).unwrap_or(ANY_PORT);
            }
            if gateway.port != ANY_PORT
                && let Ok(response) = probe
                    .get(format!("http://127.0.0.1:{}/livez", gateway.port))
                    .send()
                    .await
                && response.status().is_success()
            {
                return gateway;
            }
            assert!(Instant::now() < deadline, "no /livez:\n{}", gateway.logs());
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
    }

    /// Stops the child and waits for it to exit, so a second gateway can
    /// take its audit log.
    async fn stop(mut self) {
        self.child.kill().await.expect("the gateway stops");
    }

    fn logs(&self) -> String {
        std::fs::read_to_string(&self.log).unwrap_or_default()
    }

    fn url(&self, path: &str) -> String {
        format!("http://127.0.0.1:{}{path}", self.port)
    }

    async fn list(&self) -> Value {
        reqwest::Client::new()
            .get(self.url("/ui/api/discovery"))
            .bearer_auth(BEARER)
            .send()
            .await
            .expect("GET")
            .json()
            .await
            .expect("json")
    }

    async fn adopt(&self, body: &Value) -> (u16, String) {
        let response = reqwest::Client::new()
            .post(self.url("/ui/api/discovery/adopt"))
            .bearer_auth(BEARER)
            .json(body)
            .send()
            .await
            .expect("POST");
        (
            response.status().as_u16(),
            response.text().await.expect("body"),
        )
    }
}

fn client_file(home: &Path, servers: &Value) {
    write_owner_only(
        &home.join(".cursor/mcp.json"),
        &json!({ "mcpServers": servers }).to_string(),
    );
}

fn gateway_config(home: &Path) -> std::path::PathBuf {
    let config = home.join("gateway.yaml");
    write_owner_only(
        &config,
        &format!(
            "# operator note: keep\nserver:\n  host: \"127.0.0.1\"\n  port: {ANY_PORT}\n\
             auth:\n  enabled: true\n  bearer_token: \"{BEARER}\"\n  single_user: true\n\
             secrets:\n  store: files\nbackends: {{}}\n"
        ),
    );
    config
}

fn find_id(listing: &Value, name: &str) -> String {
    listing["servers"]
        .as_array()
        .expect("servers")
        .iter()
        .find(|s| s["name"] == name)
        .unwrap_or_else(|| panic!("{name} not listed: {listing}"))["find_id"]
        .as_str()
        .expect("find_id")
        .to_owned()
}

/// The value the `file:` reference on the `key:` line of `written` names.
fn stored_at(written: &str, key: &str) -> String {
    let reference = written
        .lines()
        .find_map(|line| line.trim().strip_prefix(key))
        .unwrap_or_else(|| panic!("no {key} line: {written}"))
        .trim()
        .trim_matches(|c| c == '\'' || c == '"');
    let stored = reference.strip_prefix("file:").expect("a files reference");
    std::fs::read_to_string(stored)
        .expect("secret file")
        .trim_end()
        .to_owned()
}

/// d4, d9, d19: an adopted find is a disabled backend; its literal header
/// (a URL server) and env value (a stdio server) are in the files store and
/// only their references are in gateway.yaml; a template header is copied as
/// written; comments are kept. A second adopt is refused as managed.
#[tokio::test]
async fn an_adopted_find_is_a_disabled_backend_with_its_secret_in_the_store() {
    let home = tempfile::tempdir().expect("home");
    let home = home.path();
    client_file(
        home,
        &json!({
            "tool": {"url": "https://tool.example.test/mcp",
                "headers": {"Authorization": "Bearer ${TOOL_TOKEN}", "X-Key": HEADER_SECRET}},
            "local": {"command": "npx", "args": ["-y", "local-server"],
                "env": {"API_KEY": SECRET}},
        }),
    );
    let config = gateway_config(home);
    let gateway = Gateway::spawn(home, &config).await;
    let listing = gateway.list().await;
    let mut revision = listing["revision"].clone();
    for name in ["tool", "local"] {
        let body = json!({"find_id": find_id(&listing, name), "revision": revision});
        let (status, answer) = gateway.adopt(&body).await;
        assert_eq!(status, 201, "{name}: {answer}\n{}", gateway.logs());
        let answer: Value = serde_json::from_str(&answer).expect("json");
        assert_eq!(answer["name"], name);
        assert_eq!(answer["enabled"], false);
        assert_eq!(answer["args_copied_verbatim"], true);
        revision = answer["revision"].clone();
    }

    let written = std::fs::read_to_string(&config).expect("config");
    assert!(written.starts_with("# operator note: keep\n"), "{written}");
    for leak in [SECRET, HEADER_SECRET] {
        assert!(!written.contains(leak), "{leak} in {written}");
    }
    assert!(written.contains("Bearer ${TOOL_TOKEN}"), "{written}");
    assert_eq!(written.matches("enabled: false").count(), 2, "{written}");
    assert_eq!(stored_at(&written, "X-Key:"), HEADER_SECRET);
    assert_eq!(stored_at(&written, "API_KEY:"), SECRET);
    // Arguments are copied as the client wrote them, in order.
    assert!(written.contains("npx -y local-server"), "{written}");

    let again = json!({"find_id": find_id(&listing, "tool"), "revision": revision});
    let (status, refused) = gateway.adopt(&again).await;
    assert_eq!(status, 409, "{refused}");
    assert!(refused.contains("\"managed\""), "{refused}");

    // Each adopt is an admin action in the audit log, which holds no value.
    let audit = std::fs::read_to_string(home.join(".mcp-gateway/transparency/transparency.jsonl"))
        .expect("the audit log reads");
    let adopts = audit
        .lines()
        .filter(|line| line.contains("admin_action") && line.contains("/ui/api/discovery/adopt"))
        .count();
    // Two adopts and the managed refusal: every admin POST is recorded.
    assert_eq!(adopts, 3, "adopts not audited one by one: {audit}");
    for leak in [SECRET, HEADER_SECRET] {
        assert!(!audit.contains(leak), "{leak} in the audit log");
    }
    assert!(!gateway.logs().contains(SECRET), "a value reached the log");

    // A restart from the written file keeps both backends disabled.
    gateway.stop().await;
    let gateway = Gateway::spawn(home, &config).await;
    let loaded = mcp_gateway::config::Config::load_literal(Some(&config)).expect("loads");
    for name in ["tool", "local"] {
        assert!(!loaded.backends[name].enabled, "{name} came back enabled");
    }
    let listing = gateway.list().await;
    let tool = listing["servers"]
        .as_array()
        .expect("servers")
        .iter()
        .find(|s| s["name"] == "tool")
        .expect("tool still listed");
    assert_eq!(tool["managed"], true, "{listing}");
}

/// d11, d18 and the body canaries: a stale revision, a client entry changed
/// since the listing, and bodies that do not parse are refused, and no
/// answer repeats anything the caller sent.
#[tokio::test]
async fn stale_changed_and_malformed_requests_are_refused_without_echo() {
    let home = tempfile::tempdir().expect("home");
    let home = home.path();
    client_file(
        home,
        &json!({"tool": {"command": "npx", "env": {"API_KEY": SECRET}}}),
    );
    let config = gateway_config(home);
    let before = std::fs::read(&config).expect("config");
    let gateway = Gateway::spawn(home, &config).await;
    let listing = gateway.list().await;
    let id = find_id(&listing, "tool");

    let (status, answer) = gateway
        .adopt(&json!({"find_id": id, "revision": "0".repeat(64)}))
        .await;
    assert_eq!(status, 409, "{answer}");
    assert!(answer.contains("\"stale\""), "{answer}");

    client_file(
        home,
        &json!({"tool": {"command": "npx", "env": {"API_KEY": "zq-changed"}}}),
    );
    let (status, answer) = gateway
        .adopt(&json!({"find_id": id, "revision": listing["revision"]}))
        .await;
    assert_eq!(status, 409, "{answer}");
    assert!(answer.contains("find_changed"), "{answer}");

    for body in [
        json!({"find_id": "zq-canary-id", "revision": listing["revision"], "command": "zq-canary-cmd"}),
        json!({"find_id": 5, "revision": "zq-canary-rev"}),
        json!({"zq-canary-key": 1}),
    ] {
        let (status, answer) = gateway.adopt(&body).await;
        assert_eq!(status, 422, "{body} answered {answer}");
        assert!(answer.contains("\"invalid_body\""), "{answer}");
        assert!(!answer.contains("zq-canary"), "{answer}");
    }
    assert_eq!(
        std::fs::read(&config).expect("config"),
        before,
        "nothing written"
    );
}

/// A literal larger than the store can hold refuses the adopt, naming its
/// field and never its value, and writes nothing.
#[tokio::test]
async fn a_value_the_store_cannot_hold_is_refused_by_field() {
    let home = tempfile::tempdir().expect("home");
    let home = home.path();
    let huge = format!("zq-huge-{}", "x".repeat(64 * 1024));
    client_file(
        home,
        &json!({"tool": {"command": "npx", "env": {"API_KEY": huge}}}),
    );
    let config = gateway_config(home);
    let before = std::fs::read(&config).expect("config");
    let gateway = Gateway::spawn(home, &config).await;
    let listing = gateway.list().await;
    let body = json!({"find_id": find_id(&listing, "tool"), "revision": listing["revision"]});
    let (status, answer) = gateway.adopt(&body).await;
    assert_eq!(status, 422, "{answer}");
    assert!(answer.contains("value_too_large"), "{answer}");
    assert!(answer.contains("env.API_KEY"), "{answer}");
    assert!(!answer.contains("zq-huge"), "the value was echoed");
    assert_eq!(
        std::fs::read(&config).expect("config"),
        before,
        "nothing written"
    );
}

/// A key allowed every backend (`backends: ["*"]`) but no admin.
const CALLER: &str = "discovery-adopt-caller-key";

/// One `gateway_invoke` of `ping` on `server` as `CALLER`, in its own session.
async fn invoke_as_caller(gateway: &Gateway, server: &str) -> Value {
    call_as_caller(
        gateway,
        "gateway_invoke",
        json!({"server": server, "tool": "ping", "arguments": {}}),
    )
    .await
}

/// One `tools/call` of `name` with `arguments` by the CALLER key, in a
/// fresh session.
async fn call_as_caller(gateway: &Gateway, name: &str, arguments: Value) -> Value {
    let http = reqwest::Client::new();
    let post = |sid: Option<String>, body: Value| {
        let mut request = http
            .post(gateway.url("/mcp"))
            .bearer_auth(CALLER)
            .header("accept", "application/json")
            .json(&body);
        if let Some(sid) = sid {
            request = request.header("mcp-session-id", sid);
        }
        request.send()
    };
    let init = post(
        None,
        json!({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
            "protocolVersion": "2025-06-18", "capabilities": {},
            "clientInfo": {"name": "adopt-grant", "version": "1"}}}),
    )
    .await
    .expect("initialize");
    let sid = init
        .headers()
        .get("mcp-session-id")
        .map(|v| v.to_str().expect("ASCII").to_owned());
    post(
        sid.clone(),
        json!({"jsonrpc": "2.0", "method": "notifications/initialized"}),
    )
    .await
    .expect("initialized");
    post(
        sid,
        json!({"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {
            "name": name,
            "arguments": arguments}}),
    )
    .await
    .expect("tools/call")
    .json()
    .await
    .expect("a JSON answer")
}

/// API7.3 under the grant rule: an adopted server is off for every key,
/// one allowed every backend included, until an admin enables it; then the
/// same key reaches it.
#[tokio::test]
async fn an_adopted_server_is_off_for_keys_until_an_admin_enables_it() {
    let home = tempfile::tempdir().expect("home");
    let home = home.path();
    let hits: mcp_http_servers::Hits = std::sync::Arc::default();
    let base = mcp_http_servers::streamable_server(&hits).await;
    // `streamable_server` answers at the URL it returns, `/mcp` included.
    client_file(home, &json!({"remote": {"url": base}}));
    let config = home.join("gateway.yaml");
    write_owner_only(
        &config,
        &format!(
            "server:\n  host: \"127.0.0.1\"\n  port: {ANY_PORT}\n\
             auth:\n  enabled: true\n  bearer_token: \"{BEARER}\"\n\
             \x20 api_keys:\n    - name: caller\n      key_sha256: \"{}\"\n\
             \x20     backends: [\"*\"]\n\
             secrets:\n  store: files\nbackends: {{}}\n",
            mcp_gateway::config::api_key_digest_spec(CALLER.as_bytes())
        ),
    );
    let gateway = Gateway::spawn(home, &config).await;
    let listing = gateway.list().await;
    let body = json!({"find_id": find_id(&listing, "remote"), "revision": listing["revision"]});
    let (status, answer) = gateway.adopt(&body).await;
    assert_eq!(status, 201, "{answer}\n{}", gateway.logs());

    let refused = invoke_as_caller(&gateway, "remote").await;
    assert!(
        !refused.to_string().contains("pong-"),
        "a disabled adopted server answered a key: {refused}"
    );

    let enabled = reqwest::Client::new()
        .patch(gateway.url("/ui/api/backends/remote"))
        .bearer_auth(BEARER)
        .json(&json!({"enabled": true}))
        .send()
        .await
        .expect("PATCH");
    assert_eq!(enabled.status().as_u16(), 200, "{}", gateway.logs());

    // Wait for the reload to register the backend by listing servers, which
    // calls no tool: a call polled before then fails, and enough failures
    // switch the tool off for the error budget's cooldown.
    let deadline = Instant::now() + STARTUP;
    loop {
        let servers = call_as_caller(&gateway, "gateway_list_servers", json!({})).await;
        if servers.to_string().contains("remote") {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "the enabled server was never registered: {servers}\n{}",
            gateway.logs()
        );
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    let answer = invoke_as_caller(&gateway, "remote").await;
    assert!(
        answer.to_string().contains("pong-"),
        "the enabled server did not answer the key: {answer}\n{}",
        gateway.logs()
    );
}

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

use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::Duration;

use serde_json::{Value, json};

const BACKEND: &str = "tidebook";
const TOOL: &str = "tide_table";
const MARKER: &str = "tidebook-answered";
const READY_BOUND: Duration = Duration::from_secs(60);
const SEARCH_BOUND: Duration = Duration::from_secs(30);
const POLL_GAP: Duration = Duration::from_millis(100);
const REQUEST_BOUND: Duration = Duration::from_secs(30);

/// A stdio MCP server with one tool. Any other request with an id gets an
/// empty result, so warm-start probes and pings are answered.
const PEER: &str = r#"
while IFS= read -r line; do
  id=$(printf '%s' "$line" | sed -n 's/.*"id":\([0-9][0-9]*\).*/\1/p')
  [ -z "$id" ] && continue
  case "$line" in
    *'"method":"initialize"'*)
      printf '{"jsonrpc":"2.0","id":%s,"result":{"protocolVersion":"2025-06-18","capabilities":{"tools":{}},"serverInfo":{"name":"tidebook","version":"0"}}}\n' "$id" ;;
    *'"method":"tools/list"'*)
      printf '{"jsonrpc":"2.0","id":%s,"result":{"tools":[{"name":"tide_table","description":"Look up the tide table for a harbour.","inputSchema":{"type":"object","properties":{"harbour":{"type":"string"}}}}]}}\n' "$id" ;;
    *'"method":"tools/call"'*)
      printf '{"jsonrpc":"2.0","id":%s,"result":{"content":[{"type":"text","text":"tidebook-answered"}]}}\n' "$id" ;;
    *)
      printf '{"jsonrpc":"2.0","id":%s,"result":{}}\n' "$id" ;;
  esac
done
"#;

struct Workspace {
    _tmp: tempfile::TempDir,
    root: PathBuf,
}

impl Workspace {
    fn new() -> Self {
        let tmp = tempfile::tempdir().expect("a temp root");
        let root = tmp.path().to_path_buf();
        for dir in ["home", "empty-path"] {
            std::fs::create_dir(root.join(dir)).expect("a temp subdir");
        }
        Self { _tmp: tmp, root }
    }

    /// The binary as a user in an empty project directory runs it: own HOME,
    /// own state dir, no inherited `MCP_GATEWAY_*` override.
    fn command(&self) -> Command {
        let mut command =
            gateway_bin::command(&self.root.join("home"), gateway_bin::Inherit::Environment);
        command
            .current_dir(&self.root)
            .env("MCP_GATEWAY_CONFIG_DIR", self.root.join("gateway-state"))
            .stdin(Stdio::null());
        command
    }

    fn run(&self, args: &[&str]) -> Output {
        self.command().args(args).output().expect("the binary runs")
    }

    fn run_ok(&self, args: &[&str]) -> String {
        let out = self.run(args);
        assert!(
            out.status.success(),
            "`{}` failed\n{}",
            args.join(" "),
            show(&out)
        );
        String::from_utf8(out.stdout).expect("stdout is UTF-8")
    }
}

fn show(out: &Output) -> String {
    format!(
        "exit: {}\n--- stdout ---\n{}\n--- stderr ---\n{}",
        out.status,
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

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

/// Every HTTP wait is bounded, and loopback never goes through an inherited
/// proxy.
fn http_client() -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(REQUEST_BOUND)
        .no_proxy()
        .build()
        .expect("an HTTP client")
}

/// One MCP client session over the gateway's HTTP endpoint.
struct Session {
    http: reqwest::Client,
    url: String,
    token: Option<String>,
    id: Option<String>,
    next: i64,
}

impl Session {
    async fn open(url: &str, token: Option<String>) -> Self {
        let mut session = Self {
            http: http_client(),
            url: url.to_string(),
            token,
            id: None,
            next: 1,
        };
        let init = session
            .request(
                "initialize",
                json!({
                    "protocolVersion": "2025-06-18",
                    "capabilities": {},
                    "clientInfo": { "name": "first-run-journey", "version": "1" }
                }),
            )
            .await;
        assert_eq!(
            init["result"]["serverInfo"]["name"], "mcp-gateway",
            "initialize: {init}"
        );
        session
            .send(&json!({ "jsonrpc": "2.0", "method": "notifications/initialized" }))
            .await;
        session
    }

    async fn send(&mut self, body: &Value) -> reqwest::Response {
        let mut request = self
            .http
            .post(&self.url)
            .header("content-type", "application/json")
            .header("accept", "application/json")
            .json(body);
        if let Some(token) = &self.token {
            request = request.bearer_auth(token);
        }
        if let Some(id) = &self.id {
            request = request.header("mcp-session-id", id);
        }
        let response = request.send().await.expect("the gateway answers");
        if let Some(id) = response.headers().get("mcp-session-id") {
            self.id = Some(id.to_str().expect("ASCII session id").to_string());
        }
        response
    }

    async fn request(&mut self, method: &str, params: Value) -> Value {
        let id = self.next;
        self.next += 1;
        let body = json!({ "jsonrpc": "2.0", "id": id, "method": method, "params": params });
        let response = self.send(&body).await;
        let status = response.status();
        let text = response.text().await.expect("a body");
        assert_eq!(status, reqwest::StatusCode::OK, "{method}: {text}");
        serde_json::from_str(&text).unwrap_or_else(|e| panic!("{method}: not JSON ({e}): {text}"))
    }

    async fn tool_names(&mut self) -> Vec<String> {
        let list = self.request("tools/list", json!({})).await;
        list["result"]["tools"]
            .as_array()
            .unwrap_or_else(|| panic!("tools/list: {list}"))
            .iter()
            .map(|t| t["name"].as_str().unwrap_or_default().to_string())
            .collect()
    }

    async fn call(&mut self, tool: &str, arguments: Value) -> Value {
        self.request(
            "tools/call",
            json!({ "name": tool, "arguments": arguments }),
        )
        .await
    }
}

/// The text payload of a `tools/call` answer, parsed as JSON.
fn payload(answer: &Value) -> Value {
    let text = answer["result"]["content"][0]["text"]
        .as_str()
        .unwrap_or_else(|| panic!("no text content: {answer}"));
    serde_json::from_str(text).unwrap_or_else(|e| panic!("payload not JSON ({e}): {text}"))
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

struct Gateway {
    child: tokio::process::Child,
    log: PathBuf,
    url: String,
}

impl Gateway {
    async fn start(ws: &Workspace) -> Self {
        let log = ws.root.join("serve.log");
        let out = std::fs::File::create(&log).expect("serve log");
        let err = out.try_clone().expect("log handle");
        let mut command = tokio::process::Command::from(ws.command());
        let child = command
            .args(["-c", "gateway.yaml", "-p", "0", "serve"])
            .stdout(Stdio::from(out))
            .stderr(Stdio::from(err))
            .kill_on_drop(true)
            .spawn()
            .expect("serve spawns");
        let mut gateway = Self {
            child,
            log,
            url: String::new(),
        };
        gateway.wait_ready().await;
        gateway
    }

    fn logs(&self) -> String {
        std::fs::read_to_string(&self.log).unwrap_or_default()
    }

    /// Read the port the child bound (`-p 0`) from its log, then wait for
    /// `/health` on it.
    async fn wait_ready(&mut self) {
        let deadline = tokio::time::Instant::now() + READY_BOUND;
        let http = http_client();
        loop {
            if let Some(status) = self.child.try_wait().expect("child status") {
                panic!("serve exited before ready ({status})\n{}", self.logs());
            }
            if self.url.is_empty()
                && let Some(port) = gateway_bin::logged_port(&self.log)
            {
                self.url = format!("http://127.0.0.1:{port}");
            }
            if !self.url.is_empty()
                && http
                    .get(format!("{}/health", self.url))
                    .send()
                    .await
                    .is_ok_and(|r| r.status().is_success())
            {
                return;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "serve not ready within {READY_BOUND:?}\n{}",
                self.logs()
            );
            tokio::time::sleep(POLL_GAP).await;
        }
    }
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

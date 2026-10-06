// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! #1868: a config found by discovery (no `--config`, no `MCP_GATEWAY_CONFIG`)
//! is watched and reloaded like a named one, and offers the reload tool.
//!
//! Each case runs the built binary with its own working directory and `HOME`
//! (maintainer decision): discovery reads both, and a child process changes
//! nothing in this one, so the cases run in parallel. Every child gets
//! `RUST_LOG=info` (the waits read INFO lines) and no inherited
//! `MCP_GATEWAY_*` variable. Waits are on completion lines, never trigger
//! lines, and edits are sequential, so one reload never absorbs the next edit.

#[path = "common/gateway_bin.rs"]
mod gateway_bin;

use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::{Duration, Instant};

use serde_json::{Value, json};
use tokio::io::{AsyncBufReadExt as _, AsyncWriteExt as _, BufReader};
use tokio::process::{Child, Command};

use gateway_bin::{ANY_PORT, reported_port};

/// Start-up, including a cold binary on a shared runner.
const STARTUP: Duration = Duration::from_secs(60);
/// One reload: a 2 s env poll and a sub-second debounce, with CI margin.
const RELOAD: Duration = Duration::from_secs(20);
/// One `/livez` probe; the start-up loop retries, so this only bounds a stall.
const PROBE: Duration = Duration::from_secs(2);
const BEARER: &str = "discovered-config-admin-token";
const PROTOCOL_VERSION: &str = "2025-06-18";
const CONFIG_RELOADED: &str = "Config reload: complete";
const ENV_RELOADED: &str = "Config reload: env file changed, reloaded";
const RELOAD_TOOL: &str = "gateway_reload_config";

fn write_owner_only(path: &Path, text: &str) {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).expect("config dir");
    }
    mcp_gateway::gateway::test_helpers::write_owner_only(path, text).expect("write owner-only");
}

/// An HTTP gateway config. `env_file` is written into `env_files` verbatim;
/// `backend` adds one HTTP backend nothing ever contacts, the "meaningful
/// change" a config edit makes so its reload logs completion.
fn http_config(port: u16, env_file: &str, auth: bool, backend: bool) -> String {
    let auth = if auth {
        // Auth on needs a transparency log (UPGRADING item 43); its default
        // path is under `~/.mcp-gateway`, and HOME is the tempdir.
        format!(
            "security:\n  transparency_log:\n    enabled: true\n\
             auth:\n  enabled: true\n  bearer_token: \"{BEARER}\"\n  single_user: true\n"
        )
    } else {
        "auth:\n  enabled: false\n".to_owned()
    };
    let backends = if backend {
        "backends:\n  added_by_edit:\n    http_url: \"http://127.0.0.1:1/mcp\"\n"
    } else {
        ""
    };
    format!(
        "server:\n  host: \"127.0.0.1\"\n  port: {port}\n{auth}env_files:\n  - '{env_file}'\n{backends}"
    )
}

/// The child's command: own cwd and HOME, a state dir inside `home`, INFO logs.
fn gateway_command(cwd: &Path, home: &Path) -> Command {
    let mut command = Command::from(gateway_bin::command(
        home,
        gateway_bin::Inherit::Environment,
    ));
    command
        .current_dir(cwd)
        .env("MCP_GATEWAY_CONFIG_DIR", home.join("state"))
        .env("RUST_LOG", "info")
        .kill_on_drop(true);
    command
}

/// An HTTP gateway whose stdout and stderr go to one log file.
struct HttpGateway {
    child: Child,
    port: u16,
    log: PathBuf,
}

impl HttpGateway {
    async fn spawn(cwd: &Path, home: &Path, args: &[&str]) -> Self {
        let log = home.join("gateway.log");
        let out = std::fs::File::create(&log).expect("log file");
        let err = out.try_clone().expect("log handle");
        let child = gateway_command(cwd, home)
            .arg("serve")
            .args(args)
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
        gateway.wait_until_serving().await;
        gateway
    }

    fn logs(&self) -> String {
        std::fs::read_to_string(&self.log).unwrap_or_default()
    }

    /// Wait for the port the child reports, then for `/livez` on it.
    async fn wait_until_serving(&mut self) {
        let deadline = Instant::now() + STARTUP;
        // A per-request timeout: one stalled connect must not outlast `STARTUP`
        // (MIK-7656). The failure still carries the gateway log.
        let probe = reqwest::Client::builder()
            .timeout(PROBE)
            .build()
            .expect("probe client");
        loop {
            if self.port == ANY_PORT {
                self.port = reported_port(&self.logs()).unwrap_or(ANY_PORT);
            }
            if self.port != ANY_PORT
                && let Ok(response) = probe
                    .get(format!("http://127.0.0.1:{}/livez", self.port))
                    .send()
                    .await
                && response.status().is_success()
            {
                return;
            }
            if let Some(status) = self.child.try_wait().expect("wait on the gateway") {
                panic!(
                    "the gateway exited {status} before serving:\n{}",
                    self.logs()
                );
            }
            assert!(
                Instant::now() < deadline,
                "the gateway never answered /livez:\n{}",
                self.logs()
            );
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
    }

    /// How many times `line` appears in the log so far.
    fn count(&self, line: &str) -> usize {
        self.logs().matches(line).count()
    }

    /// Wait until `line` appears more than `before` times.
    async fn wait_for(&self, line: &str, before: usize) {
        let deadline = Instant::now() + RELOAD;
        while self.count(line) <= before {
            assert!(
                Instant::now() < deadline,
                "`{line}` did not appear within {RELOAD:?}; the discovered config is \
                 not watched:\n{}",
                self.logs()
            );
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
    }
}

fn initialize(id: i64) -> Value {
    json!({
        "jsonrpc": "2.0", "id": id, "method": "initialize",
        "params": {
            "protocolVersion": PROTOCOL_VERSION,
            "capabilities": {},
            "clientInfo": {"name": "discovered-config", "version": "0"},
        },
    })
}

fn tools_list(id: i64) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "method": "tools/list", "params": {}})
}

fn call_reload(id: i64) -> Value {
    json!({
        "jsonrpc": "2.0", "id": id, "method": "tools/call",
        "params": {"name": RELOAD_TOOL, "arguments": {}},
    })
}

/// The JSON-RPC envelope from a response body, JSON or a single SSE event.
fn envelope(body: &str) -> Value {
    serde_json::from_str(body).unwrap_or_else(|_| {
        let data = body
            .lines()
            .filter_map(|line| line.strip_prefix("data:"))
            .map(str::trim)
            .find(|data| !data.is_empty())
            .unwrap_or_else(|| panic!("no JSON-RPC envelope in {body}"));
        serde_json::from_str(data).expect("an SSE data line holds JSON")
    })
}

fn has_tool(list: &Value, name: &str) -> bool {
    list["result"]["tools"]
        .as_array()
        .is_some_and(|tools| tools.iter().any(|tool| tool["name"] == name))
}

/// Assert a `tools/call` answered with a result that is not an error.
fn assert_success(response: &Value, what: &str) {
    assert!(response.get("error").is_none(), "{what}: {response}");
    assert_ne!(
        response["result"]["isError"],
        json!(true),
        "{what}: {response}"
    );
}

/// An admin HTTP MCP session: `initialize`, then calls carrying its session id.
struct McpSession {
    client: reqwest::Client,
    url: String,
    session: String,
}

impl McpSession {
    async fn open(port: u16) -> Self {
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert(
            reqwest::header::AUTHORIZATION,
            reqwest::header::HeaderValue::from_str(&format!("Bearer {BEARER}")).expect("header"),
        );
        let client = reqwest::Client::builder()
            .default_headers(headers)
            .build()
            .expect("http client");
        let url = format!("http://127.0.0.1:{port}/mcp");
        let response = client
            .post(&url)
            .header("Accept", "application/json, text/event-stream")
            .json(&initialize(1))
            .send()
            .await
            .expect("initialize");
        assert!(
            response.status().is_success(),
            "initialize: {}",
            response.status()
        );
        let session = response
            .headers()
            .get("mcp-session-id")
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default()
            .to_owned();
        let mut opened = Self {
            client,
            url,
            session,
        };
        opened
            .notify(json!({"jsonrpc": "2.0", "method": "notifications/initialized"}))
            .await;
        opened
    }

    async fn notify(&mut self, message: Value) {
        drop(self.post_raw(&message).await);
    }

    async fn post_raw(&self, message: &Value) -> reqwest::Response {
        let mut request = self
            .client
            .post(&self.url)
            .header("Accept", "application/json, text/event-stream")
            .json(message);
        if !self.session.is_empty() {
            request = request.header("mcp-session-id", &self.session);
        }
        request.send().await.expect("post to /mcp")
    }

    async fn request(&self, message: &Value) -> Value {
        let body = self.post_raw(message).await.text().await.expect("body");
        envelope(&body)
    }
}

/// D1 (AC1, AC3): a `gateway.yaml` found in the working directory is watched,
/// and so is its env file.
#[tokio::test]
async fn d1_a_config_found_in_the_working_directory_reloads() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (config, env) = (dir.path().join("gateway.yaml"), dir.path().join(".env"));
    write_owner_only(&env, "DISCOVERED_VALUE=one\n");
    write_owner_only(&config, &http_config(ANY_PORT, ".env", false, false));
    let gateway = HttpGateway::spawn(dir.path(), dir.path(), &[]).await;

    let before = gateway.count(CONFIG_RELOADED);
    write_owner_only(&config, &http_config(ANY_PORT, ".env", false, true));
    gateway.wait_for(CONFIG_RELOADED, before).await;

    let before = gateway.count(ENV_RELOADED);
    write_owner_only(&env, "DISCOVERED_VALUE=two\n");
    gateway.wait_for(ENV_RELOADED, before).await;
}

/// D2 (AC1): the home candidate is watched too, with its env file.
#[tokio::test]
async fn d2_a_config_found_under_home_reloads() {
    let home = tempfile::tempdir().expect("tempdir");
    let cwd = home.path().join("empty-working-dir");
    std::fs::create_dir_all(&cwd).expect("cwd");
    let dir = home.path().join(".config/mcp-gateway");
    let (config, env) = (dir.join("gateway.yaml"), dir.join(".env"));
    // Absolute: a relative env-file entry resolves from the working directory.
    let env_entry = env.display().to_string();
    write_owner_only(&env, "DISCOVERED_VALUE=one\n");
    write_owner_only(&config, &http_config(ANY_PORT, &env_entry, false, false));
    let gateway = HttpGateway::spawn(&cwd, home.path(), &[]).await;

    let before = gateway.count(CONFIG_RELOADED);
    write_owner_only(&config, &http_config(ANY_PORT, &env_entry, false, true));
    gateway.wait_for(CONFIG_RELOADED, before).await;

    let before = gateway.count(ENV_RELOADED);
    write_owner_only(&env, "DISCOVERED_VALUE=two\n");
    gateway.wait_for(ENV_RELOADED, before).await;
}

/// D3 (AC2): the reload tool is offered, and works, for a discovered config.
#[tokio::test]
async fn d3_the_reload_tool_is_offered_for_a_discovered_config() {
    let dir = tempfile::tempdir().expect("tempdir");
    write_owner_only(&dir.path().join(".env"), "DISCOVERED_VALUE=one\n");
    write_owner_only(
        &dir.path().join("gateway.yaml"),
        &http_config(ANY_PORT, ".env", true, false),
    );
    let gateway = HttpGateway::spawn(dir.path(), dir.path(), &[]).await;

    let session = McpSession::open(gateway.port).await;
    let list = session.request(&tools_list(2)).await;
    assert!(
        has_tool(&list, RELOAD_TOOL),
        "{RELOAD_TOOL} is not offered for a discovered config: {list}\n{}",
        gateway.logs()
    );
    assert_success(&session.request(&call_reload(3)).await, RELOAD_TOOL);
}

/// D4 (guard): a named config still wins over one in the working directory,
/// and only the named one is watched.
#[tokio::test]
async fn d4_an_explicit_config_still_wins() {
    let dir = tempfile::tempdir().expect("tempdir");
    let discovered = dir.path().join("gateway.yaml");
    let named = dir.path().join("other.yaml");
    write_owner_only(&dir.path().join(".env"), "DISCOVERED_VALUE=one\n");
    write_owner_only(&discovered, &http_config(ANY_PORT, ".env", false, false));
    write_owner_only(&named, &http_config(ANY_PORT, ".env", false, false));
    let named_arg = named.display().to_string();
    let gateway = HttpGateway::spawn(dir.path(), dir.path(), &["--config", &named_arg]).await;

    let before = gateway.count(CONFIG_RELOADED);
    write_owner_only(&discovered, &http_config(ANY_PORT, ".env", false, true));
    tokio::time::sleep(Duration::from_secs(3)).await;
    assert_eq!(
        gateway.count(CONFIG_RELOADED),
        before,
        "editing the unused working-directory config reloaded:\n{}",
        gateway.logs()
    );
    write_owner_only(&named, &http_config(ANY_PORT, ".env", false, true));
    gateway.wait_for(CONFIG_RELOADED, before).await;
}

/// D5 (guard): a discovered config keeps the governance store where it has
/// always been for one (`~/.mcp-gateway/control-plane`), not beside the config.
#[tokio::test]
async fn d5_a_discovered_config_keeps_the_home_governance_store() {
    let dir = tempfile::tempdir().expect("tempdir");
    write_owner_only(&dir.path().join(".env"), "DISCOVERED_VALUE=one\n");
    write_owner_only(
        &dir.path().join("gateway.yaml"),
        &http_config(ANY_PORT, ".env", true, false),
    );
    let gateway = HttpGateway::spawn(dir.path(), dir.path(), &[]).await;
    assert!(
        dir.path().join(".mcp-gateway/control-plane").exists(),
        "the governance store is not under HOME:\n{}",
        gateway.logs()
    );
    assert!(
        !dir.path().join("gateway-control-plane").exists(),
        "the governance store moved beside the discovered config"
    );
}

/// A `serve --stdio` session speaking newline-delimited JSON-RPC.
struct StdioSession {
    _child: Child,
    stdin: tokio::process::ChildStdin,
    stdout: tokio::io::Lines<BufReader<tokio::process::ChildStdout>>,
}

impl StdioSession {
    async fn open(cwd: &Path, args: &[&str]) -> Self {
        let mut child = gateway_command(cwd, cwd)
            .arg("serve")
            .arg("--stdio")
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            // Inherited: an undrained stderr pipe would stall the child.
            .stderr(Stdio::inherit())
            .spawn()
            .expect("spawn serve --stdio");
        let stdin = child.stdin.take().expect("stdin");
        let stdout = BufReader::new(child.stdout.take().expect("stdout")).lines();
        let mut session = Self {
            _child: child,
            stdin,
            stdout,
        };
        session.request(&initialize(1)).await;
        session
            .send(&json!({"jsonrpc": "2.0", "method": "notifications/initialized"}))
            .await;
        session
    }

    async fn send(&mut self, message: &Value) {
        let line = format!("{message}\n");
        self.stdin
            .write_all(line.as_bytes())
            .await
            .expect("write stdin");
        self.stdin.flush().await.expect("flush stdin");
    }

    /// Send `message` and read until the response with its id.
    async fn request(&mut self, message: &Value) -> Value {
        self.send(message).await;
        let id = message["id"].clone();
        tokio::time::timeout(STARTUP, async {
            loop {
                let line = self
                    .stdout
                    .next_line()
                    .await
                    .expect("read stdout")
                    .expect("stdout closed before the answer");
                if let Ok(value) = serde_json::from_str::<Value>(&line)
                    && value["id"] == id
                {
                    return value;
                }
            }
        })
        .await
        .expect("the stdio gateway answered")
    }
}

/// Stdio standing is already admin, so no bearer: the list shows the reload
/// tool only if a reload context exists.
async fn assert_stdio_offers_reload(cwd: &Path, args: &[&str]) {
    let mut session = StdioSession::open(cwd, args).await;
    let list = session.request(&tools_list(2)).await;
    assert!(
        has_tool(&list, RELOAD_TOOL),
        "{RELOAD_TOOL} not offered over stdio: {list}"
    );
    assert_success(&session.request(&call_reload(3)).await, RELOAD_TOOL);
}

/// D6 (AC2, stdio): a discovered config offers the reload tool over stdio.
#[tokio::test]
async fn d6_stdio_offers_the_reload_tool_for_a_discovered_config() {
    let dir = tempfile::tempdir().expect("tempdir");
    write_owner_only(&dir.path().join(".env"), "DISCOVERED_VALUE=one\n");
    write_owner_only(
        &dir.path().join("gateway.yaml"),
        &http_config(ANY_PORT, ".env", false, false),
    );
    assert_stdio_offers_reload(dir.path(), &[]).await;
}

/// D6b (AC2, stdio): a missing `--config` falls back to the discovered file,
/// and that file offers the reload tool too.
#[tokio::test]
async fn d6b_stdio_with_a_missing_config_offers_the_reload_tool_for_its_fallback() {
    let dir = tempfile::tempdir().expect("tempdir");
    write_owner_only(&dir.path().join(".env"), "DISCOVERED_VALUE=one\n");
    write_owner_only(
        &dir.path().join("gateway.yaml"),
        &http_config(ANY_PORT, ".env", false, false),
    );
    let missing = dir.path().join("missing.yaml").display().to_string();
    assert_stdio_offers_reload(dir.path(), &["--config", &missing]).await;
}

/// MIK-7634: a gateway configured with `server.port: 0` serves on the port it
/// reports, so no test hands a port to the child and waits for it to bind.
#[tokio::test]
async fn d7_a_gateway_on_port_zero_serves_on_the_port_it_reports() {
    let dir = tempfile::tempdir().expect("tempdir");
    write_owner_only(&dir.path().join(".env"), "DISCOVERED_VALUE=one\n");
    write_owner_only(
        &dir.path().join("gateway.yaml"),
        &http_config(ANY_PORT, ".env", false, false),
    );
    let gateway = HttpGateway::spawn(dir.path(), dir.path(), &[]).await;
    assert_ne!(
        gateway.port, ANY_PORT,
        "the reported port replaces the configured 0"
    );
    let probe = reqwest::Client::builder()
        .timeout(PROBE)
        .build()
        .expect("probe client")
        .get(format!("http://127.0.0.1:{}/livez", gateway.port))
        .send()
        .await
        .expect("the gateway answers on the port it reported");
    assert!(probe.status().is_success(), "{}", gateway.logs());
}

/// The banner parse survives colour codes and a module path containing "port".
#[test]
fn the_reported_port_ignores_colour_codes_and_the_module_path() {
    let plain = "2026-10-02T10:00:00Z  INFO mcp_gateway::gateway::server::support: Listening host=127.0.0.1 port=39123\n";
    let coloured = "\u{1b}[2m2026-10-02T10:00:00Z\u{1b}[0m \u{1b}[32m INFO\u{1b}[0m \u{1b}[2mmcp_gateway::gateway::server::support\u{1b}[0m: Listening \u{1b}[3mhost\u{1b}[0m\u{1b}[2m=\u{1b}[0m127.0.0.1 \u{1b}[3mport\u{1b}[0m\u{1b}[2m=\u{1b}[0m39123\n";
    assert_eq!(reported_port(plain), Some(39123));
    assert_eq!(reported_port(coloured), Some(39123));
    assert_eq!(reported_port("Listening on nothing"), None);
    assert_eq!(reported_port("Listening host=127.0.0.1 port=39"), None);
    assert_eq!(
        reported_port("Listening host=127.0.0.1 port=39123\n"),
        Some(39123)
    );
}

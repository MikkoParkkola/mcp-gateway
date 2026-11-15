// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! `GET /ui/api/status` reports `running: true` for a stdio backend whose
//! transport is connected, and `running: false` for one that exits at once,
//! both from the same response body.
//!
//! The route's in-process wire test can pin only `running: false`. A router
//! fixture never builds a connected transport, so nothing there is running.
//! This test starts the real binary, which does.
#![cfg(feature = "webui")]

#[path = "common/gateway_bin.rs"]
mod gateway_bin;
#[path = "common/windows_paths.rs"]
mod windows_paths;

use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::{Duration, Instant};

use serde_json::{Value, json};
use tokio::process::Command;
use windows_paths::{hostile_home, sh_path, yaml_single_quoted};

use gateway_bin::{ANY_PORT, reported_port};

const STARTUP: Duration = Duration::from_secs(60);
/// How long the status read may wait for the live backend to be connected.
const RUNNING_DEADLINE: Duration = Duration::from_secs(30);
const BEARER: &str = "status-running-stdio-admin";
const LIVE: &str = "live";
const DEAD: &str = "dead";

/// A stdio peer that answers the handshake and lists one tool, then keeps
/// reading so the transport stays connected.
const PEER: &str = r#"
while IFS= read -r line; do
  id=$(printf '%s' "$line" | sed -n 's/.*"id":\([0-9][0-9]*\).*/\1/p')
  case "$line" in
    *'"method":"initialize"'*)
      printf '{"jsonrpc":"2.0","id":%s,"result":{"protocolVersion":"2025-06-18","capabilities":{"tools":{}},"serverInfo":{"name":"live","version":"0"}}}\n' "$id" ;;
    *'"method":"tools/list"'*)
      printf '{"jsonrpc":"2.0","id":%s,"result":{"tools":[{"name":"ping","description":"answers","inputSchema":{"type":"object"}}]}}\n' "$id" ;;
  esac
done
"#;

struct Gateway {
    /// Reaped on stop and on drop, so no gateway outlives the test.
    process: gateway_bin::Reaped,
    port: u16,
    log: PathBuf,
}

impl Gateway {
    async fn spawn(home: &Path, config: &Path) -> Self {
        let log = home.join("gateway.log");
        let out = std::fs::File::create(&log).expect("log file");
        let err = out.try_clone().expect("log handle");
        let process = gateway_bin::Reaped::new(
            Command::from(gateway_bin::command(
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
            .expect("the built mcp-gateway binary spawns"),
        );
        let mut gateway = Self {
            process,
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

    async fn stop(self) {
        self.process.stop().await;
    }

    fn logs(&self) -> String {
        std::fs::read_to_string(&self.log).unwrap_or_default()
    }

    fn url(&self, path: &str) -> String {
        format!("http://127.0.0.1:{}{path}", self.port)
    }

    async fn status(&self) -> Value {
        let response = reqwest::Client::new()
            .get(self.url("/ui/api/status"))
            .bearer_auth(BEARER)
            .send()
            .await
            .unwrap_or_else(|error| panic!("GET /ui/api/status failed: {error}\n{}", self.logs()));
        let code = response.status();
        let text = response
            .text()
            .await
            .unwrap_or_else(|error| panic!("status body did not read: {error}\n{}", self.logs()));
        assert!(
            code.is_success(),
            "GET /ui/api/status returned {code}: {text}\n{}",
            self.logs()
        );
        serde_json::from_str(&text)
            .unwrap_or_else(|error| panic!("status body is not JSON ({error}): {text}"))
    }
}

fn gateway_config(home: &Path, live: &Path, dead: &Path) -> PathBuf {
    let config = home.join("gateway.yaml");
    let live_cmd = yaml_single_quoted(&format!("sh {}", sh_path(live)));
    let dead_cmd = yaml_single_quoted(&format!("sh {}", sh_path(dead)));
    let bearer = yaml_single_quoted(BEARER);
    mcp_gateway::gateway::test_helpers::write_owner_only(
        &config,
        format!(
            "server:\n  host: \"127.0.0.1\"\n  port: {ANY_PORT}\n\
             auth:\n  enabled: true\n  bearer_token: {bearer}\n  single_user: true\n\
             backends:\n  {LIVE}:\n    enabled: true\n    command: {live_cmd}\n  \
             {DEAD}:\n    enabled: true\n    command: {dead_cmd}\n"
        ),
    )
    .expect("write the config");
    config
}

/// The row whose `name` is `name`, or a panic that includes the body.
fn row<'a>(body: &'a Value, name: &str) -> &'a Value {
    body["servers"]
        .as_array()
        .and_then(|rows| rows.iter().find(|candidate| candidate["name"] == name))
        .unwrap_or_else(|| panic!("row {name} is missing from the status body: {body}"))
}

fn running_is_true(body: &Value, name: &str) -> bool {
    body["servers"]
        .as_array()
        .and_then(|rows| rows.iter().find(|candidate| candidate["name"] == name))
        .is_some_and(|candidate| candidate["running"] == json!(true))
}

/// A connected stdio backend reads `running: true`; a command that exits at
/// once reads `running: false`. Both values come from one status body.
#[tokio::test]
async fn a_connected_stdio_backend_reads_running_true() {
    let home_dir = hostile_home();
    let home = home_dir.path();
    let live_script = home.join("peer.sh");
    let dead_script = home.join("dead.sh");
    std::fs::write(&live_script, PEER).expect("write the live peer");
    // Exits before any handshake, so the transport never stays connected.
    std::fs::write(&dead_script, "exit 1\n").expect("write the dead command");
    let config = gateway_config(home, &live_script, &dead_script);
    let gateway = Gateway::spawn(home, &config).await;

    // The gateway connects every configured backend as it comes up (the warm
    // start with an empty list warms all of them), so nothing here starts
    // `live` by hand: the read waits until the gateway's own start has
    // connected it.
    let deadline = Instant::now() + RUNNING_DEADLINE;
    let mut body = gateway.status().await;
    while !running_is_true(&body, LIVE) {
        if Instant::now() >= deadline {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
        body = gateway.status().await;
    }

    // One body. The expected values are literals, not read back from the backend.
    assert_eq!(
        row(&body, LIVE)["running"],
        json!(true),
        "live must read a JSON boolean true: {body}\n{}",
        gateway.logs()
    );
    assert_eq!(
        row(&body, DEAD)["running"],
        json!(false),
        "dead must read a JSON boolean false: {body}\n{}",
        gateway.logs()
    );

    gateway.stop().await;
}

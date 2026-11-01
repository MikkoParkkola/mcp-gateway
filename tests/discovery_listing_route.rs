// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! `GET /ui/api/discovery` end to end: the real binary, the real scanner,
//! and a client config file in the child's own home. The admin sees the
//! server; no value, argument or home path from that file reaches the body.
//!
//! The child has its own home (`gateway_bin`), so the scan never reads the
//! test runner's real client configs, and this test changes nothing in the
//! test process.

#[path = "common/gateway_bin.rs"]
mod gateway_bin;

use std::path::Path;
use std::process::Stdio;
use std::time::{Duration, Instant};

use tokio::process::{Child, Command};

use gateway_bin::{ANY_PORT, reported_port};

const STARTUP: Duration = Duration::from_secs(60);
const PROBE: Duration = Duration::from_secs(2);
const BEARER: &str = "discovery-route-admin-token";
/// Values one leak would carry.
const SECRET: &str = "zq-discovery-env-secret";
const ARG: &str = "zq-discovery-arg";

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
        gateway.wait_until_serving().await;
        gateway
    }

    fn logs(&self) -> String {
        std::fs::read_to_string(&self.log).unwrap_or_default()
    }

    async fn wait_until_serving(&mut self) {
        let deadline = Instant::now() + STARTUP;
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
}

#[tokio::test]
async fn an_admin_sees_a_local_client_server_without_its_values() {
    let home = tempfile::tempdir().expect("home");
    let home = home.path();
    // Cursor's mcp.json sits at the same place under home on every platform.
    write_owner_only(
        &home.join(".cursor/mcp.json"),
        &serde_json::json!({"mcpServers": {"filesystem": {
            "command": "npx",
            "args": ["-y", "server-filesystem", ARG],
            "env": {"API_KEY": SECRET},
        }}})
        .to_string(),
    );
    let config = home.join("gateway.yaml");
    write_owner_only(
        &config,
        &format!(
            "server:\n  host: \"127.0.0.1\"\n  port: {ANY_PORT}\n\
             security:\n  transparency_log:\n    enabled: true\n\
             auth:\n  enabled: true\n  bearer_token: \"{BEARER}\"\n  single_user: true\n"
        ),
    );
    let gateway = Gateway::spawn(home, &config).await;
    let client = reqwest::Client::new();
    let url = format!("http://127.0.0.1:{}/ui/api/discovery", gateway.port);

    let anonymous = client.get(&url).send().await.expect("request");
    assert_eq!(anonymous.status().as_u16(), 401);

    let response = client
        .get(&url)
        .bearer_auth(BEARER)
        .send()
        .await
        .expect("request");
    assert_eq!(response.status().as_u16(), 200, "{}", gateway.logs());
    assert_eq!(
        response
            .headers()
            .get("cache-control")
            .and_then(|v| v.to_str().ok()),
        Some("no-store")
    );
    let body = response.text().await.expect("body");
    let json: serde_json::Value = serde_json::from_str(&body).expect("json");
    let server = json["servers"]
        .as_array()
        .expect("servers")
        .iter()
        .find(|s| s["name"] == "filesystem")
        .unwrap_or_else(|| panic!("the find is listed: {body}"));
    assert_eq!(server["source"], "Cursor");
    assert_eq!(server["command"], "npx");
    assert_eq!(server["config_file"], "mcp.json");
    assert_eq!(server["adoptable"], true, "{body}");
    let home_text = home.display().to_string();
    for leak in [SECRET, ARG, home_text.as_str()] {
        assert!(!body.contains(leak), "{leak} in {body}");
    }
}

// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-7268: the shipped binary does not report ready before its capability
//! catalogue has loaded.
//!
//! Startup installs the capability backend empty and scans the directories in
//! the background, after a deliberate pause that lets the listener bind first.
//! A readiness probe that answered 200 in that window routed traffic to a
//! gateway whose every capability call failed.

use std::path::Path;
use std::process::Stdio;
use std::time::Duration;

use serde_json::{Value, json};
use tokio::process::{Child, Command};

const CAPABILITIES: usize = 1000;
const TOKEN: &str = "mik-7268-admin";
const DEADLINE: Duration = Duration::from_secs(60);

fn write_capabilities(dir: &Path) {
    std::fs::create_dir_all(dir).expect("capability dir");
    for i in 0..CAPABILITIES {
        let body = format!(
            "name: cap_{i:04}\ndescription: Readiness fixture {i}\nproviders:\n  primary:\n    \
             service: rest\n    config:\n      base_url: https://example.com\n      path: /r{i}\n"
        );
        std::fs::write(dir.join(format!("cap_{i:04}.yaml")), body).expect("write capability");
    }
}

fn spawn(directory: &Path, port: u16) -> Child {
    let caps = directory.join("caps");
    let config = json!({
        "server": {"host": "127.0.0.1", "port": port},
        "auth": {"enabled": true, "bearer_token": TOKEN, "public_paths": ["/health"]},
        "capabilities": {"enabled": true, "directories": [caps.to_string_lossy()]},
    });
    let config_path = directory.join("gateway.yaml");
    mcp_gateway::gateway::test_helpers::write_owner_only(
        &config_path,
        serde_yaml::to_string(&config).expect("config YAML"),
    )
    .expect("write gateway config");
    let log = std::fs::File::create(directory.join("gateway.log")).expect("gateway log");
    Command::new(env!("CARGO_BIN_EXE_mcp-gateway"))
        .env_clear()
        .env("HOME", directory)
        .env("XDG_CONFIG_HOME", directory.join(".config"))
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .current_dir(directory)
        .arg("--config")
        .arg(&config_path)
        .arg("serve")
        .stdin(Stdio::null())
        .stdout(Stdio::from(log.try_clone().expect("clone log")))
        .stderr(Stdio::from(log))
        .kill_on_drop(true)
        .spawn()
        .expect("spawn gateway")
}

/// Poll `/readyz` unauthenticated until it answers 200, returning every
/// answer seen before it. Connection refusals (not yet bound) are skipped.
async fn readyz_until_ready(
    client: &reqwest::Client,
    child: &mut Child,
    url: &str,
    directory: &Path,
) -> Vec<(u16, String)> {
    let logs = || std::fs::read_to_string(directory.join("gateway.log")).unwrap_or_default();
    let start = tokio::time::Instant::now();
    let mut seen = Vec::new();
    loop {
        if let Some(status) = child.try_wait().expect("gateway status") {
            panic!("gateway exited {status}: {}", logs());
        }
        if let Ok(response) = client.get(format!("{url}/readyz")).send().await {
            let status = response.status().as_u16();
            let body = response.text().await.unwrap_or_default();
            seen.push((status, body));
            if status == 200 {
                return seen;
            }
        }
        assert!(
            start.elapsed() < DEADLINE,
            "never ready; seen {seen:?}: {}",
            logs()
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

#[tokio::test]
async fn readyz_is_not_ready_until_every_capability_has_loaded() {
    let directory = tempfile::tempdir().expect("gateway directory");
    write_capabilities(&directory.path().join("caps"));
    let port = {
        let reservation = std::net::TcpListener::bind("127.0.0.1:0").expect("reserve port");
        reservation.local_addr().expect("address").port()
    };
    let mut child = spawn(directory.path(), port);
    let url = format!("http://127.0.0.1:{port}");
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .expect("client");

    let seen = readyz_until_ready(&client, &mut child, &url, directory.path()).await;
    assert!(
        seen.iter()
            .any(|(status, body)| *status == 503 && body == "capabilities loading"),
        "/readyz answered 200 without first reporting the catalogue as loading: {seen:?}"
    );

    let admin: Value = client
        .get(format!("{url}/health"))
        .bearer_auth(TOKEN)
        .send()
        .await
        .expect("admin /health")
        .json()
        .await
        .expect("admin /health JSON");
    let backend = &admin["capability_backend"];
    assert_eq!(
        backend["capabilities_count"], CAPABILITIES,
        "ready with a partial catalogue: {admin}"
    );
    assert_eq!(backend["loaded"], true, "{admin}");
}

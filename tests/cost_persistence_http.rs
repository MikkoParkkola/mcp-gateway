// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The HTTP gateway saves today's cost-governance spend when it shuts down.
//!
//! The built binary runs on a seeded `costs.json`, is stopped with SIGTERM,
//! and the file must then carry a newer save with the same spend. A shutdown
//! path that skipped the save would leave the seed untouched.
//!
//! "Today" is computed when the case runs; one that straddles UTC midnight
//! sees the loader drop the seeded day.
#![cfg(all(unix, feature = "cost-governance"))]

use std::io::{Read as _, Write as _};
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use mcp_gateway::cost_accounting::persistence::{self as costs, PersistedCosts, ToolTotal};

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .and_then(|l| l.local_addr())
        .map(|a| a.port())
        .expect("a free loopback port")
}

fn spawn(dir: &Path, port: u16) -> (Child, std::path::PathBuf) {
    let config = dir.join("gateway.yaml");
    let log = dir.join("gateway.log");
    let text = format!(
        "server:\n  host: 127.0.0.1\n  port: {port}\nauth:\n  enabled: false\n\
         cost_governance:\n  enabled: true\n  budgets:\n    daily: 10.0\n\
         tasks:\n  store_dir: {}\n",
        dir.join("tasks").display()
    );
    mcp_gateway::gateway::test_helpers::write_owner_only(&config, text).expect("write config");
    let out = std::fs::File::create(&log).expect("log file");
    let err = out.try_clone().expect("log handle");
    let mut command = Command::new(env!("CARGO_BIN_EXE_mcp-gateway"));
    for (key, _) in std::env::vars_os() {
        if key.to_string_lossy().starts_with("MCP_GATEWAY_") {
            command.env_remove(key);
        }
    }
    let child = command
        .env("HOME", dir)
        .env("MCP_GATEWAY_CONFIG_DIR", dir.join("state"))
        .current_dir(dir)
        .arg("--config")
        .arg(&config)
        .stdin(Stdio::null())
        .stdout(Stdio::from(out))
        .stderr(Stdio::from(err))
        .spawn()
        .expect("the built mcp-gateway binary spawns");
    (child, log)
}

fn answers_livez(port: u16) -> bool {
    let Ok(mut stream) = std::net::TcpStream::connect(("127.0.0.1", port)) else {
        return false;
    };
    let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
    let request =
        format!("GET /livez HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\n\r\n");
    let mut answer = String::new();
    stream.write_all(request.as_bytes()).is_ok()
        && stream.read_to_string(&mut answer).is_ok()
        && answer.starts_with("HTTP/1.1 200")
}

#[test]
fn http_shutdown_saves_costs() {
    let dir = tempfile::tempdir().expect("tempdir");
    let state = dir.path().join("state");
    std::fs::create_dir_all(&state).expect("state dir");
    let file = state.join("costs.json");
    let mut seeded = PersistedCosts {
        saved_at: costs::now_secs() - 5,
        ..PersistedCosts::default()
    };
    seeded.tool_totals.insert(
        "seeded_tool".to_string(),
        ToolTotal {
            call_count: 0,
            total_cost_usd: 0.4,
            avg_cost_usd: 0.0,
        },
    );
    seeded.key_totals.insert("seeded_key".to_string(), 0.4);
    costs::save(&file, &seeded).expect("seed costs.json");

    let port = free_port();
    let (mut child, log) = spawn(dir.path(), port);
    let logs = || std::fs::read_to_string(&log).unwrap_or_default();
    let deadline = Instant::now() + Duration::from_secs(60);
    while !answers_livez(port) {
        if let Some(status) = child.try_wait().expect("wait on the gateway") {
            panic!("the gateway exited {status} before serving:\n{}", logs());
        }
        if Instant::now() > deadline {
            let _ = child.kill();
            panic!("the gateway never answered /livez:\n{}", logs());
        }
        std::thread::sleep(Duration::from_millis(200));
    }

    let signalled = Command::new("kill")
        .arg("-TERM")
        .arg(child.id().to_string())
        .status()
        .expect("run kill");
    assert!(signalled.success(), "SIGTERM was not delivered");
    let deadline = Instant::now() + Duration::from_secs(60);
    while child.try_wait().expect("wait on the gateway").is_none() {
        if Instant::now() > deadline {
            let _ = child.kill();
            panic!("the gateway did not exit after SIGTERM:\n{}", logs());
        }
        std::thread::sleep(Duration::from_millis(100));
    }

    let saved = costs::load(&file).expect("costs.json parses after shutdown");
    assert!(
        saved.saved_at > seeded.saved_at,
        "the HTTP shutdown did not save costs.json (saved_at unchanged):\n{}",
        logs()
    );
    let tool = saved
        .tool_totals
        .get("seeded_tool")
        .map(|t| t.total_cost_usd);
    assert!(
        tool.is_some_and(|t| (t - 0.4).abs() < 1e-9),
        "the shutdown save lost the per-tool spend: {tool:?}"
    );
    let key = saved.key_totals.get("seeded_key").copied();
    assert!(
        key.is_some_and(|k| (k - 0.4).abs() < 1e-9),
        "the shutdown save lost the per-key spend: {key:?}"
    );
}

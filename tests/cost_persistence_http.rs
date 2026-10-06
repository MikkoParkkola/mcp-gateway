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
// Unix-only: stops the gateway with `kill -TERM`; Windows has no SIGTERM.
#![cfg(all(unix, feature = "cost-governance"))]

#[path = "common/gateway_bin.rs"]
mod gateway_bin;

use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use mcp_gateway::cost_accounting::persistence::{self as costs, PersistedCosts, ToolTotal};

fn spawn(dir: &Path) -> (Child, std::path::PathBuf) {
    let config = dir.join("gateway.yaml");
    let log = dir.join("gateway.log");
    let text = format!(
        "server:\n  host: 127.0.0.1\n  port: {}\nauth:\n  enabled: false\n\
         cost_governance:\n  enabled: true\n  budgets:\n    daily: 10.0\n\
         tasks:\n  store_dir: {}\n",
        gateway_bin::ANY_PORT,
        dir.join("tasks").display()
    );
    mcp_gateway::gateway::test_helpers::write_owner_only(&config, text).expect("write config");
    let out = std::fs::File::create(&log).expect("log file");
    let err = out.try_clone().expect("log handle");
    let mut command = gateway_bin::command(dir, gateway_bin::Inherit::Environment);
    let child = command
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

    let (mut child, log) = spawn(dir.path());
    let logs = || std::fs::read_to_string(&log).unwrap_or_default();
    let deadline = Instant::now() + Duration::from_secs(60);
    while !gateway_bin::logged_port(&log).is_some_and(gateway_bin::answers_livez) {
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

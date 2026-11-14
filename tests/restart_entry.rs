// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Restart slice 4a's entry rows (test plan rows ENTRY-1, ENTRY-2):
//! the invocation capture at the top of `cli::run` never stops startup, whether
//! the invocation resolves or not, and whether a server or a subcommand runs.
#![cfg(unix)]

use mcp_gateway::config::Config;
use std::os::unix::process::CommandExt as _;
use std::{
    path::{Path, PathBuf},
    process::Stdio,
    time::Duration,
};
use tokio::time::Instant;
#[path = "common/gateway_bin.rs"]
mod gateway_bin;
#[path = "common/yaml.rs"]
mod yaml;

/// Hang guard for every wait in this file (test plan H8).
const BOUND: Duration = Duration::from_secs(30);

/// The first line `tool completions bash` prints: a static string in
/// `src/cli/completion.rs`, which slice 4a does not touch (test plan ENTRY-2).
const COMPLETIONS_FIRST_LINE: &str = "# mcp-gateway bash completion";

/// Runs `command` to its end with its output captured; fails the row if it is
/// still running after [`BOUND`] (test plan H8).
fn output_within(command: &mut std::process::Command) -> std::process::Output {
    use std::io::Read as _;
    let mut child = command
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn() // spawn-check: waits for exit: a completion script, no server; killed at the bound
        .expect("completions");
    let (mut out, mut err) = (
        child.stdout.take().expect("stdout"),
        child.stderr.take().expect("stderr"),
    );
    let out = std::thread::spawn(move || {
        let mut v = Vec::new();
        let _ = out.read_to_end(&mut v);
        v
    });
    let err = std::thread::spawn(move || {
        let mut v = Vec::new();
        let _ = err.read_to_end(&mut v);
        v
    });
    let deadline = std::time::Instant::now() + BOUND;
    let status = loop {
        if let Some(status) = child.try_wait().expect("poll") {
            break status;
        }
        if std::time::Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("still running after {BOUND:?}; killed");
        }
        std::thread::sleep(Duration::from_millis(50));
    };
    std::process::Output {
        status,
        stdout: out.join().expect("stdout"),
        stderr: err.join().expect("stderr"),
    }
}

fn write_config(root: &Path) -> PathBuf {
    let mut config = Config::default();
    config.auth.enabled = false;
    config.capabilities.enabled = false;
    config.tasks.store_dir = root.join("tasks").display().to_string();
    config.server.host = "127.0.0.1".into();
    config.server.port = gateway_bin::ANY_PORT;
    let path = root.join("gateway.yaml");
    mcp_gateway::gateway::test_helpers::write_owner_only(
        &path,
        yaml::to_string(&config).expect("yaml"),
    )
    .expect("config");
    path
}

/// ENTRY-1: an argv0 that resolves nowhere (PATH one empty folder, cwd an
/// empty folder) leaves restart unavailable, and the gateway still serves.
#[tokio::test]
async fn entry1_unresolvable_argv0_still_serves() {
    let root = tempfile::tempdir().expect("root");
    let config = write_config(root.path());
    let (empty_path, cwd) = (root.path().join("empty-path"), root.path().join("cwd"));
    std::fs::create_dir_all(&empty_path).expect("empty PATH dir");
    std::fs::create_dir_all(&cwd).expect("empty cwd");
    let log_path = root.path().join("gateway.log");
    let log = std::fs::File::create(&log_path).expect("log");
    let mut command =
        gateway_bin::command(&root.path().join("home"), gateway_bin::Inherit::Environment);
    command
        .arg0("no-such-gw-name")
        .env("PATH", &empty_path)
        .env("MCP_GATEWAY_CONFIG_DIR", root.path().join("state"))
        .current_dir(&cwd)
        .arg("--config")
        .arg(&config);
    let mut command = tokio::process::Command::from(command);
    command
        .stdin(Stdio::null())
        .stdout(Stdio::from(log.try_clone().expect("log handle")))
        .stderr(Stdio::from(log))
        .kill_on_drop(true);
    let mut gateway = gateway_bin::Reaped::new(command.spawn().expect("gateway"))
        .with_teardown(gateway_bin::Teardown::DrainThenRemove);
    gateway.owning(root);

    let client = reqwest::Client::new();
    let deadline = Instant::now() + BOUND;
    loop {
        if let Some(status) = gateway.child_mut().try_wait().expect("poll the gateway") {
            panic!(
                "gateway exited before answering /health: {status:?}\n{}",
                std::fs::read_to_string(&log_path).unwrap_or_default()
            );
        }
        if let Some(port) = gateway_bin::logged_port(&log_path)
            && client
                .get(format!("http://127.0.0.1:{port}/health"))
                .timeout(Duration::from_secs(10))
                .send()
                .await
                .is_ok_and(|r| r.status().is_success())
        {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "no /health answer\n{}",
            std::fs::read_to_string(&log_path).unwrap_or_default()
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let status = gateway.reap().await;
    assert!(status.success(), "stopped by its normal path: {status:?}");
}

/// ENTRY-2: a subcommand (restart `NotServe`) still runs and prints as before.
#[test]
fn entry2_subcommand_still_runs() {
    let home = tempfile::tempdir().expect("home");
    let mut command = gateway_bin::command(home.path(), gateway_bin::Inherit::Environment);
    command.args(["tool", "completions", "bash"]);
    let out = output_within(&mut command);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "{:?}\n{}",
        out.status,
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(
        stdout.lines().next(),
        Some(COMPLETIONS_FIRST_LINE),
        "{stdout}"
    );
}

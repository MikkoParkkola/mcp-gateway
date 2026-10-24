// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8783.AUTO.6: the RFC-0060 measurement window is an operator
//! instrument, off the config surface. It is switched on by a hidden
//! top-level flag or its env var, on every HTTP start path, and the old
//! config key and its `MCP_GATEWAY_SERVER__*` overlay no longer turn it on.
//!
//! The real binary: Helm, the container image and systemd start it with no
//! subcommand and top-level flags, and only a real run sees that argv.
#![cfg(unix)]

#[path = "common/gateway_bin.rs"]
mod gateway_bin;

use std::path::Path;
use std::process::{Child, Stdio};
use std::time::{Duration, Instant};

const ARRIVAL: Duration = Duration::from_secs(60);

struct Gateway {
    child: Child,
    dir: tempfile::TempDir,
    port: u16,
}

impl Drop for Gateway {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl Gateway {
    fn window(&self) -> Option<serde_json::Value> {
        let path = self
            .dir
            .path()
            .join("state/protocol-revision-telemetry/window.json");
        std::fs::read_to_string(path)
            .ok()
            .map(|t| serde_json::from_str(&t).expect("window.json is JSON"))
    }

    fn total(&self) -> u64 {
        self.window()
            .and_then(|w| w["http_segments"][0]["snapshot"]["total"].as_u64())
            .unwrap_or(0)
    }

    fn log(&self) -> String {
        std::fs::read_to_string(self.dir.path().join("gateway.log")).unwrap_or_default()
    }
}

fn config_text(dir: &Path, extra: &str) -> String {
    format!(
        "server:\n  host: 127.0.0.1\n  port: {}\n{extra}auth:\n  enabled: false\ntasks:\n  store_dir: {}\n",
        gateway_bin::ANY_PORT,
        dir.join("tasks").display()
    )
}

/// Starts the gateway with `args` before any subcommand, then `sub`, then `env`.
fn start(args: &[&str], sub: Option<&str>, env: &[(&str, &str)], config_extra: &str) -> Gateway {
    let dir = tempfile::tempdir().expect("tempdir");
    let config = dir.path().join("gateway.yaml");
    mcp_gateway::gateway::test_helpers::write_owner_only(
        &config,
        config_text(dir.path(), config_extra),
    )
    .expect("write config");
    let out = std::fs::File::create(dir.path().join("gateway.log")).expect("log file");
    let err = out.try_clone().expect("log handle");
    let mut command = gateway_bin::command(dir.path(), gateway_bin::Inherit::Environment);
    command
        .env("MCP_GATEWAY_CONFIG_DIR", dir.path().join("state"))
        .current_dir(dir.path())
        .arg("--config")
        .arg(&config)
        .args(args);
    if let Some(sub) = sub {
        command.arg(sub);
    }
    for (k, v) in env {
        command.env(k, v);
    }
    let child = command
        .stdin(Stdio::null())
        .stdout(Stdio::from(out))
        .stderr(Stdio::from(err))
        .spawn()
        .expect("the built mcp-gateway binary spawns");
    let mut gw = Gateway {
        child,
        dir,
        port: 0,
    };
    let started = Instant::now();
    loop {
        let log = gw.dir.path().join("gateway.log");
        if let Some(port) =
            gateway_bin::logged_port(&log).filter(|p| gateway_bin::answers_livez(*p))
        {
            gw.port = port;
            return gw;
        }
        let exited = gw.child.try_wait().expect("wait").is_some();
        assert!(
            started.elapsed() < ARRIVAL && !exited,
            "the gateway never served (args {args:?}, sub {sub:?}):\n{}",
            gw.log()
        );
        std::thread::sleep(Duration::from_millis(50));
    }
}

fn post_initialize(port: u16) -> String {
    use std::io::{Read as _, Write as _};
    let body = serde_json::json!({
        "jsonrpc": "2.0", "id": 1, "method": "initialize",
        "params": {"protocolVersion": "2025-11-25", "capabilities": {},
                   "clientInfo": {"name": "auto6", "version": "1"}}
    })
    .to_string();
    let mut stream = std::net::TcpStream::connect(("127.0.0.1", port)).expect("connect");
    stream.set_read_timeout(Some(ARRIVAL)).expect("timeout");
    write!(
        stream,
        "POST /mcp HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nContent-Type: application/json\r\n\
         Accept: application/json, text/event-stream\r\nContent-Length: {}\r\n\
         Connection: close\r\n\r\n{body}",
        body.len()
    )
    .expect("send");
    let mut answer = String::new();
    let _ = stream.read_to_string(&mut answer);
    answer
}

/// The window is recording: its segment exists, opened before serving.
fn assert_recording(gw: &Gateway, how: &str) {
    assert!(
        post_initialize(gw.port).starts_with("HTTP/1.1 200"),
        "{how}: not served"
    );
    let window = gw
        .window()
        .unwrap_or_else(|| panic!("{how}: no window segment:\n{}", gw.log()));
    assert_eq!(
        window["http_segments"].as_array().map(Vec::len),
        Some(1),
        "{how}: {window:#}"
    );
}

/// T2.9: the flag, with no subcommand (Helm, the image, systemd).
#[test]
fn the_flag_turns_the_window_on_with_no_subcommand() {
    let gw = start(&["--protocol-revision-window", "record"], None, &[], "");
    assert_recording(&gw, "flag, no subcommand");
}

/// T2.11: the flag before `serve`, the order `--host` takes.
#[test]
fn the_flag_turns_the_window_on_before_serve() {
    let gw = start(
        &["--protocol-revision-window", "record"],
        Some("serve"),
        &[],
        "",
    );
    assert_recording(&gw, "flag, serve");
}

/// T2.10: the env var, on both start paths.
#[test]
fn the_env_var_turns_the_window_on_on_both_start_paths() {
    for sub in [None, Some("serve")] {
        let gw = start(
            &[],
            sub,
            &[("MCP_GATEWAY_PROTOCOL_REVISION_WINDOW", "record")],
            "",
        );
        assert_recording(&gw, &format!("env, {sub:?}"));
    }
}

/// T2.10, T1.4: neither the retired key nor its old overlay spelling turns it on.
#[test]
fn the_retired_key_and_its_old_overlay_leave_the_window_off() {
    // (extra env, extra config lines, what the row is)
    type Case<'a> = (&'a [(&'a str, &'a str)], &'a str, &'a str);
    let cases: [Case; 2] = [
        (&[], "  protocol_revision_window: record\n", "file key"),
        (
            &[("MCP_GATEWAY_SERVER__PROTOCOL_REVISION_WINDOW", "record")],
            "",
            "old overlay",
        ),
    ];
    for (env, extra, how) in cases {
        let gw = start(&[], None, env, extra);
        assert!(
            post_initialize(gw.port).starts_with("HTTP/1.1 200"),
            "{how}: not served"
        );
        // A recording gateway opens its segment before it serves, so a
        // served request with no window file means the window is off.
        assert!(
            gw.window().is_none(),
            "{how}: the window must stay off: {:?}",
            gw.window()
        );
    }
}

/// T2.12: an applied hot reload does not stop a recording window.
#[test]
fn an_applied_reload_keeps_the_window_recording() {
    let gw = start(&["--protocol-revision-window", "record"], None, &[], "");
    assert_recording(&gw, "before the reload");
    let before = wait_for_total(&gw, 1, "the first request");
    // A hot-reloadable change, so the reload publishes (an unchanged or
    // retired-key-only file gives an empty patch and proves nothing).
    let config = gw.dir.path().join("gateway.yaml");
    let changed = config_text(gw.dir.path(), "")
        + "backends:\n  reload-probe:\n    command: \"true\"\n    description: added by the reload\n";
    mcp_gateway::gateway::test_helpers::write_owner_only(&config, changed).expect("rewrite config");
    let started = Instant::now();
    while !gw.log().contains("Config reload: backend added") {
        assert!(
            started.elapsed() < ARRIVAL,
            "the reload was never applied:\n{}",
            gw.log()
        );
        std::thread::sleep(Duration::from_millis(100));
    }
    assert!(
        post_initialize(gw.port).starts_with("HTTP/1.1 200"),
        "after the reload: not served"
    );
    wait_for_total(&gw, before + 1, "a request after the reload");
}

/// Waits until the segment's total reaches `at_least` (the periodic save
/// writes it); fails at the deadline. Returns the total seen.
fn wait_for_total(gw: &Gateway, at_least: u64, what: &str) -> u64 {
    let started = Instant::now();
    loop {
        let total = gw.total();
        if total >= at_least {
            return total;
        }
        assert!(
            started.elapsed() < ARRIVAL,
            "{what} was never counted: {:?}",
            gw.window()
        );
        std::thread::sleep(Duration::from_millis(200));
    }
}

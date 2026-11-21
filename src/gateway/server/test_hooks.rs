// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! `run`'s test-build hooks. `run` binds the configured
//! address and stops only on Ctrl-C or SIGTERM, so a lib row can neither reach
//! a port-0 server nor stop it. Here a row asks for the bound port and for a
//! trigger that starts the same shutdown a signal does. Declared
//! `#[cfg(test)]`: none of it reaches a release build, and the release call to
//! `shutdown_signal` stays as it was (the source row below holds both).

use std::path::Path;
use std::time::Duration;

use tokio::sync::{broadcast, oneshot};

use super::Gateway;

/// What a row asked of `run`, taken by `run` once.
#[derive(Default)]
pub(super) struct TestHooks {
    pub(super) bound_port: Option<oneshot::Sender<u16>>,
    pub(super) shutdown: Option<oneshot::Receiver<()>>,
}

impl Gateway {
    /// The port `run` binds, for a row that configured port 0.
    pub(super) fn bound_port_for_test(&mut self) -> oneshot::Receiver<u16> {
        let (sender, receiver) = oneshot::channel();
        self.test_hooks.bound_port = Some(sender);
        receiver
    }

    /// Starts `run`'s graceful shutdown as a signal would: sending, or
    /// dropping the sender.
    pub(super) fn shutdown_trigger_for_test(&mut self) -> oneshot::Sender<()> {
        let (sender, receiver) = oneshot::channel();
        self.test_hooks.shutdown = Some(receiver);
        sender
    }
}

/// `shutdown_signal`, or the row's trigger (sent or dropped), whichever comes
/// first; either way the same broadcast goes out. With no trigger asked for,
/// exactly `shutdown_signal`.
pub(super) async fn signal_or_trigger(
    shutdown_tx: broadcast::Sender<()>,
    trigger: Option<oneshot::Receiver<()>>,
) {
    let Some(trigger) = trigger else {
        return super::shutdown_signal(shutdown_tx).await;
    };
    let on_trigger = shutdown_tx.clone();
    tokio::select! {
        () = super::shutdown_signal(shutdown_tx) => {}
        _ = trigger => {
            let _ = on_trigger.send(());
        }
    }
}

/// The line a child row prints last: a filter that matched no test prints
/// nothing, so it cannot pass for a child that ran.
pub(super) const CHILD_DONE: &str = "CHILD-ROW-DONE";

/// Set by [`in_child`] to the child's home.
const CHILD_HOME: &str = "GATEWAY_TEST_CHILD_HOME";

/// Whether this process is a child [`in_child`] started. A child row run
/// directly (`--ignored`) would start a server under the real home, so it
/// returns at once instead, printing no [`CHILD_DONE`].
pub(super) fn is_child() -> bool {
    std::env::var_os(CHILD_HOME).is_some_and(|h| Some(h) == std::env::var_os("HOME"))
}

/// Run the ignored row `name` in a child test process whose home is `home`
/// (HOME and USERPROFILE; `MCP_GATEWAY_CONFIG_DIR` removed), so what the
/// server loads and saves under the home (`home/.mcp-gateway`) stays in
/// `home`, never the developer's or runner's own. Requires exit 0 and
/// [`CHILD_DONE`]; returns the child's stdout.
pub(super) async fn in_child(name: &str, home: &Path) -> String {
    let exe = std::env::current_exe().expect("the running test binary");
    let mut cmd = tokio::process::Command::new(exe);
    cmd.args([
        "--exact",
        name,
        "--ignored",
        "--nocapture",
        "--test-threads=1",
    ])
    .env("HOME", home)
    .env("USERPROFILE", home)
    .env(CHILD_HOME, home)
    .env_remove("MCP_GATEWAY_CONFIG_DIR")
    .stdout(std::process::Stdio::piped())
    .stderr(std::process::Stdio::piped())
    .kill_on_drop(true);
    let out = tokio::time::timeout(
        Duration::from_secs(120),
        cmd.spawn().expect("a child").wait_with_output(),
    )
    .await
    .expect("the child finished within 120 s")
    .expect("the child ran");
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    assert!(
        out.status.success() && stdout.contains(CHILD_DONE),
        "child {name} failed: {}\n{stdout}\n{}",
        out.status,
        String::from_utf8_lossy(&out.stderr)
    );
    stdout
}

/// The child the A2 row runs, under its name in this test binary.
const HTTP_CHILD: &str = "gateway::server::test_hooks::child_runs_the_http_server";

/// Loopback, any free port: the only settings the A2 child changes.
pub(super) fn loopback_any_port() -> crate::config::Config {
    crate::config::Config {
        server: crate::config::ServerConfig {
            host: "127.0.0.1".into(),
            port: 0,
            ..Default::default()
        },
        ..Default::default()
    }
}

/// A2's child: `run` on port 0 reports the port, answers `/health` there, and
/// returns Ok within 30 s of the trigger.
#[tokio::test]
#[ignore = "run only as a child of run_reports_its_port_and_stops_on_the_trigger"]
async fn child_runs_the_http_server() {
    if !is_child() {
        return;
    }
    let mut gw = Gateway::new(loopback_any_port()).await.expect("a gateway");
    let stop = gw.shutdown_trigger_for_test();
    let port_rx = gw.bound_port_for_test();
    let running = tokio::spawn(Box::pin(gw.run()));
    let port = match tokio::time::timeout(Duration::from_secs(30), port_rx).await {
        Ok(Ok(p)) => p,
        Ok(Err(closed)) => panic!("no port ({closed}): run ended first ({:?})", running.await),
        Err(elapsed) => panic!("no port within 30 s ({elapsed})"),
    };
    let url = format!("http://127.0.0.1:{port}/health");
    let http = reqwest::Client::builder().no_proxy().build();
    let code = match http.expect("an HTTP client").get(url).send().await {
        Ok(r) => r.status().as_u16(),
        Err(e) => panic!("/health unreachable on the reported port: {e}"),
    };
    assert_eq!(code, 200);
    stop.send(()).expect("run still holds the trigger");
    let result = tokio::time::timeout(Duration::from_secs(30), running)
        .await
        .expect("run returned within 30 s of the trigger")
        .expect("run did not panic");
    assert!(result.is_ok(), "{result:?}");
    println!("{CHILD_DONE}");
}

/// A2. A test build's `run` reports the port it bound for port 0 and stops on
/// the trigger, in a child whose home is a temp dir. Control on the
/// isolation: `run`'s shutdown saves landed in that home.
#[tokio::test]
async fn run_reports_its_port_and_stops_on_the_trigger() {
    let home = tempfile::tempdir().expect("home");
    in_child(HTTP_CHILD, home.path()).await;
    let saved = home.path().join(".mcp-gateway").join("transitions.json");
    assert!(
        saved.exists(),
        "run's saves did not land in the child's home"
    );
}

/// A2's source row: the hooks exist only in a test build. Every mod.rs line
/// naming them sits right under `#[cfg(test)]`; the release path keeps its one
/// `shutdown_signal` call under `#[cfg(not(test))]`; `shutdown_signal` itself
/// has no test arm.
#[test]
fn the_hooks_are_test_build_only() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/gateway/server");
    let read = |f: &str| std::fs::read_to_string(dir.join(f)).expect("a server file");
    let server = read("mod.rs");
    let lines: Vec<&str> = server.lines().map(str::trim).collect();
    let naming: Vec<usize> = (1..lines.len())
        .filter(|&i| lines[i].contains("test_hooks") && !lines[i].starts_with("//"))
        .collect();
    // The module line, the field, its default, the port report, the trigger
    // take, the select.
    assert_eq!(naming.len(), 6, "{naming:?}");
    for i in naming {
        assert_eq!(
            lines[i - 1],
            "#[cfg(test)]",
            "mod.rs:{} {}",
            i + 1,
            lines[i]
        );
    }
    let calls: Vec<usize> = (1..lines.len())
        .filter(|&i| lines[i].starts_with("shutdown_signal("))
        .collect();
    assert_eq!(calls.len(), 1, "{calls:?}");
    assert_eq!(lines[calls[0] - 1], "#[cfg(not(test))]");
    let support = read("support.rs");
    let at = support
        .find("pub(super) async fn shutdown_signal(")
        .expect("shutdown_signal");
    let body = &support[at..at + support[at..].find("\n}\n").expect("its end")];
    assert!(
        !body.contains("test") && !body.contains("oneshot"),
        "shutdown_signal has a test arm"
    );
}

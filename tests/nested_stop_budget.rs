// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A gateway run as another gateway's stdio backend stops its own stdio backends
//! when the parent stops, even while a call is still in flight: the parent's dropped call
//! cancels the inner's dispatch, so the inner is not busy at EOF and stops its backends
//! in time. Regression pins: a leaf that ignores EOF and SIGTERM must still be gone.
#![cfg(unix)]

use mcp_gateway::config::{BackendConfig, Config, TransportConfig};
use serde_json::{Value, json};
use std::{
    path::{Path, PathBuf},
    process::Stdio,
    time::Duration,
};
use tokio::{io::AsyncWriteExt as _, time::Instant};
#[path = "common/gateway_bin.rs"]
mod gateway_bin;
#[path = "common/pids.rs"]
mod pids;
#[path = "common/yaml.rs"]
mod yaml;
const PROTOCOL_VERSION: &str = "2025-11-25";
const READY_BOUND: Duration = Duration::from_secs(60);
/// How long a gateway's stop may take before its leaves must be gone: above the 30 s parent timeout, with slack for a loaded host.
const STOP_BOUND: Duration = Duration::from_secs(45);
/// The smallest `server.shutdown_timeout` an HTTP gateway accepts. A start below it
/// is refused, so a row that starts a gateway with it also proves it is accepted.
const HTTP_MINIMUM: Duration = Duration::from_secs(13);
/// How long a stdio gateway sent SIGTERM with stdin still open may take to exit. Its worst case is
/// the 30 s drain, the 10 s teardown bound and the 10 s serve-runtime shutdown bound (the blocked
/// stdin reader keeps the runtime waiting until that bound), 50 s in all, plus slack for a loaded
/// host. A 45 s bound sat on the typical path (30 s drain, about 5 s teardown, 10 s runtime).
const STDIO_SIGTERM_EXIT_BOUND: Duration = Duration::from_secs(75);
const LEAF_SCRIPT: &str = r#"import json, os, signal, subprocess, sys, time
name = sys.argv[1]
signal.signal(signal.SIGTERM, signal.SIG_IGN)
with open("leaf-" + name + ".pid", "w") as f:
    f.write(str(os.getpid()))
# A descendant in the leaf's process group. It inherits the ignored SIGTERM,
# so only the gateway's kill of the whole group ends it.
grandchild = subprocess.Popen(["sleep", "600"])
with open("leaf-" + name + ".grandchild.pid", "w") as f:
    f.write(str(grandchild.pid))
for line in sys.stdin:
    msg = json.loads(line)
    if "id" not in msg:
        continue
    method = msg.get("method")
    if method == "initialize":
        result = {"protocolVersion": msg["params"]["protocolVersion"], "capabilities": {"tools": {}},
                  "serverInfo": {"name": name, "version": "1"}}
    elif method == "tools/list":
        result = {"tools": [{"name": "hold", "inputSchema": {"type": "object"},
                             "annotations": {"readOnlyHint": True}}]}
    elif method == "tools/call" and msg["params"]["name"] == "hold":
        open("called-" + name, "w").close()
        time.sleep(600)
        continue
    else:
        result = {}
    print(json.dumps({"jsonrpc": "2.0", "id": msg["id"], "result": result}), flush=True)
time.sleep(600)
"#;

fn base_config(root: &Path, name: &str) -> Config {
    let mut config = Config::default();
    config.auth.enabled = false;
    config.capabilities.enabled = false;
    config.cache.default_ttl = Duration::ZERO;
    config.tasks.store_dir = root.join(format!("{name}-tasks")).display().to_string();
    config
}
fn backend(root: &Path, command: String) -> BackendConfig {
    BackendConfig {
        enabled: true,
        timeout: Duration::from_secs(120),
        transport: TransportConfig::Stdio {
            command,
            cwd: Some(root.display().to_string()),
            protocol_version: None,
        },
        ..BackendConfig::default()
    }
}
fn save(root: &Path, name: &str, config: &Config) -> PathBuf {
    let path = root.join(name);
    mcp_gateway::gateway::test_helpers::write_owner_only(
        &path,
        yaml::to_string(config).expect("yaml"),
    )
    .expect("config");
    path
}
fn write_inner_config(root: &Path, leaves: &[&str], inner_stop: Duration) -> PathBuf {
    std::fs::write(root.join("leaf.py"), LEAF_SCRIPT).expect("leaf script");
    let mut config = base_config(root, "inner");
    config.server.shutdown_timeout = inner_stop;
    for name in leaves {
        config.backends.insert(
            (*name).into(),
            backend(root, format!("python3 -u leaf.py {name}")),
        );
    }
    save(root, "inner.yaml", &config)
}
fn write_outer_config(root: &Path, inner: &Path, total: Duration) -> PathBuf {
    // Record the inner before exec so cleanup also covers failure during warm start.
    std::fs::write(root.join("inner.py"), "import os, sys\nwith open('inner.pid', 'w') as f: f.write(str(os.getpid()))\nos.execv(sys.argv[1], sys.argv[1:])\n").expect("launcher");
    let mut config = base_config(root, "outer");
    config.server.host = "127.0.0.1".into();
    config.server.port = gateway_bin::ANY_PORT;
    config.server.shutdown_timeout = total;
    let mut inner_backend = backend(
        root,
        format!(
            "python3 inner.py \"{}\" --config \"{}\" serve --stdio",
            gateway_bin::path(),
            inner.display()
        ),
    );
    std::fs::create_dir_all(root.join("inner-home")).expect("inner home");
    inner_backend
        .env
        .insert("HOME".into(), root.join("inner-home").display().to_string());
    config.backends.insert("inner".into(), inner_backend);
    save(root, "gateway.yaml", &config)
}
fn write_chain_parent(root: &Path, name: &str, child: &str, child_config: &Path) -> PathBuf {
    std::fs::write(
        root.join(format!("{child}.py")),
        format!(
            "import os, sys\nwith open('{child}.pid', 'w') as f: f.write(str(os.getpid()))\nos.execv(sys.argv[1], sys.argv[1:])\n"
        ),
    )
    .expect("chain launcher");
    let mut config = base_config(root, name);
    config.server.shutdown_timeout = Duration::from_secs(30);
    config.backends.insert(
        child.into(),
        backend(
            root,
            format!(
                "python3 {child}.py \"{}\" --config \"{}\" serve --stdio",
                gateway_bin::path(),
                child_config.display()
            ),
        ),
    );
    save(root, &format!("{name}.yaml"), &config)
}
fn logs(root: &Path) -> String {
    std::fs::read_to_string(root.join("gateway.log")).unwrap_or_default()
}
async fn post(
    client: &reqwest::Client,
    base: &str,
    session: Option<&str>,
    body: &Value,
) -> Result<(String, Option<String>), String> {
    let mut request = client
        .post(format!("{base}/mcp"))
        .header("content-type", "application/json")
        .header("accept", "application/json")
        .header("mcp-protocol-version", PROTOCOL_VERSION);
    if let Some(id) = session {
        request = request.header("mcp-session-id", id);
    }
    let response = request.json(body).send().await.map_err(|e| e.to_string())?;
    let session = response
        .headers()
        .get("mcp-session-id")
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);
    Ok((response.text().await.map_err(|e| e.to_string())?, session))
}
fn initialize() -> Value {
    json!({"jsonrpc":"2.0", "id":0, "method":"initialize", "params": {
    "protocolVersion":PROTOCOL_VERSION, "capabilities":{}, "clientInfo":{"name":"StopBudgetTest", "version":"1"}}})
}
async fn open_session(client: &reqwest::Client, base: &str, root: &Path) -> String {
    let (body, session) = post(client, base, None, &initialize())
        .await
        .expect("initialize");
    let session = session.unwrap_or_else(|| panic!("no session: {body}\n{}", logs(root)));
    post(
        client,
        base,
        Some(&session),
        &json!({"jsonrpc":"2.0", "method":"notifications/initialized"}),
    )
    .await
    .expect("initialized");
    session
}
async fn ready_port(client: &reqwest::Client, root: &Path) -> u16 {
    let deadline = Instant::now() + READY_BOUND;
    loop {
        if let Some(port) = gateway_bin::logged_port(&root.join("gateway.log"))
            && client
                .get(format!("http://127.0.0.1:{port}/health"))
                .timeout(Duration::from_secs(10))
                .send()
                .await
                .is_ok()
        {
            return port;
        }
        assert!(Instant::now() < deadline, "not ready\n{}", logs(root));
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}
fn invoke(name: &str, id: usize) -> Value {
    let args = json!({"server":name, "tool":"hold", "arguments":{}});
    let args = json!({"server":"inner", "tool":"gateway_invoke", "arguments":args});
    json!({"jsonrpc":"2.0", "id":id, "method":"tools/call", "params":{"name":"gateway_invoke", "arguments":args}})
}
// Groups are isolated by the transport, so guard each recorded group as well.
// Only for a red row: a row that saw every process gone forgets it, so no
// signal goes to a pid or group the system may since have reused.
struct KillGroup {
    pid: u32,
    root: PathBuf,
}
impl Drop for KillGroup {
    fn drop(&mut self) {
        let kill = |pid: u32| {
            let _ = std::process::Command::new("kill")
                .args(["-KILL", "--", &format!("-{pid}")])
                .stderr(Stdio::null())
                .status();
        };
        kill(self.pid);
        for name in [
            "middle.pid",
            "inner.pid",
            "leaf-leaf.pid",
            "leaf-leaf_a.pid",
            "leaf-leaf_b.pid",
        ] {
            if let Ok(text) = std::fs::read_to_string(self.root.join(name))
                && let Ok(pid) = text.trim().parse()
            {
                kill(pid);
                drop(pids::KillPid(pid));
            }
        }
    }
}
fn read_pid(root: &Path, file: &str) -> u32 {
    let text = std::fs::read_to_string(root.join(file)).unwrap_or_else(|e| panic!("{file}: {e}"));
    text.trim()
        .parse()
        .unwrap_or_else(|e| panic!("{file}: {e}"))
}
/// The action under test: a plain SIGTERM to the gateway alone. Reaped
/// signals nothing; it only reaps after the assertions.
fn sigterm(pid: u32) {
    assert!(
        std::process::Command::new("kill")
            .args(["-TERM", &pid.to_string()])
            .status()
            .expect("kill")
            .success()
    );
}

fn alive_pids(pids: &[u32]) -> Vec<u32> {
    pids.iter()
        .copied()
        .filter(|pid| pids::alive(*pid))
        .collect()
}

async fn run(total: Duration, inner_stop: Duration, leaves: &[&str]) {
    let temp = tempfile::tempdir().expect("temp root");
    let root = temp.path().to_path_buf();
    let root = root.as_path();
    let inner = write_inner_config(root, leaves, inner_stop);
    let config = write_outer_config(root, &inner, total);
    let log = std::fs::File::create(root.join("gateway.log")).expect("log");
    let mut command = tokio::process::Command::from(gateway_bin::command(
        &root.join("home"),
        gateway_bin::Inherit::Environment,
    ));
    command
        .env("MCP_GATEWAY_CONFIG_DIR", root.join("gateway-state"))
        .current_dir(root)
        .arg("--config")
        .arg(config);
    let child = command
        .stdin(Stdio::piped())
        .stdout(Stdio::from(log.try_clone().expect("log handle")))
        .stderr(Stdio::from(log))
        .process_group(0)
        .kill_on_drop(true)
        .spawn() // spawn-check: waits for exit: the SIGTERM under test, then a bounded child wait; Reaped reaps after; KillGroup covers panic
        .expect("gateway");
    let mut reaped = gateway_bin::Reaped::new(child);
    let pid = reaped.child_mut().id().expect("pid");
    let cleanup = KillGroup {
        pid,
        root: root.into(),
    };
    let stdin = reaped.child_mut().stdin.take().expect("stdin");
    let mut calls = tokio::task::JoinSet::new();
    let client = reqwest::Client::new();
    let base = format!("http://127.0.0.1:{}", ready_port(&client, root).await);
    let session = tokio::time::timeout(READY_BOUND, open_session(&client, &base, root))
        .await
        .unwrap_or_else(|_| panic!("session open deadline\n{}", logs(root)));
    for (id, name) in leaves.iter().enumerate() {
        let (client, base, session, message) = (
            client.clone(),
            base.clone(),
            session.clone(),
            invoke(name, id + 1),
        );
        calls.spawn(async move { post(&client, &base, Some(&session), &message).await });
    }
    let ready_by = Instant::now() + READY_BOUND;
    while leaves
        .iter()
        .any(|name| !root.join(format!("called-{name}")).exists())
    {
        assert!(
            Instant::now() < ready_by,
            "hold never started\n{}",
            logs(root)
        );
        assert!(
            calls.try_join_next().is_none(),
            "call returned before stop\n{}",
            logs(root)
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    // The inner gateway, each leaf and its grandchild: the grandchild is gone
    // only if the gateway killed the leaf's whole process group.
    let leaves: Vec<u32> = std::iter::once("inner.pid".to_owned())
        .chain(leaves.iter().flat_map(|name| {
            [
                format!("leaf-{name}.pid"),
                format!("leaf-{name}.grandchild.pid"),
            ]
        }))
        .map(|file| read_pid(root, &file))
        .collect();
    assert!(calls.try_join_next().is_none(), "hold returned before stop");
    assert!(
        leaves.iter().all(|pid| pids::alive(*pid)),
        "inner and leaves must be live at stop"
    );
    let deadline = Instant::now() + STOP_BOUND;
    sigterm(pid);
    tokio::time::timeout_at(deadline, reaped.child_mut().wait())
        .await
        .unwrap_or_else(|_| panic!("gateway exit deadline\n{}", logs(root)))
        .expect("gateway exit");
    while leaves.iter().any(|pid| pids::alive(*pid)) {
        assert!(
            Instant::now() < deadline,
            "inner or leaf outlived parent stop budget: {:?}\n{}",
            alive_pids(&leaves),
            logs(root)
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    // Safety net only: the gateway has already exited, so this sends no signal.
    reaped.reap().await;
    std::mem::forget(cleanup);
    drop(stdin);
}

/// A busy inner stops its leaf within the minimum parent budget plus slack.
/// Red if the inner or its leaf group outlives the outer's stop (removing the group kill fails it).
#[tokio::test]
async fn a_busy_nested_gateway_stops_its_leaf_before_the_outer_kills_it() {
    run(HTTP_MINIMUM, Duration::from_secs(8), &["leaf"]).await;
}
/// The same ownership claim holds with a 30 s parent budget.
/// Red if the inner or its leaf group outlives the outer's stop (removing the group kill fails it).
#[tokio::test]
async fn a_busy_nested_gateway_stops_its_leaf_before_the_outer_kills_it_30s() {
    run(Duration::from_secs(30), Duration::from_secs(8), &["leaf"]).await;
}
/// Both busy leaves stop within one minimum parent budget plus 15 s slack.
/// Red if the inner or its leaf group outlives the outer's stop (removing the group kill fails it).
#[tokio::test]
async fn a_busy_nested_gateway_stops_two_leaves_within_one_deadline() {
    run(HTTP_MINIMUM, Duration::from_secs(8), &["leaf_a", "leaf_b"]).await;
}

/// A nested gateway whose own stop outlasts its parent's plan leaves no leaf or grandchild alive.
/// Red if a stopping stdio gateway ignores its parent's SIGTERM and lets its leaves' waits run past its own kill.
#[tokio::test]
async fn a_nested_gateway_whose_own_stop_outlasts_its_parents_plan_leaves_no_leaf() {
    run(HTTP_MINIMUM, Duration::from_secs(30), &["leaf_a", "leaf_b"]).await;
}

/// Each nested hurry must fit its parent's remaining kill window, rather than
/// restarting 300 ms after SIGTERM and losing its reaper to its parent's kill.
/// Every pid of a three-level chain, asserted live before the stop begins.
fn live_chain(root: &Path, outer: u32, leaves: &[&str]) -> Vec<u32> {
    let mut tree = vec![
        outer,
        read_pid(root, "middle.pid"),
        read_pid(root, "inner.pid"),
    ];
    for name in leaves {
        tree.push(read_pid(root, &format!("leaf-{name}.pid")));
        tree.push(read_pid(root, &format!("leaf-{name}.grandchild.pid")));
    }
    assert_eq!(
        alive_pids(&tree),
        tree,
        "every chain level must be live before stop"
    );
    tree
}

#[tokio::test]
async fn a_three_level_nested_gateway_chain_leaves_no_leaf_after_a_hurry() {
    let temp = tempfile::tempdir().expect("temp root");
    let root = temp.path();
    let leaves = ["leaf_a", "leaf_b"];
    let inner = write_inner_config(root, &leaves, Duration::from_secs(30));
    let middle = write_chain_parent(root, "middle", "inner", &inner);
    let outer = write_chain_parent(root, "outer", "middle", &middle);
    let log = std::fs::File::create(root.join("gateway.log")).expect("log");
    let mut reaped = gateway_bin::Reaped::new(
        tokio::process::Command::from(gateway_bin::command(
            &root.join("home"),
            gateway_bin::Inherit::Environment,
        ))
        .env("RUST_LOG", "mcp_gateway=info")
        .env("MCP_GATEWAY_CONFIG_DIR", root.join("gateway-state"))
        .current_dir(root)
        .arg("--config")
        .arg(outer)
        .args(["serve", "--stdio"])
        .stdin(Stdio::piped())
        .stdout(Stdio::from(log.try_clone().expect("log handle")))
        .stderr(Stdio::from(log))
        .process_group(0)
        .kill_on_drop(true)
        .spawn()
        .expect("outer gateway"),
    );
    let pid = reaped.child_mut().id().expect("outer pid");
    let cleanup = KillGroup {
        pid,
        root: root.into(),
    };
    let mut stdin = reaped.child_mut().stdin.take().expect("stdin");
    let mut messages = vec![
        initialize(),
        json!({"jsonrpc":"2.0", "method":"notifications/initialized"}),
    ];
    for (id, name) in leaves.iter().enumerate() {
        let mut message = invoke(name, id + 1);
        let inner_call = message["params"]["arguments"].take();
        message["params"]["arguments"] =
            json!({"server":"middle", "tool":"gateway_invoke", "arguments":inner_call});
        messages.push(message);
    }
    for message in messages {
        stdin
            .write_all(format!("{message}\n").as_bytes())
            .await
            .expect("stdio");
    }
    let ready_by = Instant::now() + READY_BOUND;
    while leaves
        .iter()
        .any(|name| !root.join(format!("called-{name}")).exists())
    {
        assert!(
            Instant::now() < ready_by,
            "holds never started\n{}",
            logs(root)
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let tree = live_chain(root, pid, &leaves);
    // EOF installs the hurry listener before logging this message. The busy
    // calls keep teardown pending until the subsequent SIGTERM cuts it short.
    drop(stdin);
    let eof_by = Instant::now() + READY_BOUND;
    while !logs(root).contains("stdio: EOF reached, shutting down") {
        assert!(
            Instant::now() < eof_by,
            "outer never saw EOF\n{}",
            logs(root)
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let hurried_at = Instant::now();
    sigterm(pid);
    // Observation time, not a watchdog: the outer kills at ~300 ms; allow
    // another 2 s for scheduling and exit, not the 6 s reap reserve.
    tokio::time::sleep_until(hurried_at + Duration::from_millis(2300)).await;
    assert!(
        logs(root).contains("shutdown hurried by a signal"),
        "outer did not hurry\n{}",
        logs(root)
    );
    let alive = alive_pids(&tree);
    assert!(
        alive.is_empty(),
        "chain processes survived the outer's hurry kill window: {alive:?}; all pids: {tree:?}\n{}",
        logs(root)
    );
    tokio::time::timeout(Duration::from_secs(10), reaped.child_mut().wait())
        .await
        .expect("outer exit deadline")
        .expect("outer exit");
    reaped.reap().await;
    std::mem::forget(cleanup);
}

/// A SIGTERM to a stdio-mode gateway (what systemd or docker stop sends) leaves no
/// backend running once the gateway has exited, even a backend that ignores EOF
/// and SIGTERM and has a call in flight. Red if the gateway's teardown stops killing
/// what its backends' graceful stop left.
#[tokio::test]
async fn a_sigterm_to_a_stdio_gateway_leaves_no_backend_running() {
    let temp = tempfile::tempdir().expect("temp root");
    let root = temp.path().to_path_buf();
    let root = root.as_path();
    let config = write_inner_config(root, &["leaf"], Duration::from_secs(8));
    let log = std::fs::File::create(root.join("gateway.log")).expect("log");
    let child = tokio::process::Command::from(gateway_bin::command(
        &root.join("home"),
        gateway_bin::Inherit::Environment,
    ))
    .env("MCP_GATEWAY_CONFIG_DIR", root.join("gateway-state"))
    .current_dir(root)
    .arg("--config")
    .arg(config)
    .args(["serve", "--stdio"])
    .stdin(Stdio::piped())
    .stdout(Stdio::from(log.try_clone().expect("log handle")))
    .stderr(Stdio::from(log))
    .process_group(0)
    .kill_on_drop(true)
    .spawn() // spawn-check: waits for exit: the SIGTERM under test, then a bounded child wait; Reaped reaps after; KillGroup covers panic
    .expect("gateway");
    let mut reaped = gateway_bin::Reaped::new(child);
    let pid = reaped.child_mut().id().expect("pid");
    let cleanup = KillGroup {
        pid,
        root: root.into(),
    };
    let mut stdin = reaped.child_mut().stdin.take().expect("stdin");
    for message in [
        initialize(),
        json!({"jsonrpc":"2.0", "method":"notifications/initialized"}),
        json!({"jsonrpc":"2.0", "id":1, "method":"tools/call", "params":{
            "name":"gateway_invoke", "arguments":{"server":"leaf", "tool":"hold", "arguments":{}}
        }}),
    ] {
        stdin
            .write_all(format!("{message}\n").as_bytes())
            .await
            .expect("write stdio");
    }
    let ready_by = Instant::now() + READY_BOUND;
    while !root.join("called-leaf").exists() {
        assert!(
            Instant::now() < ready_by,
            "hold never started\n{}",
            logs(root)
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let leaf = read_pid(root, "leaf-leaf.pid");
    let grandchild = read_pid(root, "leaf-leaf.grandchild.pid");
    assert!(
        pids::alive(leaf) && pids::alive(grandchild),
        "leaf and its grandchild must be live at stop\n{}",
        logs(root)
    );
    let deadline = Instant::now() + STDIO_SIGTERM_EXIT_BOUND;
    sigterm(pid);
    tokio::time::timeout_at(deadline, reaped.child_mut().wait())
        .await
        .unwrap_or_else(|_| panic!("gateway exit deadline\n{}", logs(root)))
        .expect("gateway exit");
    while pids::alive(leaf) || pids::alive(grandchild) {
        assert!(
            Instant::now() < deadline,
            "leaf {leaf} or its grandchild {grandchild} still running after gateway exited\n{}",
            logs(root)
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    // Safety net only: the gateway has already exited, so this sends no signal.
    reaped.reap().await;
    std::mem::forget(cleanup);
    drop(stdin);
}

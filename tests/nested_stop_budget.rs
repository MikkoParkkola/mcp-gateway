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
#[path = "nested_stop_budget/fixtures.rs"]
mod fixtures;
#[path = "common/gateway_bin.rs"]
mod gateway_bin;
#[path = "common/pids.rs"]
mod pids;
#[path = "nested_stop_budget/stdio_chain.rs"]
mod stdio_chain;
#[path = "common/yaml.rs"]
mod yaml;
#[cfg(target_os = "linux")]
#[path = "nested_stop_budget/zombie_inner.rs"]
mod zombie_inner;
const PROTOCOL_VERSION: &str = "2025-11-25";
const READY_BOUND: Duration = Duration::from_secs(60);
/// What the chain's last process may outlive the configured stop total by: the
/// poll interval and a loaded host's scheduling, not a second stop.
const BUDGET_SLACK: Duration = Duration::from_secs(2);
/// When a supervisor kills a gateway still running past its stop total. The
/// kill reaches only the gateway's own process, so the backend tree must be
/// gone by then.
const EXTERNAL_KILL_AFTER: Duration = Duration::from_secs(1);
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
    std::fs::write(root.join("leaf.py"), fixtures::LEAF_SCRIPT).expect("leaf script");
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
/// A stall row's outer runs no backend health probe: a probe already running or due could
/// count the frozen inner as failed and start a recovery, and the row would then test that
/// recovery's cleanup instead of the stop's. Every other row keeps the default probes.
fn probe_backends(config: &mut Config, during: During) {
    config.failsafe.health_check.enabled = !matches!(during, During::Freeze);
}
fn write_outer_config(root: &Path, inner: &Path, total: Duration, during: During) -> PathBuf {
    // Record the inner before exec so cleanup also covers failure during warm start.
    std::fs::write(root.join("inner.py"), "import os, sys\nwith open('inner.pid', 'w') as f: f.write(str(os.getpid()))\nos.dup2(os.open('inner.log', os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o644), 2)\nos.execv(sys.argv[1], sys.argv[1:])\n").expect("launcher");
    let mut config = base_config(root, "outer");
    config.server.host = "127.0.0.1".into();
    config.server.port = gateway_bin::ANY_PORT;
    config.server.shutdown_timeout = total;
    probe_backends(&mut config, during);
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
/// The stop total of a chain parent (the stdio outer and the three-level chain's middle).
const CHAIN_PARENT_STOP: Duration = Duration::from_secs(30);
fn write_chain_parent(
    root: &Path,
    name: &str,
    child: &str,
    child_config: &Path,
    during: During,
    child_log: Option<&str>,
) -> PathBuf {
    std::fs::write(
        root.join(format!("{child}.py")),
        format!(
            "import os, sys\nwith open('{child}.pid', 'w') as f: f.write(str(os.getpid()))\nlog = os.open('{child}.log', os.O_APPEND | os.O_CREAT | os.O_WRONLY, 0o644)\nos.dup2(log, 2)\nos.execv(sys.argv[1], sys.argv[1:])\n"
        ),
    )
    .expect("chain launcher");
    let mut config = base_config(root, name);
    config.server.shutdown_timeout = CHAIN_PARENT_STOP;
    probe_backends(&mut config, during);
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
    // A backend's environment is cleared, so a child's log filter is named here.
    if let Some(filter) = child_log {
        let child_backend = config.backends.get_mut(child).expect("the child backend");
        child_backend.env.insert("RUST_LOG".into(), filter.into());
    }
    save(root, &format!("{name}.yaml"), &config)
}
/// The outer gateway's log, then each nested gateway's own (a launcher sends its stderr to
/// `<name>.log`), so a red row prints every stop.
fn logs(root: &Path) -> String {
    let read = |name: &str| std::fs::read_to_string(root.join(name)).unwrap_or_default();
    format!(
        "{}\n--- middle.log ---\n{}\n--- inner.log ---\n{}",
        read("gateway.log"),
        read("middle.log"),
        read("inner.log")
    )
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

/// What a row does to the inner gateway while the outer one stops.
#[derive(Clone, Copy)]
enum During {
    Nothing,
    /// Freeze the inner (SIGSTOP) before the outer's stop starts and never let
    /// it run again: it can end nothing, so only the outer's sweep ends its leaves.
    Freeze,
    /// Record the stop's timeline for the margin measurement (Linux only): each
    /// role's exit as it happens and the SIGTERM's instant, on one monotonic clock.
    #[cfg(target_os = "linux")]
    Watch,
}

/// An inner stop total longer than the parent's whole plan. With a short one
/// (8 s) the inner ends its leaf by itself about 2 s after its stdin closes,
/// before the parent's SIGTERM is due, and the nested need is never in play.
const INNER_OUTLASTS_THE_PLAN: Duration = Duration::from_secs(30);

/// Prints "<pid> <`CLOCK_MONOTONIC` ns>" the moment each given pid exits, through
/// a pidfd each (Linux), so a stop's timeline is read without polling. A pid
/// already gone when the watcher starts prints "<pid> gone-before".
#[cfg(target_os = "linux")]
const EXIT_WATCHER: &str = r#"import os, select, sys, time
watching = {}
poller = select.poll()
for arg in sys.argv[1:]:
    try:
        fd = os.pidfd_open(int(arg))
    except ProcessLookupError:
        print(arg, "gone-before", flush=True)
        continue
    watching[fd] = arg
    poller.register(fd, select.POLLIN)
give_up = time.monotonic() + 120
while watching and time.monotonic() < give_up:
    for fd, _ in poller.poll(1000):
        print(watching.pop(fd), time.monotonic_ns(), flush=True)
        poller.unregister(fd)
        os.close(fd)
"#;

/// The inner gateway, each leaf and its grandchild, by role (`inner`, `leaf:<name>`,
/// `grandchild:<name>`), from the pid files the chain writes. The grandchild is gone
/// only if a gateway killed the leaf's whole process group.
fn chain_roles(root: &Path, leaves: &[&str]) -> Vec<(String, u32)> {
    let mut roles = vec![("inner".to_owned(), read_pid(root, "inner.pid"))];
    for name in leaves {
        roles.push((
            format!("leaf:{name}"),
            read_pid(root, &format!("leaf-{name}.pid")),
        ));
        roles.push((
            format!("grandchild:{name}"),
            read_pid(root, &format!("leaf-{name}.grandchild.pid")),
        ));
    }
    roles
}

/// One measured stop's timeline for the margin harness (Linux: pidfd, `CLOCK_MONOTONIC`).
#[cfg(target_os = "linux")]
mod measure {
    use super::{Duration, EXIT_WATCHER, STOP_BOUND, Stdio, json};

    /// Which stop the run measured: the analyser applies its own kill instant to each.
    #[derive(Clone, Copy)]
    pub(super) enum Path {
        /// The HTTP outer's planned stop.
        Normal,
        /// The stdio outer hurried by a second signal.
        Hurried,
    }

    /// The exit watcher of one run, started on every role's pid before the stop.
    pub(super) struct Watch {
        watcher: tokio::process::Child,
        roles: Vec<(String, u32)>,
    }

    impl Watch {
        pub(super) fn start(roles: &[(String, u32)]) -> Self {
            let watcher = tokio::process::Command::new("python3")
                .args(["-I", "-c", EXIT_WATCHER])
                .args(roles.iter().map(|(_, pid)| pid.to_string()))
                .stdout(Stdio::piped())
                .kill_on_drop(true)
                .spawn() // spawn-check: not the gateway: the pidfd exit watcher of the margin measurement
                .expect("the exit watcher");
            Self {
                watcher,
                roles: roles.to_vec(),
            }
        }

        /// Waits for every exit, then prints the run's one MEASURE line: `signalled_mono_ns` (the
        /// instant taken just before the SIGTERM), the stop `total_ms`, the `path`, and `exits` as
        /// `[role, stamp]` pairs in the order seen (a stamp is `CLOCK_MONOTONIC` ns or "gone-before").
        /// Nothing here is asserted; the analyser refuses a run with a missing or repeated role.
        pub(super) async fn report(self, path: Path, total: Duration, signalled_mono_ns: u128) {
            let out = tokio::time::timeout(STOP_BOUND, self.watcher.wait_with_output())
                .await
                .expect("the exit watcher ended")
                .expect("the exit watcher's output");
            let exits: Vec<(String, String)> = String::from_utf8_lossy(&out.stdout)
                .lines()
                .filter_map(|line| line.split_once(' '))
                .map(|(pid, stamp)| {
                    let role = pid
                        .parse::<u32>()
                        .ok()
                        .and_then(|seen| self.roles.iter().find(|(_, known)| *known == seen))
                        .map_or_else(|| format!("unknown:{pid}"), |(role, _)| role.clone());
                    (role, stamp.to_owned())
                })
                .collect();
            let path = match path {
                Path::Normal => "normal",
                Path::Hurried => "hurried",
            };
            eprintln!(
                "MEASURE {}",
                json!({
                    "signalled_mono_ns": signalled_mono_ns.to_string(),
                    "total_ms": total.as_millis().to_string(),
                    "path": path,
                    "exits": exits,
                })
            );
        }
    }

    /// `CLOCK_MONOTONIC` now, in ns: the clock the watcher's `time.monotonic_ns()` reads and the
    /// stop's own deadlines run on.
    pub(super) fn now_ns() -> u128 {
        let now = rustix::time::clock_gettime(rustix::time::ClockId::Monotonic);
        u128::try_from(now.tv_sec).expect("a monotonic clock past zero") * 1_000_000_000
            + u128::try_from(now.tv_nsec).expect("nanoseconds in range")
    }
}

/// `kill -<sig> <pid>`, best effort: a pid that has already gone is the
/// row's own business to judge.
fn send(pid: u32, sig: &str) {
    let _ = std::process::Command::new("kill")
        .args([format!("-{sig}"), pid.to_string()])
        .status();
}

/// Freezes `inner` before the outer's stop starts, so it has sent nothing when that stop
/// begins: SIGSTOP, then its state read until stopped (within 10 s), then every one of its
/// `descendants` checked still alive. It is never continued; if the row fails, `KillGroup`
/// kills it (SIGKILL reaches a stopped process).
async fn freeze_before_the_stop(root: &Path, inner: u32, descendants: &[u32]) {
    send(inner, "STOP");
    // A bound for a failure only: a stopped process reads `T` at once.
    let stopped_by = Instant::now() + Duration::from_secs(10);
    while !pids::stopped(inner) {
        assert!(
            Instant::now() < stopped_by,
            "the inner never stopped\n{}",
            logs(root)
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let gone: Vec<u32> = descendants
        .iter()
        .copied()
        .filter(|pid| !pids::alive(*pid))
        .collect();
    assert!(
        gone.is_empty(),
        "the inner's descendants {gone:?} were gone before the outer's stop began\n{}",
        logs(root)
    );
}

fn alive_pids(pids: &[u32]) -> Vec<u32> {
    pids.iter()
        .copied()
        .filter(|pid| pids::alive(*pid))
        .collect()
}

/// Sends the SIGTERM, with `sent` taken just before it and nothing between, and waits until
/// every pid of the chain is gone, within `STOP_BOUND`. Returns when the signal went and when the
/// chain was gone; each row bounds that span against its own stop total.
async fn stop_and_wait_chain_gone(root: &Path, pid: u32, leaves: &[u32]) -> (Instant, Instant) {
    let deadline = Instant::now() + STOP_BOUND;
    let sent = Instant::now();
    sigterm(pid);
    while leaves.iter().any(|pid| pids::alive(*pid)) {
        assert!(
            Instant::now() < deadline,
            "inner or leaf outlived parent stop budget: {:?}\n{}",
            alive_pids(leaves),
            logs(root)
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    (sent, Instant::now())
}

/// A plain stop of the chain: when the SIGTERM went, when the last pid was gone, when the
/// outer gateway's process exited, and both gateways' logs as they stood then (the temp
/// root goes with `run`).
struct Stopped {
    sent: Instant,
    gone_at: Instant,
    exited_at: Instant,
    logs: String,
}

async fn run(total: Duration, inner_stop: Duration, leaves: &[&str]) -> Stopped {
    run_with(total, inner_stop, leaves, During::Nothing).await
}

#[allow(
    clippy::too_many_lines,
    reason = "one chain's start, stop and checks, with the freeze and the watch at their places in it"
)]
async fn run_with(
    total: Duration,
    inner_stop: Duration,
    leaves: &[&str],
    during: During,
) -> Stopped {
    let temp = tempfile::tempdir().expect("temp root");
    let root = temp.path().to_path_buf();
    let root = root.as_path();
    let inner = write_inner_config(root, leaves, inner_stop);
    let config = write_outer_config(root, &inner, total, during);
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
    let roles = chain_roles(root, leaves);
    let leaves: Vec<u32> = roles.iter().map(|(_, pid)| *pid).collect();
    assert!(calls.try_join_next().is_none(), "hold returned before stop");
    assert!(
        leaves.iter().all(|pid| pids::alive(*pid)),
        "inner and leaves must be live at stop"
    );
    if matches!(during, During::Freeze) {
        // The pid list starts with the inner gateway's (inner.pid, above).
        freeze_before_the_stop(root, leaves[0], &leaves[1..]).await;
    }
    let deadline = Instant::now() + STOP_BOUND;
    #[cfg(target_os = "linux")]
    let watch = matches!(during, During::Watch).then(|| measure::Watch::start(&roles));
    // On the watcher's clock, taken just before the SIGTERM.
    #[cfg(target_os = "linux")]
    let signalled_mono_ns = measure::now_ns();
    let (sent, gone_at) = stop_and_wait_chain_gone(root, pid, &leaves).await;
    #[cfg(target_os = "linux")]
    if let Some(watch) = watch {
        watch
            .report(measure::Path::Normal, total, signalled_mono_ns)
            .await;
    }
    let logs_then = logs(root);
    tokio::time::timeout_at(deadline, reaped.child_mut().wait())
        .await
        .unwrap_or_else(|_| panic!("gateway exit deadline\n{}", logs(root)))
        .expect("gateway exit");
    let stopped = Stopped {
        sent,
        gone_at,
        exited_at: Instant::now(),
        logs: logs_then,
    };
    // Safety net only: the gateway has already exited, so this sends no signal.
    reaped.reap().await;
    std::mem::forget(cleanup);
    drop(stdin);
    stopped
}

/// The parent stop total of the 30 s row.
const PARENT_30S: Duration = Duration::from_secs(30);

/// A busy inner stops its leaf within the minimum parent budget plus slack.
/// Red if the inner or its leaf group outlives the outer's stop (removing the group kill fails it).
#[tokio::test]
async fn a_busy_nested_gateway_stops_its_leaf_before_the_outer_kills_it() {
    // The row runs at the floor the binary states; a constant keeps the windows
    // below readable to the timing check, and this pin keeps it from going stale.
    assert_eq!(
        fixtures::http_floor_from_binary().await,
        HTTP_MINIMUM,
        "the binary's HTTP stop floor moved: HTTP_MINIMUM must follow it"
    );
    let stop = run(HTTP_MINIMUM, Duration::from_secs(8), &["leaf"]).await;
    let gone = stop.gone_at.duration_since(stop.sent);
    // Every recorded pid of the tree (inner, leaf, the leaf's own child) must
    // be gone before a supervisor's kill one second past the total, which
    // would end the outer gateway alone and orphan the rest. The poll can
    // only see the end late, so a pass is never early.
    // timing-oracle: vs EXTERNAL_KILL_AFTER (why: the kill a supervisor sends past the total reaches the outer gateway only)
    assert!(
        gone <= HTTP_MINIMUM + EXTERNAL_KILL_AFTER,
        "the chain outlived an external kill at the total plus {EXTERNAL_KILL_AFTER:?}: \
         {gone:?} against a {HTTP_MINIMUM:?} total\n{}",
        stop.logs
    );
    // P4 (RETIRE.4): a full-budget stop, measured to the outer process's exit, ends inside
    // its total: every stage ended in its share, so the exit lands by D + 200 ms.
    let exited = stop.exited_at.duration_since(stop.sent);
    // timing-oracle: vs SHUTDOWN_TIMEOUT (why: the process exits inside the stop total, short of the watchdog's slack)
    assert!(
        exited <= HTTP_MINIMUM + Duration::from_millis(200),
        "the gateway exited {exited:?} after its SIGTERM, past its {HTTP_MINIMUM:?} total\n{}",
        stop.logs
    );
}
/// One measured stop of the chain at the floor, for sizing the nested margin:
/// its timeline goes out as a MEASURE line (each role's exit from a pidfd
/// watcher and the SIGTERM's instant, both `CLOCK_MONOTONIC`; the stop total; the
/// path). It asserts no timing; the margin harness runs it many times under load
/// and reads the lines.
#[cfg(target_os = "linux")]
#[ignore = "a measurement for the margin harness, not a CI row"]
#[tokio::test]
async fn measure_one_nested_stop_for_the_margin() {
    run_with(
        HTTP_MINIMUM,
        INNER_OUTLASTS_THE_PLAN,
        &["leaf"],
        During::Watch,
    )
    .await;
}

/// A nested gateway frozen before its parent's stop and for all of it (so past
/// its nested need) ends nothing by itself: SIGTERM waits on a stopped process,
/// only the parent's SIGKILL reaches it. The parent's descendant sweep then has
/// to end the leaf and the leaf's child: once the stop is over, no process of
/// the tree is left.
/// Red if the sweep stops killing what a killed backend leaves behind.
#[tokio::test]
async fn a_nested_gateway_frozen_past_its_need_still_leaves_no_leaf() {
    run_with(
        HTTP_MINIMUM,
        INNER_OUTLASTS_THE_PLAN,
        &["leaf"],
        During::Freeze,
    )
    .await;
}

/// The same ownership claim holds with a 30 s parent budget.
/// Red if the inner or its leaf group outlives the outer's stop (removing the group kill fails it).
#[tokio::test]
async fn a_busy_nested_gateway_stops_its_leaf_before_the_outer_kills_it_30s() {
    let stop = run(PARENT_30S, Duration::from_secs(8), &["leaf"]).await;
    let gone = stop.gone_at.duration_since(stop.sent);
    // timing-oracle: vs SHUTDOWN_TIMEOUT (why: the chain must be gone inside the stop total so the sweep adds no second stop)
    assert!(
        gone <= PARENT_30S + BUDGET_SLACK,
        "the chain outlived the stop budget: {gone:?} against {:?}\n{}",
        PARENT_30S + BUDGET_SLACK,
        stop.logs
    );
}
/// Both busy leaves stop within one minimum parent budget plus 15 s slack.
/// Red if the inner or its leaf group outlives the outer's stop (removing the group kill fails it).
#[tokio::test]
async fn a_busy_nested_gateway_stops_two_leaves_within_one_deadline() {
    let stop = run(HTTP_MINIMUM, Duration::from_secs(8), &["leaf_a", "leaf_b"]).await;
    let gone = stop.gone_at.duration_since(stop.sent);
    // timing-oracle: vs SHUTDOWN_TIMEOUT (why: the chain must be gone inside the stop total so the sweep adds no second stop)
    assert!(
        gone <= HTTP_MINIMUM + BUDGET_SLACK,
        "the chain outlived the stop budget: {gone:?} against {:?}\n{}",
        HTTP_MINIMUM + BUDGET_SLACK,
        stop.logs
    );
}

/// A nested gateway whose own stop outlasts its parent's plan leaves no leaf or grandchild alive.
/// Red if a stopping stdio gateway ignores its parent's SIGTERM and lets its leaves' waits run past its own kill.
#[tokio::test]
async fn a_nested_gateway_whose_own_stop_outlasts_its_parents_plan_leaves_no_leaf() {
    let stop = run(HTTP_MINIMUM, Duration::from_secs(30), &["leaf_a", "leaf_b"]).await;
    let gone = stop.gone_at.duration_since(stop.sent);
    // timing-oracle: vs SHUTDOWN_TIMEOUT (why: the chain must be gone inside the stop total so the sweep adds no second stop)
    assert!(
        gone <= HTTP_MINIMUM + BUDGET_SLACK,
        "the chain outlived the stop budget: {gone:?} against {:?}\n{}",
        HTTP_MINIMUM + BUDGET_SLACK,
        stop.logs
    );
}

// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Heartbeat rows that need the task, child processes, a server start or a
//! source scan (test plan: O1, D8, D10-D12, F7-F10, W1-W3). The core
//! rows and the shared fixtures are in `heartbeat_tests.rs`.

use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use chrono::NaiveDate;

use super::tests::{Answer, Listener, is_install_id, nov19, read_id, release, test_client};
use super::*;

/// Wait up to 30 s of real time for `done`.
async fn until(what: &str, done: impl Fn() -> bool) {
    let r = crate::test_wait::wait_real_time(Duration::from_secs(30), done).await;
    assert!(r.is_ok(), "{what} did not happen within 30 s");
}

/// The day F9's clock reports, moved by the row.
static F9_DAY: AtomicU32 = AtomicU32::new(19);
fn f9_today() -> Option<NaiveDate> {
    NaiveDate::from_ymd_opt(2026, 11, F9_DAY.load(Ordering::SeqCst))
}

/// F9. The task checks at start, sends nothing more the same day however
/// often it ticks, sends again once the UTC day changes, and ends on
/// shutdown.
#[tokio::test]
async fn the_task_checks_at_start_and_after_a_day_and_ends_on_shutdown() {
    let rx = Listener::start(Answer::NoContent).await;
    let dir = tempfile::tempdir().expect("dir");
    F9_DAY.store(19, Ordering::SeqCst);
    let _guard = seam::register(
        dir.path(),
        seam::Target {
            url: rx.url(),
            client: test_client(),
            today: f9_today,
            every: Duration::from_millis(50),
            stall: None,
        },
    );
    let (stop, _) = tokio::sync::broadcast::channel(1);
    let task = start(
        SecurityPosture::Standard,
        dir.path().to_path_buf(),
        stop.subscribe(),
    );
    until("the start check", || rx.connections() == 1).await;
    tokio::time::sleep(Duration::from_millis(400)).await;
    assert_eq!(rx.connections(), 1, "a second send on the same day");
    F9_DAY.store(20, Ordering::SeqCst);
    until("the next day's send", || rx.connections() == 2).await;
    let _ = stop.send(());
    let ended = tokio::time::timeout(Duration::from_secs(5), task).await;
    assert!(ended.is_ok(), "the task did not end on shutdown");
}

/// F10. Shutdown does not wait for a stalled disk: the check's filesystem
/// thread is held before its first call, and the task still ends at once.
#[tokio::test]
async fn shutdown_does_not_wait_for_a_stalled_disk() {
    let rx = Listener::start(Answer::NoContent).await;
    let dir = tempfile::tempdir().expect("dir");
    let (_hold, stall) = std::sync::mpsc::channel::<()>();
    let _guard = seam::register(
        dir.path(),
        seam::Target {
            url: rx.url(),
            client: test_client(),
            today: nov19,
            every: Duration::from_millis(50),
            stall: Some(stall),
        },
    );
    let (stop, _) = tokio::sync::broadcast::channel(1);
    let task = start(
        SecurityPosture::Standard,
        dir.path().to_path_buf(),
        stop.subscribe(),
    );
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(rx.connections(), 0, "the stalled check sent");
    let _ = stop.send(());
    let ended = tokio::time::timeout(Duration::from_secs(2), task).await;
    assert!(
        ended.is_ok(),
        "shutdown waited for the stalled filesystem thread"
    );
}

/// The name a child runs, for O1.
const ONE_CHECK_CHILD: &str = "heartbeat::wiring_tests::child_runs_one_check";

/// O1's child: waits for the start file, runs one check against the
/// parent's listener, and prints its outcome and the id it read.
#[tokio::test]
#[ignore = "run only as a child of children_share_one_send_per_day"]
async fn child_runs_one_check() {
    let dir = std::path::PathBuf::from(std::env::var_os("HB_CHILD_DIR").expect("HB_CHILD_DIR"));
    let url = std::env::var("HB_CHILD_URL").expect("HB_CHILD_URL");
    let go = std::path::PathBuf::from(std::env::var_os("HB_CHILD_GO").expect("HB_CHILD_GO"));
    until("the start file", || go.exists()).await;
    let out = heartbeat_once(&release(), &dir, &test_client(), &url, nov19).await;
    let id = std::fs::read_to_string(dir.join("heartbeat").join("install-id")).unwrap_or_default();
    println!("OUTCOME={out:?} ID={id}");
}

/// O1. Four processes released together on one data dir: exactly one
/// connection, one `Sent`, and every child read the same id.
#[tokio::test]
async fn children_share_one_send_per_day() {
    let rx = Listener::start(Answer::NoContent).await;
    let dir = tempfile::tempdir().expect("dir");
    let go = dir.path().join("go");
    let children: Vec<_> = (0..4)
        .map(|_| {
            let mut cmd = tokio::process::Command::from(crate::test_home::test_binary());
            cmd.args([
                "--exact",
                ONE_CHECK_CHILD,
                "--ignored",
                "--nocapture",
                "--test-threads=1",
            ])
            .env("HB_CHILD_DIR", dir.path())
            .env("HB_CHILD_URL", rx.url())
            .env("HB_CHILD_GO", &go)
            .stdout(std::process::Stdio::piped())
            .kill_on_drop(true);
            cmd.spawn().expect("a child")
        })
        .collect();
    std::fs::write(&go, b"").expect("start");
    let mut lines = Vec::new();
    for child in children {
        let out = tokio::time::timeout(Duration::from_secs(60), child.wait_with_output())
            .await
            .expect("a child finished")
            .expect("a child ran");
        let text = String::from_utf8_lossy(&out.stdout).into_owned();
        lines.push(
            text.lines()
                .find(|l| l.starts_with("OUTCOME="))
                .map(str::to_owned)
                .unwrap_or_default(),
        );
    }
    assert_eq!(
        lines
            .iter()
            .filter(|l| l.starts_with("OUTCOME=Sent "))
            .count(),
        1,
        "{lines:?}"
    );
    assert_eq!(rx.connections(), 1);
    let id = read_id(dir.path());
    assert!(is_install_id(&id));
    assert!(
        lines.iter().all(|l| l.ends_with(&format!("ID={id}"))),
        "children read different ids: {lines:?}"
    );
}

/// The name a child runs, for D8.
const SNAPSHOT_CHILD: &str = "heartbeat::wiring_tests::child_prints_its_snapshot";

/// D8's child: prints the variable names its own snapshot read.
#[test]
#[ignore = "run only as a child of the_reader_reads_each_variable"]
fn child_prints_its_snapshot() {
    let snapshot = Snapshot::from_process(SecurityPosture::Standard);
    let names: Vec<&str> = snapshot.env.keys().map(String::as_str).collect();
    println!("READ={}", names.join(","));
}

/// D8. The production reader reads each switch variable by its exact name:
/// a child with every switch removed and exactly one set reports that one.
#[test]
fn the_reader_reads_each_variable() {
    let all: Vec<&str> = OPT_OUT
        .iter()
        .chain(CI.iter())
        .chain(PROXY.iter())
        .copied()
        .collect();
    let written = [
        "DO_NOT_TRACK",
        "NO_TELEMETRY",
        "CI",
        "GITHUB_ACTIONS",
        "TF_BUILD",
        "BUDDY",
        "HTTPS_PROXY",
        "all_proxy",
    ];
    for name in written {
        let mut cmd = crate::test_home::test_binary();
        cmd.args([
            "--exact",
            SNAPSHOT_CHILD,
            "--ignored",
            "--nocapture",
            "--test-threads=1",
        ]);
        for other in &all {
            cmd.env_remove(other);
        }
        cmd.env(name, "1");
        let out = cmd.output().expect("child");
        let text = String::from_utf8_lossy(&out.stdout).into_owned();
        let read = text
            .lines()
            .find_map(|l| l.strip_prefix("READ="))
            .unwrap_or("<none>")
            .to_owned();
        assert_eq!(read, name, "with only {name} set the reader read {read:?}");
    }
}

/// A target for `dir`: the listener, the test client, the 19th, fast ticks.
fn target_for(rx: &Listener) -> seam::Target {
    seam::Target {
        url: rx.url(),
        client: test_client(),
        today: nov19,
        every: Duration::from_millis(50),
        stall: None,
    }
}

/// Run the HTTP gateway on `dir` with `posture`, GET `/health` once it is
/// bound, then shut it down. Returns the health status and how long it took.
async fn http_start(dir: &std::path::Path, posture: SecurityPosture) -> (u16, Duration) {
    let mut config = crate::config::Config::default();
    config.server.host = "127.0.0.1".to_string();
    config.server.port = 0;
    config.tasks.store_dir = dir.join("tasks").to_string_lossy().into_owned();
    config.security.posture = posture;
    let mut gateway = crate::gateway::Gateway::new(config)
        .await
        .expect("a gateway")
        .with_data_dir(dir.to_path_buf());
    let bound = gateway.bound_port_for_test();
    let trigger = gateway.shutdown_trigger_for_test();
    let server = tokio::spawn(async move { Box::pin(gateway.run()).await });
    let port = tokio::time::timeout(Duration::from_secs(60), bound)
        .await
        .expect("bound within a minute")
        .expect("the bound port");
    let started = std::time::Instant::now();
    let status = reqwest::Client::new()
        .get(format!("http://127.0.0.1:{port}/health"))
        .send()
        .await
        .map(|r| r.status().as_u16())
        .unwrap_or(0);
    let took = started.elapsed();
    tokio::time::sleep(Duration::from_millis(300)).await;
    trigger.send(()).expect("run holds the trigger");
    let _ = tokio::time::timeout(Duration::from_secs(30), server).await;
    (status, took)
}

/// W1 + F7. A hardened HTTP gateway opens no connection to the receiver and
/// creates no heartbeat state. Control: the standard posture, against a
/// receiver that never answers, connects once and still answers `/health`
/// at once.
#[tokio::test]
async fn http_start_hardened_sends_nothing() {
    let rx = Listener::start(Answer::NoContent).await;
    let dir = tempfile::tempdir().expect("dir");
    let _guard = seam::register(dir.path(), target_for(&rx));
    let (status, _) = http_start(dir.path(), SecurityPosture::Hardened).await;
    assert_eq!(status, 200);
    assert_eq!(rx.connections(), 0, "a hardened start sent");
    assert!(
        !dir.path().join("heartbeat").exists(),
        "a hardened start created state"
    );

    let hang = Listener::start(Answer::Never).await;
    let control = tempfile::tempdir().expect("dir");
    let _control_guard = seam::register(control.path(), target_for(&hang));
    let (status, took) = http_start(control.path(), SecurityPosture::Standard).await;
    assert_eq!(status, 200);
    assert!(
        took < Duration::from_secs(2),
        "health waited on the heartbeat: {took:?}"
    );
    assert_eq!(
        hang.connections(),
        1,
        "control: the standard start did not send"
    );
}

/// Start the stdio gateway on `dir` with `posture`, send `ping`, and return
/// whether it answered within the bound. The server is dropped afterwards.
async fn stdio_start(dir: &std::path::Path, posture: SecurityPosture) -> bool {
    use tokio::io::{AsyncBufReadExt as _, AsyncWriteExt as _};
    let mut config = crate::config::Config::default();
    config.security.posture = posture;
    let gateway = crate::gateway::Gateway::new(config)
        .await
        .expect("a gateway")
        .with_data_dir(dir.to_path_buf());
    let (mut client, input) = tokio::io::duplex(64 * 1024);
    let (output, reader) = tokio::io::duplex(1 << 20);
    let task = tokio::spawn(async move { drop(gateway.run_stdio_on(input, output, None).await) });
    let ping = b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"ping\"}\n";
    client.write_all(ping).await.expect("write");
    let mut lines = tokio::io::BufReader::new(reader).lines();
    let answered = tokio::time::timeout(Duration::from_secs(2), lines.next_line())
        .await
        .is_ok_and(|l| l.is_ok_and(|l| l.is_some()));
    tokio::time::sleep(Duration::from_millis(300)).await;
    task.abort();
    answered
}

/// W2 + F8. A hardened stdio gateway opens no connection and creates no
/// state. Control: the standard posture, against a receiver that never
/// answers, connects once and still answers `ping` at once.
#[tokio::test]
async fn stdio_start_hardened_sends_nothing() {
    let rx = Listener::start(Answer::NoContent).await;
    let dir = tempfile::tempdir().expect("dir");
    let _guard = seam::register(dir.path(), target_for(&rx));
    assert!(
        stdio_start(dir.path(), SecurityPosture::Hardened).await,
        "no answer to ping"
    );
    assert_eq!(rx.connections(), 0, "a hardened stdio start sent");
    assert!(!dir.path().join("heartbeat").exists());

    let hang = Listener::start(Answer::Never).await;
    let control = tempfile::tempdir().expect("dir");
    let _control_guard = seam::register(control.path(), target_for(&hang));
    assert!(
        stdio_start(control.path(), SecurityPosture::Standard).await,
        "ping waited on the heartbeat"
    );
    assert_eq!(
        hang.connections(),
        1,
        "control: the standard stdio start did not send"
    );
}

/// Every `.rs` file under `dir`, as (path relative to the crate, text).
fn rust_files(dir: &std::path::Path) -> Vec<(String, String)> {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut out = Vec::new();
    let mut todo = vec![dir.to_path_buf()];
    while let Some(d) = todo.pop() {
        for entry in std::fs::read_dir(&d).expect("readable dir").flatten() {
            let p = entry.path();
            if p.is_dir() {
                todo.push(p);
            } else if p.extension().is_some_and(|e| e == "rs") {
                let rel = p
                    .strip_prefix(root)
                    .expect("under the crate")
                    .to_string_lossy()
                    .replace('\\', "/");
                out.push((rel, std::fs::read_to_string(&p).expect("readable")));
            }
        }
    }
    out.sort();
    out
}

/// The production files that call `heartbeat::start(`.
fn start_callers(files: &[(String, String)]) -> Vec<String> {
    files
        .iter()
        .filter(|(_, text)| {
            crate::test_source_text::production_text(text).contains("heartbeat::start(")
        })
        .map(|(path, _)| path.clone())
        .collect()
}

/// D10. `heartbeat::start` is called from exactly the two server starts and
/// nowhere else (no CLI command); a planted CLI caller fails by name.
#[test]
fn start_is_called_only_from_the_two_servers() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let files = rust_files(&root.join("src"));
    assert_eq!(
        start_callers(&files),
        [
            "src/gateway/server/run.rs",
            "src/gateway/server/stdio_loop.rs"
        ],
    );
    let mut planted = files;
    planted.push((
        "src/commands/planted.rs".to_owned(),
        "fn planted() { crate::heartbeat::start(p, d, s); }".to_owned(),
    ));
    assert!(start_callers(&planted).contains(&"src/commands/planted.rs".to_owned()));
}

/// W3. The production start reaches the receiver through
/// `production_client()` and the `URL` constant, never the test builder.
#[test]
fn production_start_uses_the_production_client_and_url() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let text = std::fs::read_to_string(root.join("src/heartbeat.rs")).expect("heartbeat.rs");
    let production = crate::test_source_text::production_text(&text);
    let start = production.find("pub(crate) fn start(").expect("start");
    let body = &production[start..];
    let body = &body[..body.find("\n}\n").expect("the end of start")];
    assert!(
        body.contains("production_client()"),
        "start does not use production_client()"
    );
    assert!(body.contains("URL"), "start does not use the URL constant");
    assert!(
        !body.contains("base_builder()"),
        "start uses the test builder directly"
    );
}

/// The functions in `text` whose body builds a gateway command but never
/// sets `DO_NOT_TRACK` (a lexical split at each `fn `: a nested fn ends the
/// outer chunk early, which can only flag more, never less).
fn helpers_without_dnt(text: &str) -> Vec<String> {
    let starts: Vec<usize> = text
        .match_indices("fn ")
        .map(|(i, _)| i)
        .filter(|&i| i == 0 || text[..i].ends_with(char::is_whitespace))
        .collect();
    let mut out = Vec::new();
    for (k, &s) in starts.iter().enumerate() {
        let chunk = &text[s..starts.get(k + 1).copied().unwrap_or(text.len())];
        let name: String = chunk[3..]
            .chars()
            .take_while(|c| c.is_alphanumeric() || *c == '_')
            .collect();
        if chunk.contains("CARGO_BIN_EXE_mcp-gateway") && !chunk.contains("DO_NOT_TRACK") {
            out.push(name);
        }
    }
    out
}

/// D11. Each test helper that builds a gateway command sets
/// `DO_NOT_TRACK=1` on it; a planted helper without it fails by name.
#[test]
fn each_gateway_helper_sets_dnt() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut missing = Vec::new();
    for (path, text) in rust_files(&root.join("tests/common")) {
        for name in helpers_without_dnt(&text) {
            missing.push(format!("{path}::{name}"));
        }
    }
    assert!(
        missing.is_empty(),
        "gateway helpers without DO_NOT_TRACK: {missing:?}"
    );
    let planted = r#"fn planted() -> Command { Command::new(env!("CARGO_BIN_EXE_mcp-gateway")) }"#;
    assert_eq!(helpers_without_dnt(planted), ["planted"]);
}

/// The launch commands that start a container or pod.
const LAUNCHERS: [&str; 8] = [
    "docker run",
    "podman run",
    "docker compose up",
    "docker compose run",
    "kubectl run",
    "kubectl apply",
    "helm install",
    "helm upgrade",
];

/// The launches in `text` (continued lines joined) that start the gateway
/// image or chart without `DO_NOT_TRACK=1` on that launch.
fn launches_without_dnt(text: &str) -> Vec<String> {
    let joined = text.replace("\\\r\n", " ").replace("\\\n", " ");
    joined
        .lines()
        .filter(|l| LAUNCHERS.iter().any(|c| l.contains(c)))
        .filter(|l| l.contains("mcp-gateway"))
        .filter(|l| !l.contains("DO_NOT_TRACK=1"))
        .map(|l| l.trim().to_owned())
        .collect()
}

/// Every shell script under `scripts/` and every workflow, as (path, text).
fn launch_sources() -> Vec<(String, String)> {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut out = Vec::new();
    let mut todo = vec![root.join("scripts"), root.join(".github").join("workflows")];
    while let Some(d) = todo.pop() {
        for entry in std::fs::read_dir(&d).into_iter().flatten().flatten() {
            let p = entry.path();
            if p.is_dir() {
                todo.push(p);
            } else if p
                .extension()
                .is_some_and(|e| e == "sh" || e == "yml" || e == "yaml")
            {
                if let Ok(text) = std::fs::read_to_string(&p) {
                    out.push((
                        p.strip_prefix(root)
                            .expect("under the crate")
                            .to_string_lossy()
                            .into_owned(),
                        text,
                    ));
                }
            }
        }
    }
    out
}

/// D12. Every launch of the gateway image or chart in our scripts and
/// workflows passes `DO_NOT_TRACK=1` on that launch itself; one planted
/// launch per form, without it, fails.
#[test]
fn every_image_launch_sets_dnt() {
    let mut missing = Vec::new();
    for (path, text) in launch_sources() {
        for launch in launches_without_dnt(&text) {
            missing.push(format!("{path}: {launch}"));
        }
    }
    assert!(
        missing.is_empty(),
        "launches without DO_NOT_TRACK=1: {missing:?}"
    );
    for launcher in LAUNCHERS {
        let planted = format!("{launcher} \\\n  ghcr.io/mikkoparkkola/mcp-gateway:test\n");
        assert_eq!(
            launches_without_dnt(&planted).len(),
            1,
            "planted {launcher} was not caught"
        );
        let kept =
            format!("{launcher} -e DO_NOT_TRACK=1 \\\n  ghcr.io/mikkoparkkola/mcp-gateway:test\n");
        assert!(
            launches_without_dnt(&kept).is_empty(),
            "{launcher} with the variable was refused"
        );
    }
}

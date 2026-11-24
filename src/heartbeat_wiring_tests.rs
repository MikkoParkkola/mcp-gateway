// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Heartbeat rows that need the task, child processes, a server start or a
//! source scan (test plan: O1, D8, D10-D12, F7-F10, W1-W3). The core
//! rows and the shared fixtures are in `heartbeat_tests.rs`.

use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use chrono::NaiveDate;

use std::collections::BTreeSet;

use super::fixtures::{
    Answer, CI_NAMES, Listener, PROXY_NAMES, is_install_id, nov19, read_id, release, test_client,
};
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
            // limit-under-test (absorbed-by: until): only the task's check period; a slow runner checks less often before until's bound
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
    // Two more checks finished on the same day (events, not a wait).
    until("two more checks on the 19th", || {
        seam::outcomes(dir.path()).len() >= 3
    })
    .await;
    assert_eq!(rx.connections(), 1, "a second send on the same day");
    assert_eq!(
        seam::outcomes(dir.path())[..3],
        [Outcome::Sent, Outcome::NoClaim, Outcome::NoClaim]
    );
    F9_DAY.store(20, Ordering::SeqCst);
    until("the next day's send", || rx.connections() == 2).await;
    let _ = stop.send(());
    let ended = tokio::time::timeout(Duration::from_secs(5), task).await;
    assert!(
        matches!(ended, Ok(Ok(()))),
        "the task did not end on shutdown"
    );
}

/// F10. Shutdown does not wait for a stalled disk: the check's filesystem
/// thread is held before its first call, and the task still ends at once.
#[tokio::test]
async fn shutdown_does_not_wait_for_a_stalled_disk() {
    let rx = Listener::start(Answer::NoContent).await;
    let dir = tempfile::tempdir().expect("dir");
    let (reached_tx, reached) = std::sync::mpsc::channel::<()>();
    let (release, release_rx) = std::sync::mpsc::channel::<()>();
    let (done_tx, done) = std::sync::mpsc::channel::<()>();
    let _guard = seam::register(
        dir.path(),
        seam::Target {
            url: rx.url(),
            client: test_client(),
            today: nov19,
            // limit-under-test (absorbed-by: until): only the task's check period; a slow runner checks less often before until's bound
            every: Duration::from_millis(50),
            stall: Some(seam::Stall {
                reached: reached_tx,
                release: release_rx,
                done: done_tx,
            }),
        },
    );
    let (stop, _) = tokio::sync::broadcast::channel(1);
    let task = start(
        SecurityPosture::Standard,
        dir.path().to_path_buf(),
        stop.subscribe(),
    );
    // The check really started and is held at its first filesystem call
    // (tp-r1: without this the do-nothing stub passed).
    let at_stall =
        tokio::task::spawn_blocking(move || reached.recv_timeout(Duration::from_secs(30)));
    assert!(
        at_stall.await.expect("join").is_ok(),
        "the check never reached its filesystem work"
    );
    let _ = stop.send(());
    let ended = tokio::time::timeout(Duration::from_secs(2), task).await;
    assert!(
        matches!(ended, Ok(Ok(()))),
        "shutdown waited for the stalled filesystem thread"
    );
    assert_eq!(rx.connections(), 0, "the stalled check sent");
    // Let the thread finish before its temp dir goes, so nothing writes later.
    let _ = release.send(());
    let finished = tokio::task::spawn_blocking(move || done.recv_timeout(Duration::from_secs(30)));
    assert!(
        finished.await.expect("join").is_ok(),
        "the filesystem thread never finished"
    );
}

/// The name a child runs, for O1.
const ONE_CHECK_CHILD: &str = "heartbeat::wiring_tests::child_runs_one_check";

/// The value after `key` anywhere in `text` (libtest may print `test <name>
/// ... ` before a child's own line), up to the end of that line.
pub(super) fn marker<'a>(text: &'a str, key: &str) -> Option<&'a str> {
    text.lines()
        .find_map(|l| l.find(key).map(|at| l[at + key.len()..].trim_end()))
}

/// O1's child: announces it is ready, waits for the start file, runs one
/// check against the parent's listener, and prints its outcome and id.
#[tokio::test]
#[ignore = "run only as a child of children_share_one_send_per_day"]
async fn child_runs_one_check() {
    let dir = std::path::PathBuf::from(std::env::var_os("HB_CHILD_DIR").expect("HB_CHILD_DIR"));
    let url = std::env::var("HB_CHILD_URL").expect("HB_CHILD_URL");
    let go = std::path::PathBuf::from(std::env::var_os("HB_CHILD_GO").expect("HB_CHILD_GO"));
    let ready =
        std::path::PathBuf::from(std::env::var_os("HB_CHILD_READY").expect("HB_CHILD_READY"));
    std::fs::write(&ready, b"").expect("ready");
    until("the start file", || go.exists()).await;
    let out = heartbeat_once(&release(), &dir, &test_client(), &url, nov19).await;
    let id = std::fs::read_to_string(dir.join("heartbeat").join("install-id")).unwrap_or_default();
    println!("HBOUT={out:?} HBID={id}");
}

/// O1. Four processes, all ready, released together on one data dir: exactly
/// one request, one `Sent`, every other child `NoClaim`, every child exits 0
/// and read the same id.
#[tokio::test]
async fn children_share_one_send_per_day() {
    let rx = Listener::start(Answer::NoContent).await;
    let dir = tempfile::tempdir().expect("dir");
    let go = dir.path().join("go");
    let readies: Vec<_> = (0..4)
        .map(|i| dir.path().join(format!("ready-{i}")))
        .collect();
    let children: Vec<_> = readies
        .iter()
        .map(|ready| {
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
            .env("HB_CHILD_READY", ready)
            .stdout(std::process::Stdio::piped())
            .kill_on_drop(true);
            cmd.spawn().expect("a child")
        })
        .collect();
    until("every child ready", || readies.iter().all(|r| r.exists())).await;
    std::fs::write(&go, b"").expect("start");
    let mut seen = Vec::new();
    for child in children {
        let out = tokio::time::timeout(Duration::from_secs(60), child.wait_with_output())
            .await
            .expect("a child finished")
            .expect("a child ran");
        assert!(out.status.success(), "a child failed: {out:?}");
        let text = String::from_utf8_lossy(&out.stdout).into_owned();
        let outcome = marker(&text, "HBOUT=")
            .and_then(|v| v.split(' ').next())
            .unwrap_or("")
            .to_owned();
        let id = marker(&text, "HBID=").unwrap_or("").to_owned();
        seen.push((outcome, id));
    }
    assert_eq!(
        seen.iter().filter(|(o, _)| o == "Sent").count(),
        1,
        "{seen:?}"
    );
    assert!(
        seen.iter().all(|(o, _)| o == "Sent" || o == "NoClaim"),
        "{seen:?}"
    );
    assert_eq!(rx.requests().len(), 1);
    let id = read_id(dir.path());
    assert!(is_install_id(&id));
    assert!(
        seen.iter().all(|(_, i)| *i == id),
        "children read different ids: {seen:?}"
    );
}

/// The name a child runs, for D8.
const SNAPSHOT_CHILD: &str = "heartbeat::wiring_tests::child_prints_its_snapshot";

/// D8's child: prints each variable its own snapshot read, with its value.
#[test]
#[ignore = "run only as a child of the_reader_reads_each_variable"]
fn child_prints_its_snapshot() {
    let snapshot = Snapshot::from_process(SecurityPosture::Standard);
    let read: Vec<String> = snapshot
        .env
        .iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect();
    println!("HBREAD=[{}]", read.join(","));
}

/// Run D8's child with every switch removed and `set` added; what it read.
fn read_by_child(all: &[&str], set: &[(&str, &str)]) -> BTreeSet<String> {
    let mut cmd = crate::test_home::test_binary();
    cmd.args([
        "--exact",
        SNAPSHOT_CHILD,
        "--ignored",
        "--nocapture",
        "--test-threads=1",
    ]);
    for name in all {
        cmd.env_remove(name);
    }
    for (name, value) in set {
        cmd.env(name, value);
    }
    cmd.stdout(std::process::Stdio::piped());
    let mut child = cmd.spawn().expect("child");
    let deadline = std::time::Instant::now() + Duration::from_secs(60);
    while child.try_wait().expect("wait").is_none() {
        if std::time::Instant::now() > deadline {
            let _ = child.kill();
            panic!("the reader child ran past 60 s");
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    let out = child.wait_with_output().expect("output");
    assert!(out.status.success(), "the reader child failed: {out:?}");
    let text = String::from_utf8_lossy(&out.stdout).into_owned();
    let list = marker(&text, "HBREAD=[").expect("the child printed its snapshot");
    let list = list.strip_suffix(']').unwrap_or(list);
    list.split(',')
        .filter(|e| !e.is_empty())
        .map(str::to_owned)
        .collect()
}

/// D8. The production reader reads every switch variable by its exact name
/// and value (all 26, from the rows' own literal lists): a child with every
/// switch removed reads nothing (control), and with exactly one set reads
/// that one. On Windows a proxy name and its other-case twin are one
/// variable, so both spellings may be reported, with the one value.
#[test]
fn the_reader_reads_each_variable() {
    let opt_out = ["DO_NOT_TRACK", "NO_TELEMETRY"];
    let all: Vec<&str> = opt_out
        .iter()
        .chain(CI_NAMES.iter())
        .chain(PROXY_NAMES.iter())
        .copied()
        .collect();
    assert_eq!(all.len(), 26);
    assert!(
        read_by_child(&all, &[]).is_empty(),
        "control: a cleared child read something"
    );
    for name in &all {
        let value = format!("v-{name}");
        let read = read_by_child(&all, &[(name, &value)]);
        let mut want = BTreeSet::from([format!("{name}={value}")]);
        if cfg!(windows) && PROXY_NAMES.contains(name) {
            let twin = PROXY_NAMES
                .iter()
                .find(|n| *n != name && n.eq_ignore_ascii_case(name))
                .expect("a twin");
            if read.contains(&format!("{twin}={value}")) {
                want.insert(format!("{twin}={value}"));
            }
        }
        assert_eq!(read, want, "with only {name} set");
    }
}

/// The name a child runs, for P3.
const PLANTED_CHILD: &str = "heartbeat::wiring_tests::child_sends_with_planted_env";

/// P3's child: one check whose snapshot reads the child's real environment.
#[tokio::test]
#[ignore = "run only as a child of planted_host_and_config_never_reach_the_request"]
async fn child_sends_with_planted_env() {
    let dir = std::path::PathBuf::from(std::env::var_os("HB_CHILD_DIR").expect("HB_CHILD_DIR"));
    let url = std::env::var("HB_CHILD_URL").expect("HB_CHILD_URL");
    let snapshot = Snapshot::read(Build::Release, SecurityPosture::Standard, |n| {
        std::env::var_os(n)
    });
    let out = heartbeat_once(&snapshot, &dir, &test_client(), &url, nov19).await;
    println!("HBOUT={out:?}");
}

/// P3. A host name, user name, config dir and backend name in the process's
/// real environment never reach the request, and the check still sends.
#[tokio::test]
async fn planted_host_and_config_never_reach_the_request() {
    let rx = Listener::start(Answer::NoContent).await;
    let dir = tempfile::tempdir().expect("dir");
    let planted = [
        ("HOSTNAME", "planted-host-7f3a"),
        ("COMPUTERNAME", "planted-host-7f3a"),
        ("USER", "planted-user-7f3a"),
        ("USERNAME", "planted-user-7f3a"),
        ("MCP_GATEWAY_BACKEND", "planted-backend-7f3a"),
    ];
    let mut cmd = tokio::process::Command::from(crate::test_home::test_binary());
    // Every switch cleared, so the child's own snapshot decides to send even
    // where this process runs under CI or a proxy (tp-r2).
    for name in ["DO_NOT_TRACK", "NO_TELEMETRY"]
        .iter()
        .chain(CI_NAMES.iter())
        .chain(PROXY_NAMES.iter())
    {
        cmd.env_remove(name);
    }
    cmd.args([
        "--exact",
        PLANTED_CHILD,
        "--ignored",
        "--nocapture",
        "--test-threads=1",
    ])
    .env("HB_CHILD_DIR", dir.path())
    .env("HB_CHILD_URL", rx.url())
    .envs(planted)
    .env(
        "MCP_GATEWAY_CONFIG_DIR",
        dir.path().join("planted-config-7f3a"),
    )
    .stdout(std::process::Stdio::piped())
    .kill_on_drop(true);
    let out = tokio::time::timeout(Duration::from_secs(60), cmd.output())
        .await
        .expect("the child finished")
        .expect("the child ran");
    assert!(out.status.success(), "{out:?}");
    let text = String::from_utf8_lossy(&out.stdout).into_owned();
    assert_eq!(marker(&text, "HBOUT="), Some("Sent"), "{text}");
    let seen = rx.requests();
    assert_eq!(seen.len(), 1);
    let whole = format!("{:?}", seen[0]);
    assert!(
        !whole.contains("7f3a"),
        "a planted value reached the request: {whole}"
    );
}

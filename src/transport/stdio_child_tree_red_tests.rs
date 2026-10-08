// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8080 red proof (throwaway, never merged): T1, T5 and D1 from
//! `stdio_child_tree_tests.rs`, using only today's API. Counter assertions
//! (`group_signals_sent`) are dropped: the field does not exist here.

use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use rustix::process::{Pid, WaitId, WaitIdOptions, waitid};

use super::{PROTOCOL_VERSION, StdioTransport};
use crate::transport::Transport;

const ROW_LIMIT: Duration = Duration::from_secs(5);

async fn started(after: &str) -> (tempfile::TempDir, Arc<StdioTransport>) {
    let workspace = tempfile::tempdir().expect("workspace");
    let script = r#"id_of() { printf '%s' "$1" | sed -n 's/.*"id":\([0-9][0-9]*\).*/\1/p'; }
echo $$ > leader.pid
read -r request
printf '{"jsonrpc":"2.0","id":%s,"result":{"protocolVersion":"PROTO","capabilities":{}}}\n' "$(id_of "$request")"
read -r initialized
AFTER
"#
    .replace("PROTO", PROTOCOL_VERSION)
    .replace("AFTER", after);
    std::fs::write(workspace.path().join("server.sh"), script).expect("write server");
    let transport = StdioTransport::new(
        "sh server.sh",
        HashMap::new(),
        Some(workspace.path().to_string_lossy().into_owned()),
        Duration::from_secs(30),
        None,
    );
    transport.start().await.expect("handshake");
    (workspace, transport)
}

fn pid_of(raw: u32) -> Pid {
    Pid::from_raw(i32::try_from(raw).expect("pid fits")).expect("non-zero pid")
}

fn kernel_view(pid: Pid) -> Option<bool> {
    let options = WaitIdOptions::EXITED | WaitIdOptions::NOHANG | WaitIdOptions::NOWAIT;
    match waitid(WaitId::Pid(pid), options) {
        Ok(status) => Some(status.is_some()),
        Err(rustix::io::Errno::CHILD) => None,
        Err(e) => panic!("waitid: {e}"),
    }
}

async fn poll_until(what: &str, mut done: impl FnMut() -> bool) {
    let deadline = tokio::time::Instant::now() + ROW_LIMIT;
    while !done() {
        assert!(
            tokio::time::Instant::now() < deadline,
            "{what} within {ROW_LIMIT:?}"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

async fn pid_file(dir: &Path, name: &str) -> Pid {
    let file = dir.join(name);
    let mut raw = String::new();
    poll_until("a pid is recorded", || {
        raw = std::fs::read_to_string(&file).unwrap_or_default();
        raw.ends_with('\n')
    })
    .await;
    pid_of(raw.trim().parse().expect("a pid"))
}

async fn gone(pid: Pid) {
    poll_until("the process is gone", || {
        rustix::process::test_kill_process(pid).is_err()
    })
    .await;
}

/// T1: expected RED here (is_connected reaps through try_wait).
#[tokio::test]
async fn red_t1_is_connected_reports_an_exit_without_reaping_it() {
    let (w, t) = started("sleep 60 </dev/null & echo $! > d.pid\nexit 0").await;
    let child = pid_file(w.path(), "d.pid").await;
    let pid = pid_file(w.path(), "leader.pid").await;
    poll_until("the leader exits", || kernel_view(pid) == Some(true)).await;
    assert!(
        t.connected.load(std::sync::atomic::Ordering::Relaxed),
        "flag still set"
    );
    assert!(!t.is_connected(), "the exit is observed");
    let after = kernel_view(pid);
    let _ = t.close().await;
    let _ = rustix::process::kill_process(child, rustix::process::Signal::KILL);
    assert_eq!(after, Some(true), "is_connected reaped the leader");
}

/// T5 (behaviour part only; the before-the-reap order needs the counter).
#[tokio::test]
async fn red_t5_a_failed_start_keeps_the_status_and_ends_the_group() {
    let w = tempfile::tempdir().expect("workspace");
    let script =
        "echo $$ > leader.pid\nsleep 60 </dev/null 2>/dev/null & echo $! > d.pid\nexit 3\n";
    std::fs::write(w.path().join("server.sh"), script).expect("write server");
    let t = StdioTransport::new(
        "sh server.sh",
        HashMap::new(),
        Some(w.path().to_string_lossy().into_owned()),
        Duration::from_secs(1),
        None,
    );
    tokio::time::timeout(Duration::from_secs(10), t.start())
        .await
        .expect("a failed start returns")
        .expect_err("nothing answers initialize");
    let child = pid_file(w.path(), "d.pid").await;
    let leader = pid_file(w.path(), "leader.pid").await;
    assert_eq!(t.exit_status().and_then(|s| s.code()), Some(3));
    assert_eq!(kernel_view(leader), None, "the leader is reaped");
    gone(child).await;
}

/// D1: a member forking in a tight loop while close runs.
#[tokio::test]
async fn red_d1_close_ends_a_group_that_keeps_forking() {
    let forker = "(while :; do sleep 30 </dev/null >/dev/null 2>&1 & echo $! >> pids; sleep 0.005; done) </dev/null >/dev/null 2>&1 &\necho $! >> pids\nwhile IFS= read -r l; do :; done";
    let (w, t) = started(forker).await;
    let file = w.path().join("pids");
    poll_until("the member forks", || {
        std::fs::read_to_string(&file).map_or(0, |s| s.lines().count()) >= 10
    })
    .await;
    t.close().await.expect("close");
    let recorded: Vec<Pid> = std::fs::read_to_string(&file)
        .expect("pids")
        .lines()
        .filter_map(|l| l.trim().parse().ok())
        .map(pid_of)
        .collect();
    for pid in recorded {
        gone(pid).await;
    }
}

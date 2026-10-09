// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8080: the group leader is reaped only after the group's last signal.
//!
//! A5: one signal per phase, close then pre-reap, so a finish sends two.
//!
//! Oracle: `group_signals_sent` (signals actually sent) and `signals_refused`,
//! read off the tree while it is in the slot, or off the reaper's record once
//! a close or retire handed it over (MIK-7923), plus the kernel's own view of
//! the leader (`waitid` NOWAIT in the test) and of a descendant in the group.

use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use rustix::process::{Pid, WaitId, WaitIdOptions, waitid};

use super::super::{PROTOCOL_VERSION, StdioTransport};
use super::{ChildTree, Counts, Leader, Reap, native_child};
use crate::transport::Transport;

const ROW_LIMIT: Duration = Duration::from_secs(5);

/// Starts `sh server.sh`: answers `initialize`, reads the notification, then
/// runs `after`. The workspace is the script's cwd, for pid files.
async fn started(
    after: &str,
    max_frame: Option<usize>,
) -> (tempfile::TempDir, Arc<StdioTransport>) {
    let workspace = tempfile::tempdir().expect("workspace");
    let script = r#"id_of() { printf '%s' "$1" | sed -n 's/.*"id":\([0-9][0-9]*\).*/\1/p'; }
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
    if let Some(bytes) = max_frame {
        transport.set_max_frame_bytes(bytes);
    }
    transport.start().await.expect("handshake");
    (workspace, transport)
}

/// A descendant in the leader's group that outlives it, its pid in `d.pid`.
const DESCENDANT: &str = "sleep 60 </dev/null >/dev/null 2>&1 & echo $! > d.pid";

/// Run `f` on the started tree.
async fn with_tree<T>(t: &StdioTransport, f: impl FnOnce(&mut ChildTree) -> T) -> T {
    f(t.child.lock().tree.as_mut().expect("a started tree"))
}

/// The reaper's record of the tree whose leader was `pid`, once it finished.
async fn finished(pid: Pid) -> Counts {
    let raw = u32::try_from(pid.as_raw_nonzero().get()).expect("pid fits");
    let mut found = None;
    poll_until("the reaper finishes the tree", || {
        found = super::super::reaper::FINISHED
            .lock()
            .iter()
            .rev()
            .find(|counts| counts.pid == Some(raw))
            .copied();
        found.is_some()
    })
    .await;
    found.expect("a finished record")
}

/// `(sent, refused)` of the tree the reaper finished for leader `pid`.
async fn sent_after(pid: Pid) -> (usize, usize) {
    let counts = finished(pid).await;
    (counts.sent, counts.refused)
}

fn pid_of(raw: u32) -> Pid {
    Pid::from_raw(i32::try_from(raw).expect("pid fits")).expect("non-zero pid")
}

async fn leader(t: &StdioTransport) -> Pid {
    pid_of(with_tree(t, |c| c.pid()).await.expect("leader pid"))
}

/// The kernel's view, from the test itself: `Some(true)` zombie,
/// `Some(false)` running, `None` reaped (ECHILD).
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

/// The leader has exited and is still a zombie.
async fn leader_exited(t: &StdioTransport) -> Pid {
    let pid = leader(t).await;
    poll_until("the leader exits", || kernel_view(pid) == Some(true)).await;
    pid
}

async fn descendant(dir: &Path) -> Pid {
    let file = dir.join("d.pid");
    let mut raw = String::new();
    poll_until("the descendant records its pid", || {
        raw = std::fs::read_to_string(&file).unwrap_or_default();
        raw.ends_with('\n')
    })
    .await;
    pid_of(raw.trim().parse().expect("a pid"))
}

fn alive(pid: Pid) -> bool {
    rustix::process::test_kill_process(pid).is_ok()
}

async fn gone(pid: Pid) {
    poll_until("the descendant is gone", || !alive(pid)).await;
}

async fn sent(t: &StdioTransport) -> (usize, usize) {
    with_tree(t, |c| (c.group_signals_sent, c.signals_refused)).await
}

/// T1: `is_connected` sees the exit without reaping it. The descendant keeps
/// stdout open, so the reader never clears `connected` and the probe decides.
#[tokio::test]
async fn is_connected_reports_an_exit_without_reaping_it() {
    let (w, t) = started("sleep 60 </dev/null & echo $! > d.pid\nexit 0", None).await;
    let child = descendant(w.path()).await;
    let pid = leader_exited(&t).await;
    assert!(
        t.connected.load(std::sync::atomic::Ordering::Relaxed),
        "flag still set"
    );
    assert!(!t.is_connected(), "the exit is observed");
    assert_eq!(
        kernel_view(pid),
        Some(true),
        "is_connected reaped the leader"
    );
    t.close().await.expect("close");
    gone(child).await;
}

/// T2: close after an observed exit signals the group once per phase, then
/// reaps.
#[tokio::test]
async fn close_after_the_exit_signals_each_phase_once_then_reaps() {
    let (w, t) = started(&format!("{DESCENDANT}\nexit 0"), None).await;
    let child = descendant(w.path()).await;
    let pid = leader_exited(&t).await;
    t.close().await.expect("close");
    assert_eq!(sent_after(pid).await, (2, 0));
    assert_eq!(kernel_view(pid), None, "the leader is reaped by close");
    gone(child).await;
}

/// T6: a second close sends nothing and keeps the first status.
#[tokio::test]
async fn a_second_close_sends_nothing() {
    let (_w, t) = started("exit 7", None).await;
    let pid = leader_exited(&t).await;
    t.close().await.expect("close");
    let first = finished(pid).await.status;
    assert_eq!(first.and_then(|s| s.code()), Some(7));
    t.close().await.expect("second close");
    assert_eq!(sent_after(pid).await, (2, 0));
    let raw = u32::try_from(pid.as_raw_nonzero().get()).expect("pid fits");
    let records = super::super::reaper::FINISHED
        .lock()
        .iter()
        .filter(|counts| counts.pid == Some(raw))
        .count();
    assert_eq!(records, 1, "the second close handed nothing over");
    assert_eq!(t.child.lock().last_status(), first);
}

/// P1: the probe's mapping. EINTR and an unexpected errno cannot be forced
/// with a real child, so the mapping is a table; T1/F1 cover real waitid.
#[test]
fn the_probe_maps_each_waitid_result() {
    use rustix::io::Errno;
    assert_eq!(Leader::from_probe(Ok(false)), Some(Leader::Running));
    assert_eq!(Leader::from_probe(Ok(true)), Some(Leader::Zombie));
    assert_eq!(Leader::from_probe(Err(Errno::CHILD)), Some(Leader::Gone));
    assert_eq!(Leader::from_probe(Err(Errno::INTR)), None, "EINTR retries");
    assert_eq!(
        Leader::from_probe(Err(Errno::INVAL)),
        Some(Leader::Unproven)
    );
}

/// P1 against the platform's waitid: Running, Zombie, then Gone.
#[tokio::test]
async fn the_probe_reads_a_real_leader() {
    let (w, t) = started("while [ ! -f go ]; do sleep 0.05; done\nexit 0", None).await;
    assert_eq!(with_tree(&t, |c| c.leader_state()).await, Leader::Running);
    std::fs::write(w.path().join("go"), "").expect("release the leader");
    let pid = leader_exited(&t).await;
    assert_eq!(with_tree(&t, |c| c.leader_state()).await, Leader::Zombie);
    t.close().await.expect("close");
    assert_eq!(kernel_view(pid), None, "reaped: the leader's ids are gone");
}

/// T4: the reader-error kill is the close phase's one signal; the close
/// after it adds only the pre-reap signal, then reaps.
#[tokio::test]
async fn a_reader_error_then_close_adds_only_the_pre_reap_signal() {
    let oversized = "head -c 600 /dev/zero | tr '\\0' x\necho\nwhile IFS= read -r l; do :; done";
    let (w, t) = started(&format!("{DESCENDANT}\n{oversized}"), Some(512)).await;
    let child = descendant(w.path()).await;
    let pid = leader(&t).await;
    let deadline = tokio::time::Instant::now() + ROW_LIMIT;
    while sent(&t).await.0 == 0 {
        assert!(tokio::time::Instant::now() < deadline, "the reader errors");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    poll_until("the killed leader is a zombie, not reaped", || {
        kernel_view(pid) == Some(true)
    })
    .await;
    t.close().await.expect("close");
    assert_eq!(sent_after(pid).await, (2, 0));
    assert_eq!(kernel_view(pid), None, "the leader is reaped by close");
    gone(child).await;
}

/// T7: once handed over, the tree is the reaper's: a close cancelled while it
/// waits still leaves the group ended, each phase signalled once, then reaped.
#[tokio::test]
async fn a_cancelled_close_still_ends_the_tree() {
    let (w, t) = started(&format!("{DESCENDANT}\nexit 0"), None).await;
    let child = descendant(w.path()).await;
    let pid = leader_exited(&t).await;
    let closer = {
        let t = Arc::clone(&t);
        tokio::spawn(async move { t.close().await })
    };
    poll_until("close hands the tree over", || {
        t.child.lock().tree.is_none()
    })
    .await;
    closer.abort();
    let _ = closer.await;
    assert_eq!(sent_after(pid).await, (2, 0));
    assert_eq!(kernel_view(pid), None, "the reaper reaped the leader");
    gone(child).await;
}

/// F1: after a reap behind the tree's back the group may not be ours: close
/// and the drop path send nothing, refuse, and the descendant is left alive.
#[tokio::test]
async fn a_foreign_reap_leaks_rather_than_signals() {
    use rustix::process::{Signal, kill_process};
    let heartbeat = "(while :; do echo x >> hb; sleep 0.1; done) </dev/null >/dev/null 2>&1 &";
    let (w, t) = started(&format!("{heartbeat} echo $! > d.pid\nexit 0"), None).await;
    let child = descendant(w.path()).await;
    let pid = leader_exited(&t).await;
    let mut tree = t.child.lock().tree.take().expect("tree");
    tree.reap_bypassing_tree().await;
    t.child.lock().tree = Some(tree);
    t.close().await.expect("close");
    let (signals, refused) = sent_after(pid).await;
    // Proof of life before cleanup, so a failed assertion still cleans up.
    let beats = || std::fs::metadata(w.path().join("hb")).map_or(0, |m| m.len());
    let before = beats();
    tokio::time::sleep(Duration::from_millis(500)).await;
    let after = beats();
    let _ = kill_process(child, Signal::KILL);
    assert_eq!(signals, 0, "a group not proven ours was signalled");
    assert!(refused >= 1, "the refusal is recorded");
    assert!(after > before, "the descendant's heartbeat stopped");
}

/// D1: a member forking in a tight loop while close runs. Each child
/// records its own pid before it sleeps, so a child whose parent dies
/// between fork and record still registers; late registrations get a
/// bounded window, and every registered pid must be gone.
#[tokio::test]
async fn close_ends_a_group_that_keeps_forking() {
    let forker = "(while :; do sh -c 'echo $$ >> pids; exec sleep 30' </dev/null >/dev/null 2>&1 & sleep 0.005; done) </dev/null >/dev/null 2>&1 &\necho $! >> pids\nwhile IFS= read -r l; do :; done";
    let (w, t) = started(forker, None).await;
    let file = w.path().join("pids");
    let registered = || -> Vec<Pid> {
        std::fs::read_to_string(&file)
            .unwrap_or_default()
            .lines()
            .filter_map(|l| l.trim().parse().ok())
            .map(pid_of)
            .collect()
    };
    poll_until("the member forks", || registered().len() >= 10).await;
    t.close().await.expect("close");
    tokio::time::sleep(Duration::from_millis(300)).await;
    let pids = registered();
    let survivors: Vec<Pid> = pids.iter().copied().filter(|p| alive(*p)).collect();
    for pid in &survivors {
        let _ = rustix::process::kill_process(*pid, rustix::process::Signal::KILL);
    }
    for pid in pids {
        gone(pid).await;
    }
    assert!(survivors.is_empty(), "outlived close: {survivors:?}");
}

/// `reap_step` driven by hand, as the reaper drives it: the close signal and
/// the A5 signal once each, then the reap goes through the native tokio child,
/// so tokio recorded the exit and its kill_on_drop is disarmed (MIK-7923).
#[tokio::test]
async fn a_stepped_tree_signals_each_phase_once_then_reaps_natively() {
    let (w, t) = started(
        &format!("{DESCENDANT}\nwhile IFS= read -r l; do :; done"),
        None,
    )
    .await;
    let child = descendant(w.path()).await;
    let pid = leader(&t).await;
    let mut tree = t.child.lock().tree.take().expect("a started tree");
    let deadline = std::time::Instant::now() + ROW_LIMIT;
    let status = loop {
        match tree.reap_step(std::time::Instant::now()) {
            Reap::Done(status) => break status,
            Reap::Pending => {
                assert!(std::time::Instant::now() < deadline, "reaped in time");
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        }
    };
    assert!(status.is_some(), "reaped, not abandoned");
    assert_eq!((tree.group_signals_sent, tree.signals_refused), (2, 0));
    let native = native_child(&mut *tree.wrapper).expect("a tokio child at the bottom");
    assert!(
        native.try_wait().expect("try_wait").is_some(),
        "tokio recorded the exit, so kill_on_drop is disarmed"
    );
    assert_eq!(kernel_view(pid), None, "the leader is reaped");
    drop(tree);
    gone(child).await;
}

/// A5's wait ends when the killed leader exits, not after its 1 s grace:
/// ten live backends closed one after another take well under ten graces.
#[tokio::test]
async fn closing_ten_live_backends_does_not_add_a_grace_each() {
    let mut started_ones = Vec::new();
    for _ in 0..10 {
        started_ones.push(started("while IFS= read -r l; do :; done", None).await);
    }
    let mut pids = Vec::new();
    for (_w, t) in &started_ones {
        pids.push(leader(t).await);
    }
    let began = std::time::Instant::now();
    for ((_w, t), pid) in started_ones.iter().zip(&pids) {
        t.close().await.expect("close");
        assert_eq!(
            sent_after(*pid).await,
            (2, 0),
            "close and pre-reap both signalled"
        );
    }
    let took = began.elapsed();
    assert!(took < Duration::from_secs(3), "ten closes took {took:?}");
}

/// T5: a start that times out after the leader died (a descendant holds
/// stdout open, so this is the late path: settle, then close). The group is
/// signalled before the reap, the real exit status is kept, nothing survives.
#[tokio::test]
async fn a_failed_start_signals_the_group_before_the_reap() {
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
    let child = descendant(w.path()).await;
    let leader: u32 = std::fs::read_to_string(w.path().join("leader.pid"))
        .expect("leader pid")
        .trim()
        .parse()
        .expect("a pid");
    assert_eq!(t.exit_status().and_then(|s| s.code()), Some(3));
    assert_eq!(kernel_view(pid_of(leader)), None, "the leader is reaped");
    assert_eq!(
        sent_after(pid_of(leader)).await,
        (2, 0),
        "close and pre-reap, before the reap"
    );
    gone(child).await;
}

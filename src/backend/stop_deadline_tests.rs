// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A gateway stop waits for the kill of a stdio tree it does not stop itself:
//! a capability-executor child let go while idle. The child joined the
//! registry's stop deadline when it was built, but sits outside the registry,
//! so `stop_all_by` stops no transport of it and would return while the tree
//! is still in its exit waits.

use std::sync::Arc;
use std::time::Duration;

use rustix::process::{Pid, WaitId, WaitIdOptions, waitid};

use super::{Backend, BackendRegistry};
use crate::config::{BackendConfig, FailsafeConfig, TransportConfig};

/// Answers `initialize` and `tools/list`, records its pid, and on EOF ignores
/// SIGTERM and keeps running: only the group SIGKILL ends it.
const PEER: &str = r#"import json, os, signal, sys, time
open("leader.pid", "w").write(str(os.getpid()))
for line in sys.stdin:
    req = json.loads(line)
    if "id" not in req:
        continue
    if req.get("method") == "initialize":
        body = {"result": {"protocolVersion": "2025-06-18", "capabilities": {},
                           "serverInfo": {"name": "stays", "version": "1"}}}
    elif req.get("method") == "tools/list":
        body = {"result": {"tools": []}}
    else:
        body = {"error": {"code": -32601, "message": "not found"}}
    print(json.dumps({"jsonrpc": "2.0", "id": req["id"], **body}), flush=True)
signal.signal(signal.SIGTERM, signal.SIG_IGN)
while True:
    time.sleep(0.05)
"#;

/// Kills [`PEER`]'s whole group when the row ends, so a red run (a stop that
/// never killed it) leaks no backend: one that ignores EOF and SIGTERM would
/// otherwise run on, holding whatever it inherited.
struct KillGroupOnDrop(Pid);

impl KillGroupOnDrop {
    /// Whether the guard may signal the group: only while its leader is still
    /// this process's child, unreaped (a reaped pid may name someone else's
    /// group by now).
    fn may_signal(&self) -> bool {
        kernel_view(self.0).is_some()
    }
}

impl Drop for KillGroupOnDrop {
    fn drop(&mut self) {
        if self.may_signal() {
            let _ = rustix::process::kill_process_group(self.0, rustix::process::Signal::KILL);
        }
    }
}

/// The guard does not signal a group whose leader the reaper already reaped:
/// its pid may have been reused.
#[tokio::test]
async fn the_guard_does_not_signal_a_reaped_group() {
    let dir = tempfile::tempdir().expect("temp dir");
    let backend = stays(dir.path(), "reaped");
    backend.ensure_started().await.expect("the backend starts");
    let pid = leader_pid(dir.path());
    let guard = KillGroupOnDrop(pid);
    assert!(guard.may_signal(), "a running leader may be signalled");
    backend.stop().await.expect("stop");
    let by = std::time::Instant::now() + Duration::from_secs(15);
    while kernel_view(pid).is_some() {
        assert!(std::time::Instant::now() < by, "the leader was never reaped");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(!guard.may_signal(), "a reaped leader's pid is not signalled");
}

/// `Some(false)` running, `Some(true)` exited unreaped, `None` reaped.
fn kernel_view(pid: Pid) -> Option<bool> {
    let options = WaitIdOptions::EXITED | WaitIdOptions::NOHANG | WaitIdOptions::NOWAIT;
    match waitid(WaitId::Pid(pid), options) {
        Ok(status) => Some(status.is_some()),
        Err(rustix::io::Errno::CHILD) => None,
        Err(e) => panic!("waitid: {e}"),
    }
}

/// A stdio backend running [`PEER`] in `dir`.
fn stays(dir: &std::path::Path, name: &str) -> Arc<Backend> {
    std::fs::write(dir.join("peer.py"), PEER).expect("write peer");
    Arc::new(Backend::new(
        name,
        BackendConfig {
            transport: TransportConfig::Stdio {
                command: "python3 peer.py".to_string(),
                cwd: Some(dir.display().to_string()),
                protocol_version: None,
            },
            timeout: Duration::from_secs(10),
            ..BackendConfig::default()
        },
        &FailsafeConfig::default(),
        Duration::from_secs(60),
    ))
}

/// The pid [`PEER`] last recorded in `dir`.
fn leader_pid(dir: &std::path::Path) -> Pid {
    let raw: i32 = std::fs::read_to_string(dir.join("leader.pid"))
        .expect("pid file")
        .trim()
        .parse()
        .expect("pid");
    Pid::from_raw(raw).expect("non-zero pid")
}

#[tokio::test]
async fn a_gateway_stop_waits_for_an_idle_released_child_to_be_killed() {
    let dir = tempfile::tempdir().expect("temp dir");
    let registry = BackendRegistry::new();
    let child = stays(dir.path(), "capability:stays");
    // As the capability executor builds it: joined to the registry's stop
    // deadline, never registered.
    let _ = child.stop_deadline.set(registry.stop_deadline());
    child.ensure_started().await.expect("the child starts");
    let pid = leader_pid(dir.path());
    let _reap = KillGroupOnDrop(pid);

    // Let go while idle, with a long plan of its own.
    child.hand_over_now(Duration::from_secs(120));
    let stop_by = tokio::time::Instant::now()
        + crate::transport::KILL_RESERVE_FOR_TEST
        + Duration::from_secs(2);
    registry.stop_all_by(stop_by).await;

    assert_ne!(
        kernel_view(pid),
        Some(false),
        "the gateway stop returned while the released child still ran"
    );
}

/// A requested restart whose old backend ignores EOF and SIGTERM (only the
/// kill ends it) still completes within its close budget: the old close is
/// hard-limited, and its plan (EOF wait, SIGTERM wait, kill) fits inside it.
#[tokio::test]
async fn a_restart_of_a_backend_that_ignores_every_signal_completes_in_bound() {
    let dir = tempfile::tempdir().expect("temp dir");
    let backend = stays(dir.path(), "stays");
    backend.ensure_started().await.expect("the backend starts");
    let old = leader_pid(dir.path());
    let _reap = KillGroupOnDrop(old);
    // The close budget, plus room for the new child's start on a loaded host.
    let bound = backend.budgets.close_stage + Duration::from_secs(10);
    let restarted = tokio::time::timeout(bound, backend.force_restart())
        .await
        .expect("the restart completes within its bound");
    assert!(restarted.is_ok(), "the restart failed: {restarted:?}");
    assert_ne!(
        kernel_view(old),
        Some(false),
        "the old backend still runs after the restart"
    );
    backend.stop().await.expect("stop");
}

/// A backend whose stop waits on its lifecycle lock (a restart holding it)
/// cannot hold the gateway stop past its deadline: `stop_all_by` gives up at
/// the deadline and retires what is left.
#[tokio::test]
async fn a_stop_stuck_on_a_lifecycle_lock_ends_at_its_deadline() {
    let dir = tempfile::tempdir().expect("temp dir");
    let registry = BackendRegistry::new();
    let backend = stays(dir.path(), "stuck");
    assert!(registry.register(Arc::clone(&backend)), "registered");
    backend.ensure_started().await.expect("the backend starts");
    let pid = leader_pid(dir.path());
    let _reap = KillGroupOnDrop(pid);
    // As a restart in flight holds it; `Backend::stop` waits up to its
    // lifecycle budget (15 s) for it.
    let _held = backend.lifecycle.write().await;
    let started = tokio::time::Instant::now();
    registry.stop_all_by(started + Duration::from_secs(1)).await;
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "the stop outran its deadline: {:?}",
        started.elapsed()
    );
    // What the stop left running is retired on its way out: killed at once.
    let by = std::time::Instant::now() + Duration::from_secs(5);
    while kernel_view(pid) == Some(false) {
        assert!(
            std::time::Instant::now() < by,
            "the stop returned with the stuck backend still running"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

/// A graceful handover that comes after the gateway stop returned (an idle
/// release racing the return) is killed on its first step: the stop leaves
/// its deadline at the moment it ended.
#[tokio::test]
async fn a_handover_after_the_gateway_stop_returns_is_killed_at_once() {
    let dir = tempfile::tempdir().expect("temp dir");
    let registry = BackendRegistry::new();
    let child = stays(dir.path(), "capability:late");
    let _ = child.stop_deadline.set(registry.stop_deadline());
    child.ensure_started().await.expect("the child starts");
    let pid = leader_pid(dir.path());
    let _reap = KillGroupOnDrop(pid);
    // Nothing registered: the stop returns at once, its deadline far off.
    let far = tokio::time::Instant::now() + Duration::from_secs(60);
    registry.stop_all_by(far).await;
    child.hand_over_now(Duration::from_secs(120));
    let by = std::time::Instant::now() + Duration::from_secs(5);
    while kernel_view(pid) == Some(false) {
        assert!(
            std::time::Instant::now() < by,
            "a handover after the stop returned was left in its waits"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

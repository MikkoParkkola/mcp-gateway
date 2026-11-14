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

/// Ends the row's backend when the row ends, through its owner, so a red run
/// (a stop that never killed it) leaks no backend built to ignore signals:
/// its stop deadline moves to now (a tree already handed over is killed on
/// the reaper's next step) and every live tree is retired (killed at once by
/// the tree itself, serialized with its reap). No pid is signalled from test
/// code: a reaped pid may name someone else's group by then.
struct EndOnDrop(Arc<Backend>);

impl Drop for EndOnDrop {
    fn drop(&mut self) {
        if let Some(deadline) = self.0.stop_deadline.get() {
            deadline.move_earlier(std::time::Instant::now());
        }
        self.0.retire_now();
    }
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

/// A stdio backend running [`PEER`] in `dir`, joined to `deadline` (a
/// registry's, or its own for a row with none), which [`EndOnDrop`] ends it by.
fn stays(
    dir: &std::path::Path,
    name: &str,
    deadline: Arc<crate::transport::StopDeadline>,
) -> Arc<Backend> {
    std::fs::write(dir.join("peer.py"), PEER).expect("write peer");
    let backend = Arc::new(Backend::new(
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
    ));
    let _ = backend.stop_deadline.set(deadline);
    backend
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
    // As the capability executor builds it: joined to the registry's stop
    // deadline, never registered.
    let child = stays(dir.path(), "capability:stays", registry.stop_deadline());
    let _end = EndOnDrop(Arc::clone(&child));
    child.ensure_started().await.expect("the child starts");
    let pid = leader_pid(dir.path());

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
    let backend = stays(dir.path(), "stays", Arc::default());
    let _end = EndOnDrop(Arc::clone(&backend));
    backend.ensure_started().await.expect("the backend starts");
    let old = leader_pid(dir.path());
    // The 10 s close budget, plus 10 s for the new child's start on a loaded
    // host.
    let bound = Duration::from_secs(20);
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
    let backend = stays(dir.path(), "stuck", registry.stop_deadline());
    let _end = EndOnDrop(Arc::clone(&backend));
    assert!(registry.register(Arc::clone(&backend)), "registered");
    backend.ensure_started().await.expect("the backend starts");
    let pid = leader_pid(dir.path());
    // As a restart in flight holds it; `Backend::stop` waits up to its
    // lifecycle budget (15 s) for it.
    let _held = backend.lifecycle.write().await;
    let started = tokio::time::Instant::now();
    registry.stop_all_by(started + Duration::from_secs(1)).await;
    assert!(
        started.elapsed() < Duration::from_secs(10),
        "the stop outran its deadline: {:?}",
        started.elapsed()
    );
    // What the stop left running is retired on its way out: killed at once.
    let by = std::time::Instant::now() + Duration::from_secs(10);
    while kernel_view(pid) == Some(false) {
        assert!(
            std::time::Instant::now() < by,
            "the stop returned with the stuck backend still running"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

/// A hurry must reach live trees even while a restart holds the lifecycle
/// lock: waiting for the retire sweep at the full deadline misses the kill cut.
#[tokio::test]
async fn a_hurried_stop_hands_a_lock_held_backends_live_tree_to_the_reaper_at_once() {
    use crate::transport::{HURRY_WINDOW, KILL_RESERVE_FOR_TEST};

    let dir = tempfile::tempdir().expect("temp dir");
    let registry = BackendRegistry::new();
    let backend = stays(dir.path(), "stuck", registry.stop_deadline());
    let _end = EndOnDrop(Arc::clone(&backend));
    assert!(registry.register(Arc::clone(&backend)), "registered");
    backend.ensure_started().await.expect("the backend starts");
    let pid = leader_pid(dir.path());
    assert_eq!(kernel_view(pid), Some(false), "premise: the tree is live");
    assert_eq!(
        registry.stop_deadline().handed_len(),
        0,
        "premise: nothing handed over yet"
    );
    let _held = backend.lifecycle.write().await;
    let started = tokio::time::Instant::now();
    let cut = started + KILL_RESERVE_FOR_TEST + HURRY_WINDOW;
    registry.stop_deadline().hurry(started.into_std());
    // Keep stop_all_by polled and the lifecycle lock held, and wait for the
    // tree to leave the running state. Handed over, it is killed about
    // HURRY_WINDOW after the hurry plus what load adds, seconds before `cut`;
    // not handed over, only the stop's RetireOnDrop sweep kills it, after `cut`.
    // So the bug is told by when the tree went relative to `cut`, an event,
    // not by a sample at a fixed instant (the reap's own timing is pinned by
    // the transport's clock-free hurry rows).
    let ((), (handed, gone_at)) = tokio::time::timeout(Duration::from_secs(30), async {
        tokio::join!(registry.stop_all_by(cut), async {
            // One yield lets the stop take its first step, where a hurried
            // stop hands every live tree over before it waits on the lock.
            tokio::task::yield_now().await;
            let handed = registry.stop_deadline().handed_len();
            while kernel_view(pid) == Some(false) {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
            (handed, tokio::time::Instant::now())
        })
    })
    .await
    .expect("the hurried stop completes within the watchdog");
    assert_eq!(
        handed, 1,
        "the hurried stop did not hand the live tree over before waiting on the held lifecycle lock"
    );
    assert!(
        gone_at < cut,
        "live tree still running {:?} after the hurry; a held lifecycle lock delayed handover until the {cut:?} deadline",
        gone_at.duration_since(started)
    );
}

/// A graceful handover that comes after the gateway stop returned (an idle
/// release racing the return) is killed on its first step: the stop leaves
/// its deadline at the moment it ended.
#[tokio::test]
async fn a_handover_after_the_gateway_stop_returns_is_killed_at_once() {
    let dir = tempfile::tempdir().expect("temp dir");
    let registry = BackendRegistry::new();
    let child = stays(dir.path(), "capability:late", registry.stop_deadline());
    let _end = EndOnDrop(Arc::clone(&child));
    child.ensure_started().await.expect("the child starts");
    let pid = leader_pid(dir.path());
    // Nothing registered: the stop returns at once, its deadline far off.
    let far = tokio::time::Instant::now() + Duration::from_secs(60);
    registry.stop_all_by(far).await;
    child.hand_over_now(Duration::from_secs(120));
    let by = std::time::Instant::now() + Duration::from_secs(10);
    while kernel_view(pid) == Some(false) {
        assert!(
            std::time::Instant::now() < by,
            "a handover after the stop returned was left in its waits"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

/// A backend a reload registers while the gateway stop is starting, after
/// the stop took the backends it will retire, is either refused (the stop's
/// latch is already set) or retired with the rest. Here its stop is stuck on
/// a restart's lifecycle lock until the deadline, so only the retirement can
/// end its tree. The registration is made at the stop's seam, so the window
/// is hit every run, not by timing.
#[tokio::test]
async fn a_backend_registered_as_the_stop_starts_is_refused_or_retired() {
    let dir = tempfile::tempdir().expect("temp dir");
    let registry = Arc::new(BackendRegistry::new());
    let backend = stays(dir.path(), "late", registry.stop_deadline());
    let _end = EndOnDrop(Arc::clone(&backend));
    backend.ensure_started().await.expect("the backend starts");
    let pid = leader_pid(dir.path());
    let _held = backend.lifecycle.write().await;
    // `None` until the seam fires: a hook that never ran must fail the row,
    // not read as a refused registration.
    let registered: Arc<std::sync::Mutex<Option<bool>>> = Arc::new(std::sync::Mutex::new(None));
    let (late, seen, by_registry) = (
        Arc::clone(&backend),
        Arc::clone(&registered),
        Arc::clone(&registry),
    );
    super::registry::stop_seam::after_sweep_runs(move || {
        *seen.lock().expect("lock") = Some(by_registry.register(late));
    });
    registry
        .stop_all_by(tokio::time::Instant::now() + Duration::from_secs(1))
        .await;
    let registered = registered
        .lock()
        .expect("lock")
        .expect("premise: the stop's seam fired and the late backend tried to register");
    if registered {
        let by = std::time::Instant::now() + Duration::from_secs(10);
        while kernel_view(pid) == Some(false) {
            assert!(
                std::time::Instant::now() < by,
                "registered as the stop started, and left running behind it"
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }
}

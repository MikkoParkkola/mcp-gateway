// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Health recovery, restarts and shutdown racing a start.

use super::*;

/// A transport whose `close()` parks until released, letting a test position
/// itself INSIDE the reaper's post-take window: transport already removed from
/// the slot, stop not yet finished.
struct BlockingCloseMock {
    entered_close: Arc<AtomicBool>,
    release: Arc<AtomicBool>,
}

#[async_trait]
impl Transport for BlockingCloseMock {
    async fn request(&self, _method: &str, _params: Option<Value>) -> Result<JsonRpcResponse> {
        Ok(JsonRpcResponse::success_serialized(
            RequestId::Number(1),
            json!({}),
        ))
    }

    async fn notify(&self, _method: &str, _params: Option<Value>) -> Result<()> {
        Ok(())
    }

    fn is_connected(&self) -> bool {
        true
    }

    async fn close(&self) -> Result<()> {
        self.entered_close.store(true, Ordering::SeqCst);
        while !self.release.load(Ordering::SeqCst) {
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
        Ok(())
    }
}

// GW.IDLE.RACE.2 - the health probe must not restart a backend the reaper is
// in the middle of stopping.
//
// The window is between the reaper taking the transport and its stop being
// complete. A probe entering there sees a slot with no transport; if it cannot
// tell "deliberately stopped" from "not started yet" it calls ensure_started()
// and respawns the process the sweep just released - a periodic silent no-op,
// which is the exact failure this feature exists to prevent. Recording
// `stopped_when_idle` under the same write guard that takes the transport is
// what closes it; recording it after `close()` completes leaves it open.
//
// The test parks the reaper inside `close()` so it is genuinely in the window,
// rather than asserting after the stop has finished - the mistake that let six
// earlier tests pass against broken code.
#[tokio::test(flavor = "multi_thread")]
async fn the_health_probe_does_not_restart_a_backend_mid_stop() {
    let dir = tempfile::tempdir().expect("create temp dir");
    let log = dir.path().join("spawns");
    let backend = stoppable_backend_with_command(
        &format!("sh -c 'echo spawn >> {}; sleep 1'", log.display()),
        Duration::from_secs(1),
    );

    let entered_close = Arc::new(AtomicBool::new(false));
    let release = Arc::new(AtomicBool::new(false));
    backend.set_transport_for_test(Arc::new(BlockingCloseMock {
        entered_close: Arc::clone(&entered_close),
        release: Arc::clone(&release),
    }));
    backend.shared_entry().last_used.store(0, Ordering::Relaxed);

    let stopper = {
        let backend = Arc::clone(&backend);
        tokio::spawn(async move { backend.stop_if_idle().await })
    };

    // Park until the reaper is demonstrably inside the window.
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while !entered_close.load(Ordering::SeqCst) {
        assert!(
            std::time::Instant::now() < deadline,
            "the reaper never reached close(); the test never entered the window"
        );
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
    assert!(
        backend.shared_entry().transport.read().is_none(),
        "precondition: the reaper has taken the transport"
    );

    let spawns_before = spawn_count(&log);
    let _ = backend.health_probe(Duration::from_millis(200)).await;

    assert_eq!(
        spawn_count(&log),
        spawns_before,
        "the health probe spawned a child while the reaper was stopping this \
         backend; stopping and restarting on every sweep is the silent no-op \
         this feature exists to prevent"
    );
    assert!(
        backend.shared_entry().transport.read().is_none(),
        "the health probe installed a transport for a backend being stopped"
    );

    release.store(true, Ordering::SeqCst);
    assert!(
        stopper.await.expect("stopper task panicked"),
        "stop_if_idle should report that it closed a live transport"
    );
}

// GW.IDLE.RACE.3 - the evictor must never remove a slot a request is using.
//
// Scope, stated honestly: this covers the eviction PREDICATE, not the
// acquisition window. That a lease is claimed under the same shard guard the
// predicate runs under is atomicity by construction - `pooled_entry_with` runs
// its callback before releasing the guard and is the only path to an
// incremented entry - and is not what this test proves. What it proves is the
// invariant that construction exists to protect: an evictor that can see a
// live lease must decline, and must not close a transport out from under it.
#[tokio::test]
async fn a_leased_slot_is_never_evicted() {
    let backend = per_user_backend();
    let key = per_user_key("userA");
    let mock = Arc::new(SessionMock::new("A"));
    backend.set_pooled_transport_for_test(&key, Arc::clone(&mock) as Arc<dyn Transport>);

    let lease = backend.begin_activity(&key).unwrap();
    // begin_activity touches the idle clock, so re-stale it: the lease must be
    // the ONLY thing keeping this slot alive, or the test proves nothing.
    backend
        .pooled_entry(&key)
        .unwrap()
        .last_used
        .store(0, Ordering::Relaxed);

    assert_eq!(
        backend.evict_idle_per_user_entries(Duration::from_secs(1)),
        0,
        "the evictor removed a slot with a live lease on it"
    );
    assert!(
        backend.pool.contains_key(&key),
        "the leased slot is gone from the pool; its holder is now an orphan"
    );
    assert!(
        !mock.closed.load(Ordering::SeqCst),
        "the evictor closed a transport a live request is holding"
    );

    drop(lease);
    // Dropping the guard touches the clock too.
    backend
        .pooled_entry(&key)
        .unwrap()
        .last_used
        .store(0, Ordering::Relaxed);

    assert_eq!(
        backend.evict_idle_per_user_entries(Duration::from_secs(1)),
        1,
        "once the lease is released the slot must become evictable again, \
         or in_flight leaks and the slot is immortal"
    );
    // The close runs detached (#2245): poll for it, bounded, not a fixed wait.
    for _ in 0..200 {
        if mock.closed.load(Ordering::SeqCst) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(
        mock.closed.load(Ordering::SeqCst),
        "the evicted slot's transport was never closed"
    );
}

/// A transport whose closed-flag lives OUTSIDE it, so a test can observe the
/// close without holding an `Arc` to the transport itself. Holding one would
/// keep the strong count above the drain threshold and make the assertion
/// depend on the drain cap rather than on the behaviour under test.
struct ClosedFlagMock {
    closed: Arc<AtomicBool>,
    dropped: Arc<AtomicBool>,
}

impl Drop for ClosedFlagMock {
    fn drop(&mut self) {
        self.dropped.store(true, Ordering::SeqCst);
    }
}

#[async_trait]
impl Transport for ClosedFlagMock {
    async fn request(&self, _method: &str, _params: Option<Value>) -> Result<JsonRpcResponse> {
        Ok(JsonRpcResponse::success_serialized(
            RequestId::Number(1),
            json!({}),
        ))
    }

    async fn notify(&self, _method: &str, _params: Option<Value>) -> Result<()> {
        Ok(())
    }

    fn is_connected(&self) -> bool {
        true
    }

    async fn close(&self) -> Result<()> {
        self.closed.store(true, Ordering::SeqCst);
        Ok(())
    }
}

// GW.IDLE.RACE.4 - health recovery must not close a transport a client is
// still using, and must not leak it either.
//
// force_restart() is the health loop's escape hatch for a wedged backend. It
// used to take the shared transport and close it with no regard for in-flight
// work, so a probe failing while an ordinary request was mid-call killed that
// request's stdio child underneath it.
//
// The fix is ownership, not timing: recovery drops its reference and the
// transport goes away when the LAST caller drops theirs. So this asserts both
// halves - untouched while a caller holds it, and actually released once that
// caller lets go. The release is witnessed by the mock's Drop, because with
// ownership-based cleanup nothing calls close() on this path; a test asserting
// close() would be asserting the old design.
#[tokio::test(flavor = "multi_thread")]
async fn health_recovery_does_not_close_a_transport_a_request_is_using() {
    // A command that cannot spawn at all, so start_entry fails immediately
    // instead of waiting out an MCP init timeout. What happens to the OLD
    // transport is settled before the new one is built, so the failure is
    // irrelevant to the assertions.
    let backend =
        stoppable_backend_with_command("/nonexistent-mcp-binary", Duration::from_secs(60));
    let closed = Arc::new(AtomicBool::new(false));
    let dropped = Arc::new(AtomicBool::new(false));
    backend.set_transport_for_test(Arc::new(ClosedFlagMock {
        closed: Arc::clone(&closed),
        dropped: Arc::clone(&dropped),
    }));

    // Exactly what an in-flight request owns when recovery fires.
    let lease = backend.begin_activity(&PoolKey::Shared).unwrap();
    let held = backend
        .shared_entry()
        .transport
        .read()
        .clone()
        .expect("transport installed above");

    let _ = backend.force_restart().await;

    assert!(
        !closed.load(Ordering::SeqCst),
        "health recovery closed the transport while a request was still using it"
    );
    assert!(
        !dropped.load(Ordering::SeqCst),
        "the transport was destroyed while a request still held it"
    );
    assert!(
        held.is_connected(),
        "the in-flight caller's transport is no longer usable"
    );

    // Release it the way a finishing request would. It must then be CLOSED, not
    // merely dropped: close() is what sends an HTTP backend's per-session
    // DELETEs, and skipping them abandons upstream sessions on every recovery.
    drop(held);
    drop(lease);

    // Wait for BOTH: the mock sets `closed` inside close(), but the cleanup task
    // only releases its Arc after close() returns. Asserting `dropped` the
    // instant `closed` is observed is a race - another worker can see the store
    // before the mock is destroyed.
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    while !(closed.load(Ordering::SeqCst) && dropped.load(Ordering::SeqCst)) {
        assert!(
            std::time::Instant::now() < deadline,
            "the replaced transport was not closed AND released after its last \
             holder let go (closed={}, released={}); recovery leaked it and, for \
             HTTP, its upstream session with it",
            closed.load(Ordering::SeqCst),
            dropped.load(Ordering::SeqCst)
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

// GW.IDLE.RACE.6 - shutdown must wait for a replaced transport's cleanup.
//
// A transport that force_restart replaced while it was in use is no longer in
// `pool`, so `stop()`'s loop over the pool cannot see it: only its cleanup task
// holds it. Detach that task and the runtime can exit with its `close()` unrun,
// which skips an HTTP backend's per-session DELETEs at exactly the reload and
// shutdown boundaries where abandoning a session matters most.
//
// The holder here is released while `stop()` is already waiting, so the test
// distinguishes waiting from not waiting: without the drain, `stop()` returns
// before the release and the transport is still open when it does.
#[tokio::test(flavor = "multi_thread")]
async fn shutdown_waits_for_a_replaced_transports_cleanup() {
    let backend =
        stoppable_backend_with_command("/nonexistent-mcp-binary", Duration::from_secs(60));
    let closed = Arc::new(AtomicBool::new(false));
    let dropped = Arc::new(AtomicBool::new(false));
    backend.set_transport_for_test(Arc::new(ClosedFlagMock {
        closed: Arc::clone(&closed),
        dropped: Arc::clone(&dropped),
    }));

    let lease = backend.begin_activity(&PoolKey::Shared).unwrap();
    let held = backend
        .shared_entry()
        .transport
        .read()
        .clone()
        .expect("transport installed above");

    // Replaced while in use: cleanup is deferred and the old transport is now
    // reachable only from its cleanup task.
    let _ = backend.force_restart().await;
    drop(lease);
    assert!(
        !closed.load(Ordering::SeqCst),
        "precondition: cleanup is still waiting on the holder"
    );

    // Let go only once shutdown is already under way.
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(150)).await;
        drop(held);
    });

    backend.stop().await.expect("stop");

    assert!(
        closed.load(Ordering::SeqCst),
        "stop() returned while a replaced transport was still open; its cleanup \
         was detached, so shutdown can drop it unrun and abandon the session"
    );
}

// GW.IDLE.RACE.7 - recovery must not restart a backend that is shutting down.
//
// The health loop only checks its shutdown signal between ticks, so a probe
// already in flight can call force_restart() while stop() is tearing the
// backend down. stop() has by then taken every transport out of the pool, so a
// restart there spawns a fresh child process that nothing left alive will ever
// close: an orphan MCP server outliving the gateway. It also registers a
// cleanup after shutdown's final drain, which is how this was found.
//
// The witness is on disk: the backend's command appends a line per spawn, so
// the assertion counts real spawn attempts rather than trusting an in-memory
// flag. (It counts launches from that log; it does not inspect the process
// table itself.)
#[tokio::test(flavor = "multi_thread")]
async fn recovery_does_not_restart_a_backend_that_is_stopping() {
    let dir = tempfile::tempdir().expect("create temp dir");
    let log = dir.path().join("spawns");
    let backend = stoppable_backend_with_command(
        &format!("sh -c 'echo spawn >> {}; sleep 1'", log.display()),
        Duration::from_secs(60),
    );
    backend.set_transport_for_test(Arc::new(SessionMock::new("live")));

    backend.stop().await.expect("stop");

    let spawns_before = spawn_count(&log);
    let _ = backend.force_restart().await;

    assert_eq!(
        spawn_count(&log),
        spawns_before,
        "force_restart spawned a child for a backend that had already been \
         stopped; nothing remains to close it, so it outlives the gateway"
    );
    assert!(
        backend.shared_entry().transport.read().is_none(),
        "a stopped backend was given a live transport by health recovery"
    );
}

// GW.IDLE.RACE.8 - shutdown must exclude a restart that is already running.
//
// The `stopping` latch alone cannot do this: force_restart reads it and THEN
// does async work, so it can pass the check before stop() latches and go on to
// register a cleanup after the final drain, or start a child after teardown.
// The check and the work it guards are not one operation, so a flag cannot
// close the window - only mutual exclusion can.
//
// Positioned inside the window rather than after it: the test holds the shared
// side of the lifecycle lock, which is exactly what an in-flight restart holds,
// and asserts shutdown cannot proceed past it.
#[tokio::test(flavor = "multi_thread")]
async fn shutdown_waits_for_a_restart_already_in_flight() {
    let backend =
        stoppable_backend_with_command("/nonexistent-mcp-binary", Duration::from_secs(60));
    backend.set_transport_for_test(Arc::new(SessionMock::new("live")));

    // Stand in for a restart that has passed its own stopping check.
    let restarting = backend.lifecycle.read().await;

    let stopped = Arc::new(AtomicBool::new(false));
    let shutdown_task = {
        let backend = Arc::clone(&backend);
        let stopped = Arc::clone(&stopped);
        tokio::spawn(async move {
            let _ = backend.stop().await;
            stopped.store(true, Ordering::SeqCst);
        })
    };

    // Bounded wait: unexcluded shutdown would have completed many times over.
    tokio::time::sleep(Duration::from_millis(150)).await;
    assert!(
        !stopped.load(Ordering::SeqCst),
        "stop() ran to completion while a restart was still in flight; it can \
         therefore latch and drain before that restart registers its cleanup or \
         starts its child"
    );

    drop(restarting);

    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while !stopped.load(Ordering::SeqCst) {
        assert!(
            std::time::Instant::now() < deadline,
            "stop() never completed after the restart finished"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    shutdown_task.await.expect("shutdown task panicked");
}

// GW.IDLE.RACE.9 - a restart that finishes after shutdown must undo itself.
//
// The lifecycle lock normally stops these overlapping, but `stop()` bounds its
// wait for that lock rather than hanging shutdown forever, so correctness
// cannot depend on having won it. Starting is slow: a flag read BEFORE a slow
// operation says nothing about the world after it. If shutdown ran to
// completion in the meantime it has already walked every transport in the
// pool, so a child started afterwards is one nothing will ever close.
//
// The test drives that window directly - the latch is flipped WHILE the start
// is in progress, which is precisely the state a timed-out lock leaves behind -
// rather than asserting the easy case where shutdown finished first. The child
// is a real MCP responder, because the undo only matters when the start
// SUCCEEDS; a failed start has nothing to undo.
//
#[cfg(unix)] // Unix-only: the witness is the process table, read via kill(1).
#[tokio::test(flavor = "multi_thread")]
async fn a_restart_that_outlives_shutdown_closes_what_it_started() {
    let dir = tempfile::tempdir().expect("create temp dir");
    let server = dir.path().join("server.sh");
    let pidfile = dir.path().join("child.pid");
    std::fs::write(
        &server,
        format!(
            r#"echo $$ > "{}"
sleep 0.3
while IFS= read -r request; do
    case "$request" in
        *'"method":"initialize"'*)
            printf '%s\n' '{{"jsonrpc":"2.0","id":1,"result":{{"protocolVersion":"2025-11-25"}}}}'
            ;;
    esac
done
"#,
            pidfile.display()
        ),
    )
    .expect("write server");

    let backend = stoppable_backend_with_command(
        &format!("sh {}", server.display()),
        Duration::from_secs(60),
    );

    let flipper = {
        let backend = Arc::clone(&backend);
        tokio::spawn(async move {
            // Inside the child's pre-handshake delay: the start is under way
            // and has not yet installed anything.
            tokio::time::sleep(Duration::from_millis(100)).await;
            // Exactly what stop() does to the latch, minus the lock it may have
            // failed to acquire.
            backend.replaced_transport_cleanups.lock().stopping = true;
        })
    };

    let outcome = backend.force_restart().await;
    flipper.await.expect("flipper task panicked");

    assert!(
        matches!(outcome, Ok(crate::backend::RestartOutcome::SkippedStopping)),
        "a restart that finished after shutdown reported success: {outcome:?}"
    );
    assert!(
        backend.shared_entry().transport.read().is_none(),
        "the restart left a transport installed on a backend that had already \
         been shut down; nothing remains to close it"
    );

    // An empty slot is not evidence the process died - close() could have
    // failed, or done nothing. The child recorded its own pid, so ask the
    // process table.
    let pid = std::fs::read_to_string(&pidfile)
        .expect("child recorded its pid")
        .trim()
        .to_string();
    let alive = || {
        std::process::Command::new("kill")
            .args(["-0", &pid])
            .status()
            .is_ok_and(|s| s.success())
    };
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while alive() {
        assert!(
            std::time::Instant::now() < deadline,
            "the restart emptied the slot but its child (pid {pid}) is still \
             running; it outlives the gateway"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

// GW.IDLE.RACE.10 - a start racing shutdown must never outlive it.
//
// The ORDINARY start path (no lifecycle lock) can be mid-start when shutdown
// runs; unless publishing is ordered against the pool traversal its child
// outlives the gateway. The test drives the race and checks the process table.
#[cfg(unix)] // Unix-only: the witness is read via kill(1).
#[tokio::test(flavor = "multi_thread")]
async fn an_ordinary_start_racing_shutdown_leaves_no_child_behind() {
    let dir = tempfile::tempdir().expect("create temp dir");
    let server = dir.path().join("server.sh");
    let pidfile = dir.path().join("child.pid");
    std::fs::write(
        &server,
        format!(
            r#"echo $$ > "{pid}"
i=0; while [ ! -e "{release}" ] && [ $i -lt 600 ]; do sleep 0.05; i=$((i+1)); done
[ -e "{release}" ] || exit 1
while IFS= read -r request; do
    case "$request" in
        *'"method":"initialize"'*)
            printf '%s\n' '{{"jsonrpc":"2.0","id":1,"result":{{"protocolVersion":"2025-11-25"}}}}'
            ;;
    esac
done
"#,
            pid = pidfile.display(),
            release = dir.path().join("release").display()
        ),
    )
    .expect("write server");

    let backend = stoppable_backend_with_command(
        &format!("sh {}", server.display()),
        Duration::from_secs(60),
    );

    let starter = {
        let backend = Arc::clone(&backend);
        tokio::spawn(async move { backend.ensure_started().await })
    };

    // The child blocks on a release file written once stop() has set its latch.
    // A gate that times out ends the child: it never reaches the handshake.
    let deadline = std::time::Instant::now() + Duration::from_millis(2500);
    while !std::fs::read_to_string(&pidfile).is_ok_and(|pid| !pid.trim().is_empty())
        && std::time::Instant::now() < deadline
    {
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    let pid = std::fs::read_to_string(&pidfile)
        .expect("child recorded its pid before shutdown")
        .trim()
        .to_string();
    let alive = || {
        std::process::Command::new("kill")
            .args(["-0", &pid])
            .status()
            .is_ok_and(|s| s.success())
    };
    assert!(alive(), "precondition: the racing start's child is running");

    let release = dir.path().join("release");
    let (gate, released) = (Arc::clone(&backend), release.clone());
    tokio::spawn(async move {
        while !gate.replaced_transport_cleanups.lock().stopping {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        std::fs::write(released, "").expect("release the child");
    });
    backend.stop().await.expect("stop");
    assert!(release.exists(), "child ran past the gate");

    // Checked BEFORE awaiting the starter: awaiting it first would only prove
    // the child dies EVENTUALLY (the publish refusal closes it). The claim is
    // that by the time stop() RETURNS, nothing it started is still running.
    assert!(
        !alive(),
        "stop() returned while the racing start's child (pid {pid}) was still \
         running; a start that has spawned but not yet published owns a live \
         process that the pool traversal cannot see"
    );
    assert!(
        backend.shared_entry().transport.read().is_none(),
        "a start published a transport into a backend that had already been \
         shut down; stop() has walked the pool and will not revisit it"
    );

    let _ = starter.await;
}

// GW.IDLE.RACE.11 - a start arriving AFTER shutdown must not spawn at all.
//
// The in-flight counter closes the case where a start was already running when
// shutdown began. It says nothing about one that arrives afterwards: `stop()`
// observes zero, returns, and the next request enters the start path with
// nothing to stop it. Waiting for the publish to refuse it is too late - the
// child is already spawned by then and lives for the length of a handshake.
//
// Ordering is what makes this airtight, and it is worth stating because it is
// easy to get backwards: the guard is taken BEFORE the latch is read. So either
// the increment lands first and shutdown's counter wait sees it, or the read
// happens after the latch was set and the start refuses. There is no ordering
// in which a start both escapes the counter and misses the latch.
//
#[cfg(unix)] // Unix-only: the witness is the process table, read via kill(1).
#[tokio::test(flavor = "multi_thread")]
async fn a_start_after_shutdown_never_spawns_a_child() {
    use crate::backend::RestartOutcome::SkippedStopping;
    let dir = tempfile::tempdir().expect("create temp dir");
    let log = dir.path().join("spawns");
    let backend = stoppable_backend_with_command(
        &format!("sh -c 'echo spawn >> {}; sleep 5'", log.display()),
        Duration::from_secs(60),
    );

    backend.stop().await.expect("stop");
    assert_eq!(
        spawn_count(&log),
        0,
        "precondition: nothing was started before shutdown"
    );

    // Every ordinary route into the start path, after shutdown has returned.
    let started = backend.ensure_started().await;
    let restarted = backend.force_restart().await;

    assert!(
        started.is_err(),
        "a stopped backend reported a successful start"
    );
    assert!(
        matches!(restarted, Ok(SkippedStopping)),
        "force_restart on a stopped backend should report that it did nothing, \
         got {restarted:?}"
    );
    assert_eq!(
        spawn_count(&log),
        0,
        "a start after shutdown spawned a child process; it is closed only when \
         the publish refuses it, so it runs for the length of a handshake with \
         shutdown already finished"
    );
    assert!(
        backend.shared_entry().transport.read().is_none(),
        "a stopped backend was given a live transport"
    );
}

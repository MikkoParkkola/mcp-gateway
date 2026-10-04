// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Wedged and slow closes, concurrent stops and child reaping.

use super::*;

/// Never finishes closing. Models the real hang the shutdown path already
/// guards against: `StdioTransport::close` waits on the writer mutex, which a
/// request blocked writing to a child that stopped reading holds forever.
struct WedgedCloseMock;

#[async_trait]
impl Transport for WedgedCloseMock {
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
        std::future::pending::<()>().await;
        Ok(())
    }
}

// One wedged backend must not cost every OTHER backend its idle stop.
//
// The sweep walks backends one after another inside a single task, so an
// unbounded close here is not a local delay: the loop never reaches the next
// backend, never ticks again, and the feature silently stops working for the
// whole gateway. The shutdown path already bounds close() for this exact
// reason; the idle path has the same hazard and needs the same bound.
#[tokio::test(start_paused = true)]
async fn a_wedged_close_cannot_wedge_the_idle_sweep() {
    let mut backend = stoppable_backend(Duration::from_secs(1));
    {
        let b = Arc::get_mut(&mut backend).expect("sole owner before the test starts");
        b.budgets.close_stage = Duration::from_secs(10);
    }
    backend.set_transport_for_test(Arc::new(WedgedCloseMock));
    backend
        .pool
        .get(&PoolKey::Shared)
        .unwrap()
        .value()
        .last_used
        .store(0, Ordering::Relaxed);

    // Generous relative to the 10s budget: this asserts the close is bounded at
    // all, not where the bound sits.
    let stopped = tokio::time::timeout(Duration::from_secs(600), backend.stop_if_idle())
        .await
        .expect("a close that never finishes must be abandoned, not awaited forever");

    assert!(
        stopped,
        "the transport was taken out of the pool, so the slot is stopped whether or not \
         the child died with it"
    );
    assert_eq!(
        backend.lifecycle(),
        BackendLifecycle::Dormant,
        "abandoning the close must still leave the slot stopped, not half-running"
    );
}

/// Closes slowly, so a caller that returns without waiting is visible.
struct SlowCloseMock {
    closed: Arc<AtomicBool>,
}

#[async_trait]
impl Transport for SlowCloseMock {
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
        tokio::time::sleep(Duration::from_secs(30)).await;
        self.closed.store(true, Ordering::SeqCst);
        Ok(())
    }
}

// GW.IDLE.RACE.12 - stop() must be single-flight, not merely idempotent.
//
// "stop returned" has to mean "everything is closed". Otherwise one caller can
// let the runtime exit while another's cleanup is still running, and the child
// processes this feature exists to reclaim survive anyway. The gateway exposes
// several concurrent reload and shutdown entry points, so "callers must not
// race" was never a contract anyone could honour.
//
// Reaching that window takes work, and three earlier attempts each failed for a
// DIFFERENT reason - worth listing, because each looked like a working test:
//
//   1. Two concurrent stops, slow close: passes without the gate, because the
//      lifecycle write guard serialises them anyway.
//   2. Same with a reader held so both lose that guard: still passes, because
//      the second caller waits out its OWN lifecycle timeout, which with the
//      shipped budgets outlasts the first caller's close.
//   3. Close made longer than that timeout: the close-stage budget aborts it
//      first, so the test measures that instead.
//
// The window is closed by an accident of the shipped budgets, not by design.
// So this test sets its own: a short lifecycle wait and a long close stage, so
// the second caller's timeout expires while the first is still closing. Paused
// time keeps it free.
#[tokio::test(start_paused = true)]
async fn concurrent_stops_wait_for_one_teardown() {
    let mut backend =
        stoppable_backend_with_command("/nonexistent-mcp-binary", Duration::from_secs(60));
    {
        let b = Arc::get_mut(&mut backend).expect("sole owner before the test starts");
        b.budgets.lifecycle_wait = Duration::from_secs(1);
        b.budgets.close_stage = Duration::from_secs(120);
        b.budgets.drain = Duration::from_secs(1);
    }

    let closed = Arc::new(AtomicBool::new(false));
    backend.set_transport_for_test(Arc::new(SlowCloseMock {
        closed: Arc::clone(&closed),
    }));

    // Deny lifecycle exclusion to BOTH callers so each times out and proceeds
    // without it - the state in which nothing but the single-flight gate makes
    // the second one wait.
    let _restart_in_flight = backend.lifecycle.read().await;

    let second = {
        let backend = Arc::clone(&backend);
        let closed = Arc::clone(&closed);
        tokio::spawn(async move {
            backend.stop().await.expect("second stop");
            closed.load(Ordering::SeqCst)
        })
    };

    backend.stop().await.expect("first stop");
    assert!(
        closed.load(Ordering::SeqCst),
        "stop() returned before the transport was closed"
    );
    assert!(
        second.await.expect("second stop task panicked"),
        "a concurrent stop() returned while the transport was still closing; \
         that caller can now let the runtime exit with children alive"
    );
}

// THE QUESTION. close() times out inside stop_if_idle -- is the child orphaned?
//
// Real time, not start_paused: the reap is done by the OS plus tokio's orphan
// queue, and paused time would burn the whole poll loop in zero real time.
#[cfg(unix)]
#[tokio::test]
async fn a_close_that_times_out_still_reaps_the_child() {
    let (child, pid) = spawn_probe_child().await;

    let mut backend = stoppable_backend(Duration::from_secs(1));
    {
        let b = Arc::get_mut(&mut backend).expect("sole owner before the test starts");
        b.budgets.close_stage = Duration::from_millis(100);
    }
    // Constructed inline on purpose: a local binding would leave a stray Arc
    // clone alive and silently turn this into the control test below.
    backend.set_transport_for_test(Arc::new(RealChildWedgedClose {
        child: tokio::sync::Mutex::new(Some(child)),
    }));
    backend
        .pool
        .get(&PoolKey::Shared)
        .expect("the pool entry exists once a transport is installed")
        .value()
        .last_used
        .store(0, Ordering::Relaxed);

    assert!(
        backend.stop_if_idle().await,
        "stop_if_idle must report a stop even when close() times out"
    );

    for _ in 0..40 {
        if super::eviction_close_bound_tests::is_reaped(pid) {
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    let state = process_state(pid).unwrap_or_else(|| "<gone>".to_string());
    let _ = std::process::Command::new("kill")
        .args(["-9", &pid.to_string()])
        .status();
    panic!(
        "child {pid} still alive 2s after close() timed out (ps stat = {state}); \
         the idle sweep leaked a process the gateway can no longer reach"
    );
}

// CONTROL. Same wedged close, but one Arc clone outlives the sweep.
//
// Two jobs. It proves the probe above can actually observe a survivor (a probe
// that always reports "reaped" proves nothing), and it isolates the mechanism:
// what reaps the child is the pool dropping the LAST Arc, not close() itself.
#[cfg(unix)]
#[tokio::test]
async fn a_surviving_transport_clone_orphans_the_child() {
    let (child, pid) = spawn_probe_child().await;

    let mut backend = stoppable_backend(Duration::from_secs(1));
    {
        let b = Arc::get_mut(&mut backend).expect("sole owner before the test starts");
        b.budgets.close_stage = Duration::from_millis(100);
    }
    let survivor: Arc<dyn Transport> = Arc::new(RealChildWedgedClose {
        child: tokio::sync::Mutex::new(Some(child)),
    });
    backend.set_transport_for_test(Arc::clone(&survivor));
    backend
        .pool
        .get(&PoolKey::Shared)
        .expect("the pool entry exists once a transport is installed")
        .value()
        .last_used
        .store(0, Ordering::Relaxed);

    assert!(
        backend.stop_if_idle().await,
        "stop_if_idle must report a stop"
    );

    tokio::time::sleep(Duration::from_millis(500)).await;
    let alive = is_alive(pid);

    drop(survivor);
    for _ in 0..40 {
        if !is_alive(pid) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let _ = std::process::Command::new("kill")
        .args(["-9", &pid.to_string()])
        .status();

    assert!(
        alive,
        "child {pid} died even though a transport clone was still held; \
         the reap is then NOT tied to dropping the last Arc and the sibling \
         test's verdict does not mean what it claims"
    );
}

// The leak question, independent of reachability: if a caller-scoped clone DOES
// outlive the sweep (ops.rs:25 / lifecycle.rs:1029 shape), is the child lost, or
// merely reaped late? Function-scoped clone, dropped at scope end, no explicit
// kill in the measured window.
#[cfg(unix)]
#[tokio::test]
async fn a_caller_scoped_clone_delays_the_reap_but_does_not_leak_it() {
    let (child, pid) = spawn_probe_child().await;

    let mut backend = stoppable_backend(Duration::from_secs(1));
    {
        let b = Arc::get_mut(&mut backend).expect("sole owner before the test starts");
        b.budgets.close_stage = Duration::from_millis(100);
    }
    let transport: Arc<dyn Transport> = Arc::new(RealChildWedgedClose {
        child: tokio::sync::Mutex::new(Some(child)),
    });
    backend.set_transport_for_test(Arc::clone(&transport));
    backend
        .pool
        .get(&PoolKey::Shared)
        .expect("the pool entry exists once a transport is installed")
        .value()
        .last_used
        .store(0, Ordering::Relaxed);

    {
        // Stands in for the caller's local `let transport = self.shared_transport()`.
        let _caller_scoped = Arc::clone(&transport);
        drop(transport); // the pool's Arc and this one are now the only strong refs

        assert!(
            backend.stop_if_idle().await,
            "stop_if_idle must report a stop"
        );
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert!(
            is_alive(pid),
            "child {pid} died while the caller still held the transport"
        );
    } // caller's frame ends here — nothing else references the transport

    for _ in 0..40 {
        if !is_alive(pid) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let leaked = is_alive(pid);
    let _ = std::process::Command::new("kill")
        .args(["-9", &pid.to_string()])
        .status();

    assert!(
        !leaked,
        "child {pid} was still alive 2s after the last transport clone left \
         scope: the child is LEAKED, not merely reaped late"
    );
}

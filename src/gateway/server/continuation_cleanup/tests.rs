use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Weak};
use std::time::Duration;

use tokio::sync::mpsc::{UnboundedReceiver, unbounded_channel};

use super::{CleanupEvent, CleanupRuntime, spawn_cleanup};
use crate::gateway::server::AbortOnDrop;
use crate::protocol::continuation::{ContinuationState, Routing, TestScanBarrier};

const T: u64 = 1_000;
const TICK: Duration = Duration::from_secs(1);

/// Keep a runnable waker while waiting so Tokio cannot auto-advance paused time.
/// Real time is only a deadlock watchdog; it never decides a passing interval.
async fn without_advancing_time<F: std::future::Future>(future: F) -> Option<F::Output> {
    use std::task::Poll;
    let before = tokio::time::Instant::now();
    let watchdog = std::time::Instant::now() + Duration::from_secs(5);
    let mut future = std::pin::pin!(future);
    let result = std::future::poll_fn(|cx| match future.as_mut().poll(cx) {
        Poll::Ready(value) => Poll::Ready(Some(value)),
        Poll::Pending if std::time::Instant::now() >= watchdog => Poll::Ready(None),
        Poll::Pending => {
            cx.waker().wake_by_ref();
            Poll::Pending
        }
    })
    .await;
    assert_eq!(
        tokio::time::Instant::now(),
        before,
        "observation advanced the injected scheduler clock"
    );
    result
}

struct Fixture {
    state: Arc<ContinuationState>,
    epoch: Arc<AtomicU64>,
    events: UnboundedReceiver<CleanupEvent>,
    guard: AbortOnDrop,
    ready: bool,
    clock_calls: Arc<AtomicU64>,
    scans: Arc<AtomicU64>,
}

impl Fixture {
    async fn start() -> Self {
        let state = Arc::new(ContinuationState::new());
        let epoch = Arc::new(AtomicU64::new(T));
        let (sender, mut events) = unbounded_channel();
        let clock = Arc::clone(&epoch);
        let clock_calls = Arc::new(AtomicU64::new(0));
        let calls = Arc::clone(&clock_calls);
        let scans = Arc::new(AtomicU64::new(0));
        let handle = spawn_cleanup(
            Arc::downgrade(&state),
            CleanupRuntime {
                epoch: Arc::new(move || {
                    calls.fetch_add(1, Ordering::SeqCst);
                    clock.load(Ordering::SeqCst)
                }),
                events: Some(sender),
                scans: Some(Arc::clone(&scans)),
            },
        );
        // Record missing readiness without aborting setup: occupancy assertions
        // still expose absent cleanup on the scaffolding baseline.
        let ready = matches!(
            without_advancing_time(events.recv()).await,
            Some(Some(CleanupEvent::Ready))
        );
        Self {
            state,
            epoch,
            events,
            guard: AbortOnDrop::new(handle),
            ready,
            clock_calls,
            scans,
        }
    }

    async fn tick(&mut self, epoch: u64) -> Option<usize> {
        self.epoch.store(epoch, Ordering::SeqCst);
        tokio::time::advance(TICK).await;
        match without_advancing_time(self.events.recv()).await {
            Some(Some(CleanupEvent::Scanned { removed })) => Some(removed),
            _ => None,
        }
    }

    async fn hold(&self, deadline: u64) -> String {
        self.state
            .in_flight()
            .hold("fixture", deadline, T)
            .await
            .expect("live fixture admission")
    }
}

#[tokio::test(start_paused = true)]
async fn expiry_1_idle_tick_reclaims_only_the_expired_record() {
    let mut fixture = Fixture::start().await;
    let expired = fixture.hold(T + 2).await;
    let live = fixture.hold(T + 100).await;
    let scan = fixture.tick(T + 3).await;
    let raw = fixture.state.in_flight().snapshot().await;
    assert!(
        !raw.contains_key(&expired),
        "idle worker left expired state resident"
    );
    assert_eq!(raw.get(&live), Some(&(T + 100)), "live state was discarded");
    assert_eq!(raw.len(), 1);
    assert_eq!(
        scan,
        Some(1),
        "reclaimed count must reflect the scan itself"
    );
    assert!(fixture.ready);
}

#[tokio::test(start_paused = true)]
async fn expiry_2_deadline_equality_is_live_then_next_epoch_expires() {
    let mut fixture = Fixture::start().await;
    let key = fixture.hold(T + 2).await;
    let equality_scan = fixture.tick(T + 2).await;
    assert_eq!(
        fixture.state.in_flight().snapshot().await.get(&key),
        Some(&(T + 2))
    );
    let expired_scan = fixture.tick(T + 3).await;
    assert!(
        !fixture
            .state
            .in_flight()
            .snapshot()
            .await
            .contains_key(&key)
    );
    assert_eq!(equality_scan, Some(0));
    assert_eq!(expired_scan, Some(1));
}

#[tokio::test(start_paused = true)]
async fn expiry_7_backwards_epoch_defers_expiry_without_freezing_ticks() {
    let mut fixture = Fixture::start().await;
    let key = fixture.hold(T + 2).await;
    let backwards = fixture.tick(T - 100).await;
    assert!(
        fixture
            .state
            .in_flight()
            .snapshot()
            .await
            .contains_key(&key)
    );
    let forward = fixture.tick(T + 3).await;
    assert!(
        !fixture
            .state
            .in_flight()
            .snapshot()
            .await
            .contains_key(&key)
    );
    assert_eq!(backwards, Some(0));
    assert_eq!(forward, Some(1));
}

#[tokio::test(start_paused = true)]
async fn expiry_7_missed_ticks_are_skipped_instead_of_bursting() {
    let mut fixture = Fixture::start().await;
    let expired = fixture.hold(T + 2).await;
    let live = fixture.hold(T + 100).await;
    fixture.epoch.store(T + 3, Ordering::SeqCst);
    tokio::time::advance(Duration::from_secs(10)).await;
    assert_eq!(
        without_advancing_time(fixture.events.recv()).await,
        Some(Some(CleanupEvent::Scanned { removed: 1 }))
    );
    let raw = fixture.state.in_flight().snapshot().await;
    assert!(!raw.contains_key(&expired));
    assert!(raw.contains_key(&live));
    // Let the ready worker poll again without advancing virtual time.
    for _ in 0..16 {
        tokio::task::yield_now().await;
    }
    assert_eq!(
        fixture.events.try_recv(),
        Err(tokio::sync::mpsc::error::TryRecvError::Empty)
    );
    assert_eq!(fixture.scans.load(Ordering::SeqCst), 1);
    assert!(fixture.ready);
}

#[tokio::test(start_paused = true)]
async fn expiry_5_drop_aborts_worker_and_releases_clock_capture() {
    let mut fixture = Fixture::start().await;
    assert_eq!(fixture.tick(T).await, Some(0));
    let Fixture {
        state,
        epoch,
        mut events,
        guard,
        ready,
        clock_calls,
        scans,
    } = fixture;
    let weak_clock = Arc::downgrade(&epoch);
    drop(epoch);
    let before = (
        clock_calls.load(Ordering::SeqCst),
        scans.load(Ordering::SeqCst),
    );
    drop(guard);
    assert_eq!(without_advancing_time(events.recv()).await, Some(None));
    assert!(
        weak_clock.upgrade().is_none(),
        "cancelled worker retained clock"
    );
    for _ in 0..3 {
        tokio::time::advance(TICK).await;
        tokio::task::yield_now().await;
        assert_eq!(
            (
                clock_calls.load(Ordering::SeqCst),
                scans.load(Ordering::SeqCst)
            ),
            before
        );
        assert_eq!(
            events.try_recv(),
            Err(tokio::sync::mpsc::error::TryRecvError::Disconnected)
        );
    }
    assert!(state.in_flight().snapshot().await.is_empty());
    assert!(ready);
}

#[tokio::test(start_paused = true)]
async fn expiry_5_worker_does_not_keep_continuation_state_alive() {
    let fixture = Fixture::start().await;
    let Fixture {
        state,
        epoch: _,
        mut events,
        guard,
        ready,
        clock_calls,
        scans,
    } = fixture;
    let weak: Weak<ContinuationState> = Arc::downgrade(&state);
    drop(state);
    assert!(
        weak.upgrade().is_none(),
        "worker owns a strong state reference while idle"
    );
    tokio::time::advance(TICK).await;
    assert_eq!(without_advancing_time(events.recv()).await, Some(None));
    let before = (
        clock_calls.load(Ordering::SeqCst),
        scans.load(Ordering::SeqCst),
    );
    tokio::time::advance(Duration::from_secs(3)).await;
    tokio::task::yield_now().await;
    assert_eq!(
        (
            clock_calls.load(Ordering::SeqCst),
            scans.load(Ordering::SeqCst)
        ),
        before
    );
    drop(guard);
    assert!(ready);
}

#[tokio::test(start_paused = true)]
async fn expiry_6_scan_races_observers_without_losing_live_entries() {
    let mut fixture = Fixture::start().await;
    let expired = fixture.hold(T + 2).await;
    let live = fixture.hold(T + 100).await;
    let completed = fixture.hold(T + 100).await;
    for _ in 3..4096 {
        fixture.hold(T + 100).await;
    }
    let barrier = Arc::new(TestScanBarrier::default());
    fixture
        .state
        .in_flight()
        .set_scan_barrier(Arc::clone(&barrier));
    fixture.epoch.store(T + 3, Ordering::SeqCst);
    tokio::time::advance(TICK).await;
    assert!(
        without_advancing_time(barrier.entered.notified())
            .await
            .is_some(),
        "scheduled worker never acquired scan lock"
    );
    let state = Arc::clone(&fixture.state);
    let hold = tokio::spawn(async move { state.in_flight().hold("racing", T + 100, T + 3).await });
    let state = Arc::clone(&fixture.state);
    let route_key = live.clone();
    let route = tokio::spawn(async move { state.in_flight().route(&route_key, T + 3).await });
    let state = Arc::clone(&fixture.state);
    let complete_key = completed.clone();
    let complete =
        tokio::spawn(async move { state.in_flight().complete(&complete_key, T + 3).await });
    for _ in 0..16 {
        tokio::task::yield_now().await;
    }
    assert!(
        !hold.is_finished() && !route.is_finished() && !complete.is_finished(),
        "worker released table lock before scan/observers contended"
    );
    barrier.release.notify_one();
    let admitted = without_advancing_time(hold)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(
        without_advancing_time(route)
            .await
            .expect("route did not finish")
            .expect("route task failed"),
        Routing::Here
    );
    assert!(
        without_advancing_time(complete)
            .await
            .expect("complete did not finish")
            .expect("complete task failed")
    );
    assert_eq!(
        without_advancing_time(fixture.events.recv()).await,
        Some(Some(CleanupEvent::Scanned { removed: 1 }))
    );
    let raw = fixture.state.in_flight().snapshot().await;
    assert!(!raw.contains_key(&expired));
    assert!(!raw.contains_key(&completed));
    assert!(raw.contains_key(&live));
    assert!(
        raw.contains_key(&admitted),
        "scan lost concurrent insertion"
    );
    assert_eq!(raw.len(), 4095);
}

#[tokio::test(start_paused = true)]
async fn expiry_1_cleanup_does_not_depend_on_test_event_telemetry() {
    let state = Arc::new(ContinuationState::new());
    let key = state.in_flight().hold("fixture", T + 2, T).await.unwrap();
    let epoch = Arc::new(AtomicU64::new(T));
    let callback = Arc::clone(&epoch);
    let guard = AbortOnDrop::new(spawn_cleanup(
        Arc::downgrade(&state),
        CleanupRuntime {
            epoch: Arc::new(move || callback.load(Ordering::SeqCst)),
            events: None,
            scans: None,
        },
    ));
    // Ensure spawn gets a poll turn before the exact interval starts.
    tokio::task::yield_now().await;
    epoch.store(T + 3, Ordering::SeqCst);
    tokio::time::advance(TICK).await;
    let observed = without_advancing_time(async {
        loop {
            if !state.in_flight().snapshot().await.contains_key(&key) {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await;
    assert_eq!(
        observed,
        Some(()),
        "normal production-shaped runtime did not clean without test telemetry"
    );
    drop(guard);
}

#[tokio::test]
async fn expiry_1_direct_scan_reports_exact_removed_count_without_observers() {
    let state = ContinuationState::new();
    let table = state.in_flight();
    let expired_a = table.hold("fixture", T + 1, T).await.unwrap();
    let expired_b = table.hold("fixture", T + 2, T).await.unwrap();
    let live = table.hold("fixture", T + 3, T).await.unwrap();
    let removed = table.reclaim_now(T + 3).await;
    let raw = table.snapshot().await;
    assert_eq!(removed, 2);
    assert!(!raw.contains_key(&expired_a));
    assert!(!raw.contains_key(&expired_b));
    assert_eq!(raw.get(&live), Some(&(T + 3)));
    assert_eq!(raw.len(), 1);
    assert_eq!(table.reclaim_now(T + 3).await, 0);
}

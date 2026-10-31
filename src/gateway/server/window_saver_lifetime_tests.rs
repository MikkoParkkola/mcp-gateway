// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The saver's writer threads and the seal: no segment opens after the seal,
//! and the saver's handle covers every writer it spawned.

use super::*;

/// Bound on each wait for something that must happen (a hang guard); local
/// so the timing gate resolves it in this file.
const ARRIVAL: Duration = Duration::from_secs(30);

/// The data directory below `rig`, made unwritable (a file stands where it
/// should be) so the saver's first open fails.
fn unwritable_data_dir(rig: &Rig) -> std::path::PathBuf {
    let data_dir = rig.dir.path().join("data");
    std::fs::write(&data_dir, "not a directory").expect("plant a file");
    data_dir
}

fn make_writable(data_dir: &std::path::Path) {
    std::fs::remove_file(data_dir).expect("remove the plant");
    std::fs::create_dir(data_dir).expect("a writable directory");
}

/// W1: an open that failed, a checkpoint spawned before the broadcast and held
/// before it tries the sink, the seal run to completion, the directory
/// writable again: released after the seal, the checkpoint opens no segment.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn no_segment_opens_after_the_seal() {
    let rig = Rig::new();
    let data_dir = unwritable_data_dir(&rig);
    let path = window::window_paths(&data_dir).0;
    let (held_in, held_go) = stall_seam::arm(&path, Role::BeforeLock);
    let (sealed_in, sealed_go) = stall_seam::arm(&path, Role::Sealed);
    drop(sealed_go); // an acknowledgement only: the seal is not held
    let (done_in, done_go) = stall_seam::arm(&path, Role::CheckpointDone);
    drop(done_go);
    let saver = start_window_saver(
        ProtocolRevisionWindow::Record,
        data_dir.clone(),
        "127.0.0.1:39401".parse().expect("address"),
        rig.counts(),
        rig.shutdown.subscribe(),
        SaverSettings {
            every: Duration::from_millis(50),
            ..settings(ARRIVAL)
        },
    )
    .await
    .expect("a failed open still serves");
    held_in
        .recv_timeout(ARRIVAL)
        .expect("a checkpoint is held before the sink");
    make_writable(&data_dir);
    rig.shutdown.send(()).expect("the saver subscribed");
    sealed_in
        .recv_timeout(ARRIVAL)
        .expect("the seal ran to completion");
    // One held checkpoint, alone at the sink: every other one is still held.
    held_go.send(()).expect("release one checkpoint");
    done_in
        .recv_timeout(ARRIVAL)
        .expect("the released checkpoint ended");
    drop(held_go); // release the rest
    tokio::time::timeout(ARRIVAL, saver)
        .await
        .expect("the saver ends")
        .expect("the saver does not panic");
    let segments = window::load(&data_dir).map_or_else(|_| Vec::new(), |w| w.http_segments);
    assert!(
        segments.is_empty(),
        "a segment opened after the seal: {segments:?}"
    );
}

/// Settings with a checkpoint every 50 ms and the given close bound.
fn quick(close_bound: Duration) -> SaverSettings {
    SaverSettings {
        every: Duration::from_millis(50),
        ..settings(close_bound)
    }
}

/// The drain's warning when a write outlives the close bound.
const STILL_RUNNING: &str = "a window write is still running";

/// Wait for a gate signal off this thread: the rows that read the saver's
/// warnings run on one thread, which a blocking wait would stall.
async fn arrive(signal: std::sync::mpsc::Receiver<()>) -> std::sync::mpsc::Receiver<()> {
    tokio::task::spawn_blocking(move || {
        signal.recv_timeout(ARRIVAL).expect("the signal arrives");
        signal
    })
    .await
    .expect("the wait does not panic")
}

/// W2a: a checkpoint held before it takes the sink, through the seal: the
/// saver is still pending once it drains, and its handle resolves only after
/// that checkpoint ends, with no NOT_DURABLE warning. One thread, so the
/// saver task logs into this test's capture.
#[tokio::test]
async fn the_handle_waits_for_a_write_in_flight() {
    let (_log, still_running) = crate::test_log_capture::live_count(STILL_RUNNING);
    let rig = Rig::new();
    let path = rig.window_path();
    let (held_in, held_go) = stall_seam::arm(&path, Role::BeforeLock);
    let (draining_in, draining_go) = stall_seam::arm(&path, Role::Draining);
    drop(draining_go);
    let (done_in, done_go) = stall_seam::arm(&path, Role::CheckpointDone);
    drop(done_go);
    let saver = rig
        .start(ProtocolRevisionWindow::Record, quick(ARRIVAL))
        .await
        .expect("record");
    let _held_in = arrive(held_in).await;
    rig.shutdown.send(()).expect("the saver subscribed");
    let _draining_in = arrive(draining_in).await;
    assert!(
        !saver.is_finished(),
        "the handle resolved with a write in flight"
    );
    assert!(
        done_in.try_recv().is_err(),
        "premise: the held checkpoint has not ended"
    );
    drop(held_go);
    tokio::time::timeout(ARRIVAL, saver)
        .await
        .expect("the saver ends once its writers do")
        .expect("the saver does not panic");
    assert!(
        done_in.try_recv().is_ok(),
        "the handle resolved before the held checkpoint ended"
    );
    assert_eq!(
        *still_running.borrow(),
        0,
        "a drain within its bound reported the window not durable"
    );
}

/// W2b: a checkpoint held past the bound: the handle resolves at the bound
/// with the checkpoint still held and warns NOT_DURABLE once; the
/// checkpoint, released, ends before the row does.
#[tokio::test]
async fn a_write_held_past_the_bound_does_not_hold_the_handle() {
    let (_log, still_running) = crate::test_log_capture::live_count(STILL_RUNNING);
    let rig = Rig::new();
    let path = rig.window_path();
    let (held_in, held_go) = stall_seam::arm(&path, Role::BeforeLock);
    let (done_in, done_go) = stall_seam::arm(&path, Role::CheckpointDone);
    drop(done_go);
    let saver = rig
        .start(ProtocolRevisionWindow::Record, quick(CLOSE_BOUND))
        .await
        .expect("record");
    let held_in = arrive(held_in).await;
    stop(&rig, saver).await;
    assert_eq!(
        *still_running.borrow(),
        1,
        "a drain past its bound did not report the window not durable"
    );
    assert!(
        done_in.try_recv().is_err(),
        "premise: the checkpoint is still held"
    );
    // No checkpoint spawns once the saver has stopped: every one held at the
    // gate has entered it by now, and each ends before the row does.
    let held = 1 + held_in.try_iter().count();
    drop(held_go);
    for _ in 0..held {
        done_in
            .recv_timeout(ARRIVAL)
            .expect("a released checkpoint ends before the row does");
    }
    assert!(rig.writes_ended(), "a released checkpoint never ended");
}

/// W2c: the last writer ends after `idle` read a nonzero count and before it
/// awaited: the drain still resolves, because its `Notified` future was
/// created before the read.
#[tokio::test]
async fn the_drain_sees_a_writer_that_ends_before_its_await() {
    let writers = Arc::new(Writers::default());
    writers.running.fetch_add(1, Ordering::SeqCst);
    let ending = Arc::clone(&writers);
    *writers
        .between_read_and_await
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner) =
        Some(Box::new(move || ending.finished()));
    tokio::time::timeout(ARRIVAL, writers.idle())
        .await
        .expect("the last writer's wakeup was lost");
}

/// W2c: one writer ending wakes every drain waiting on it, not just one: the
/// wakeup is `notify_waiters`, never `notify_one`.
#[tokio::test]
async fn every_waiting_drain_wakes_when_the_last_writer_ends() {
    let writers = Writers::default();
    writers.running.fetch_add(1, Ordering::SeqCst);
    let first = writers.idle();
    let second = writers.idle();
    tokio::pin!(first, second);
    // Each drain is polled to its await, so both are parked on the wakeup
    // before the writer ends.
    assert!(
        futures::poll!(first.as_mut()).is_pending() && futures::poll!(second.as_mut()).is_pending(),
        "premise: both wait"
    );
    writers.finished();
    assert!(
        futures::poll!(first.as_mut()).is_ready() && futures::poll!(second.as_mut()).is_ready(),
        "a waiting drain was not woken"
    );
}

/// W2d: a writer that cannot start leaves no count behind, and a writer that
/// panics is uncounted as it unwinds: both drains resolve at once.
#[tokio::test]
async fn a_failed_spawn_or_a_panicking_writer_leaves_no_count() {
    let writers = Arc::new(Writers::default());
    writers.fail_next_spawn.store(true, Ordering::SeqCst);
    assert!(
        writers.spawn("refused", || {}).is_err(),
        "premise: the spawn failed"
    );
    assert_eq!(writers.running.load(Ordering::SeqCst), 0);
    tokio::time::timeout(ARRIVAL, writers.idle())
        .await
        .expect("a failed spawn left a count behind");
    let (ended, ended_rx) = std::sync::mpsc::channel::<()>();
    writers
        .spawn("panics", move || {
            let _ended = ended;
            panic!("a writer that panics");
        })
        .expect("the spawn starts");
    // The sender drops as the writer unwinds; the count is gone by then.
    let _ = ended_rx.recv_timeout(ARRIVAL);
    tokio::time::timeout(ARRIVAL, writers.idle())
        .await
        .expect("a panicking writer left a count behind");
}

/// Fails while set: a clock that can be made unreadable at the seal alone.
static CLOCK_FAILS: AtomicBool = AtomicBool::new(false);

fn clock_unreadable_at_the_seal() -> Result<u64, ClockBeforeEpoch> {
    if CLOCK_FAILS.load(Ordering::SeqCst) {
        Err(ClockBeforeEpoch)
    } else {
        crate::clock::unix_millis()
    }
}

/// W1b: a seal whose clock is unreadable writes no seal, but still leaves the
/// sink sealed: a checkpoint released after it writes nothing more.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_seal_with_no_clock_still_ends_the_writes() {
    let rig = Rig::new();
    let path = rig.window_path();
    let (held_in, held_go) = stall_seam::arm(&path, Role::BeforeLock);
    let (sealed_in, sealed_go) = stall_seam::arm(&path, Role::Sealed);
    drop(sealed_go);
    let (done_in, done_go) = stall_seam::arm(&path, Role::CheckpointDone);
    drop(done_go);
    let saver = rig
        .start(
            ProtocolRevisionWindow::Record,
            SaverSettings {
                clock_ms: clock_unreadable_at_the_seal,
                ..quick(ARRIVAL)
            },
        )
        .await
        .expect("record");
    assert_eq!(rig.segments().len(), 1, "premise: the segment opened");
    held_in
        .recv_timeout(ARRIVAL)
        .expect("a checkpoint is held before the sink");
    CLOCK_FAILS.store(true, Ordering::SeqCst);
    rig.shutdown.send(()).expect("the saver subscribed");
    sealed_in
        .recv_timeout(ARRIVAL)
        .expect("the seal ran to completion");
    CLOCK_FAILS.store(false, Ordering::SeqCst);
    rig.served.store(50, Ordering::SeqCst);
    held_go.send(()).expect("release one checkpoint");
    done_in
        .recv_timeout(ARRIVAL)
        .expect("the released checkpoint ended");
    drop(held_go);
    tokio::time::timeout(ARRIVAL, saver)
        .await
        .expect("the saver ends")
        .expect("the saver does not panic");
    let segment = rig.segments().remove(0);
    assert_ne!(
        segment.snapshot.total, 50,
        "a checkpoint wrote after the seal: {segment:?}"
    );
}

/// W1b: a seal whose close fails (the window unreadable while the close
/// runs) still leaves the sink sealed: a checkpoint released after it, into
/// a window readable again, writes nothing more.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_seal_whose_close_fails_still_ends_the_writes() {
    let rig = Rig::new();
    let path = rig.window_path();
    let (held_in, held_go) = stall_seam::arm(&path, Role::BeforeLock);
    let (close_in, close_go) = stall_seam::arm(&path, Role::Close);
    let (sealed_in, sealed_go) = stall_seam::arm(&path, Role::Sealed);
    drop(sealed_go);
    let (done_in, done_go) = stall_seam::arm(&path, Role::CheckpointDone);
    drop(done_go);
    let saver = rig
        .start(ProtocolRevisionWindow::Record, quick(ARRIVAL))
        .await
        .expect("record");
    held_in
        .recv_timeout(ARRIVAL)
        .expect("a checkpoint is held before the sink");
    rig.shutdown.send(()).expect("the saver subscribed");
    close_in.recv_timeout(ARRIVAL).expect("the close starts");
    let window = std::fs::read(&path).expect("read the window");
    std::fs::write(&path, b"not a window").expect("break the window");
    close_go.send(()).expect("release the close");
    sealed_in
        .recv_timeout(ARRIVAL)
        .expect("the seal ran to completion");
    std::fs::write(&path, window).expect("restore the window");
    rig.served.store(50, Ordering::SeqCst);
    held_go.send(()).expect("release one checkpoint");
    done_in
        .recv_timeout(ARRIVAL)
        .expect("the released checkpoint ended");
    drop(held_go);
    tokio::time::timeout(ARRIVAL, saver)
        .await
        .expect("the saver ends")
        .expect("the saver does not panic");
    let segment = rig.segments().remove(0);
    assert!(
        !segment.closed_cleanly,
        "premise: the close failed: {segment:?}"
    );
    assert_ne!(
        segment.snapshot.total, 50,
        "a checkpoint wrote after a failed seal: {segment:?}"
    );
}

/// W3: a saver started directly attributes its open to the starting test's
/// thread, though the open runs on a writer thread of its own.
#[tokio::test]
async fn the_window_open_names_the_test_that_started_the_saver() {
    let rig = Rig::new();
    let saver = rig
        .start(ProtocolRevisionWindow::Record, settings(ARRIVAL))
        .await
        .expect("record");
    assert_eq!(
        stall_seam::opened_by(&rig.window_path()).as_deref(),
        Some(crate::test_late_write::Creator::default().name()),
        "the window's opener is not this test"
    );
    stop(&rig, saver).await;
}

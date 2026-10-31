// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The saver's writer threads and the seal: no segment opens after the seal,
//! and the saver's handle covers every writer it spawned.

use super::*;

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

/// W2a: a checkpoint held before it takes the sink, through the seal: the
/// saver starts draining while it is held, and its handle resolves only
/// after that checkpoint ends.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_handle_waits_for_a_write_in_flight() {
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
    held_in
        .recv_timeout(ARRIVAL)
        .expect("a checkpoint is held before the sink");
    rig.shutdown.send(()).expect("the saver subscribed");
    draining_in
        .recv_timeout(ARRIVAL)
        .expect("the saver drains its writers after the seal");
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
}

/// W2b: a checkpoint held past the bound: the handle resolves at the bound
/// with the checkpoint still held, and the checkpoint, released, ends before
/// the row does.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_write_held_past_the_bound_does_not_hold_the_handle() {
    let rig = Rig::new();
    let path = rig.window_path();
    let (held_in, held_go) = stall_seam::arm(&path, Role::BeforeLock);
    let (done_in, done_go) = stall_seam::arm(&path, Role::CheckpointDone);
    drop(done_go);
    let saver = rig
        .start(ProtocolRevisionWindow::Record, quick(CLOSE_BOUND))
        .await
        .expect("record");
    held_in
        .recv_timeout(ARRIVAL)
        .expect("a checkpoint is held before the sink");
    stop(&rig, saver).await;
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
    let writers = Arc::new(Writers::default());
    writers.running.fetch_add(1, Ordering::SeqCst);
    let first = tokio::spawn({
        let writers = Arc::clone(&writers);
        async move { writers.idle().await }
    });
    let second = tokio::spawn({
        let writers = Arc::clone(&writers);
        async move { writers.idle().await }
    });
    // On this one-thread runtime each yield runs both spawned drains up to
    // their await, so both are parked on the wakeup before the writer ends.
    for _ in 0..3 {
        tokio::task::yield_now().await;
    }
    assert!(
        !first.is_finished() && !second.is_finished(),
        "premise: both wait"
    );
    writers.finished();
    tokio::time::timeout(ARRIVAL, async {
        first.await.expect("no panic");
        second.await.expect("no panic");
    })
    .await
    .expect("a waiting drain was not woken");
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

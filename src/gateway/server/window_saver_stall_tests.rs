// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Design rows 16, 18 and 20: writes that stall or fail around the open and
//! the seal. Each gate holds one role of write (`Open`, `Checkpoint`,
//! `Close`), so a periodic checkpoint can never stand in for the final write.

use super::*;

/// Bound on each wait for something that must happen (a hang guard); local
/// so the timing gate resolves it in this file.
const ARRIVAL: Duration = Duration::from_secs(30);

// The windows of the two elapsed-bound asserts in
// `a_stalled_open_delays_serving_by_its_bound_only`, declared here so the
// timing gate resolves each as a literal sum (5.2 s and 5.3 s: over its 5 s
// cutoff). Each repeats a value the parent file owns; the checks below keep
// the copies equal to it.
const ALLOWANCE: Duration = Duration::from_secs(5);
const CLOSE_BOUND: Duration = Duration::from_millis(300);
const OPEN_BOUND: Duration = Duration::from_millis(200);
const _: () = assert!(ALLOWANCE.as_millis() == super::ALLOWANCE.as_millis());
const _: () = assert!(CLOSE_BOUND.as_millis() == super::CLOSE_BOUND.as_millis());

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_stalled_checkpoint_never_overtakes_the_final_write() {
    // Row 16.
    let rig = Rig::new();
    let quick = SaverSettings {
        every: Duration::from_millis(50),
        ..settings(ARRIVAL)
    };
    let saver = rig
        .start(ProtocolRevisionWindow::Record, quick)
        .await
        .expect("record");
    rig.served.store(2, Ordering::SeqCst);
    let (checkpoint_in, checkpoint_go) = stall_seam::arm(&rig.window_path(), Role::Checkpoint);
    let (close_in, close_go) = stall_seam::arm(&rig.window_path(), Role::Close);
    checkpoint_in
        .recv_timeout(ARRIVAL)
        .expect("a checkpoint is in flight");
    rig.served.store(6, Ordering::SeqCst);
    rig.shutdown.send(()).expect("subscribed");
    assert!(
        wait_for(|| rig.seal.load(Ordering::SeqCst)),
        "the seal waits for no write"
    );
    assert!(
        close_in.try_recv().is_err(),
        "the final write ran while a checkpoint held the sink"
    );
    drop(checkpoint_go); // release this and every later checkpoint
    close_in
        .recv_timeout(ARRIVAL)
        .expect("the final write follows it");
    close_go.send(()).expect("release the final write");
    tokio::time::timeout(ARRIVAL, saver)
        .await
        .expect("bounded")
        .expect("no panic");
    let segment = rig.segments().remove(0);
    assert!(segment.closed_cleanly, "{segment:?}");
    assert_eq!(
        segment.snapshot.total, 6,
        "the checkpoint's older counts won"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_stalled_open_delays_serving_by_its_bound_only() {
    // Row 18 arm 1: never released.
    let rig = Rig::new();
    let (open_in, open_go) = stall_seam::arm(&rig.window_path(), Role::Open);
    let started = std::time::Instant::now();
    let saver = rig
        .start(ProtocolRevisionWindow::Record, stalled_open(CLOSE_BOUND))
        .await
        .expect("record");
    assert_eq!(
        stalled_open(CLOSE_BOUND).open_bound,
        OPEN_BOUND,
        "the local open bound drifted from the saver's settings"
    );
    // timing-oracle: vs WINDOW_OPEN_STARTUP_BOUND (MIK-7211)
    assert!(
        started.elapsed() < OPEN_BOUND + ALLOWANCE,
        "serving waited past the open bound: {:?}",
        started.elapsed()
    );
    open_in.recv_timeout(ARRIVAL).expect("the open started");
    let broadcast = std::time::Instant::now();
    stop(&rig, saver).await;
    // timing-oracle: vs CLOSE_BOUND (MIK-7211)
    assert!(broadcast.elapsed() < CLOSE_BOUND + ALLOWANCE);
    assert!(rig.seal.load(Ordering::SeqCst));
    assert!(rig.segments().is_empty(), "{:?}", rig.segments());
    drop(open_go);
    // Releasing the gate lets the open, then the abandoned final write, run
    // on their detached threads. Wait for the last one before the rig drops
    // its directory: a write landing mid-removal left the folder behind in
    // the shared temp directory.
    assert!(
        wait_for(|| rig.segments().first().is_some_and(|s| s.closed_cleanly)),
        "the released writes never landed: {:?}",
        rig.segments()
    );
    let root = rig.dir.path().to_owned();
    drop(rig);
    assert!(!root.exists(), "a write outlived the rig's directory");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_stalled_open_released_after_the_deadline_lands_the_sealed_counts() {
    // Row 18 arm 2: the final write was abandoned at the deadline but still
    // waits behind the open on its own thread; once the open lands, the
    // final write lands too, with exactly the sealed counts (late data is
    // correct data), never the counts served after the seal.
    let rig = Rig::new();
    let (open_in, open_go) = stall_seam::arm(&rig.window_path(), Role::Open);
    let saver = rig
        .start(ProtocolRevisionWindow::Record, stalled_open(CLOSE_BOUND))
        .await
        .expect("record");
    open_in.recv_timeout(ARRIVAL).expect("the open started");
    rig.served.store(2, Ordering::SeqCst);
    stop(&rig, saver).await;
    rig.served.store(50, Ordering::SeqCst);
    open_go.send(()).expect("release the open");
    let landed = wait_for(|| rig.segments().first().is_some_and(|s| s.closed_cleanly));
    assert!(
        landed,
        "the queued final write never landed: {:?}",
        rig.segments()
    );
    assert_eq!(rig.segments()[0].snapshot.total, 2);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_late_open_still_seals_one_clean_segment() {
    // Row 18 arm 3: the open times out at startup, then completes before
    // the shutdown deadline; the final write lands in it.
    let rig = Rig::new();
    let (open_in, open_go) = stall_seam::arm(&rig.window_path(), Role::Open);
    let saver = rig
        .start(ProtocolRevisionWindow::Record, stalled_open(ARRIVAL))
        .await
        .expect("record");
    open_in.recv_timeout(ARRIVAL).expect("the open started");
    rig.served.store(3, Ordering::SeqCst);
    rig.shutdown.send(()).expect("subscribed");
    assert!(wait_for(|| rig.seal.load(Ordering::SeqCst)));
    open_go.send(()).expect("release the open");
    tokio::time::timeout(ARRIVAL, saver)
        .await
        .expect("bounded")
        .expect("no panic");
    let segments = rig.segments();
    assert_eq!(segments.len(), 1, "{segments:?}");
    assert!(segments[0].closed_cleanly);
    assert_eq!(segments[0].snapshot.total, 3);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_failed_open_is_retried_and_records_every_count_since_start() {
    // Row 20: a file where the data directory should be fails the open.
    let rig = Rig::new();
    let data_dir = rig.dir.path().join("data");
    std::fs::write(&data_dir, "not a directory").expect("plant a file");
    rig.served.store(5, Ordering::SeqCst);
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
    std::fs::remove_file(&data_dir).expect("remove the plant");
    std::fs::create_dir(&data_dir).expect("a writable directory");
    let opened = wait_for(|| window::load(&data_dir).is_ok_and(|w| w.http_segments.len() == 1));
    assert!(opened, "a later tick never retried the open");
    stop(&rig, saver).await;
    let segment = window::load(&data_dir)
        .expect("reopen")
        .http_segments
        .remove(0);
    assert!(segment.closed_cleanly);
    assert_eq!(segment.snapshot.total, 5);
}

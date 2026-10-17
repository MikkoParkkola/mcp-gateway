// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Design rows 16, 18 and 20: writes that stall or fail around the open and
//! the seal. Each release is one `()` on the gate; every write to the window
//! file (the open included) passes the gate once.

use super::*;

#[tokio::test]
async fn a_stalled_checkpoint_never_overtakes_the_final_write() {
    // Row 16.
    let rig = Rig::new();
    let quick = SaverSettings {
        every: Duration::from_millis(50),
        ..settings(ARRIVAL)
    };
    let saver = rig.start(ProtocolRevisionWindow::Record, quick).await.expect("record");
    rig.served.store(2, Ordering::SeqCst);
    let (entered, release) = stall_seam::arm(&rig.window_path());
    entered.recv_timeout(ARRIVAL).expect("a checkpoint is in flight");
    rig.served.store(6, Ordering::SeqCst);
    rig.shutdown.send(()).expect("subscribed");
    assert!(
        wait_for(|| rig.seal.load(Ordering::SeqCst)),
        "the seal waits for no write"
    );
    release.send(()).expect("release the checkpoint");
    entered.recv_timeout(ARRIVAL).expect("the final write follows it");
    release.send(()).expect("release the final write");
    tokio::time::timeout(ARRIVAL, saver).await.expect("bounded").expect("no panic");
    let segment = rig.segments().remove(0);
    assert!(segment.closed_cleanly, "{segment:?}");
    assert_eq!(segment.snapshot.total, 6, "the checkpoint's older counts won");
}

#[tokio::test]
async fn a_stalled_open_delays_serving_by_its_bound_only() {
    // Row 18 arm 1: never released.
    let rig = Rig::new();
    let (entered, release) = stall_seam::arm(&rig.window_path());
    let started = std::time::Instant::now();
    let saver = rig
        .start(ProtocolRevisionWindow::Record, settings(Duration::from_millis(300)))
        .await
        .expect("record");
    entered.recv_timeout(ARRIVAL).expect("the open started");
    assert!(started.elapsed() < ARRIVAL, "serving waited past the open bound");
    stop(&rig, saver).await;
    assert!(rig.seal.load(Ordering::SeqCst));
    assert!(rig.segments().is_empty(), "{:?}", rig.segments());
    drop(release);
}

#[tokio::test]
async fn a_late_open_still_seals_one_clean_segment() {
    // Row 18 arm 3: the open times out at startup, then completes before
    // the shutdown deadline; the final write lands in it.
    let rig = Rig::new();
    let (entered, release) = stall_seam::arm(&rig.window_path());
    let saver = rig.start(ProtocolRevisionWindow::Record, settings(ARRIVAL)).await.expect("record");
    entered.recv_timeout(ARRIVAL).expect("the open started");
    rig.served.store(3, Ordering::SeqCst);
    rig.shutdown.send(()).expect("subscribed");
    assert!(wait_for(|| rig.seal.load(Ordering::SeqCst)));
    release.send(()).expect("release the open");
    entered.recv_timeout(ARRIVAL).expect("the final write follows the open");
    release.send(()).expect("release the final write");
    tokio::time::timeout(ARRIVAL, saver).await.expect("bounded").expect("no panic");
    let segments = rig.segments();
    assert_eq!(segments.len(), 1, "{segments:?}");
    assert!(segments[0].closed_cleanly);
    assert_eq!(segments[0].snapshot.total, 3);
}

#[tokio::test]
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
    let segment = window::load(&data_dir).expect("reopen").http_segments.remove(0);
    assert!(segment.closed_cleanly);
    assert_eq!(segment.snapshot.total, 5);
}

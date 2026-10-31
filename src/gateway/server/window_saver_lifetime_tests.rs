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

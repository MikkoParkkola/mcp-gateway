// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The first-snapshot measurement (kept, run by name). Helpers are the parent modules'.
use super::*;

/// The cost of the stop's first snapshot, the one the graceful handover takes
/// before it closes stdin: a fresh transport each time, so the sweep is built
/// and the table read cold. Printed as p50, p99 and max over 60 starts for a
/// lone process and for a four-member tree. Run by hand under load:
/// `cargo test --lib measure_the_first_snapshot -- --ignored --nocapture`.
#[tokio::test]
#[ignore = "a measurement, run by hand with --nocapture"]
async fn measure_the_first_snapshot_on_the_handover_path() {
    // M-SNAP is judged on a host of at least 1,000 processes: pad with idle
    // sleeps up to that (they end on their own), and print the count read.
    let procs = || {
        std::fs::read_dir("/proc").map_or(0, |d| {
            d.flatten()
                .filter(|e| {
                    e.file_name()
                        .to_string_lossy()
                        .bytes()
                        .all(|b| b.is_ascii_digit())
                })
                .count()
        })
    };
    let pad = 1_050_usize.saturating_sub(procs());
    let _padder = std::process::Command::new("sh")
        .arg("-c")
        .arg(format!(
            "i=0; while [ $i -lt {pad} ]; do sleep 900 & i=$((i+1)); done; wait"
        ))
        .spawn()
        .expect("padding");
    while procs() < 1_000 {
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    println!("host processes: {}", procs());
    let mut worst = Duration::ZERO;
    for (what, tail) in [
        ("lone process", "exec sleep 60"),
        (
            "four members",
            "sleep 60 &\nsleep 60 &\nsleep 60 &\nwhile :; do sleep 0.05; done",
        ),
    ] {
        let mut took = Vec::new();
        for _ in 0..60 {
            let (_w, t) = started(tail, None).await;
            // Let a backgrounded member be forked before the table is read.
            tokio::time::sleep(Duration::from_millis(100)).await;
            let at = std::time::Instant::now();
            t.child.lock().tree.as_mut().expect("tree").sweep_snapshot();
            took.push(at.elapsed());
            t.close().await.expect("close");
        }
        took.sort();
        println!(
            "snapshot {what}: p50 {:?} p99 {:?} max {:?}",
            took[took.len() / 2],
            took[took.len() * 99 / 100],
            took[took.len() - 1]
        );
        worst = worst.max(took[took.len() * 99 / 100]);
    }
    // The fail-fast bound: a p99 over the 5 ms slice sends the walk back.
    assert!(worst <= Duration::from_millis(5), "p99 {worst:?} over 5 ms");
}

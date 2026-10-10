// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Concurrent sinks on one data directory lose no counted request.
//!
//! `persist` holds an exclusive file lock across read, add and write of the
//! durable window. Each thread opens its own sink, as a separate gateway
//! process would. With the lock a no-op (non-unix before this fix), two
//! sinks read the same window and the second write drops the first's count.

use super::*;

#[test]
fn concurrent_sinks_count_every_request() {
    const SINKS: usize = 8;
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().to_path_buf();
    DurableTelemetrySink::open(&root).expect("create the window");
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(SINKS));
    let handles: Vec<_> = (0..SINKS)
        .map(|_| {
            let root = root.clone();
            let barrier = std::sync::Arc::clone(&barrier);
            std::thread::spawn(move || {
                let mut sink = DurableTelemetrySink::open(&root).expect("durable sink");
                let mut registry = Registry::new();
                registry.observe_request(Some("2025-11-25"), "codex", Transport::Stdio);
                barrier.wait();
                sink.persist_registry(&registry)
            })
        })
        .collect();
    for handle in handles {
        handle
            .join()
            .unwrap()
            .expect("a locked persist never fails");
    }
    assert_eq!(
        load_durable_window(&root).unwrap().snapshot.total,
        u64::try_from(SINKS).unwrap(),
        "a concurrent persist dropped another sink's count"
    );
}

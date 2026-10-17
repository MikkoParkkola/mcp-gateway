// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Design rows 5, 6, 8 and the sink half of 11 and 16: every row reopens the
//! file and asserts exact totals and lifecycle fields.

use std::collections::BTreeMap;

use super::*;

fn identity(started_ms: u64) -> WriterIdentity {
    WriterIdentity {
        listen: "127.0.0.1:39401".to_string(),
        exe: "/opt/mcp-gateway/mcp-gateway".to_string(),
        process_started_at_ms: started_ms,
    }
}

/// A directory where the atomic write's temporary file must be created, so
/// the next write fails before its rename (for root too). Returns its path.
fn block_the_temporary_file(data_dir: &std::path::Path) -> std::path::PathBuf {
    let blocker = window_paths(data_dir).0.with_extension("json.tmp");
    std::fs::create_dir(&blocker).expect("plant a directory at the temporary path");
    blocker
}

fn counts(http_requests: u64) -> SegmentCounts {
    // Built from the merged snapshot, so the sink rows judge only the sink:
    // every request here is HTTP, so the merged view is the HTTP slice.
    let mut registry = crate::protocol_revision_telemetry::Registry::new();
    for _ in 0..http_requests {
        registry.observe_request(None, "other", Transport::Http);
    }
    SegmentCounts {
        snapshot: registry.snapshot(),
        missing_revision_agents: BTreeMap::from([("curl".to_string(), http_requests)]),
        tools_list_shadow: empty_shadow_counts(),
    }
}

#[test]
fn a_v1_window_is_refused_and_left_byte_identical() {
    let dir = tempfile::tempdir().expect("tempdir");
    // A frozen v1 file, as 4.0.0 prereleases wrote it (not through today's
    // sink, which writes v2).
    let path = window_paths(dir.path()).0;
    std::fs::create_dir_all(path.parent().expect("parent")).expect("telemetry dir");
    let v1 = serde_json::json!({
        "schema_version": "mcp_protocol_revision_window.v1",
        "started_at_unix_seconds": 1_790_959_779_u64,
        "updated_at_unix_seconds": 1_790_959_800_u64,
        "snapshot": {"by_revision": {"2025-11-25": 3}, "by_client": {"claude": 3},
                     "by_transport": {"stdio": 3}, "unattributed": 0, "total": 3},
        "tools_list_shadow": empty_shadow_counts(),
    });
    std::fs::write(&path, serde_json::to_vec_pretty(&v1).expect("json")).expect("plant v1");
    let before = std::fs::read(&path).expect("v1 bytes");

    let error = HttpSegmentSink::open(dir.path(), identity(1_000), 1).expect_err("v1 is refused");
    assert!(error.to_string().contains("archive"), "{error}");
    assert_eq!(
        std::fs::read(&path).expect("bytes after"),
        before,
        "v1 was rewritten"
    );

    let stdio = crate::protocol_revision_telemetry::DurableTelemetrySink::open(dir.path())
        .expect_err("the stdio sink refuses v1 too");
    assert!(stdio.to_string().contains("archive"), "{stdio}");
    assert_eq!(
        std::fs::read(&path).expect("bytes after"),
        before,
        "v1 was rewritten"
    );
}

#[test]
fn two_process_lifetimes_keep_separate_exact_segments() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut first = HttpSegmentSink::open(dir.path(), identity(1_000), 10).expect("open first");
    first.checkpoint(&counts(3), 11).expect("checkpoint");
    first.close(&counts(4), 12, 12_500).expect("close first");
    let mut second = HttpSegmentSink::open(dir.path(), identity(13_000), 13).expect("open second");
    second
        .checkpoint(&counts(2), 14)
        .expect("checkpoint second");

    let window = load(dir.path()).expect("reopen");
    let totals: Vec<u64> = window
        .http_segments
        .iter()
        .map(|s| s.snapshot.total)
        .collect();
    assert_eq!(totals, vec![4, 2]);
    assert_eq!(window.http_segments[0].sealed_at_ms, Some(12_500));
    assert!(window.http_segments[0].closed_cleanly);
    assert!(!window.http_segments[1].closed_cleanly);
    assert_eq!(window.http_segments[1].sealed_at_ms, None);
    assert_eq!(
        window.http_segments[0].missing_revision_agents.get("curl"),
        Some(&4)
    );
}

#[test]
fn nothing_writes_a_segment_after_its_close() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut sink = HttpSegmentSink::open(dir.path(), identity(1_000), 10).expect("open");
    sink.close(&counts(5), 11, 11_000).expect("close");
    sink.checkpoint(&counts(1), 12)
        .expect("a checkpoint after close is a no-op");

    let segment = load(dir.path()).expect("reopen").http_segments[0].clone();
    assert!(
        segment.closed_cleanly,
        "a late checkpoint reopened the segment"
    );
    assert_eq!(
        segment.snapshot.total, 5,
        "a late checkpoint replaced the sealed counts"
    );
    assert_eq!(segment.last_checkpoint_at, 11);
}

#[test]
fn an_idle_interval_still_writes_a_checkpoint_and_an_empty_close_lands() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut sink = HttpSegmentSink::open(dir.path(), identity(1_000), 10).expect("open");
    sink.checkpoint(&SegmentCounts::empty(), 15)
        .expect("idle checkpoint");
    assert_eq!(
        load(dir.path()).expect("reopen").http_segments[0].last_checkpoint_at,
        15
    );
    sink.close(&SegmentCounts::empty(), 16, 16_000)
        .expect("close with no requests");
    let segment = load(dir.path()).expect("reopen").http_segments[0].clone();
    assert!(segment.closed_cleanly);
    assert_eq!(segment.snapshot.total, 0);
}

#[test]
fn a_failed_write_followed_by_a_success_loses_no_count() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut sink = HttpSegmentSink::open(dir.path(), identity(1_000), 10).expect("open");
    let blocker = block_the_temporary_file(dir.path());
    let failed = sink.checkpoint(&counts(3), 11);
    std::fs::remove_dir(&blocker).expect("unblock");
    assert!(
        failed.is_err(),
        "a blocked temporary file must fail the write"
    );
    assert_eq!(
        load(dir.path()).expect("reopen").http_segments[0]
            .snapshot
            .total,
        0
    );

    sink.checkpoint(&counts(7), 12)
        .expect("the next write succeeds");
    assert_eq!(
        load(dir.path()).expect("reopen").http_segments[0]
            .snapshot
            .total,
        7
    );
}

#[test]
fn a_seal_time_without_a_close_is_rejected_on_read() {
    let mut window = WindowV2::empty(1);
    let dir = tempfile::tempdir().expect("tempdir");
    let mut sink = HttpSegmentSink::open(dir.path(), identity(1_000), 1).expect("open");
    sink.checkpoint(&SegmentCounts::empty(), 1)
        .expect("checkpoint");
    window.http_segments = load(dir.path()).expect("reopen").http_segments;
    window.http_segments[0].sealed_at_ms = Some(5);
    assert!(validate_window_v2(&window).is_err());
}

#[test]
fn the_stdio_sink_writes_only_stdio_counts_into_the_v2_window() {
    // Row 15: the MIK-8364 saver and the signal-stop persist both reach
    // `persist_registry` / `persist_global`; HTTP traffic in the same
    // process never lands in `stdio`.
    let dir = tempfile::tempdir().expect("tempdir");
    let mut sink = crate::protocol_revision_telemetry::DurableTelemetrySink::open(dir.path())
        .expect("stdio sink");
    let mut registry = crate::protocol_revision_telemetry::Registry::new();
    registry.observe_request(Some("2025-06-18"), "codex", Transport::Stdio);
    registry.observe_request(None, "codex", Transport::Stdio);
    for _ in 0..5 {
        registry.observe_request(Some("2025-11-25"), "claude", Transport::Http);
    }
    sink.persist_registry(&registry).expect("persist");

    let window = load(dir.path()).expect("the stdio sink writes the v2 window");
    assert_eq!(window.stdio.total, 2);
    assert_eq!(window.stdio.by_transport.get("stdio"), Some(&2));
    assert!(window.http_segments.is_empty());
}

#[test]
fn a_failed_close_leaves_the_segment_open_for_a_retried_close() {
    // `closed` is set only once the sealed write has landed: a close that
    // fails must not turn the sink into a no-op, or the retry seals nothing.
    let dir = tempfile::tempdir().expect("tempdir");
    let mut sink = HttpSegmentSink::open(dir.path(), identity(1_000), 10).expect("open");
    let blocker = block_the_temporary_file(dir.path());
    let failed = sink.close(&counts(3), 11, 11_000);
    std::fs::remove_dir(&blocker).expect("unblock");
    assert!(
        failed.is_err(),
        "a blocked temporary file must fail the close"
    );
    assert!(!load(dir.path()).expect("reopen").http_segments[0].closed_cleanly);

    sink.close(&counts(3), 12, 11_000)
        .expect("the retried close lands");
    let segment = load(dir.path()).expect("reopen").http_segments[0].clone();
    assert!(segment.closed_cleanly);
    assert_eq!(segment.sealed_at_ms, Some(11_000));
    assert_eq!(segment.snapshot.total, 3);
}

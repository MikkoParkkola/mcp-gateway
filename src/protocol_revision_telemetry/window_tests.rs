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
    crate::protocol_revision_telemetry::DurableTelemetrySink::open(dir.path()).expect("v1 window");
    let path = window_paths(dir.path()).0;
    let before = std::fs::read(&path).expect("v1 bytes");

    let error = HttpSegmentSink::open(dir.path(), identity(1_000), 1).expect_err("v1 is refused");
    assert!(error.to_string().contains("archive"), "{error}");
    assert_eq!(std::fs::read(&path).expect("bytes after"), before, "v1 was rewritten");
}

#[test]
fn two_process_lifetimes_keep_separate_exact_segments() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut first = HttpSegmentSink::open(dir.path(), identity(1_000), 10).expect("open first");
    first.checkpoint(&counts(3), 11).expect("checkpoint");
    first.close(&counts(4), 12, 12_500).expect("close first");
    let mut second = HttpSegmentSink::open(dir.path(), identity(13_000), 13).expect("open second");
    second.checkpoint(&counts(2), 14).expect("checkpoint second");

    let window = load(dir.path()).expect("reopen");
    let totals: Vec<u64> = window.http_segments.iter().map(|s| s.snapshot.total).collect();
    assert_eq!(totals, vec![4, 2]);
    assert_eq!(window.http_segments[0].sealed_at_ms, Some(12_500));
    assert!(window.http_segments[0].closed_cleanly);
    assert!(!window.http_segments[1].closed_cleanly);
    assert_eq!(window.http_segments[1].sealed_at_ms, None);
    assert_eq!(window.http_segments[0].missing_revision_agents.get("curl"), Some(&4));
}

#[test]
fn nothing_writes_a_segment_after_its_close() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut sink = HttpSegmentSink::open(dir.path(), identity(1_000), 10).expect("open");
    sink.close(&counts(5), 11, 11_000).expect("close");
    sink.checkpoint(&counts(1), 12).expect("a checkpoint after close is a no-op");

    let segment = load(dir.path()).expect("reopen").http_segments[0].clone();
    assert!(segment.closed_cleanly, "a late checkpoint reopened the segment");
    assert_eq!(segment.snapshot.total, 5, "a late checkpoint replaced the sealed counts");
    assert_eq!(segment.last_checkpoint_at, 11);
}

#[test]
fn an_idle_interval_still_writes_a_checkpoint_and_an_empty_close_lands() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut sink = HttpSegmentSink::open(dir.path(), identity(1_000), 10).expect("open");
    sink.checkpoint(&SegmentCounts::empty(), 15).expect("idle checkpoint");
    assert_eq!(load(dir.path()).expect("reopen").http_segments[0].last_checkpoint_at, 15);
    sink.close(&SegmentCounts::empty(), 16, 16_000).expect("close with no requests");
    let segment = load(dir.path()).expect("reopen").http_segments[0].clone();
    assert!(segment.closed_cleanly);
    assert_eq!(segment.snapshot.total, 0);
}

#[cfg(unix)]
#[test]
fn a_failed_write_followed_by_a_success_loses_no_count() {
    use std::os::unix::fs::PermissionsExt as _;
    let dir = tempfile::tempdir().expect("tempdir");
    let mut sink = HttpSegmentSink::open(dir.path(), identity(1_000), 10).expect("open");
    let telemetry = dir.path().join(DURABLE_TELEMETRY_DIR);
    std::fs::set_permissions(&telemetry, std::fs::Permissions::from_mode(0o500)).expect("chmod");
    let failed = sink.checkpoint(&counts(3), 11);
    std::fs::set_permissions(&telemetry, std::fs::Permissions::from_mode(0o700)).expect("chmod");
    assert!(failed.is_err(), "the read-only directory must fail the write");
    assert_eq!(load(dir.path()).expect("reopen").http_segments[0].snapshot.total, 0);

    sink.checkpoint(&counts(7), 12).expect("the next write succeeds");
    assert_eq!(load(dir.path()).expect("reopen").http_segments[0].snapshot.total, 7);
}

#[test]
fn a_seal_time_without_a_close_is_rejected_on_read() {
    let mut window = WindowV2::empty(1);
    let dir = tempfile::tempdir().expect("tempdir");
    let mut sink = HttpSegmentSink::open(dir.path(), identity(1_000), 1).expect("open");
    sink.checkpoint(&SegmentCounts::empty(), 1).expect("checkpoint");
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

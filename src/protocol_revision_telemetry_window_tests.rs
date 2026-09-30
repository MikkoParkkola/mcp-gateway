// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Test plan: `docs/design/2026-09-30-u1-durable-per-transport-window.md`
//! §"Test plan". Numbers in test names follow that list.

use std::collections::BTreeMap;

use super::*;
use crate::protocol_revision_telemetry::{Registry, RetirementBlocked, Snapshot, Transport};

const DAY: u64 = 24 * 60 * 60;
const PROD: &str = "127.0.0.1:39401";
const PREFIX: &str = "/opt/mcp-gateway/";

fn declaration() -> Declaration {
    Declaration {
        population: vec![Transport::Http],
        listen: PROD.to_string(),
        exe_prefix: PREFIX.to_string(),
    }
}

fn http_snapshot(revision: &str, n: u64) -> Snapshot {
    let mut registry = Registry::new();
    for _ in 0..n {
        registry.observe_request(Some(revision), "claude", Transport::Http);
    }
    registry.transport_snapshot(Transport::Http)
}

fn segment(opened_at: u64, closed_at: u64, closed: bool, snapshot: Snapshot) -> Segment {
    Segment {
        listen: PROD.to_string(),
        exe: format!("{PREFIX}4.0.0/mcp-gateway"),
        process_started_at: opened_at,
        opened_at,
        last_checkpoint_at: closed_at,
        closed_cleanly: closed,
        opened_while_another_was_open: false,
        snapshot,
        missing_revision_agents: BTreeMap::new(),
        tools_list_shadow: super::empty_shadow_counts(),
    }
}

fn window_of(segments: Vec<Segment>) -> WindowV2 {
    let mut window = WindowV2::empty(0);
    window.http_segments = segments;
    window
}

fn outcome(window: &WindowV2) -> Result<Vec<String>, WindowBlocked> {
    decide(window, &declaration()).1
}

fn identity(listen: &str, started: u64) -> WriterIdentity {
    WriterIdentity {
        listen: listen.to_string(),
        exe: format!("{PREFIX}4.0.0/mcp-gateway"),
        process_started_at: started,
    }
}

#[test]
fn t1_stdio_observation_or_other_declaration_blocks() {
    let mut window = window_of(vec![segment(0, 8 * DAY, true, http_snapshot("2026-07-28", 10_000))]);
    let mut registry = Registry::new();
    registry.observe_request(Some("2025-06-18"), "claude", Transport::Stdio);
    window.stdio = registry.transport_snapshot(Transport::Stdio);
    assert_eq!(outcome(&window), Err(WindowBlocked::PopulationMismatch));

    window.stdio = Snapshot::default();
    let both = Declaration {
        population: vec![Transport::Http, Transport::Stdio],
        ..declaration()
    };
    assert_eq!(decide(&window, &both).1, Err(WindowBlocked::PopulationMismatch));
    assert!(outcome(&window).is_ok(), "the same window certifies under [http]");
}

#[test]
fn t2_sealed_span_excludes_the_open_segment_and_ignores_the_wall_clock() {
    let clean = window_of(vec![
        segment(0, 3 * DAY, true, http_snapshot("2026-07-28", 5_000)),
        segment(3 * DAY + 5, 6 * DAY, true, http_snapshot("2026-07-28", 5_000)),
        segment(6 * DAY + 5, 8 * DAY, true, http_snapshot("2026-07-28", 5_000)),
    ]);
    let candidates = outcome(&clean).expect("three clean segments over eight days certify");
    assert!(candidates.contains(&"2025-06-18".to_string()));

    // 500 old-revision requests in the open newest segment are outside the span.
    let mut with_open = clean.clone();
    with_open
        .http_segments
        .push(segment(8 * DAY + 5, 8 * DAY + 60, false, http_snapshot("2025-06-18", 500)));
    let (span, result) = decide(&with_open, &declaration());
    assert_eq!(result, outcome(&clean));
    assert_eq!(span.expect("sealed span").ended_at, 8 * DAY);

    // A six-day span read a month later is still too short.
    let short = window_of(vec![segment(0, 6 * DAY, true, http_snapshot("2026-07-28", 5_000))]);
    assert_eq!(
        outcome(&short),
        Err(WindowBlocked::Retirement(RetirementBlocked::WindowTooShort))
    );
}

#[test]
fn t3_unclean_and_concurrent_writers_block_but_a_same_second_restart_passes() {
    let unclean = window_of(vec![
        segment(0, 4 * DAY, false, http_snapshot("2026-07-28", 100)),
        segment(4 * DAY + 5, 8 * DAY, true, http_snapshot("2026-07-28", 100)),
    ]);
    assert_eq!(outcome(&unclean), Err(WindowBlocked::UncleanSegment));

    let dir = tempfile::tempdir().expect("tempdir");
    HttpSegmentSink::open(dir.path(), identity(PROD, 10), 10).expect("first writer");
    HttpSegmentSink::open(dir.path(), identity(PROD, 11), 11).expect("second writer");
    let (path, _) = window_paths(dir.path());
    let window = read_window_v2(&path).expect("read");
    assert!(window.http_segments[1].opened_while_another_was_open);

    let dir = tempfile::tempdir().expect("tempdir");
    let mut first = HttpSegmentSink::open(dir.path(), identity(PROD, 10), 10).expect("open");
    first.checkpoint(&SegmentCounts::default(), 10, true).expect("close");
    HttpSegmentSink::open(dir.path(), identity(PROD, 10), 10).expect("same-second restart");
    let window = read_window_v2(&path_of(dir.path())).expect("read");
    assert!(!window.http_segments[1].opened_while_another_was_open);
}

fn path_of(dir: &std::path::Path) -> std::path::PathBuf {
    window_paths(dir).0
}

#[test]
fn t4_foreign_writers_and_coverage_gaps_block() {
    let good = || segment(0, 8 * DAY, true, http_snapshot("2026-07-28", 100));
    let mut compat_after = good();
    compat_after.listen = "127.0.0.1:39411".to_string();
    compat_after.opened_at = 8 * DAY + 5;
    compat_after.process_started_at = 8 * DAY + 5;
    compat_after.last_checkpoint_at = 9 * DAY;
    assert_eq!(outcome(&window_of(vec![good(), compat_after])), Err(WindowBlocked::ForeignWriter));

    let mut compat_only = good();
    compat_only.listen = "127.0.0.1:39411".to_string();
    assert_eq!(outcome(&window_of(vec![compat_only])), Err(WindowBlocked::ForeignWriter));

    let mut dev_build = good();
    dev_build.exe = "/home/dev/mcp-gateway/target/release/mcp-gateway".to_string();
    assert_eq!(outcome(&window_of(vec![dev_build])), Err(WindowBlocked::ForeignWriter));

    let gap = |seconds: u64| {
        window_of(vec![
            segment(0, 4 * DAY, true, http_snapshot("2026-07-28", 100)),
            segment(4 * DAY + seconds, 8 * DAY, true, http_snapshot("2026-07-28", 100)),
        ])
    };
    assert_eq!(outcome(&gap(3_600)), Err(WindowBlocked::CoverageGap));
    assert!(outcome(&gap(10)).is_ok());
}

fn counts(revision: &str, n: u64) -> SegmentCounts {
    SegmentCounts {
        snapshot: http_snapshot(revision, n),
        missing_revision_agents: BTreeMap::new(),
        tools_list_shadow: super::empty_shadow_counts(),
    }
}

#[test]
fn t5_checkpoints_are_cumulative_and_survive_a_failed_write() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = path_of(dir.path());
    let mut sink = HttpSegmentSink::open(dir.path(), identity(PROD, 100), 100).expect("open");

    // An idle interval still advances the checkpoint.
    sink.checkpoint(&SegmentCounts::default(), 105, false).expect("idle");
    assert_eq!(read_window_v2(&path).unwrap().http_segments[0].last_checkpoint_at, 105);

    // A failed write (the file replaced by a directory) loses nothing: the
    // next write carries the same cumulative counts.
    sink.checkpoint(&counts("2026-07-28", 3), 110, false).expect("first");
    let saved = std::fs::read(&path).unwrap();
    std::fs::remove_file(&path).unwrap();
    std::fs::create_dir(&path).unwrap();
    assert!(sink.checkpoint(&counts("2026-07-28", 7), 115, false).is_err());
    std::fs::remove_dir(&path).unwrap();
    std::fs::write(&path, saved).unwrap();
    sink.checkpoint(&counts("2026-07-28", 7), 120, false).expect("recovered");
    let window = read_window_v2(&path).unwrap();
    assert_eq!(window.http_segments[0].snapshot.total, 7);
    assert!(!window.http_segments[0].closed_cleanly);

    // A shutdown with no new requests still writes the close.
    sink.checkpoint(&counts("2026-07-28", 7), 125, true).expect("close");
    let window = read_window_v2(&path).unwrap();
    assert!(window.http_segments[0].closed_cleanly);
    assert_eq!(window.http_segments[0].snapshot.total, 7);
}

#[test]
fn t5_internal_observations_never_reach_a_segment() {
    let mut registry = Registry::new();
    registry.observe_request(Some("2025-06-18"), "claude", Transport::Internal);
    registry.observe_request(Some("2026-07-28"), "claude", Transport::Http);
    let http = registry.transport_snapshot(Transport::Http);
    assert_eq!(http.total, 1);
    assert_eq!(http.by_revision.get("2025-06-18"), None);
}

#[test]
fn t6_two_process_lifetimes_keep_separate_counts_that_sum_exactly() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut first = HttpSegmentSink::open(dir.path(), identity(PROD, 0), 0).expect("open 1");
    first.checkpoint(&counts("2026-07-28", 40), 4 * DAY, true).expect("close 1");
    let mut second = HttpSegmentSink::open(dir.path(), identity(PROD, 4 * DAY + 5), 4 * DAY + 5)
        .expect("open 2");
    second.checkpoint(&counts("2026-07-28", 60), 8 * DAY, true).expect("close 2");
    let window = read_window_v2(&path_of(dir.path())).unwrap();
    let (span, result) = decide(&window, &declaration());
    assert_eq!(span.expect("span").snapshot.total, 100);
    assert!(result.is_ok());
}

#[test]
fn t6_stdio_deltas_survive_a_process_restart() {
    // Was `mcp728_u1_2_stdio_window_survives_process_restart` (MIK-7218).
    use crate::protocol_revision_telemetry::DurableTelemetrySink;
    let dir = tempfile::tempdir().expect("tempdir");
    let mut first = DurableTelemetrySink::open(dir.path()).expect("first process");
    let mut registry = Registry::new();
    for _ in 0..60 {
        registry.observe_request(Some("2025-11-25"), "claude", Transport::Stdio);
    }
    first.persist_registry(&registry).expect("first persist");
    first.persist_registry(&registry).expect("a repeat adds nothing");
    let mut second = DurableTelemetrySink::open(dir.path()).expect("second process");
    let mut registry = Registry::new();
    for _ in 0..40 {
        registry.observe_request(Some("2025-11-25"), "claude", Transport::Stdio);
    }
    second.persist_registry(&registry).expect("second persist");
    let window = read_window_v2(&path_of(dir.path())).unwrap();
    assert_eq!(window.stdio.total, 100);
    assert!(window.http_segments.is_empty());
}

#[test]
fn t7_agent_keys_are_bounded_and_client_info_does_not_hide_the_family() {
    let mut registry = Registry::new();
    for i in 0..1_000 {
        let agent = format!("agent-{i}/1.0");
        registry.observe_request_from(None, "", Transport::Http, Some(&agent));
    }
    registry.observe_request_from(None, "some-script", Transport::Http, Some("curl/8.4.0"));
    registry.observe_request_from(None, "claude-code", Transport::Http, Some("curl/8.4.0"));
    let agents = registry.missing_revision_agents();
    assert!(agents.len() <= 16);
    assert_eq!(agents.get("curl"), Some(&1));
    assert_eq!(agents.get("claude"), Some(&1));
    assert_eq!(agents.get("other"), Some(&1_000));
    assert!(agents.keys().all(|key| !key.starts_with("agent-")));

    let mut window = WindowV2::empty(0);
    window.missing_revision_agents.insert("agent-7/1.0".to_string(), 1);
    assert!(validate_window_v2(&window).is_err());
}

#[test]
fn t8_a_v1_window_is_refused_and_left_byte_identical() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = path_of(dir.path());
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    let v1 = br#"{"schema_version":"mcp_protocol_revision_window.v1","started_at_unix_seconds":1}"#;
    std::fs::write(&path, v1).unwrap();
    let error = HttpSegmentSink::open(dir.path(), identity(PROD, 1), 1).expect_err("v1 refused");
    assert!(error.to_string().contains("archive"), "{error}");
    assert!(crate::protocol_revision_telemetry::DurableTelemetrySink::open(dir.path()).is_err());
    assert_eq!(std::fs::read(&path).unwrap(), v1);
}

#[test]
fn t10_declaration_requires_every_value() {
    let ok = parse_declaration(Some("http"), Some(PROD), Some(PREFIX)).expect("valid");
    assert_eq!(ok, declaration());
    assert!(parse_declaration(None, Some(PROD), Some(PREFIX)).is_err());
    assert!(parse_declaration(Some("http,stdio"), Some(PROD), Some(PREFIX)).is_err());
    assert!(parse_declaration(Some("http"), Some("39401"), Some(PREFIX)).is_err());
    assert!(parse_declaration(Some("http"), Some(PROD), Some("~/.local/")).is_err());
    assert!(parse_declaration(Some("http"), Some(PROD), None).is_err());
}

#[test]
fn t9_missing_revisions_stay_in_the_two_percent_gate() {
    let mut registry = Registry::new();
    for _ in 0..92 {
        registry.observe_request(Some("2026-07-28"), "claude", Transport::Http);
    }
    for _ in 0..8 {
        registry.observe_request_from(None, "", Transport::Http, Some("Python-urllib/3.12"));
    }
    let snapshot = registry.transport_snapshot(Transport::Http);
    let window = window_of(vec![segment(0, 8 * DAY, true, snapshot)]);
    assert_eq!(
        outcome(&window),
        Err(WindowBlocked::Retirement(
            RetirementBlocked::UnattributedAtOrAboveRetirementThreshold
        ))
    );
}

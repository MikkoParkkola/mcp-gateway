// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Design rows 1-4, 9, 10, 17 and 21: the decision reads only sealed
//! evidence from the declared writer.

use std::collections::BTreeMap;

use super::*;
use crate::protocol_revision_telemetry::window::{Segment, WindowV2};
use crate::protocol_revision_telemetry::{Registry, empty_shadow_counts};

const DAY_MS: u64 = 86_400_000;
const LISTEN: &str = "127.0.0.1:39401";
const EXE: &str = "/opt/mcp-gateway/4.0.0/mcp-gateway";

fn declaration() -> Declaration {
    Declaration {
        population: vec![Transport::Http],
        listen: LISTEN.to_string(),
        exe_prefix: "/opt/mcp-gateway/".to_string(),
    }
}

/// `requests` HTTP requests at 2026-07-28, plus `unattributed` with none.
fn snapshot(requests: u64, unattributed: u64) -> Snapshot {
    let mut registry = Registry::new();
    for _ in 0..requests {
        registry.observe_request_from(Some("2026-07-28"), "claude", Transport::Http, None);
    }
    for _ in 0..unattributed {
        registry.observe_request_from(None, "claude", Transport::Http, None);
    }
    registry.snapshot()
}

/// A clean segment whose process starts at `start_ms` and seals at
/// `sealed_ms`. Every timestamp differs from the one a wrong evaluator might
/// read instead: the open is 1 s after the start, and the last checkpoint is
/// 2 s before the seal, so only `opened_at` and `sealed_at_ms` give the span,
/// and only `process_started_at_ms` and `sealed_at_ms` give gaps and overlap.
fn sealed(start_ms: u64, sealed_ms: u64, requests: u64) -> Segment {
    Segment {
        listen: LISTEN.to_string(),
        exe: EXE.to_string(),
        process_started_at_ms: start_ms,
        opened_at: start_ms / 1000 + 1,
        last_checkpoint_at: (sealed_ms / 1000).saturating_sub(2),
        sealed_at_ms: Some(sealed_ms),
        closed_cleanly: true,
        snapshot: snapshot(requests, 0),
        missing_revision_agents: BTreeMap::new(),
        tools_list_shadow: empty_shadow_counts(),
    }
}

fn open(start_ms: u64, requests: u64) -> Segment {
    Segment {
        sealed_at_ms: None,
        closed_cleanly: false,
        ..sealed(start_ms, start_ms, requests)
    }
}

fn window(segments: Vec<Segment>) -> WindowV2 {
    WindowV2 {
        http_segments: segments,
        ..WindowV2::empty(0)
    }
}

/// Three clean back-to-back segments over 7.5 days.
fn seven_days() -> Vec<Segment> {
    vec![
        sealed(0, 3 * DAY_MS, 4_000),
        sealed(3 * DAY_MS + 10_000, 6 * DAY_MS, 4_000),
        sealed(6 * DAY_MS + 10_000, 7 * DAY_MS + DAY_MS / 2, 2_000),
    ]
}

#[test]
fn seven_sealed_days_certify_and_the_span_is_the_sealed_time() {
    let (span, outcome) = decide(&window(seven_days()), &declaration());
    let span = span.expect("a sealed span");
    assert_eq!(span.started_at, 1, "the span starts at the first open");
    assert_eq!(span.segments, 3);
    assert_eq!(span.snapshot.total, 10_000);
    assert_eq!(span.ended_at_ms, 7 * DAY_MS + DAY_MS / 2);
    let retired = outcome.expect("certified");
    assert!(retired.iter().any(|revision| revision == "2024-11-05"));
}

#[test]
fn stdio_is_never_certified() {
    let mut file = window(seven_days());
    file.stdio = {
        let mut registry = Registry::new();
        registry.observe_request_from(Some("2025-06-18"), "codex", Transport::Stdio, None);
        registry.snapshot()
    };
    assert_eq!(
        decide(&file, &declaration()).1,
        Err(WindowBlocked::PopulationMismatch)
    );
    let stdio_declared = Declaration {
        population: vec![Transport::Http, Transport::Stdio],
        ..declaration()
    };
    assert_eq!(
        decide(&window(seven_days()), &stdio_declared).1,
        Err(WindowBlocked::PopulationMismatch)
    );
}

#[test]
fn an_open_newest_segment_is_outside_the_span_with_its_counts() {
    let mut segments = seven_days();
    let mut late = open(8 * DAY_MS, 0);
    late.snapshot = {
        let mut registry = Registry::new();
        for _ in 0..500 {
            registry.observe_request_from(Some("2024-11-05"), "claude", Transport::Http, None);
        }
        registry.snapshot()
    };
    late.process_started_at_ms = 7 * DAY_MS + DAY_MS / 2 + 5_000;
    segments.push(late);
    let (span, outcome) = decide(&window(segments), &declaration());
    assert_eq!(span.expect("span").snapshot.total, 10_000);
    assert!(outcome.expect("certified").iter().any(|r| r == "2024-11-05"));
}

#[test]
fn a_span_under_seven_days_is_too_short_however_old_the_file() {
    let file = window(vec![sealed(0, 6 * DAY_MS, 10_000)]);
    assert_eq!(
        decide(&file, &declaration()).1,
        Err(WindowBlocked::Retirement(RetirementBlocked::WindowTooShort))
    );
}

#[test]
fn an_unclean_segment_followed_by_another_blocks() {
    let mut segments = seven_days();
    segments.insert(1, open(3 * DAY_MS + 1_000, 10));
    assert_eq!(
        decide(&window(segments), &declaration()).1,
        Err(WindowBlocked::UncleanSegment)
    );
}

#[test]
fn a_successor_started_before_its_predecessor_sealed_is_concurrent() {
    let mut segments = seven_days();
    // 300 ms before the first segment's seal: sub-second overlap (row 21).
    segments[1].process_started_at_ms = 3 * DAY_MS - 300;
    assert_eq!(
        decide(&window(segments), &declaration()).1,
        Err(WindowBlocked::ConcurrentHttpWriters)
    );
    let mut same_instant = seven_days();
    same_instant[1].process_started_at_ms = 3 * DAY_MS;
    assert!(decide(&window(same_instant), &declaration()).1.is_ok());
}

#[test]
fn a_foreign_writer_blocks_wherever_it_sits() {
    for (index, listen, exe) in [
        (1, "127.0.0.1:39411", EXE),
        (0, "127.0.0.1:39411", EXE),
        (2, LISTEN, "/Users/dev/worktree/target/debug/mcp-gateway"),
    ] {
        let mut segments = seven_days();
        segments[index].listen = listen.to_string();
        segments[index].exe = exe.to_string();
        assert_eq!(
            decide(&window(segments), &declaration()).1,
            Err(WindowBlocked::ForeignWriter),
            "segment {index}"
        );
    }
}

#[test]
fn a_gap_past_the_restart_budget_blocks_and_a_short_one_passes() {
    let mut gap = seven_days();
    gap[1].process_started_at_ms = 3 * DAY_MS + 3_600_000;
    assert_eq!(
        decide(&window(gap), &declaration()).1,
        Err(WindowBlocked::CoverageGap)
    );
    assert!(decide(&window(seven_days()), &declaration()).1.is_ok());
}

#[test]
fn eight_percent_unattributed_blocks_whatever_the_breakdown_says() {
    let mut segments = seven_days();
    segments[0].snapshot = snapshot(3_200, 800);
    segments[0].missing_revision_agents = BTreeMap::from([("claude".to_string(), 800)]);
    assert_eq!(
        decide(&window(segments), &declaration()).1,
        Err(WindowBlocked::Retirement(
            RetirementBlocked::UnattributedAtOrAboveRetirementThreshold
        ))
    );
}

#[test]
fn no_sealed_segment_is_its_own_block() {
    assert_eq!(
        decide(&window(vec![open(0, 10)]), &declaration()).1,
        Err(WindowBlocked::NoSealedSegment)
    );
}

#[test]
fn the_declaration_requires_every_value() {
    let ok = parse_declaration(Some("http"), Some(LISTEN), Some("/opt/mcp-gateway/"));
    assert_eq!(ok.expect("valid"), declaration());
    for (population, listen, prefix) in [
        (None, Some(LISTEN), Some("/opt/")),
        (Some("http"), None, Some("/opt/")),
        (Some("http"), Some(LISTEN), None),
        (Some("stdio"), Some(LISTEN), Some("/opt/")),
        (Some("http"), Some("not-an-address"), Some("/opt/")),
        (Some("http"), Some(LISTEN), Some("relative/path")),
    ] {
        assert!(
            parse_declaration(population, listen, prefix).is_err(),
            "{population:?} {listen:?} {prefix:?}"
        );
    }
}

#[test]
fn the_seven_day_boundary_is_measured_from_the_open_to_the_seal() {
    // Opened at 1 s; sealed exactly seven days later passes, 1 ms less is short.
    let exact = sealed(0, 1_000 + 7 * DAY_MS, 10_000);
    assert!(decide(&window(vec![exact]), &declaration()).1.is_ok());
    let short = sealed(0, 1_000 + 7 * DAY_MS - 1, 10_000);
    assert_eq!(
        decide(&window(vec![short]), &declaration()).1,
        Err(WindowBlocked::Retirement(RetirementBlocked::WindowTooShort))
    );
}

#[test]
fn the_operator_command_names_this_module_exactly() {
    let here = module_path!().trim_start_matches("mcp_gateway::");
    assert_eq!(OPERATOR_TEST, format!("{here}::u1_production_decision"));
}

#[test]
fn the_operator_run_refuses_a_missing_variable_and_writes_its_decision() {
    let data = tempfile::tempdir().expect("tempdir");
    let path = crate::protocol_revision_telemetry::window::window_paths(data.path()).0;
    std::fs::create_dir_all(path.parent().expect("parent")).expect("dir");
    let file = serde_json::to_vec(&window(seven_days())).expect("json");
    std::fs::write(&path, file).expect("window");
    let full = |key: &str| match key {
        "U1_DATA_DIR" => Some(data.path().display().to_string()),
        "U1_POPULATION" => Some("http".to_string()),
        "U1_LISTEN" => Some(LISTEN.to_string()),
        "U1_EXE_PREFIX" => Some("/opt/mcp-gateway/".to_string()),
        _ => None,
    };
    for missing in ["U1_DATA_DIR", "U1_POPULATION", "U1_LISTEN", "U1_EXE_PREFIX"] {
        let without = |key: &str| if key == missing { None } else { full(key) };
        assert!(run_operator(&without).is_err(), "ran without {missing}");
    }
    let report = run_operator(&full).expect("a complete declaration runs");
    assert!(report.contains("| total | 10000 |"), "{report}");
    assert!(report.contains(EXE), "the report lists each writer: {report}");
    let written = std::fs::read(path.with_file_name("decision.json")).expect("decision.json");
    let decision: serde_json::Value = serde_json::from_slice(&written).expect("JSON");
    assert!(
        decision["retire"].as_array().is_some_and(|r| !r.is_empty()),
        "{decision}"
    );

    // Blocked evidence: a declaration naming another writer certifies nothing.
    let foreign = |key: &str| match key {
        "U1_LISTEN" => Some("127.0.0.1:39411".to_string()),
        _ => full(key),
    };
    let report = run_operator(&foreign).expect("a blocked decision still reports");
    assert!(report.contains("ForeignWriter"), "{report}");
    let written = std::fs::read(path.with_file_name("decision.json")).expect("decision.json");
    let decision: serde_json::Value = serde_json::from_slice(&written).expect("JSON");
    assert_eq!(decision["retire"], serde_json::json!([]), "{decision}");
    assert_eq!(decision["blocked"], "ForeignWriter", "{decision}");
    let malformed = |key: &str| match key {
        "U1_EXE_PREFIX" => Some("relative/path".to_string()),
        _ => full(key),
    };
    assert!(run_operator(&malformed).is_err(), "a relative prefix ran");
}

/// The operator's entry point. Ignored: it reads the real environment.
#[test]
#[ignore = "operator command: run with the U1_* variables (see OPERATOR_TEST)"]
fn u1_production_decision() {
    let report = run_operator(&|key| std::env::var(key).ok()).expect("the U1 decision runs");
    println!("{report}");
}

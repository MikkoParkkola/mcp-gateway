// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! API2.10 Joiner-level rows R18, R44(b) and R45: the join stays in step with
//! the page, the carried window, and the charged read-ahead.

use serde_json::{Map, json};

use super::answer::{Effect, Findings, Joined, Searched};
use super::answer_fixture::{Dl, Fixture};
use super::answer_list_tests::{get, row_of};
use super::joiner::{Joiner, Seen};
use super::reader::{Line, Which};
use super::rows::Check;
use crate::security::audit::{AuditEnvelope, AuditWho};
use crate::security::transparency_log::recompute_entry_hash;

#[tokio::test]
async fn r18_joined_stays_in_step_with_the_lines() {
    let fx = Fixture::new(None);
    let envelope = AuditEnvelope::ok(AuditWho::from_actor_id("c"));
    for (i, e) in ["delivered", "refused", "annotated", "rewritten"]
        .into_iter()
        .enumerate()
    {
        fx.call(&format!("gw-{e}"));
        if i % 2 == 0 {
            let mut admin = Map::new();
            admin.insert("event".into(), "admin_action".into());
            fx.logger.append_event(admin, &envelope).unwrap();
        }
        fx.delivery(&format!("gw-{e}"), &Dl::effect(e));
    }
    fx.call("gw-no_record");
    for query in [vec![], vec![("limit", "2")], vec![("effect", "refused")]] {
        let (_, page) = get(&fx, &query).await;
        for r in page["rows"].as_array().unwrap() {
            if let Some(t) = r["trace_id"].as_str() {
                assert_eq!(r["effect"], &t[3..], "{t} in {page}");
            }
        }
    }
    let (_, only) = get(&fx, &[("effect", "refused")]).await;
    assert_eq!(row_of(&only, "gw-refused")["effect"], "refused");
}

fn call_line() -> Line {
    Line {
        log: Which::Invocation,
        entry: json!({"counter": 1, "trace_id": "gw-t", "request_hash": "sha256:aa"}),
        segment: 0,
        span: None,
    }
}

#[test]
fn r44b_the_window_is_finished_by_carried_bytes_not_by_a_reset() {
    let carried_check = Check::bare(None);
    let mut carried = Joiner::new(&carried_check);
    let far = Seen {
        above: 300 * 1024,
        head_covered: false,
    };
    let joined = carried.join(&call_line(), far);
    carried.count(&joined);
    assert_eq!(joined, Joined::NoRecord(Searched::Finished));
    assert_eq!(carried.join_incomplete, 0);
    let reset_check = Check::bare(None);
    let mut reset = Joiner::new(&reset_check);
    let near = Seen {
        above: 10,
        head_covered: false,
    };
    let joined = reset.join(&call_line(), near);
    reset.count(&joined);
    assert_eq!(joined, Joined::NoRecord(Searched::Unfinished));
    assert_eq!(reset.join_incomplete, 1);
}

#[test]
fn r45_read_ahead_is_charged_to_the_budget() {
    use std::fmt::Write as _;

    use super::strict_scan::{Forward, Next};
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("lines.jsonl");
    let mut body = String::new();
    for i in 0..30_000 {
        writeln!(body, "{{\"n\":{i}}}").unwrap();
    }
    assert!(body.len() > 300 * 1024);
    std::fs::write(&path, body).unwrap();
    let budget = 70 * 1024;
    let mut scan = Forward::open(std::fs::File::open(&path).unwrap(), 0, budget).unwrap();
    let mut lines = 0;
    while let Next::Line(_) = scan.next_line().unwrap() {
        lines += 1;
    }
    assert!(lines > 1_000, "read {lines} lines");
    assert!(
        scan.pulled() > 0 && scan.pulled() <= budget,
        "{}",
        scan.pulled()
    );
}

/// An unsigned delivery record line for `trace`, with `findings`.
fn delivery_line(trace: &str, findings: &serde_json::Value) -> Line {
    let mut entry = json!({
        "counter": 2, "trace_id": trace, "event": "response_delivery_attempt",
        "response_stage": "transport_finalized", "response_effect": "annotated",
        "response_findings": findings,
    });
    // The trust rule reads a record with a wrong hash as invalid.
    entry["entry_hash"] = recompute_entry_hash(&entry).unwrap().into();
    Line {
        log: Which::Invocation,
        entry,
        segment: 0,
        span: None,
    }
}

/// Guard (passes before the fixes): a found record is complete by the writer
/// contract, so an unfinished window never downgrades it.
#[test]
fn r7c_a_found_record_stays_found_when_the_window_is_unfinished() {
    let joiner_check = Check::bare(None);
    let mut joiner = Joiner::new(&joiner_check);
    assert!(joiner.observe(&delivery_line("gw-t", &json!([]))));
    let near = Seen {
        above: 10,
        head_covered: false,
    };
    let answer = joiner.join(&call_line(), near);
    joiner.count(&answer);
    assert_eq!(answer.effect(), Effect::Annotated, "{answer:?}");
    assert!(matches!(answer, Joined::Found(_)), "{answer:?}");
    assert_eq!(joiner.join_incomplete, 0);
}

fn listed(joined: Joined) -> Vec<serde_json::Value> {
    match joined {
        Joined::Found(d) => match d.findings {
            Findings::Scanned { list, .. } => list,
            other => panic!("not scanned: {other:?}"),
        },
        other => panic!("not found: {other:?}"),
    }
}

#[test]
fn findings_are_projected_through_kind_severity_and_where_only() {
    let joiner_check = Check::bare(None);
    let mut joiner = Joiner::new(&joiner_check);
    let findings = json!([
        {"kind": "k", "severity": "low", "where": "text", "payload": "a pasted secret"},
        {"kind": {"deep": "object"}, "severity": "high", "where": "text"},
        "not an object",
    ]);
    joiner.observe(&delivery_line("gw-t", &findings));
    let seen = Seen {
        above: 0,
        head_covered: true,
    };
    let list = listed(joiner.join(&call_line(), seen));
    assert_eq!(
        list,
        [
            json!({"kind": "k", "severity": "low", "where": "text"}),
            json!({"severity": "high", "where": "text"}),
        ]
    );
}

#[test]
fn a_finding_field_is_capped_so_the_projection_stays_bounded() {
    let joiner_check = Check::bare(None);
    let mut joiner = Joiner::new(&joiner_check);
    let long = "k".repeat(10_000);
    let findings = json!([{"kind": long, "severity": "low", "where": "text"}]);
    joiner.observe(&delivery_line("gw-t", &findings));
    let seen = Seen {
        above: 0,
        head_covered: true,
    };
    let list = listed(joiner.join(&call_line(), seen));
    let kind = list[0]["kind"].as_str().unwrap();
    assert!(kind.len() <= 128, "{}", kind.len());
}

#[test]
fn a_finding_field_keeps_the_first_128_characters_not_bytes() {
    let joiner_check = Check::bare(None);
    let mut joiner = Joiner::new(&joiner_check);
    let text: String = "é日🦀a".chars().cycle().take(200).collect();
    let findings = json!([{"kind": text, "severity": text, "where": text}]);
    joiner.observe(&delivery_line("gw-t", &findings));
    let seen = Seen {
        above: 0,
        head_covered: true,
    };
    let list = listed(joiner.join(&call_line(), seen));
    let want: String = text.chars().take(128).collect();
    assert!(want.len() > 128, "premise: bytes and characters differ");
    for key in ["kind", "severity", "where"] {
        assert_eq!(list[0][key].as_str(), Some(want.as_str()), "{key}");
    }
}

// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! API2.10 Joiner-level rows R18, R44(b) and R45: the join stays in step with
//! the page, the carried window, and the charged read-ahead.

use serde_json::{Map, json};

use super::answer::{Joined, Searched};
use super::answer_fixture::{Dl, Fixture};
use super::answer_list_tests::{get, row_of};
use super::joiner::{Joiner, Seen};
use super::reader::{Line, Which};
use crate::security::audit::{AuditEnvelope, AuditWho};

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
    }
}

#[test]
fn r44b_the_window_is_finished_by_carried_bytes_not_by_a_reset() {
    let mut carried = Joiner::new(None);
    let far = Seen {
        above: 300 * 1024,
        head_covered: false,
    };
    let joined = carried.join(&call_line(), far);
    carried.count(&joined);
    assert_eq!(joined, Joined::NoRecord(Searched::Finished));
    assert_eq!(carried.join_incomplete, 0);
    let mut reset = Joiner::new(None);
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

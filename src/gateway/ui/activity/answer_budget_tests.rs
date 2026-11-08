// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! API2.10 row R43: the pager's assembly re-read draws from the page budget.

use serde_json::Map;

use super::answer_fixture::Fixture;
use super::reader::{Limits, Look, Seen, read_page_joined};
use crate::security::audit::{AuditEnvelope, AuditWho};

const MIB: u64 = 1 << 20;

fn page(fx: &Fixture, cursor: Option<&super::reader::Cursor>, bytes: u64) -> super::reader::Page {
    let limits = Limits {
        matches: 200,
        bytes,
    };
    let look = Look::Carried(Seen {
        above: 0,
        head_covered: true,
    });
    read_page_joined(&fx.path, None, cursor, limits, look, |_, _| true).unwrap()
}

#[test]
fn r43_the_assembly_probe_is_not_taken_past_the_remaining_budget() {
    let fx = Fixture::new(None);
    fx.call("gw-c");
    let mut pad = Map::new();
    pad.insert("event".into(), "pad".into());
    pad.insert("pad".into(), "x".repeat(2 << 20).into());
    let envelope = AuditEnvelope::ok(AuditWho::from_actor_id("c"));
    fx.logger.append_event(pad, &envelope).unwrap();
    let first = page(&fx, None, 3 * MIB);
    assert!(first.bytes_examined <= 3 * MIB, "{}", first.bytes_examined);
    assert!(first.scan_exhausted);
    let cursor = first.next.expect("a resumable cursor");
    let second = page(&fx, Some(&cursor), 8 * MIB);
    assert!(second.lines.iter().any(|l| l.entry["trace_id"] == "gw-c"));
}

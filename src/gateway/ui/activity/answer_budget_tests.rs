// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! API2.10 row R43: the pager's assembly re-read draws from the page budget.

use serde_json::Map;

use super::answer_fixture::Fixture;
use super::reader::{Limits, Look, Seen, read_page_joined};
use crate::security::audit::{AuditEnvelope, AuditWho};
use crate::security::transparency_log::pager::ASSEMBLY_WINDOW;

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

/// A record of 2 MiB, under the 4 MiB record cap.
fn pad(fx: &Fixture) {
    let mut pad = Map::new();
    pad.insert("event".into(), "pad".into());
    pad.insert("pad".into(), "x".repeat(2 << 20).into());
    let envelope = AuditEnvelope::ok(AuditWho::from_actor_id("c"));
    fx.logger.append_event(pad, &envelope).unwrap();
}

#[test]
fn r43_an_unadvanced_page_may_pass_its_budget_by_the_record_cap_at_most() {
    let fx = Fixture::new(None);
    fx.call("gw-c");
    pad(&fx);
    let first = page(&fx, None, 3 * MIB);
    // An unadvanced page assembles the record whatever its budget, and may
    // pass the budget by at most the record cap.
    assert!(first.bytes_examined <= 3 * MIB + ASSEMBLY_WINDOW);
    let mut cursor = first.next;
    let mut reached_call = first.lines.iter().any(|l| l.entry["trace_id"] == "gw-c");
    for _ in 0..64 {
        let Some(c) = cursor.take() else { break };
        let next = page(&fx, Some(&c), 8 * MIB);
        reached_call |= next.lines.iter().any(|l| l.entry["trace_id"] == "gw-c");
        assert!(
            !next.lines.is_empty() || next.next.as_ref() != Some(&c),
            "a page returned no row and the same cursor"
        );
        cursor = next.next;
    }
    assert!(cursor.is_none() && reached_call);
}

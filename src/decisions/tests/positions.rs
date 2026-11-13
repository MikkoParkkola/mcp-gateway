// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A decision that closes refusals by position, and the note it is written
//! as: order independence, the equal-time case, the note's round trip and
//! its id.

use serde_json::{Map, Value};

use super::super::{
    Fold, LogPos, OpenRequest, Source, UiDecision, decisions_from_record, decisions_of, event_id,
    record_fields,
};
use super::{AGENT, at, count, decision, deny, missing, pos, ready};

fn close(capability: &str, offsets: &[u64]) -> Fold {
    Fold::Decided(decision(capability, offsets))
}

#[test]
fn a_position_close_leaves_a_refusal_at_an_equal_time_open() {
    let mut set = ready();
    deny(&mut set, 1, &missing("stripe.charges", 5));
    set.live(pos(Source::Access, 2), close("stripe.charges", &[1]));
    assert_eq!(count(&set), 0, "the shown refusal is closed");
    // The same minute, another position: not what the admin saw.
    deny(&mut set, 3, &missing("stripe.charges", 5));
    assert_eq!(
        count(&set),
        1,
        "a later refusal reopens, even at an equal time"
    );
}

#[test]
fn a_decision_replayed_before_its_refusals_closes_them_all_the_same() {
    let mut set = ready();
    set.replayed(pos(Source::Access, 9), close("stripe.charges", &[1, 2]));
    set.replayed(
        pos(Source::Access, 1),
        Fold::Denial(missing("stripe.charges", 5)),
    );
    set.replayed(
        pos(Source::Access, 2),
        Fold::Denial(missing("stripe.charges", 1)),
    );
    set.expire(at(10));
    assert_eq!(count(&set), 0);
}

#[test]
fn a_position_close_is_dropped_with_its_refusals_at_the_retention_edge() {
    let mut set = ready();
    deny(&mut set, 1, &missing("stripe.charges", 5));
    set.live(pos(Source::Access, 2), close("stripe.charges", &[1]));
    set.evict_before(5);
    assert!(
        set.requested.is_empty(),
        "a close whose refusals left the log is not kept"
    );
}

fn request() -> OpenRequest {
    let positions = |offsets: &[u64]| -> Vec<LogPos> {
        offsets.iter().map(|o| pos(Source::Access, *o)).collect()
    };
    OpenRequest {
        item: Value::Null,
        authority: "https://idp.example".to_string(),
        subject: "alice".to_string(),
        agent: AGENT.to_string(),
        entries: vec![
            ("stripe.refunds".to_string(), positions(&[7, 3])),
            ("stripe.charges".to_string(), positions(&[1])),
        ],
    }
}

#[test]
fn the_event_id_follows_what_was_denied_and_not_the_order_it_is_listed_in() {
    let mut reordered = request();
    reordered.entries.reverse();
    reordered.entries[1].1.reverse();
    assert_eq!(event_id(&request()), event_id(&reordered));

    let mut wider = request();
    wider.entries[1].1.push(pos(Source::Access, 8));
    assert_ne!(
        event_id(&request()),
        event_id(&wider),
        "another refusal is another id"
    );
    let mut other_agent = request();
    other_agent.agent = "mtls:other".to_string();
    assert_ne!(event_id(&request()), event_id(&other_agent));
}

#[test]
fn a_written_note_reads_back_into_the_decisions_it_was_written_from() {
    let open = request();
    let id = event_id(&open);
    let fields: Map<String, Value> =
        record_fields(&open, "not needed", &"a".repeat(64), &id, at(1));
    let read = decisions_from_record(&fields).expect("a well-formed decline");
    let mut wrote = decisions_of(&open);
    let key = |d: &UiDecision| d.capability.clone();
    wrote.sort_by_key(key);
    let mut got = read;
    got.sort_by_key(key);
    assert_eq!(got, wrote);
    assert_eq!(got[0].closes.len(), 1, "stripe.charges had one refusal");
}

#[test]
fn a_note_that_is_not_a_complete_decline_closes_nothing() {
    let open = request();
    let good = record_fields(&open, "r", &"a".repeat(64), &event_id(&open), at(1));
    for broken in [
        |f: &mut Map<String, Value>| drop(f.remove("decision")),
        |f: &mut Map<String, Value>| drop(f.insert("decision".into(), "allow".into())),
        |f: &mut Map<String, Value>| drop(f.insert("entries".into(), Value::Array(Vec::new()))),
        |f: &mut Map<String, Value>| drop(f.remove("agent")),
        |f: &mut Map<String, Value>| {
            drop(f.insert(
                "entries".into(),
                serde_json::json!([{"capability": "c", "positions": []}]),
            ));
        },
    ] {
        let mut fields = good.clone();
        broken(&mut fields);
        assert!(decisions_from_record(&fields).is_none(), "{fields:?}");
    }
}

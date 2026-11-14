// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A decision that closes refusals by position, and the record it is written
//! as: order independence, the equal-time case, the record's round trip and
//! its id.

use serde_json::Value;

use super::super::{
    Fold, LogPos, OpenRequest, Source, UiDecision, decision_record, decisions_from_record,
    decisions_of, event_id,
};
use super::{AGENT, at, count, decision, deny, missing, pos, ready};

#[test]
fn a_position_close_leaves_a_refusal_at_an_equal_time_open() {
    let mut set = ready();
    deny(&mut set, 1, &missing("stripe.charges", 5));
    set.apply_decisions(vec![decision("stripe.charges", &[1])]);
    assert_eq!(count(&set), 0, "the shown refusal is closed");
    // The same minute, another position: not what the admin saw.
    deny(&mut set, 3, &missing("stripe.charges", 5));
    assert_eq!(
        count(&set),
        1,
        "a later refusal reopens, even at an equal time"
    );
}

/// At a start the governance audit can be read after the refusals, so a
/// decision can be folded after a later refusal of the same capability: it
/// still closes only the refusal it names.
#[test]
fn a_decision_folded_after_a_later_refusal_closes_only_its_own() {
    let mut set = ready();
    deny(&mut set, 1, &missing("stripe.charges", 5));
    deny(&mut set, 2, &missing("stripe.charges", 6));
    set.apply_decisions(vec![decision("stripe.charges", &[1])]);
    assert_eq!(count(&set), 1, "the later refusal stays open");
}

#[test]
fn a_decision_replayed_before_its_refusals_closes_them_all_the_same() {
    let mut set = ready();
    set.apply_decisions(vec![decision("stripe.charges", &[1, 2])]);
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
    set.apply_decisions(vec![decision("stripe.charges", &[1])]);
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

/// The id's layout is pinned by a vector computed outside this code from the
/// documented encoding, so a change to the encoder cannot move it unseen.
#[test]
fn the_event_id_matches_its_fixed_vector() {
    assert_eq!(
        event_id(&request()),
        "51fb8053d14f565dadf0e07d194788b27146441b712629300251c2c9b70438c5"
    );
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
fn a_written_record_reads_back_into_the_decisions_it_was_written_from() {
    let open = request();
    let record = decision_record(&open, &"a".repeat(64));
    let read = decisions_from_record(&record).expect("a well-formed decline");
    let mut wrote = decisions_of(&open);
    let key = |d: &UiDecision| d.capability.clone();
    wrote.sort_by_key(key);
    let mut got = read;
    got.sort_by_key(key);
    assert_eq!(got, wrote);
    assert_eq!(got[0].closes.len(), 1, "stripe.charges had one refusal");
}

#[test]
fn a_record_with_no_capability_or_no_refusal_closes_nothing() {
    let good = decision_record(&request(), &"a".repeat(64));
    let mut no_capability = good.clone();
    no_capability.entries.clear();
    assert!(decisions_from_record(&no_capability).is_none());
    let mut no_refusal = good;
    no_refusal.entries[0].positions.clear();
    assert!(decisions_from_record(&no_refusal).is_none());
}

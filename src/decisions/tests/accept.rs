// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! An accept's ids and its record: the key, the event id and the row ids
//! (pinned to fixed vectors), and that only a decline closes refusals.

use serde_json::{Value, json};

use super::super::record::{AcceptTtl, accept_event_id, accept_key, accept_row_id};
use super::super::{LogPos, OpenRequest, Source, decision_record, decisions_from_record};
use super::{AGENT, at, count, deny, grant, missing, ready};
use crate::control_plane::{UiDecisionKind, UiDecisionRecord};
use crate::identity_grants::GrantScope;

fn pos(entry: &str, counter: u64) -> LogPos {
    LogPos {
        log: Source::Access,
        entry: entry.to_owned(),
        counter,
    }
}

/// Two capabilities, one refusal each.
fn request() -> OpenRequest {
    OpenRequest {
        item: Value::Null,
        authority: "https://idp.example".to_owned(),
        subject: "alice".to_owned(),
        agent: AGENT.to_owned(),
        entries: vec![
            ("stripe.charges".to_owned(), vec![pos("hash-1", 1)]),
            ("stripe.refunds".to_owned(), vec![pos("hash-2", 2)]),
        ],
    }
}

/// The administrator who accepts.
const ADMIN: &str = "admin-1";

const DIGEST: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

/// R1a: the encoding is pinned by fixed vectors, computed outside this code
/// from the documented layout.
#[test]
fn the_accept_ids_match_their_fixed_vectors() {
    let key = accept_key(&request(), ADMIN, DIGEST, AcceptTtl::Seconds(3600));
    assert_eq!(
        key,
        "5a978ef54b8a7f2d6b2b15f1ffe4fc5544bdd6bcc475e42788de0de3e016d1f4"
    );
    assert_eq!(
        accept_event_id(&key, 0),
        "c4928fcdd7a9a09b80d7a6669f42d44fd004037e8b83ec3b87538e3d49e1f3dd"
    );
    assert_eq!(
        accept_row_id(&key, "stripe.charges", 0),
        "6f1a1fdf31d9deb1a3bc83cfe8b2b312acdac24c90437a7ae839137dd9898c00"
    );
}

/// R1b: each input alone changes the key; the order positions are listed in
/// does not.
#[test]
fn each_accept_input_changes_the_key_and_the_listing_order_does_not() {
    let base = accept_key(&request(), ADMIN, DIGEST, AcceptTtl::Seconds(60));
    let mut reordered = request();
    reordered.entries.reverse();
    assert_eq!(
        accept_key(&reordered, ADMIN, DIGEST, AcceptTtl::Seconds(60)),
        base
    );

    let changed = |edit: &dyn Fn(&mut OpenRequest)| {
        let mut other = request();
        edit(&mut other);
        accept_key(&other, ADMIN, DIGEST, AcceptTtl::Seconds(60))
    };
    assert_ne!(changed(&|r| r.authority.push('x')), base, "authority");
    assert_ne!(changed(&|r| r.subject.push('x')), base, "subject");
    assert_ne!(changed(&|r| r.agent.push('x')), base, "agent");
    assert_ne!(
        changed(&|r| r.entries[0].1[0].counter = 9),
        base,
        "a position"
    );
    assert_ne!(changed(&|r| r.entries[0].0.push('x')), base, "a capability");
    assert_ne!(
        accept_key(&request(), "admin-2", DIGEST, AcceptTtl::Seconds(60)),
        base,
        "another administrator"
    );
    let digest = "b".repeat(64);
    assert_ne!(
        accept_key(&request(), ADMIN, &digest, AcceptTtl::Seconds(60)),
        base,
        "digest"
    );
    assert_ne!(
        accept_key(&request(), ADMIN, DIGEST, AcceptTtl::Seconds(120)),
        base,
        "ttl"
    );
    assert_ne!(
        accept_key(&request(), ADMIN, DIGEST, AcceptTtl::Permanent),
        base,
        "permanent"
    );
}

/// R1e: field boundaries cannot be moved between fields.
#[test]
fn the_accept_key_keeps_its_field_boundaries() {
    let mut one = request();
    one.authority = "ab".to_owned();
    one.subject = "c".to_owned();
    let mut two = request();
    two.authority = "a".to_owned();
    two.subject = "bc".to_owned();
    assert_ne!(
        accept_key(&one, ADMIN, DIGEST, AcceptTtl::Permanent),
        accept_key(&two, ADMIN, DIGEST, AcceptTtl::Permanent)
    );
    // The agent and the administrator are neighbouring fields too.
    let mut three = request();
    three.agent.push('x');
    assert_ne!(
        accept_key(&three, ADMIN, DIGEST, AcceptTtl::Permanent),
        accept_key(&request(), "xadmin-1", DIGEST, AcceptTtl::Permanent)
    );
}

/// R1c, R1d: the request's generation changes the event id and no row id; a
/// capability's generation changes only its own row id, so after a partial
/// revoke the live row keeps its id.
#[test]
fn generations_move_only_the_ids_they_belong_to() {
    let key = accept_key(&request(), ADMIN, DIGEST, AcceptTtl::Permanent);
    assert_ne!(accept_event_id(&key, 0), accept_event_id(&key, 1));
    let live = accept_row_id(&key, "stripe.charges", 0);
    let revoked_before = accept_row_id(&key, "stripe.refunds", 0);
    // stripe.refunds' row was revoked: its generation is 1, the request's is 1.
    assert_eq!(accept_row_id(&key, "stripe.charges", 0), live);
    assert_ne!(accept_row_id(&key, "stripe.refunds", 1), revoked_before);
    assert_ne!(
        accept_row_id(&key, "stripe.charges", 0),
        accept_row_id(&key, "stripe.refunds", 0),
        "the capability is part of the row id"
    );
}

/// R2b, R3: only a decline closes refusals. An accept record, an unknown kind
/// and a record mixing the two close nothing; a decline in the old form (no
/// kind) and the new form both do, unless they name rows or an expiry.
#[test]
fn only_a_decline_record_closes_refusals() {
    let decline = decision_record(&request(), DIGEST);
    assert!(
        decisions_from_record(&decline).is_some(),
        "new-form decline"
    );
    let mut old = decline.clone();
    old.decision = None;
    assert!(
        decisions_from_record(&old).is_some(),
        "a decline written before accepts"
    );

    let mut accept = decline.clone();
    accept.decision = Some(UiDecisionKind::Accept);
    accept.rows = vec![("r1".to_owned(), "sha256:ab".to_owned())];
    assert!(decisions_from_record(&accept).is_none(), "an accept");
    let mut rows_no_kind = decline.clone();
    rows_no_kind.decision = None;
    rows_no_kind.rows = vec![("r1".to_owned(), "sha256:ab".to_owned())];
    assert!(
        decisions_from_record(&rows_no_kind).is_none(),
        "rows without a kind"
    );
    let mut decline_with_expiry = decline.clone();
    decline_with_expiry.expires_at = Some(chrono::DateTime::from_timestamp(0, 0).expect("epoch"));
    assert!(
        decisions_from_record(&decline_with_expiry).is_none(),
        "a decline with an expiry"
    );
    let mut decline_with_rows = decline;
    decline_with_rows.rows = vec![("r1".to_owned(), "sha256:ab".to_owned())];
    assert!(
        decisions_from_record(&decline_with_rows).is_none(),
        "a decline with rows"
    );

    let mut unk = serde_json::to_value(decision_record(&request(), DIGEST)).expect("serialises");
    unk["decision"] = json!("maybe");
    assert!(
        serde_json::from_value::<UiDecisionRecord>(unk).is_err(),
        "an unrecognised kind does not read as a record at all"
    );
}

/// R3b: an accepted request is closed by its published grant, not by its
/// record, so revoking the grant opens it again.
#[test]
fn an_accepted_request_closes_by_its_grant_and_reopens_on_revoke() {
    let mut set = ready();
    deny(&mut set, 1, &missing("stripe.charges", 1));
    let mut accept = decision_record(&request(), DIGEST);
    accept.decision = Some(UiDecisionKind::Accept);
    accept.rows = vec![("r1".to_owned(), "sha256:ab".to_owned())];
    // Folded as the startup replay folds every kept record.
    set.apply_decisions(
        decisions_from_record(&accept)
            .into_iter()
            .flatten()
            .collect(),
    );
    assert_eq!(count(&set), 1, "the record alone closes nothing");
    let mut row = grant("stripe.charges", GrantScope::Execute);
    set.set_grants(vec![row.clone()], at(2));
    assert_eq!(count(&set), 0, "the published grant closes it");
    row.revoked_at = Some(at(3));
    set.set_grants(vec![row], at(4));
    assert_eq!(count(&set), 1, "revoking the grant opens it again");
}

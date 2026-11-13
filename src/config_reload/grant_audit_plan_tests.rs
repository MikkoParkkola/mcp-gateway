// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A grant row an accept's audit record names is accounted for only when
//! its id AND digest match one undisputed claim; every other case keeps the
//! out-of-band path. Each attribution row is checked against its no-claim
//! control first.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use super::grant_audit::{JournalRead, PlannedRecord};
use super::grant_audit_plan::{Claim, Outside, State, plan};
use super::grant_audit_tests::row;
use crate::control_plane::GrantChangeVerb;
use crate::identity_grants::IdentityGrant;
use crate::identity_grants::journal::grant_digest;

const GRANTS: &str = "/grants/identity-grants.yaml";

/// A state with an empty baseline: an unknown served row is a change.
fn based() -> State {
    State {
        grants: Some(BTreeMap::new()),
        ..State::fresh(Path::new(GRANTS))
    }
}

fn claim(row_id: &str, digest: &str, event_id: &str) -> Claim {
    Claim {
        row_id: row_id.to_owned(),
        digest: digest.to_owned(),
        event_id: event_id.to_owned(),
    }
}

fn run(
    state: &State,
    rows: &[IdentityGrant],
    journal: &JournalRead,
    claims: &[Claim],
) -> (Vec<PlannedRecord>, State) {
    let (records, next, _, _) = plan(state, rows, journal, claims, &BTreeSet::new());
    (records, next)
}

/// The targets of the records planned with `verb`.
fn with_verb(records: &[PlannedRecord], verb: GrantChangeVerb) -> Vec<String> {
    records
        .iter()
        .filter(|r| r.event.grant_change.as_ref().map(|c| c.verb) == Some(verb))
        .map(|r| r.event.target_id.clone())
        .collect()
}

fn out_of_band(records: &[PlannedRecord]) -> Vec<String> {
    with_verb(records, GrantChangeVerb::OutOfBand)
}

/// R5 (red first), R5b: a claim that matches the row id but not its digest,
/// or the digest but not the row id, explains nothing.
#[test]
fn a_claim_must_match_both_the_row_id_and_its_digest() {
    let rows = vec![row("g1", "r")];
    let digest = grant_digest(&rows[0]);
    let none = &JournalRead::Missing;
    assert_eq!(
        out_of_band(&run(&based(), &rows, none, &[]).0),
        ["g1"],
        "control"
    );
    let wrong_digest = [claim("g1", "sha256:other", "e1")];
    assert_eq!(
        out_of_band(&run(&based(), &rows, none, &wrong_digest).0),
        ["g1"]
    );
    let wrong_id = [claim("g2", &digest, "e1")];
    assert_eq!(
        out_of_band(&run(&based(), &rows, none, &wrong_id).0),
        ["g1"]
    );
}

/// R6, R6g: a single claim, or several identical ones, with the row's id and
/// digest accounts for it; the baseline then holds that digest.
#[test]
fn a_matching_claim_accounts_for_its_row() {
    let rows = vec![row("g1", "r")];
    let digest = grant_digest(&rows[0]);
    let none = &JournalRead::Missing;
    assert_eq!(
        out_of_band(&run(&based(), &rows, none, &[]).0),
        ["g1"],
        "control"
    );
    for claims in [
        vec![claim("g1", &digest, "e1")],
        vec![claim("g1", &digest, "e1"), claim("g1", &digest, "e1")],
    ] {
        let (records, next) = run(&based(), &rows, none, &claims);
        assert!(
            records.is_empty(),
            "{claims:?}: {:?}",
            out_of_band(&records)
        );
        assert_eq!(
            next.grants.as_ref().and_then(|g| g.get("g1")),
            Some(&digest)
        );
    }
}

/// R6b: claims that disagree on the digest or the event id explain nothing.
#[test]
fn disagreeing_claims_explain_nothing() {
    let rows = vec![row("g1", "r")];
    let digest = grant_digest(&rows[0]);
    let none = &JournalRead::Missing;
    for claims in [
        vec![claim("g1", &digest, "e1"), claim("g1", &digest, "e2")],
        vec![
            claim("g1", &digest, "e1"),
            claim("g1", "sha256:other", "e1"),
        ],
    ] {
        assert_eq!(
            out_of_band(&run(&based(), &rows, none, &claims).0),
            ["g1"],
            "{claims:?}"
        );
    }
}

/// R6c: a claim for a row that is not served adds nothing: no record, and
/// the baseline does not gain it (no-claim control: no record either).
#[test]
fn a_claim_for_a_row_not_served_adds_nothing() {
    let none = &JournalRead::Missing;
    let (control, _) = run(&based(), &[], none, &[]);
    assert!(control.is_empty());
    let (records, next) = run(&based(), &[], none, &[claim("g9", "sha256:ab", "e1")]);
    assert!(records.is_empty(), "{:?}", out_of_band(&records));
    assert_eq!(next.grants, Some(BTreeMap::new()));
}

/// R6d: while the gap is set a claim does not apply; the row plans as it
/// would without one (indeterminate).
#[test]
fn a_claim_does_not_apply_under_a_gap() {
    let rows = vec![row("g1", "r")];
    let digest = grant_digest(&rows[0]);
    let gap = State {
        gap: true,
        ..based()
    };
    let none = &JournalRead::Missing;
    let (control, _) = run(&gap, &rows, none, &[]);
    let (with, _) = run(&gap, &rows, none, &[claim("g1", &digest, "e1")]);
    assert!(with_verb(&control, GrantChangeVerb::Indeterminate).contains(&"g1".to_owned()));
    assert_eq!(
        with_verb(&with, GrantChangeVerb::Indeterminate),
        with_verb(&control, GrantChangeVerb::Indeterminate)
    );
}

/// R6e: where this plan's journal touched the row, the journal decides and
/// a claim is ignored (here the journal names another digest, so the row is
/// out-of-band; applying the claim would hide that).
#[test]
fn the_journal_decides_a_row_it_touched() {
    let rows = vec![row("g1", "r")];
    let digest = grant_digest(&rows[0]);
    let entry = crate::identity_grants::journal::JournalEntry {
        v: crate::identity_grants::journal::JOURNAL_VERSION,
        entry_id: "j1".to_owned(),
        verb: crate::identity_grants::journal::JournalVerb::Add,
        grant_id: "g1".to_owned(),
        prev_digest: None,
        digest: "sha256:journalled".to_owned(),
        expires_at: None,
        at: chrono::DateTime::from_timestamp(0, 0).expect("epoch"),
        actor: "unknown".to_owned(),
        os_account: None,
    };
    let mut line = serde_json::to_vec(&entry).expect("a journal line");
    line.push(b'\n');
    let journal = &JournalRead::Bytes(line);
    let (control, _) = run(&based(), &rows, journal, &[]);
    assert_eq!(out_of_band(&control), ["g1"], "control");
    let (with, _) = run(&based(), &rows, journal, &[claim("g1", &digest, "e1")]);
    assert_eq!(out_of_band(&with), ["g1"]);
}

/// R6f: the accounted digest survives the state file: re-planned without the
/// claim nothing is owed, and a later change of the row is seen.
#[test]
fn an_accounted_row_survives_a_state_round_trip() {
    let dir = tempfile::tempdir().expect("dir");
    let path = dir.path().join("state.json");
    let rows = vec![row("g1", "r")];
    let digest = grant_digest(&rows[0]);
    let none = &JournalRead::Missing;
    let (_, next) = run(&based(), &rows, none, &[claim("g1", &digest, "e1")]);
    next.save(&path).expect("saved");
    let loaded = State::load(&path, Path::new(GRANTS)).expect("loaded");
    let (again, after) = run(&loaded, &rows, none, &[]);
    assert!(again.is_empty(), "{:?}", out_of_band(&again));
    let changed = vec![row("g1", "another reason")];
    assert_eq!(out_of_band(&run(&after, &changed, none, &[]).0), ["g1"]);
}

/// JRN.3: a served row whose digest is not the one its records name is
/// recorded out-of-band and returned with both digests for the warning,
/// which the plan does not give itself: a plan may still be refused
/// (control: a row whose digest matches is neither recorded nor returned).
#[test]
fn a_row_changed_outside_the_gateway_is_returned_with_both_digests() {
    let before = row("g1", "r");
    let after = row("g1", "edited");
    let state = State {
        grants: Some(BTreeMap::from([("g1".to_owned(), grant_digest(&before))])),
        ..based()
    };
    let none = &JournalRead::Missing;
    let plan_of = |rows: &[IdentityGrant]| plan(&state, rows, none, &[], &BTreeSet::new());
    let (same, _, _, quiet) = plan_of(std::slice::from_ref(&before));
    assert!(same.is_empty(), "control: {:?}", out_of_band(&same));
    assert!(quiet.is_empty(), "control: {quiet:?}");
    let ((records, _, _, outside), logs) =
        crate::test_log_capture::capture_warnings(|| plan_of(std::slice::from_ref(&after)));
    assert_eq!(out_of_band(&records), ["g1"]);
    let want = Outside {
        id: "g1".to_owned(),
        expected: Some(grant_digest(&before)),
        actual: Some(grant_digest(&after)),
    };
    assert_eq!(outside, [want]);
    assert!(!logs.contains("outside the gateway"), "{logs}");
}

/// A claim explains only a row the records do not already name: with the
/// baseline at a later digest, a file reverted outside the gateway to the
/// digest an old accept named stays out-of-band (control: no claim).
#[test]
fn a_stale_claim_does_not_explain_a_revert_of_a_known_row() {
    let accepted = row("g1", "r");
    let later = row("g1", "later");
    let state = State {
        grants: Some(BTreeMap::from([("g1".to_owned(), grant_digest(&later))])),
        ..based()
    };
    let none = &JournalRead::Missing;
    let reverted = std::slice::from_ref(&accepted);
    assert_eq!(
        out_of_band(&run(&state, reverted, none, &[]).0),
        ["g1"],
        "control"
    );
    let stale = [claim("g1", &grant_digest(&accepted), "e1")];
    assert_eq!(out_of_band(&run(&state, reverted, none, &stale).0), ["g1"]);
}

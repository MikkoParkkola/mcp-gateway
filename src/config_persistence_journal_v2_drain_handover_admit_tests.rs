// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Admission rows: each reports its cases one by one, and the maximal size bounds every reachable donor.

use super::super::super::abandoned::{encode_frame, frames_of, marked};
use super::super::super::fixtures::{collect_case, decision};
use super::super::super::{FrozenRecord, JournalV2, ParkReason, Phase, ResultClass, TokenState};
use super::super::fixtures::{OUTCOME, OUTCOME_DIGEST, attempt, decided, record, staged, state};
use super::tests::{file_bytes, journal_bytes, rig};
use super::{HandoverError, admits, hand_over, maximal_size};
use crate::security::transparency_log::settle::{Reason, Role};

/// The byte length of the frames a handover of `donor` would write.
fn encoded_len(donor: &JournalV2) -> usize {
    frames_of(donor)
        .expect("the donor is bound")
        .iter()
        .map(|frame| encode_frame(frame).expect("a frame fits").len())
        .sum()
}

/// A decided, accepted donor, built the way the handover rig builds one, with no session.
fn standard() -> JournalV2 {
    let dir = tempfile::tempdir().expect("donor directory");
    let mut donor = state(dir.path());
    decided(&mut donor);
    staged(&mut donor);
    donor.phase = Phase::Accepted;
    donor
}

fn edit_tokens(donor: &mut JournalV2, mut edit: impl FnMut(&mut TokenState)) {
    if let Some(writer) = donor.writer.as_mut() {
        edit(writer);
    }
    for token in &mut donor.attempts {
        edit(token);
    }
}

fn edit_records(donor: &mut JournalV2, mut edit: impl FnMut(&mut FrozenRecord)) {
    edit_tokens(donor, |token| {
        edit(&mut token.intent);
        for frozen in &mut token.records {
            edit(frozen);
        }
    });
}

struct Donor {
    name: &'static str,
    journal: JournalV2,
    /// The cleared writer still owes the terminal `decided` would have frozen.
    owe_terminal: bool,
}

fn donors() -> Vec<Donor> {
    let standard = standard();
    let mut cleared = standard.clone();
    {
        let writer = cleared.writer.as_mut().expect("a writer");
        writer.intent_counter = None;
        writer.records.clear();
    }
    let mut with_attempt = standard.clone();
    {
        let mut extra = attempt();
        extra.decision = Some(decision(ResultClass::NotWritten, Reason::Refused));
        with_attempt.attempts.push(extra);
    }
    let mut root = standard.clone();
    {
        let writer = root.writer.take().expect("a writer");
        root.attempts.push(writer);
    }
    vec![
        Donor {
            name: "standard",
            journal: standard,
            owe_terminal: false,
        },
        Donor {
            name: "cleared",
            journal: cleared,
            owe_terminal: true,
        },
        Donor {
            name: "with attempt",
            journal: with_attempt,
            owe_terminal: false,
        },
        Donor {
            name: "root",
            journal: root,
            owe_terminal: false,
        },
    ]
}

fn reachable(donor: &Donor, marked_donor: &JournalV2) -> Vec<(String, JournalV2)> {
    let mut variants = Vec::new();
    variants.push(("marked".to_owned(), marked_donor.clone()));

    let mut wide = marked_donor.clone();
    edit_tokens(&mut wide, |token| {
        token.intent_counter = Some(9_999_999_999);
    });
    variants.push(("wide counter".to_owned(), wide));

    let mut delivered = marked_donor.clone();
    edit_records(&mut delivered, |frozen| frozen.delivered = true);
    variants.push(("delivered".to_owned(), delivered));

    let mut undelivered = marked_donor.clone();
    edit_records(&mut undelivered, |frozen| frozen.delivered = false);
    variants.push(("undelivered".to_owned(), undelivered));

    for (reason, label) in [
        (ParkReason::InvalidPayload, "invalid payload"),
        (ParkReason::ContentConflict, "content conflict"),
        (ParkReason::ArtifactCorrupt, "artifact corrupt"),
    ] {
        let mut parked = marked_donor.clone();
        edit_records(&mut parked, |frozen| frozen.parked = Some(reason));
        variants.push((format!("parked {label}"), parked));
    }

    if donor.owe_terminal {
        let mut terminal = marked_donor.clone();
        let writer = terminal
            .writer
            .as_mut()
            .expect("the cleared donor has a writer");
        writer
            .records
            .push(record(Role::Outcome, OUTCOME, OUTCOME_DIGEST));
        writer.intent_counter = Some(9_999_999_999);
        variants.push(("terminal record".to_owned(), terminal));
    }
    // Everything at once: the widest counters, every record undelivered and parked, and the
    // owed terminal frozen. The bound must cover the combination, not only each change alone.
    for reason in [
        ParkReason::InvalidPayload,
        ParkReason::ContentConflict,
        ParkReason::ArtifactCorrupt,
    ] {
        let mut worst = marked_donor.clone();
        if donor.owe_terminal {
            let writer = worst
                .writer
                .as_mut()
                .expect("the cleared donor has a writer");
            writer
                .records
                .push(record(Role::Outcome, OUTCOME, OUTCOME_DIGEST));
        }
        edit_tokens(&mut worst, |token| token.intent_counter = Some(u64::MAX));
        edit_records(&mut worst, |frozen| {
            frozen.delivered = false;
            frozen.parked = Some(reason);
        });
        variants.push((format!("combined {reason:?}"), worst));
    }
    variants
}

#[test]
fn maximal_size_bounds_every_state() {
    const ROW: &str = "maximal_size_bounds_every_state";
    let mut failures = Vec::new();
    for donor in donors() {
        let marked_donor = marked(&donor.journal);
        let bound = maximal_size(&marked_donor);
        for (variant, body) in reachable(&donor, &marked_donor) {
            let case = format!("{}/{}", donor.name, variant);
            collect_case(
                &mut failures,
                ROW,
                &case,
                "encoded length within the maximal size",
                || {
                    let len = encoded_len(&body);
                    assert!(
                        len <= bound,
                        "{case}: encoded {len} exceeds the maximal size {bound}"
                    );
                    Ok(())
                },
            );
        }
        let case = format!("{}/admits", donor.name);
        collect_case(
            &mut failures,
            ROW,
            &case,
            "the maximal size admits and one byte under refuses",
            || {
                assert!(bound > 0, "{case}: maximal_size is positive, got {bound}");
                assert!(
                    admits(&marked_donor, bound),
                    "{case}: the maximal size admits the donor"
                );
                assert!(
                    !admits(&marked_donor, bound - 1),
                    "{case}: one byte under the maximal size refuses"
                );
                Ok(())
            },
        );
    }
    assert!(failures.is_empty(), "{ROW}:\n{}", failures.join("\n"));
}

fn refuses(what: &str, edit: impl FnOnce(&mut JournalV2)) {
    let mut rig = rig(edit);
    let before = journal_bytes(&rig.path);
    assert_eq!(
        hand_over(&mut rig.session),
        Err(HandoverError::Journal),
        "{what}"
    );
    assert_eq!(
        journal_bytes(&rig.path),
        before,
        "{what}: journal untouched"
    );
    assert_eq!(file_bytes(&rig.path), None, "{what}: no abandoned file");
}

#[test]
fn handover_refuses_undecided_and_parked() {
    const ROW: &str = "handover_refuses_undecided_and_parked";
    let mut failures = Vec::new();
    collect_case(
        &mut failures,
        ROW,
        "undecided",
        "refused, the journal unchanged, no abandoned file",
        || {
            refuses("undecided", |donor| {
                donor.writer.as_mut().expect("a writer").decision = None;
            });
            Ok(())
        },
    );
    collect_case(
        &mut failures,
        ROW,
        "parked",
        "refused, the journal unchanged, no abandoned file",
        || {
            refuses("parked", |donor| {
                donor.writer.as_mut().expect("a writer").intent.parked =
                    Some(ParkReason::InvalidPayload);
            });
            Ok(())
        },
    );
    assert!(failures.is_empty(), "{ROW}:\n{}", failures.join("\n"));
}

/// A token whose terminal is already frozen is never built again, so its intent payload is never
/// parsed: the size bound must not refuse it for a payload only a builder would read.
#[test]
fn handover_admits_prefrozen_unparseable() {
    const ROW: &str = "handover_admits_prefrozen_unparseable";
    let mut rig = rig(|donor| {
        donor.writer.as_mut().expect("a writer").intent.payload_json = b"not json".to_vec();
    });
    let bound = maximal_size(&marked(&rig.donor));
    assert_ne!(bound, usize::MAX, "{ROW}: the bound is finite");
    assert_eq!(hand_over(&mut rig.session), Ok(()), "{ROW}: handed over");
    assert!(file_bytes(&rig.path).is_some(), "{ROW}: the file exists");
}

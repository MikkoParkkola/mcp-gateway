// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Placement rows: what an existing abandoned file is against the donor, and when a journal
//! may be finished. Each row reports its cases one by one instead of stopping at the first.

use super::super::fixtures::{JOURNAL_V2_HANDED_OVER, collect_case};
use super::super::{Fact, JournalError, JournalV2, ParkReason, Pending, Phase};
use super::fixtures::{HANDED_OVER_JSON, donor, file, handed_over, record_0, record_1, reframe};
use super::{Placement, against_donor, marked};
use crate::config_persistence::commit::{Action, FileRevision};

const OLD: &[u8] = b"old: 1\n";
const NEW: &[u8] = b"new: 2\n";

fn torn(frame: &[u8], n: usize) -> Vec<u8> {
    frame[..n].to_vec()
}

/// The handed-over journal golden, not yet accepted: one intent, a durable fact.
fn handed_over_journal() -> JournalV2 {
    JournalV2::decode(JOURNAL_V2_HANDED_OVER).expect("handed-over journal golden")
}

/// The same journal ready to finish: its change committed and accepted.
fn ready() -> JournalV2 {
    let mut state = handed_over_journal();
    state.phase = Phase::Accepted;
    state.original_revision = Some(FileRevision::of(OLD));
    state.new_revision = Some(FileRevision::of(NEW));
    state.fact = Some(Fact::Committed(FileRevision::of(NEW)));
    state
}

fn unflagged(mut state: JournalV2) -> JournalV2 {
    state.writer.as_mut().expect("a writer").handed_over = false;
    state
}

fn finish_gate_cases() -> Vec<(&'static str, JournalV2, Result<(), JournalError>)> {
    let mut parked = ready();
    parked.writer.as_mut().expect("a writer").intent.parked = Some(ParkReason::InvalidPayload);
    let mut no_fact = ready();
    no_fact.phase = Phase::Intended;
    no_fact.fact = None;
    let mut not_accepted = ready();
    not_accepted.phase = Phase::Staged;
    let mut pending = ready();
    pending.phase = Phase::Staged;
    pending.fact = None;
    pending.pending = Some(Pending {
        action: Action::Forward,
        expected: FileRevision::of(NEW),
        pre_action: FileRevision::of(OLD),
        tried: false,
    });
    let mut other_version = ready();
    other_version.version = 3;
    vec![
        ("ready", ready(), Ok(())),
        ("parked record", parked, Err(JournalError::Finish)),
        ("no durable fact", no_fact, Err(JournalError::Finish)),
        (
            "committed, not accepted",
            not_accepted,
            Err(JournalError::Finish),
        ),
        ("pending action", pending, Err(JournalError::Finish)),
        (
            "an unfinished token",
            unflagged(ready()),
            Err(JournalError::Finish),
        ),
        (
            "another version",
            other_version,
            Err(JournalError::UnsupportedVersion),
        ),
    ]
}

#[test]
fn finish_ready_refuses_what_finish_refuses() {
    const ROW: &str = "finish_ready_refuses_what_finish_refuses";
    let mut failures = Vec::new();
    for (name, state, expected) in finish_gate_cases() {
        collect_case(
            &mut failures,
            ROW,
            name,
            "the one check finish makes",
            || {
                assert_eq!(state.finish_ready(), expected, "{name}");
                Ok(())
            },
        );
    }
    collect_case(
        &mut failures,
        ROW,
        "marked_makes_an_undelivered_token_finishable",
        "an unfinished token passes once it is marked handed over, and a parked one still does not",
        || {
            let undelivered = unflagged(ready());
            assert_eq!(
                undelivered.finish_ready(),
                Err(JournalError::Finish),
                "unmarked"
            );
            assert_eq!(marked(&undelivered).finish_ready(), Ok(()), "marked");
            let mut parked = unflagged(ready());
            parked.writer.as_mut().expect("a writer").intent.parked =
                Some(ParkReason::ContentConflict);
            assert_eq!(
                marked(&parked).finish_ready(),
                Err(JournalError::Finish),
                "a parked record stays refused after marking"
            );
            Ok(())
        },
    );
    assert!(failures.is_empty(), "{ROW}:\n{}", failures.join("\n"));
}

#[test]
fn marked_flags_every_token_and_leaves_the_donor_alone() {
    const ROW: &str = "marked_flags_every_token_and_leaves_the_donor_alone";
    let mut state = unflagged(donor());
    let mut attempt = state.writer.clone().expect("a writer");
    attempt.intent_id = super::super::IntentId("attempt-2".to_owned());
    attempt.handed_over = false;
    state.attempts.push(attempt);
    let before = state.clone();
    let after = marked(&state);
    assert_eq!(state, before, "{ROW}: the donor is not changed");
    assert!(
        after
            .writer
            .iter()
            .chain(&after.attempts)
            .all(|t| t.handed_over),
        "{ROW}: every token is flagged"
    );
    assert_eq!(after.attempts.len(), 1, "{ROW}: the attempt is kept");
    assert_eq!(
        after.writer.as_ref().map(|t| &t.records),
        before.writer.as_ref().map(|t| &t.records),
        "{ROW}: records are kept"
    );
}

#[test]
fn placement_exact_cases() {
    const ROW: &str = "placement_exact_cases";
    let (i, r0, r1) = (handed_over(), record_0(), record_1());
    let whole = file(&[&i, &r0, &r1]);
    let (b1, b2) = (i.len(), i.len() + r0.len());
    let donor = marked(&donor());
    let mut failures = Vec::new();
    collect_case(
        &mut failures,
        ROW,
        "every_cut",
        "the whole file cut at every byte is Absent, Missing, Torn or Whole as its frames say",
        || {
            for n in 0..=whole.len() {
                let expected = match n {
                    0 => Placement::Absent,
                    n if n == whole.len() => Placement::Whole,
                    n if n == b1 => Placement::Missing { complete: 1 },
                    n if n == b2 => Placement::Missing { complete: 2 },
                    n => {
                        let (complete, start) = if n < b1 {
                            (0, 0)
                        } else if n < b2 {
                            (1, b1)
                        } else {
                            (2, b2)
                        };
                        Placement::Torn {
                            complete,
                            start,
                            proof: super::TornProof { start },
                        }
                    }
                };
                assert_eq!(
                    against_donor(&whole[..n], &donor),
                    expected,
                    "cut at byte {n}"
                );
            }
            Ok(())
        },
    );
    collect_case(
        &mut failures,
        ROW,
        "proof_carries_the_start",
        "a torn placement's proof names the same start as the placement",
        || {
            let bytes = file(&[&i, &torn(&r0, 10)]);
            match against_donor(&bytes, &donor) {
                Placement::Torn { start, proof, .. } => {
                    assert_eq!((start, proof.start()), (b1, b1));
                }
                other => panic!("expected a torn placement, got {other:?}"),
            }
            Ok(())
        },
    );
    assert!(failures.is_empty(), "{ROW}:\n{}", failures.join("\n"));
}

#[test]
fn placement_clean_foreign_refused() {
    const ROW: &str = "placement_clean_foreign_refused";
    let (i, r0, r1) = (handed_over(), record_0(), record_1());
    let altered = |from: &str, to: &str| {
        assert!(
            HANDED_OVER_JSON.contains(from),
            "the variant must change the golden"
        );
        reframe(&HANDED_OVER_JSON.replace(from, to))
    };
    let mut bad_sum = handed_over();
    bad_sum[4] = if bad_sum[4] == b'0' { b'1' } else { b'0' };
    let cases: Vec<(&str, Vec<u8>)> = vec![
        ("a gap", file(&[&r0])),
        ("a reorder", file(&[&r0, &i])),
        ("a duplicate", file(&[&i, &i])),
        ("a frame past the canonical end", file(&[&i, &r0, &r1, &i])),
        (
            "a torn tail after the whole sequence",
            file(&[&i, &r0, &r1, &torn(&i, 10)]),
        ),
        (
            "a payload-altered intent",
            file(&[
                &altered(r#""intent_counter":null"#, r#""intent_counter":7"#),
                &r0,
                &r1,
            ]),
        ),
        (
            "another binding",
            file(&[
                &altered(
                    r#""log_id":"opaque-log:fixture""#,
                    r#""log_id":"opaque-log:other""#,
                ),
                &r0,
                &r1,
            ]),
        ),
        (
            "owner facts written before the flag",
            file(&[
                &altered(r#""handed_over":true"#, r#""handed_over":false"#),
                &r0,
                &r1,
            ]),
        ),
        (
            "another role",
            file(&[
                &altered(
                    r#""role":"config_save_intent""#,
                    r#""role":"config_recovery_intent""#,
                ),
                &r0,
                &r1,
            ]),
        ),
        ("a bad checksum", file(&[&bad_sum, &r0, &r1])),
    ];
    let donor = marked(&donor());
    let mut failures = Vec::new();
    for (name, bytes) in cases {
        collect_case(
            &mut failures,
            ROW,
            name,
            "a file the donor does not prove is Foreign",
            || {
                assert_eq!(against_donor(&bytes, &donor), Placement::Foreign, "{name}");
                Ok(())
            },
        );
    }
    assert!(failures.is_empty(), "{ROW}:\n{}", failures.join("\n"));
}

#[test]
fn placement_empty_donor_and_post_flag_bytes() {
    const ROW: &str = "placement_empty_donor_and_post_flag_bytes";
    let mut failures = Vec::new();
    collect_case(
        &mut failures,
        ROW,
        "empty_file_for_an_empty_donor_is_whole",
        "no tokens and no bytes is Whole, not Absent; any frame is Foreign",
        || {
            let mut empty = donor();
            empty.writer = None;
            assert_eq!(
                against_donor(b"", &marked(&empty)),
                Placement::Whole,
                "empty"
            );
            assert_eq!(
                against_donor(&handed_over(), &marked(&empty)),
                Placement::Foreign,
                "a frame"
            );
            Ok(())
        },
    );
    collect_case(
        &mut failures,
        ROW,
        "post_flag_bytes",
        "frames carry handed_over: true, so they match the marked donor and not the unmarked one",
        || {
            let unmarked = unflagged(donor());
            let bytes = file(&[&handed_over(), &record_0(), &record_1()]);
            assert_eq!(
                against_donor(&bytes, &marked(&unmarked)),
                Placement::Whole,
                "marked"
            );
            assert_eq!(
                against_donor(&bytes, &unmarked),
                Placement::Foreign,
                "unmarked"
            );
            Ok(())
        },
    );
    assert!(failures.is_empty(), "{ROW}:\n{}", failures.join("\n"));
}

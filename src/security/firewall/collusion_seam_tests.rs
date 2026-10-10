// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! `MIK-8113`: a seam between plan steps is held under its composite source
//! with one `allowed_flows` mask per contributor; it leaves without being a
//! relay only by an egress that matches an entry of every contributor.

use std::time::Instant;

use super::{CollusionDetector, RelayAction, RelayParams};

const ALICE: &str = "principal-a";
const BOB: &str = "principal-b";
const SEAM: &str = "[mock:alpha+mock:beta]";
const EGRESS: &str = "mock:post_message";
/// Two fields joined: every k-gram over them spans both.
const TEXT: &str =
    "north slope rows seven to twelve, late pearssouth terrace rows one to six, early quinces";

/// Every k-gram kept, so each row checks the seams its text holds under any
/// hash key.
fn detector() -> CollusionDetector {
    let mut det = CollusionDetector::new(RelayParams {
        action: RelayAction::Observe,
        ..RelayParams::default()
    });
    det.keep_every_kgram();
    det
}

fn seam(det: &CollusionDetector, masks: Vec<u64>, now: Instant) {
    det.record_seam_at(SEAM, ALICE, (true, masks), det.fingerprints(TEXT), now);
}

/// Alpha's text may leave by entry 1, beta's by entry 2: an egress matching
/// both is an allowed flow; one matching entry 1 only is a relay.
#[test]
fn a_seam_leaves_only_by_a_flow_every_contributor_allows() {
    let det = detector();
    let now = Instant::now();
    seam(&det, vec![0b01, 0b10], now);
    assert!(
        det.check_egress_flows_at(BOB, (EGRESS, 0b11), TEXT, now)
            .is_none(),
        "an egress every contributor allows is a flow"
    );
    assert!(
        det.check_egress_flows_at(BOB, (EGRESS, 0b01), TEXT, now)
            .is_some(),
        "beta's text left by a flow only alpha's may take"
    );
}

/// The same seam delivered again keeps its masks: a repeat never widens
/// what the joined text may leave by.
#[test]
fn a_repeated_seam_keeps_every_contributors_limit() {
    let det = detector();
    let now = Instant::now();
    seam(&det, vec![0b01, 0b10], now);
    seam(&det, vec![0b01, 0b10], now);
    assert!(
        det.check_egress_flows_at(BOB, (EGRESS, 0b01), TEXT, now)
            .is_some(),
        "a repeat widened the seam's flows"
    );
}

/// Control: an ordinary source allowed by entry 1 leaves by it.
#[test]
fn an_ordinary_source_leaves_by_any_entry_it_matched() {
    let det = detector();
    let now = Instant::now();
    det.record_fingerprints_at(
        "mock:alpha",
        ALICE,
        (true, 0b01),
        det.fingerprints(TEXT),
        now,
    );
    assert!(
        det.check_egress_flows_at(BOB, (EGRESS, 0b01), TEXT, now)
            .is_none()
    );
    assert!(
        det.check_egress_flows_at(BOB, (EGRESS, 0b10), TEXT, now)
            .is_some()
    );
}

const FIELD_A: &str = "north slope rows seven to twelve, late pears";
const FIELD_B: &str = "south terrace rows one to six, early quinces";

fn seam_fps(det: &CollusionDetector, parts: &[(&str, Option<u32>)]) -> Vec<u64> {
    det.seam_fingerprints(parts)
        .into_iter()
        .map(|(fp, _)| fp)
        .collect()
}

/// Whether a relay of `relayed` shares a fingerprint with the seams.
fn matched(det: &CollusionDetector, parts: &[(&str, Option<u32>)], relayed: &str) -> bool {
    let seams = seam_fps(det, parts);
    det.fingerprints(relayed)
        .iter()
        .any(|fp| seams.contains(fp))
}

/// `MIK-8113.SEAM.2` (unit): two steps' fields side by side make seams
/// touching both steps, and the pair relayed run together matches one.
#[test]
fn two_steps_fields_side_by_side_make_a_seam() {
    let det = detector();
    let parts = [(FIELD_A, Some(0)), (FIELD_B, Some(1))];
    let seams = det.seam_fingerprints(&parts);
    assert!(!seams.is_empty(), "no seam across the two steps");
    assert!(seams.iter().all(|(_, steps)| steps == &[0, 1]), "{seams:?}");
    assert!(matched(&det, &parts, &format!("{FIELD_A}{FIELD_B}")));
    assert!(matched(&det, &parts, &format!("{FIELD_A}\n{FIELD_B}")));
}

/// One step's two fields are its own receipt's run, not a seam.
#[test]
fn one_steps_fields_make_no_seam() {
    let det = detector();
    assert!(
        det.seam_fingerprints(&[(FIELD_A, Some(0)), (FIELD_B, Some(0))])
            .is_empty()
    );
    assert!(
        det.seam_fingerprints(&[(FIELD_A, Some(0)), (FIELD_B, None)])
            .is_empty()
    );
}

/// `MIK-8113` R8: short engine text between the steps' fields is text the
/// caller got in between; the seam across it still matches.
#[test]
fn short_engine_text_between_steps_keeps_the_seam() {
    let det = detector();
    let parts = [(FIELD_A, Some(0)), (", ", None), (FIELD_B, Some(1))];
    assert!(matched(&det, &parts, &format!("{FIELD_A}, {FIELD_B}")));
}

/// Engine text longer than a k-gram: no window reaches across it.
#[test]
fn long_engine_text_between_steps_has_no_seam() {
    let det = detector();
    let filler = "No reading was available for this field, so the playbook used its default text.";
    assert!(
        det.seam_fingerprints(&[(FIELD_A, Some(0)), (filler, None), (FIELD_B, Some(1))])
            .is_empty()
    );
}

/// `MIK-8113` R5: whitespace-padded and decomposed Hangul leaves are matched
/// as egress normalizes them.
#[test]
fn padded_and_decomposed_leaves_keep_the_seam() {
    let det = detector();
    let hangul = "\u{1100}\u{1161}\u{11A8} \u{1102}\u{1161} \u{1103}\u{1161}\u{11AB} rows of the eastern terrace";
    let padded = format!("   {FIELD_A}  \t");
    let parts = [(padded.as_str(), Some(0)), (hangul, Some(1))];
    assert!(matched(&det, &parts, &format!("{FIELD_A} {hangul}")));
}

/// `MIK-8113` R6: five 16-char leaves from five steps: every fingerprint of
/// the run spans at least two of them and is a seam.
#[test]
fn a_run_over_many_short_leaves_is_seamed_throughout() {
    let det = detector();
    let leaves = [
        "pears and quince",
        "s on the north s",
        "lope, rows seven",
        " to twelve, then",
        " the south terra",
    ];
    let parts: Vec<(&str, Option<u32>)> =
        leaves.iter().zip(0..).map(|(l, i)| (*l, Some(i))).collect();
    let seams = seam_fps(&det, &parts);
    let whole = det.fingerprints(&leaves.concat());
    assert!(
        !whole.is_empty() && whole.iter().all(|fp| seams.contains(fp)),
        "{whole:?} vs {seams:?}"
    );
}

/// `MIK-8113.SEAM.4`: 10,000 one-char leaves from 100 steps, one pass.
#[test]
fn many_tiny_leaves_are_read_in_one_pass() {
    let det = detector();
    let chars: Vec<String> = (0..10_000)
        .map(|i| char::from(b'a' + u8::try_from(i * 7 % 26).unwrap_or(0)).to_string())
        .collect();
    let parts: Vec<(&str, Option<u32>)> = chars
        .iter()
        .zip(0..)
        .map(|(c, i)| (c.as_str(), Some(i % 100)))
        .collect();
    let start = std::time::Instant::now();
    let seams = det.seam_fingerprints(&parts);
    assert!(!seams.is_empty());
    assert!(
        start.elapsed() < std::time::Duration::from_secs(5),
        "{:?}",
        start.elapsed()
    );
}

/// A leaf that opens with a combining mark composes with the leaf before it
/// when values are run together. That boundary is normalized as one piece;
/// an unrelated seam elsewhere in the same form is still found.
#[test]
fn a_composing_boundary_elsewhere_keeps_other_seams() {
    let det = detector();
    let parts = [
        (FIELD_A, Some(0)),
        (FIELD_B, Some(1)),
        ("cafe", Some(2)),
        ("\u{301} terrace rows, closing time", Some(3)),
    ];
    assert!(
        matched(&det, &parts, &format!("{FIELD_A}{FIELD_B}")),
        "one composing boundary dropped every run-together seam"
    );
}

/// A mark from another step that composes with the seam's own last char
/// costs only the k-grams over that boundary: the seam before it stays.
#[test]
fn a_mark_composing_with_a_seams_field_keeps_the_seam() {
    let det = detector();
    let parts = [
        (FIELD_A, Some(0)),
        (FIELD_B, Some(1)),
        ("\u{301} terrace rows, closing time", Some(2)),
    ];
    assert!(
        matched(&det, &parts, &format!("{FIELD_A}{FIELD_B}")),
        "a composing mark erased the seam before it"
    );
}

/// Hangul jamo split over leaves, with an empty leaf between them, compose
/// when run together; the seam elsewhere in the form stays.
#[test]
fn jamo_split_over_empty_leaves_keep_other_seams() {
    let det = detector();
    let parts = [
        (FIELD_A, Some(0)),
        (FIELD_B, Some(1)),
        ("\u{1100}", Some(2)),
        ("", Some(3)),
        ("\u{1161}", Some(4)),
        ("\u{11A8}", Some(5)),
    ];
    assert!(
        matched(&det, &parts, &format!("{FIELD_A}{FIELD_B}")),
        "composing jamo erased an unrelated seam"
    );
}

/// NFC can carry a composition back across a long run of marks: a final
/// acute composes with the `e` before eighty marks of other steps. The seam
/// pass normalizes as the whole text is normalized, so every seam
/// fingerprint is one a relay of the delivered text computes.
#[test]
fn a_composition_across_many_marks_keeps_seams_exact() {
    let det = detector();
    let marks = "\u{315}".repeat(80);
    let parts = [
        (FIELD_A, Some(0)),
        ("south terrace rows one to six, early quince", Some(1)),
        (marks.as_str(), Some(2)),
        ("\u{301}", Some(3)),
    ];
    let texts: Vec<&str> = parts.iter().map(|(t, _)| *t).collect();
    let mut egress = det.fingerprints(&texts.join("\n"));
    egress.extend(det.fingerprints(&texts.concat()));
    let seams = seam_fps(&det, &parts);
    assert!(!seams.is_empty(), "premise: a seam across the first two");
    assert!(
        seams.iter().all(|fp| egress.contains(fp)),
        "a seam fingerprint no relay of the delivered text computes"
    );
}

/// Marks of another step that survive normalization unchanged keep that
/// step: a field followed by forty such marks is a seam of both steps.
#[test]
fn surviving_marks_keep_their_own_step() {
    let det = detector();
    let marks = "\u{315}".repeat(40);
    let parts = [
        ("north slope rows seven to twelve", Some(0)),
        (marks.as_str(), Some(1)),
    ];
    let seams = det.seam_fingerprints(&parts);
    assert!(!seams.is_empty(), "marks of another step lost their step");
    assert!(seams.iter().all(|(_, steps)| steps == &[0, 1]), "{seams:?}");
}

/// A Tibetan vowel sign whose decomposition opens with a mark reorders
/// with the marks before it, so it is never a cut: every seam fingerprint
/// is one a relay of the delivered text computes.
#[test]
fn a_starter_decomposing_to_marks_is_not_a_cut() {
    let det = detector();
    let parts = [
        (FIELD_A, Some(0)),
        ("south terrace rows one to six \u{F40}\u{F74}", Some(1)),
        ("\u{F73}", Some(2)),
    ];
    let texts: Vec<&str> = parts.iter().map(|(t, _)| *t).collect();
    let mut egress = det.fingerprints(&texts.join("\n"));
    egress.extend(det.fingerprints(&texts.concat()));
    let seams = seam_fps(&det, &parts);
    assert!(!seams.is_empty(), "premise: a seam across the first two");
    assert!(
        seams.iter().all(|fp| egress.contains(fp)),
        "a seam fingerprint no relay of the delivered text computes"
    );
}

/// A leading jamo composes with the trailing jamo of the field before it
/// (two starters): that boundary is normalized as one piece, so every seam
/// fingerprint is one a relay of the delivered text computes.
#[test]
fn composing_jamo_across_fields_keep_seams_exact() {
    let det = detector();
    let parts = [
        (FIELD_A, Some(0)),
        ("south terrace rows one to six \u{1100}", Some(1)),
        ("\u{1161}\u{11A8} early quinces", Some(2)),
    ];
    let texts: Vec<&str> = parts.iter().map(|(t, _)| *t).collect();
    let mut egress = det.fingerprints(&texts.join("\n"));
    egress.extend(det.fingerprints(&texts.concat()));
    let seams = seam_fps(&det, &parts);
    assert!(!seams.is_empty(), "premise: seams across the fields");
    assert!(
        seams.iter().all(|fp| egress.contains(fp)),
        "a seam fingerprint no relay of the delivered text computes"
    );
}

/// `MIK-8209` K6: a key-path join is read run together only. Its seam
/// fingerprints are all of the run-together form; none comes from the
/// newline-joined form alone.
#[test]
fn a_join_seam_has_no_newline_form() {
    use super::SeamForms;
    let det = detector();
    let parts = [(FIELD_A, Some(0)), (FIELD_B, Some(1))];
    let together: std::collections::HashSet<u64> = det
        .fingerprints(&format!("{FIELD_A}{FIELD_B}"))
        .into_iter()
        .collect();
    let seams = det.seam_fingerprints_in(&parts, SeamForms::RunTogether);
    assert!(!seams.is_empty(), "premise: the two fields seam");
    assert!(
        seams.iter().all(|(fp, _)| together.contains(fp)),
        "a newline-form fingerprint in a join seam"
    );
}

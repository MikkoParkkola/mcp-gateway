// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! `MIK-8205`: the seam pass's work bound (test plan 3C) and boundary
//! equality (3D). Work is counted, never timed.

use super::super::super::{CollusionDetector, K, RelayAction, RelayParams};
use super::{COUNTERS, Counters, MAX_SEAM_PIECES, MAX_SEAM_SPANS, SEAM_SIDE_BYTES};

/// Every k-gram kept, so a row's outcome does not depend on the hash key.
fn detector() -> CollusionDetector {
    let mut det = CollusionDetector::new(RelayParams {
        action: RelayAction::Observe,
        ..RelayParams::default()
    });
    det.keep_every_kgram();
    det
}

/// Run the seam pass on `runs` with fresh counters; its output, whether a
/// cap cut it, and the work it did.
fn pass(det: &CollusionDetector, runs: &[Vec<String>]) -> (Vec<u64>, bool, Counters) {
    let runs: Vec<Vec<&str>> = runs
        .iter()
        .map(|r| r.iter().map(String::as_str).collect())
        .collect();
    COUNTERS.with(|c| *c.borrow_mut() = Counters::default());
    let (fps, cut) = det.seam_excuse_fingerprints(&runs);
    (fps, cut, COUNTERS.with(|c| *c.borrow()))
}

/// gpt's empty-piece input: 24 A's, `n` empty pieces, 24 B's, one run.
fn empty_pieces(n: usize) -> Vec<String> {
    std::iter::once("A".repeat(24))
        .chain(std::iter::repeat_n(String::new(), n))
        .chain(std::iter::once("B".repeat(24)))
        .collect()
}

/// The work does not grow with the empty pieces past the cap: every counter
/// is the same at 10,000 and 100,000, the index stops at the cap, and the
/// cut is reported.
#[test]
fn empty_pieces_past_the_cap_cost_the_same_at_any_count() {
    let det = detector();
    let (fps10, cut10, work10) = pass(&det, &[empty_pieces(10_000)]);
    let (fps100, cut100, work100) = pass(&det, &[empty_pieces(100_000)]);
    assert!(cut10 && cut100, "the piece cap was not reported");
    assert_eq!(work10, work100, "work grew with the empty pieces");
    assert_eq!(fps10, fps100);
    assert_eq!(
        work10.index_visits, MAX_SEAM_PIECES,
        "the index did not stop at the cap"
    );
}

/// The same input at 1,000,000 empty pieces (manual: run with `--ignored`).
#[test]
#[ignore = "headline run: 1,000,000 empty pieces, about the request body limit"]
fn empty_pieces_at_a_million_cost_the_same() {
    let det = detector();
    let (_, _, small) = pass(&det, &[empty_pieces(10_000)]);
    let (_, _, large) = pass(&det, &[empty_pieces(1_000_000)]);
    assert_eq!(small, large, "work grew with the empty pieces");
}

/// Inside the cap, the walk across 1,000 empty pieces visits none of them,
/// and the seam over them is produced.
#[test]
fn the_walk_skips_empty_pieces_inside_the_cap() {
    let det = detector();
    let (a, b) = ("A".repeat(30), "B".repeat(30));
    let mut run = vec![a.clone(), "~".to_owned()];
    run.extend(std::iter::repeat_n(String::new(), 1_000));
    run.push(b.clone());
    let (fps, cut, work) = pass(&det, &[run]);
    assert!(!cut, "premise: inside every cap");
    assert_eq!(work.walk_empty_visits, 0, "the walk visited empty pieces");
    let expected = det.fingerprints(&format!("{a}{b}"));
    assert!(
        !expected.is_empty(),
        "premise: the one-gap text has windows"
    );
    assert!(
        expected.iter().all(|f| fps.contains(f)),
        "the seam over the empties is missing"
    );
}

/// The quota can run out partway through a round-robin round: three runs of
/// 2,000 pieces reach 4,095 after 1,365 rounds, so the next round takes one
/// piece and stops. Mutant w2 (#3726) took the whole round, 4,098.
#[test]
fn the_piece_quota_stops_partway_through_a_round() {
    let det = detector();
    let run = vec![String::new(); 2_000];
    let (_, cut, work) = pass(&det, &[run.clone(), run.clone(), run]);
    assert!(cut, "the piece cap was not reported");
    assert_eq!(
        work.index_visits, MAX_SEAM_PIECES,
        "the index overshot the cap"
    );
}

/// `n` distinct pieces of `len` chars each (a letter, then digits), no
/// whitespace, so normalisation leaves them as they are.
fn distinct(n: usize, len: usize) -> Vec<String> {
    (0..n)
        .map(|i| {
            let head = char::from(b'a' + u8::try_from(i % 26).expect("small"));
            let body = format!("{i:0>width$}", width = len - 1);
            format!("{head}{}", &body[body.len() - (len - 1)..])
        })
        .collect()
}

/// Span generation stops at the cap: never more than `MAX_SEAM_SPANS`
/// candidates exist, on a run whose full candidate list is about 8 million.
#[test]
fn span_candidates_stop_at_the_cap() {
    let det = detector();
    let (_, cut, work) = pass(&det, &[distinct(4_096, 1)]);
    assert!(cut, "premise: more spans than the cap");
    assert_eq!(work.spans_attempted, MAX_SEAM_SPANS);
    assert!(
        work.candidates <= MAX_SEAM_SPANS + 1,
        "{} candidates generated",
        work.candidates
    );
}

/// The span cap counts spans, not fingerprints: with sampling forced to keep
/// nothing, the pass still attempts exactly `MAX_SEAM_SPANS` spans.
#[test]
fn the_span_cap_counts_spans_when_no_fingerprint_is_kept() {
    let mut det = detector();
    det.sample = u64::MAX;
    let (fps, cut, work) = pass(&det, &[distinct(4_096, 47)]);
    assert!(fps.is_empty(), "premise: sampling keeps nothing");
    assert!(cut);
    assert_eq!(
        work.spans_attempted, MAX_SEAM_SPANS,
        "the cap counted something else"
    );
}

/// Large pieces: every span reads only its two capped sides, so the bytes
/// read are exactly spans x 2 x `SEAM_SIDE_BYTES`, not spans x piece size.
#[test]
fn large_pieces_read_only_the_boundary() {
    // Sampling keeps nothing, so the fingerprint cap cannot stop the pass
    // before the span cap this row measures.
    let mut det = detector();
    det.sample = u64::MAX;
    let (_, _, work) = pass(&det, &[distinct(500, 20 * 1_024)]);
    assert_eq!(work.spans_attempted, MAX_SEAM_SPANS);
    assert_eq!(work.bytes_read, MAX_SEAM_SPANS * 2 * SEAM_SIDE_BYTES);
}

/// Hashing per span (design §8): two full ASCII sides with a clean boundary
/// hash exactly the K - 1 windows overlapping it, each starting inside the
/// left side's last K - 1 chars; no window wholly on one side is hashed.
#[test]
fn a_span_hashes_only_the_windows_over_its_boundary() {
    let det = detector();
    let run = distinct(3, 2 * SEAM_SIDE_BYTES);
    super::HASHED_AT.with(|h| h.borrow_mut().clear());
    let (_, _, work) = pass(&det, &[run]);
    assert_eq!(
        work.spans_attempted, 1,
        "premise: one span (omit the middle piece)"
    );
    assert_eq!(work.hashes, K - 1, "hashes per span");
    let at = super::HASHED_AT.with(|h| h.borrow().clone());
    assert_eq!(at.len(), K - 1);
    assert!(
        at.iter().all(|&(s, left)| s + K > left && s < left),
        "a window wholly on one side was hashed: {at:?}"
    );
}

/// The 3D oracle on a three-piece run, whose only span omits the middle:
/// safety (every seam is a window of the one-gap text) and completeness
/// (every one-gap window the caller does not already hold, as a piece or as
/// the run's join, is a seam). Both sets are asserted non-empty.
fn assert_boundary_equality(left: &str, middle: &str, right: &str) {
    let det = detector();
    let run = vec![left.to_owned(), middle.to_owned(), right.to_owned()];
    let (seams, cut, _) = pass(&det, &[run]);
    assert!(!cut, "premise: inside every cap");
    let one_gap = det.fingerprints(&format!("{left}{right}"));
    assert!(
        !one_gap.is_empty(),
        "premise: the one-gap text has a window"
    );
    let held: std::collections::HashSet<u64> =
        [left, middle, right, &format!("{left}{middle}{right}")]
            .iter()
            .flat_map(|t| det.fingerprints(t))
            .collect();
    let needed: Vec<u64> = one_gap
        .iter()
        .copied()
        .filter(|f| !held.contains(f))
        .collect();
    assert!(!needed.is_empty(), "premise: the forward needs an excuse");
    assert!(
        seams.iter().all(|f| one_gap.contains(f)),
        "a seam is not a window of the one-gap text"
    );
    assert!(
        needed.iter().all(|f| seams.contains(f)),
        "a needed window is not excused"
    );
}

/// The one window of `["A"*24, "~", "B"*24]`, touching both run ends.
#[test]
fn a_window_touching_both_run_ends_is_excused() {
    assert_boundary_equality(&"A".repeat(24), "~", &"B".repeat(24));
}

/// `e` + U+0301 composes across the seam into one char.
#[test]
fn a_char_composed_across_the_seam_is_part_of_it() {
    assert_boundary_equality(
        &format!("{}e", "a".repeat(47)),
        "~",
        &format!("\u{301}{}", "b".repeat(47)),
    );
}

/// Hangul L (U+1100) and V (U+1161) compose across the seam.
#[test]
fn hangul_composed_across_the_seam_is_part_of_it() {
    assert_boundary_equality(
        &format!("{}\u{1100}", "a".repeat(24)),
        "~",
        &format!("\u{1161}{}", "b".repeat(24)),
    );
}

/// Combining marks reorder across the seam (U+0323 sorts before U+0301).
#[test]
fn marks_reordered_across_the_seam_are_part_of_it() {
    assert_boundary_equality(
        &format!("{}x\u{301}", "a".repeat(47)),
        "~",
        &format!("\u{323}{}", "b".repeat(47)),
    );
}

/// A seam inside a whitespace run, and one beside a stripped control.
#[test]
fn whitespace_and_stripped_controls_at_the_seam() {
    assert_boundary_equality(
        &format!("{}   ", "a".repeat(40)),
        "~",
        &format!("  {}", "b".repeat(40)),
    );
    assert_boundary_equality(
        &format!("{}\u{200b}", "a".repeat(40)),
        "~",
        &format!("\u{200b}{}", "b".repeat(40)),
    );
}

/// A slice over 256 bytes with a combining sequence across byte 256, near
/// the seam: one normalisation walk, no chunk cut, so the windows still
/// match the one-gap text.
#[test]
fn a_combining_sequence_past_byte_256_keeps_equality() {
    let left = format!("{}e\u{301}{}", "a".repeat(255), "a".repeat(30));
    assert_boundary_equality(&left, "~", &"b".repeat(47));
}

/// The piece quota is shared round-robin across runs: a 4,096-piece label
/// run first (map order puts `kind` before `text`) still leaves the text
/// run eligible pieces and seams.
#[test]
fn a_long_label_run_does_not_take_the_text_runs_quota() {
    let det = detector();
    let labels = vec!["chunk".to_owned(); 4_096];
    let text = distinct(3, 47);
    let (fps, _, _) = pass(&det, &[labels, text.clone()]);
    let only_text = det.fingerprints(&format!("{}{}", text[0], text[2]));
    assert!(
        !only_text.is_empty(),
        "premise: the text run's one-gap text has windows"
    );
    assert!(
        only_text.iter().any(|f| fps.contains(f)),
        "the text run got no seams"
    );
}

/// A side that normalisation collapses (5,000 spaces) stops at
/// `SEAM_SIDE_BYTES` short of K chars: that span is skipped and the cut is
/// reported, while another span of the same delivery still yields seams.
#[test]
fn a_collapsing_side_skips_its_span_and_reports_the_cut() {
    let det = detector();
    let padded = format!("{}{}", "a".repeat(10), " ".repeat(5_000));
    let run = vec![
        padded,
        "~".to_owned(),
        "b".repeat(47),
        "~".to_owned(),
        "c".repeat(47),
    ];
    let (fps, cut, _) = pass(&det, &[run]);
    assert!(cut, "the skipped span was not reported");
    let other = det.fingerprints(&format!("{}{}", "b".repeat(47), "c".repeat(47)));
    assert!(
        other.iter().any(|f| fps.contains(f)),
        "the other span's seams are missing"
    );
}

/// A side the byte cap cut at a safe point but left under K normalised
/// chars (five x's after spaces no cut may start with) is skipped and
/// reported too, while another span still yields seams. Mutant h3 (#3726)
/// kept such a side and reported nothing.
#[test]
fn a_short_side_after_a_safe_cut_skips_its_span_and_reports_it() {
    let det = detector();
    let padded = format!("{}{}{}", "a".repeat(10), " ".repeat(1_019), "x".repeat(5));
    let run = vec![
        padded,
        "~".to_owned(),
        "b".repeat(47),
        "~".to_owned(),
        "c".repeat(47),
    ];
    let (fps, cut, _) = pass(&det, &[run]);
    assert!(cut, "the skipped span was not reported");
    let other = det.fingerprints(&format!("{}{}", "b".repeat(47), "c".repeat(47)));
    assert!(
        other.iter().any(|f| fps.contains(f)),
        "the other span's seams are missing"
    );
}

/// The artificial edge (design r3.3 step 5): the left piece's byte cap
/// falls between L and V of a Hangul L+V+T syllable, then 973 spaces that
/// collapse, then 45 a's. The compose-safe cut moves past V and T (no cut
/// inside the syllable is safe) and past the spaces, leaving 45 chars, under
/// K: the span is skipped and reported, and no seam is made up. Cutting at
/// the next starter instead keeps V and T as stray jamo, 48 normalised chars,
/// so a kept window opens with a standalone T that the one-gap text (where
/// L+V+T compose into one syllable) never holds: the safety check fails it.
#[test]
fn a_cap_inside_a_hangul_syllable_never_makes_up_a_window() {
    let det = detector();
    let tail = format!("\u{1161}\u{11a8}{}{}", " ".repeat(973), "a".repeat(45));
    assert_eq!(
        tail.len(),
        SEAM_SIDE_BYTES,
        "premise: the cap falls just before V"
    );
    let left = format!("{}\u{1100}{tail}", "x".repeat(10));
    let right = "b".repeat(47);
    let (seams, cut, _) = pass(&det, &[vec![left.clone(), "~".to_owned(), right.clone()]]);
    let one_gap = det.fingerprints(&format!("{left}{right}"));
    assert!(
        seams.iter().all(|f| one_gap.contains(f)),
        "a window the one-gap text never holds was excused"
    );
    assert!(cut, "the skipped span was not reported");
}

/// The per-delivery fingerprint cap stops the pass on large input before the
/// span cap: every k-gram kept, each span of the large-pieces run yields 47
/// fingerprints, so exactly `SEAM_EXCUSE_FINGERPRINTS` are stored after
/// ceil(4,096 / 47) = 88 spans, and the cut is reported. (The large-pieces
/// row forces sampling empty to measure the span cap; this row pins the cap
/// that fires first.)
#[test]
fn the_fingerprint_cap_stops_the_pass_on_large_input() {
    let det = detector();
    let (fps, cut, work) = pass(&det, &[distinct(500, 20 * 1_024)]);
    assert!(cut, "the fingerprint cap was not reported");
    assert_eq!(fps.len(), super::SEAM_EXCUSE_FINGERPRINTS);
    assert_eq!(
        work.spans_attempted,
        super::SEAM_EXCUSE_FINGERPRINTS.div_ceil(K - 1)
    );
}

// Store isolation (test plan 3B): the detector with an injected clock.

const SOURCE: &str = "alpha:read";
const EGRESS: &str = "alpha:post";

/// Three 47-char pieces, the one-gap text `p0 p2`, and the seams alice gets
/// for the run, recorded at `at`.
fn alice_seams(det: &CollusionDetector, at: std::time::Instant) -> String {
    let run = distinct(3, 47);
    let refs: Vec<&str> = run.iter().map(String::as_str).collect();
    let (fps, _) = det.seam_excuse_fingerprints(&[refs]);
    assert!(!fps.is_empty(), "premise: the run has seams");
    det.record_seam_excuses_at(SOURCE, "alice", &fps, at);
    format!("{}{}", run[0], run[2])
}

/// Seams never make a fingerprint `Common`: six callers' seams, then
/// carol's sensitive copy, and dave (who holds nothing) is still reported.
#[test]
fn seams_never_make_evidence_common() {
    let det = detector();
    let t0 = std::time::Instant::now();
    let joined = alice_seams(&det, t0);
    for who in ["bea", "cy", "di", "ed", "fay", "gus"] {
        let run = distinct(3, 47);
        let refs: Vec<&str> = run.iter().map(String::as_str).collect();
        let (fps, _) = det.seam_excuse_fingerprints(&[refs]);
        det.record_seam_excuses_at(SOURCE, who, &fps, t0);
    }
    det.record_delivery_at(SOURCE, "carol", true, &joined, t0);
    assert!(
        det.check_egress_at("dave", EGRESS, &joined, t0).is_some(),
        "dave was not reported"
    );
}

/// Seams never extend `Common`'s lifetime: five ordinary holders of the join
/// at t0 make it `Common`; alice's seam delivery at t0+599 s must not refresh
/// that, so once the t0 deliveries leave the window, carol's sensitive copy
/// (t0+601 s) is evidence against dave at t0+700 s.
#[test]
fn seams_never_refresh_common() {
    let det = detector();
    let t0 = std::time::Instant::now();
    let s = std::time::Duration::from_secs;
    let run = distinct(3, 47);
    let joined = format!("{}{}", run[0], run[2]);
    for who in ["bea", "cy", "di", "ed", "fay"] {
        det.record_delivery_at(SOURCE, who, false, &joined, t0);
    }
    alice_seams(&det, t0 + s(599));
    det.record_delivery_at(SOURCE, "carol", true, &joined, t0 + s(601));
    assert!(
        det.check_egress_at("dave", EGRESS, &joined, t0 + s(700))
            .is_some(),
        "Common outlived its holders"
    );
}

/// Seams expire with the window: alice's seams at t0 no longer excuse her at
/// t0+700 s; seams at t0+650 s still do.
#[test]
fn seams_expire_with_the_window() {
    let s = std::time::Duration::from_secs;
    let t0 = std::time::Instant::now();
    let stale = detector();
    let joined = alice_seams(&stale, t0);
    stale.record_delivery_at(SOURCE, "carol", true, &joined, t0 + s(601));
    assert!(
        stale
            .check_egress_at("alice", EGRESS, &joined, t0 + s(700))
            .is_some(),
        "an expired seam excused"
    );
    let fresh = detector();
    let run = distinct(3, 47);
    fresh.record_delivery_at(
        SOURCE,
        "carol",
        true,
        &format!("{}{}", run[0], run[2]),
        t0 + s(601),
    );
    let joined = alice_seams(&fresh, t0 + s(650));
    assert!(
        fresh
            .check_egress_at("alice", EGRESS, &joined, t0 + s(700))
            .is_none(),
        "a live seam did not excuse"
    );
}

/// A seam is never evidence: alice's seams sit in the seam store and not in
/// the evidence entries, and dave forwarding that text is not reported until
/// carol is actually delivered it.
#[test]
fn a_seam_is_never_evidence() {
    let det = detector();
    let t0 = std::time::Instant::now();
    let joined = alice_seams(&det, t0);
    {
        let state = det.state.lock();
        assert!(state.seams.len() > 0, "premise: the seams were stored");
        let fps = det.fingerprints(&joined);
        assert!(
            fps.iter().all(|f| !state.entries.contains_key(f)),
            "a seam reached the evidence entries"
        );
    }
    assert!(
        det.check_egress_at("dave", EGRESS, &joined, t0).is_none(),
        "a seam witnessed against dave"
    );
    det.record_delivery_at(SOURCE, "carol", true, &joined, t0);
    assert!(
        det.check_egress_at("dave", EGRESS, &joined, t0).is_some(),
        "premise: the text can be evidence"
    );
}

/// Past `MAX_SEAM_EXCUSES` the store evicts only seams: carol's evidence,
/// recorded first, still reports dave after the flood, and the store holds
/// exactly the cap.
#[test]
fn the_seam_store_evicts_only_seams() {
    let det = detector();
    let t0 = std::time::Instant::now();
    let run = distinct(3, 47);
    let joined = format!("{}{}", run[0], run[2]);
    det.record_delivery_at(SOURCE, "carol", true, &joined, t0);
    let flood: Vec<u64> =
        (0..u64::try_from(super::MAX_SEAM_EXCUSES).expect("fits") + 1_000).collect();
    det.record_seam_excuses_at(SOURCE, "flooder", &flood, t0);
    assert_eq!(
        det.state.lock().seams.len(),
        super::MAX_SEAM_EXCUSES,
        "the store is not at its cap"
    );
    assert!(
        det.check_egress_at("dave", EGRESS, &joined, t0).is_some(),
        "the flood evicted evidence"
    );
}

/// Seams are confined to their own (source, caller) pair: alice's seams from
/// `alpha:read` do not excuse her against a copy carol got from another tool,
/// and do not excuse erin; against carol's copy from the same tool, they
/// excuse alice.
#[test]
fn seams_are_confined_to_their_source_and_caller() {
    let t0 = std::time::Instant::now();
    let other_tool = detector();
    let joined = alice_seams(&other_tool, t0);
    other_tool.record_delivery_at("alpha:other", "carol", true, &joined, t0);
    assert!(
        other_tool
            .check_egress_at("alice", EGRESS, &joined, t0)
            .is_some(),
        "a seam crossed sources"
    );
    let other_caller = detector();
    let joined = alice_seams(&other_caller, t0);
    other_caller.record_delivery_at(SOURCE, "carol", true, &joined, t0);
    assert!(
        other_caller
            .check_egress_at("erin", EGRESS, &joined, t0)
            .is_some(),
        "a seam crossed callers"
    );
    assert!(
        other_caller
            .check_egress_at("alice", EGRESS, &joined, t0)
            .is_none(),
        "premise: alice is excused"
    );
}

// The compose-safe cut predicate (safe_cut delta, gpt's three inputs).

/// Never cut before a mark: A and three U+0316, cut, three more U+0316 and
/// U+0301. Full NFC composes A with the acute across the lower-class marks,
/// though three chars each side look the same apart and together.
#[test]
fn a_cut_before_a_mark_is_never_safe() {
    let props = super::Props::new();
    assert!(!props.safe_cut(
        ["", "A\u{316}\u{316}\u{316}"],
        ["\u{316}\u{316}\u{316}\u{301}", ""]
    ));
}

/// A control matching strips is not a barrier: L, ZWJ, cut, V, T compose
/// once ZWJ is dropped, so the cut is unsafe.
#[test]
fn a_stripped_control_is_no_barrier_to_composition() {
    let props = super::Props::new();
    assert!(!props.safe_cut(["", "x\u{1100}\u{200d}"], ["\u{1161}\u{11a8}", ""]));
}

/// Context crosses pieces: L in an earlier piece, V in the piece cut after
/// it, T after the cut: the V|T cut is unsafe.
#[test]
fn cut_context_crosses_piece_boundaries() {
    let props = super::Props::new();
    assert!(!props.safe_cut(["x\u{1100}", "\u{1161}"], ["\u{11a8}y", ""]));
}

/// A plain ASCII cut is safe (the predicate is not refusing everything).
#[test]
fn a_cut_between_plain_letters_is_safe() {
    let props = super::Props::new();
    assert!(props.safe_cut(["", "abc"], ["def", ""]));
}

/// A cut before capital iota after alpha, U+0313 and U+0300 is safe (gpt,
/// correcting the delta): U+1F8A decomposes to alpha, U+0313, U+0300 and
/// U+0345, a combining mark, not capital iota, so iota after the marks does
/// not compose. The cut before U+0345 is refused by the starter rule.
#[test]
fn a_cut_before_greek_iota_after_alpha_and_marks_is_safe() {
    let props = super::Props::new();
    assert!(props.safe_cut(["", "\u{391}\u{313}\u{300}"], ["\u{399}", ""]));
    assert!(!props.safe_cut(["", "\u{391}\u{313}\u{300}"], ["\u{345}", ""]));
}

/// Context across pieces, through the side fill: the run holds L, then a
/// piece of only ZWJ (dropped by matching), then V, T, 973 spaces and 45 a's
/// (exactly `SEAM_SIDE_BYTES`). The fill takes that piece whole and
/// overflows on the ZWJ piece, so the only candidate cut is between the ZWJ
/// and V. Judged with L from the earlier piece, it is unsafe: the span is
/// skipped. Judged without it, the side would open with stray V and T, 48
/// normalised chars, and a kept window starting with a standalone T, which
/// the one-gap text (where L, V and T compose) never holds.
#[test]
fn cut_context_from_an_earlier_piece_reaches_the_fill() {
    let det = detector();
    let vt = format!("\u{1161}\u{11a8}{}{}", " ".repeat(973), "a".repeat(45));
    assert_eq!(
        vt.len(),
        SEAM_SIDE_BYTES,
        "premise: the V+T piece fills the side exactly"
    );
    let x = "x".repeat(10);
    let right = "b".repeat(47);
    let run = vec![
        x.clone(),
        "\u{1100}".to_owned(),
        "\u{200d}".to_owned(),
        vt.clone(),
        "~".to_owned(),
        right.clone(),
    ];
    let (seams, _, _) = pass(&det, &[run]);
    // The run has other legal spans (omitting the ZWJ piece, or it and the
    // V+T piece), so the oracle is the one window the wrong cut makes up: a
    // standalone T, a space, 45 a's and the first b.
    let made_up = det.fingerprints(&format!("\u{11a8} {}b", "a".repeat(45)));
    assert!(
        !made_up.is_empty(),
        "premise: the made-up window has a fingerprint"
    );
    assert!(
        made_up.iter().all(|f| !seams.contains(f)),
        "a window the one-gap text never holds was excused"
    );
}

/// A run cut short by the piece cap (gpt): the right side reaching its end
/// cannot be judged, since the acute past the cap composes with the A and
/// its marks. No window ending in the bare A is excused.
#[test]
fn a_run_cut_by_the_piece_cap_makes_up_no_window_at_its_end() {
    let det = detector();
    let mut run = vec![
        "a".repeat(47),
        "~".to_owned(),
        format!("{}A{}", "b".repeat(40), "\u{316}".repeat(7)),
    ];
    run.extend(std::iter::repeat_n(String::new(), 4_093));
    run.push("\u{301}".to_owned());
    let (seams, _, _) = pass(&det, &[run]);
    let bad = det.fingerprints(&format!("{}{}A", "a".repeat(7), "b".repeat(40)));
    assert!(
        !bad.is_empty(),
        "premise: the suspect window has a fingerprint"
    );
    assert!(
        bad.iter().all(|f| !seams.contains(f)),
        "a window past the piece cap was excused"
    );
}

/// A flood of stripped controls cannot make the cut scans unbounded (gpt):
/// 100,000 ZWJ before the side's text, and every scan reads at most
/// `RAW_SCAN` raw chars.
#[test]
fn a_control_flood_keeps_the_cut_scans_bounded() {
    let det = detector();
    let flood = format!("{}{}", "\u{200d}".repeat(100_000), "a".repeat(1_024));
    let (_, _, work) = pass(&det, &[vec![flood, "~".to_owned(), "b".repeat(47)]]);
    let per_span = 2 * super::RAW_SCAN * (SEAM_SIDE_BYTES + 2);
    assert!(
        work.scanned <= work.spans_attempted * per_span,
        "{} chars scanned",
        work.scanned
    );
}

/// The one-char margin at an artificial edge (grok, #3726 h1): a left side
/// cut to exactly K chars (47 x's and an e) before a seam where the e
/// composes with the right side's acute. The window at the cut, start 0, is
/// not hashed. The margin is a deliberate fail-safe: that window is real
/// text, so dropping it can only withhold an excuse.
#[test]
fn the_window_at_an_artificial_edge_is_not_hashed() {
    let det = detector();
    let left = format!("{}{}{}e", "a".repeat(10), " ".repeat(976), "x".repeat(47));
    let right = format!("\u{301}{}", "b".repeat(47));
    super::HASHED_AT.with(|h| h.borrow_mut().clear());
    let (_, _, work) = pass(&det, &[vec![left, "~".to_owned(), right]]);
    assert_eq!(work.spans_attempted, 1, "premise: one span");
    let at = super::HASHED_AT.with(|h| h.borrow().clone());
    assert_eq!(at.len(), K - 1, "hashes at the cut edge: {at:?}");
    assert!(
        at.iter().all(|&(s, _)| s > 0),
        "the window at the cut was hashed"
    );
}

/// Cut context on a run the piece cap truncated (grok, #3726 c5): the right
/// side's cap falls in the last indexed piece, so nothing after it is known
/// and the span is skipped. The same run inside the cap yields seams. A
/// deliberate fail-safe: skipping can only withhold an excuse.
#[test]
fn cut_context_past_the_piece_cap_skips_the_span() {
    let det = detector();
    let mut run = vec![String::new(); MAX_SEAM_PIECES - 3];
    run.extend(["a".repeat(47), "~".to_owned(), "x".repeat(2_000)]);
    let (whole, _, _) = pass(&det, &[run.clone()]);
    assert!(
        !whole.is_empty(),
        "premise: inside the cap the span has seams"
    );
    run.push("y".to_owned());
    let (cut_short, cut, _) = pass(&det, &[run]);
    assert!(cut, "the piece cap was not reported");
    assert!(
        cut_short.is_empty(),
        "a span cut by the piece cap made seams"
    );
}

/// The right-side twin of
/// `a_short_side_after_a_safe_cut_skips_its_span_and_reports_it` (grok
/// improvement, #3726): the right side's cap cut leaves 5 chars, under K.
#[test]
fn a_short_right_side_after_a_safe_cut_skips_its_span_and_reports_it() {
    let det = detector();
    let padded = format!("{}{}{}", "x".repeat(5), " ".repeat(1_019), "a".repeat(10));
    let run = vec![
        "c".repeat(47),
        "~".to_owned(),
        "b".repeat(47),
        "~".to_owned(),
        padded,
    ];
    let (fps, cut, _) = pass(&det, &[run]);
    assert!(cut, "the skipped span was not reported");
    let other = det.fingerprints(&format!("{}{}", "c".repeat(47), "b".repeat(47)));
    assert!(
        other.iter().any(|f| fps.contains(f)),
        "the other span's seams are missing"
    );
}

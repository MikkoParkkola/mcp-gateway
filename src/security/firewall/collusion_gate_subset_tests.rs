// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! `MIK-8205`: a holder forwarding a subset of whole pieces it was
//! delivered, against the same tool's exact join delivered to another
//! caller (design §14.1 "Subsets"). A child of the key-path rows, so it
//! reuses their private fixtures.

use serde_json::json;

use super::super::super::{CollusionAction, CollusionConfig};
use crate::security::firewall::{Firewall, FirewallConfig};

use super::{TEXTS, deliver, flat, labelled_parts, observing, pieces, relay_found, reported, text};

/// The subset `pieces` without their middle piece, run together.
fn without_middle(pieces: &[String]) -> String {
    let middle = pieces.len() / 2;
    pieces
        .iter()
        .enumerate()
        .filter(|(k, _)| *k != middle)
        .map(|(_, p)| p.as_str())
        .collect()
}

/// Per text: alice is delivered the pieces (S3b) by `alpha:read{i}`; with
/// `carol`, that same tool delivers carol the exact join of the subset on
/// another call. Returns the texts where `who` forwarding the subset is
/// reported. Each piece is under one k-gram, so only a k-gram spanning the
/// seam the subset created can match.
fn subset_reported(who: &str, carol: bool) -> Vec<usize> {
    let fw = observing();
    (0..TEXTS)
        .filter(|&i| {
            let (text, tool) = (text(i), format!("read{i}"));
            let pieces = pieces(&text);
            let subset = without_middle(&pieces);
            deliver(&fw, "alice", &tool, &labelled_parts(&pieces));
            if carol {
                deliver(&fw, "carol", &tool, &flat(&subset));
            }
            reported(&fw, who, &subset)
        })
        .collect()
}

/// `MIK-8205` SUBSET.1: alice forwarding a subset of whole pieces she was
/// delivered is not a relay, though the same tool delivered carol that
/// exact join on another call.
#[test]
fn a_subset_forward_against_its_sources_exact_join_is_not_a_relay() {
    let reported = subset_reported("alice", true);
    assert!(
        reported.is_empty(),
        "subset forwards reported: {reported:?}"
    );
}

/// `MIK-8205` falsifier: without carol's join the same forward is not
/// reported, so carol's delivery is what refuses alice.
#[test]
fn a_subset_forward_with_no_competing_join_is_not_a_relay() {
    let reported = subset_reported("alice", false);
    assert!(
        reported.is_empty(),
        "subset forwards reported: {reported:?}"
    );
}

/// `MIK-8205` SUBSET.2 control: bob, delivered nothing by the tool,
/// forwarding carol's join is a relay.
#[test]
fn a_non_holder_forwarding_the_sources_exact_join_is_a_relay() {
    let reported = subset_reported("bob", true);
    assert_eq!(reported.len(), TEXTS, "missed relays");
}

/// Piece `k` of text `i`: a letter naming `k`, then 46 chars of `text(i)`
/// with spaces as `_`, so no whitespace collapses and the normalised length
/// stays 47. Unique across texts, so a forward of two pieces holds k-grams
/// only across their seam; and no two pieces of a run share a first char, so
/// a window across one gap never equals a window across another.
fn piece47(i: usize, k: usize) -> String {
    let tag = char::from(b'A' + u8::try_from(k).expect("few pieces"));
    let piece: String = std::iter::once(tag)
        .chain(
            text(i)
                .chars()
                .map(|c| if c == ' ' { '_' } else { c })
                .skip(k * 46)
                .take(46),
        )
        .collect();
    assert_eq!(piece.chars().count(), 47, "premise: text {i} has piece {k}");
    piece
}

/// Per text: alice is delivered `run` (S3b) by `alpha:read{i}` in one call;
/// carol is delivered `held` flat, from the same tool, on another. Returns
/// the texts where alice forwarding `forward` is reported.
fn alice_reported(
    run: impl Fn(usize) -> Vec<String>,
    held: impl Fn(usize) -> String,
    forward: impl Fn(usize) -> String,
) -> Vec<usize> {
    let fw = observing();
    (0..TEXTS)
        .filter(|&i| {
            let tool = format!("read{i}");
            deliver(&fw, "alice", &tool, &labelled_parts(&run(i)));
            deliver(&fw, "carol", &tool, &flat(&held(i)));
            reported(&fw, "alice", &forward(i))
        })
        .collect()
}

/// `MIK-8205`: omitting several adjacent pieces is one gap.
#[test]
fn omitting_adjacent_pieces_is_one_gap() {
    let p = |i, k| piece47(i, k);
    let reported = alice_reported(
        |i| vec![p(i, 0), p(i, 1), p(i, 2), p(i, 3)],
        |i| format!("{}{}", p(i, 0), p(i, 3)),
        |i| format!("{}{}", p(i, 0), p(i, 3)),
    );
    assert!(
        reported.is_empty(),
        "multi-piece omissions reported: {reported:?}"
    );
}

/// `MIK-8205` bound: pieces forwarded out of delivered order are not
/// excused, though the same tool delivered carol that reordered join.
#[test]
fn a_reordered_subset_is_a_relay() {
    let p = |i, k| piece47(i, k);
    let reordered = |i| format!("{}{}", p(i, 2), p(i, 0));
    let reported = alice_reported(|i| vec![p(i, 0), p(i, 1), p(i, 2)], reordered, reordered);
    assert_eq!(reported.len(), TEXTS, "reordered forwards excused");
}

/// `MIK-8205` control for the reorder row: the same pieces in delivered
/// order, against carol's join of them, are excused.
#[test]
fn an_in_order_subset_is_not_a_relay() {
    let p = |i, k| piece47(i, k);
    let in_order = |i| format!("{}{}", p(i, 0), p(i, 2));
    let reported = alice_reported(|i| vec![p(i, 0), p(i, 1), p(i, 2)], in_order, in_order);
    assert!(
        reported.is_empty(),
        "in-order forwards reported: {reported:?}"
    );
}

/// `MIK-8205` bound: pieces from two deliveries carry no delivered order
/// between them, so their seam is not excused. The control is
/// `an_in_order_subset_is_not_a_relay` (both pieces in one delivery).
#[test]
fn a_seam_across_two_deliveries_is_a_relay() {
    let fw = observing();
    let reported: Vec<usize> = (0..TEXTS)
        .filter(|&i| {
            let tool = format!("read{i}");
            let (p0, p2) = (piece47(i, 0), piece47(i, 2));
            deliver(
                &fw,
                "alice",
                &tool,
                &labelled_parts(&[p0.clone(), piece47(i, 1)]),
            );
            deliver(
                &fw,
                "alice",
                &tool,
                &labelled_parts(&[p2.clone(), piece47(i, 3)]),
            );
            deliver(&fw, "carol", &tool, &flat(&format!("{p0}{p2}")));
            reported(&fw, "alice", &format!("{p0}{p2}"))
        })
        .collect();
    assert_eq!(reported.len(), TEXTS, "cross-delivery seams excused");
}

/// The run `[p1, p2, m, p4, p5]` of the two-gap rows: `p1`, `p5` are 47
/// chars, the kept middle `m` 45, so a forward of `p1 m p5` puts both gaps
/// inside one 48-char window.
fn two_gap_run(i: usize) -> Vec<String> {
    let m: String = piece47(i, 2).chars().take(45).collect();
    vec![
        piece47(i, 0),
        piece47(i, 1),
        m,
        piece47(i, 3),
        piece47(i, 4),
    ]
}

/// `MIK-8205` bound: a forward with two gaps inside one window is not
/// excused, though the same tool delivered carol that join.
#[test]
fn two_gaps_in_one_window_are_a_relay() {
    let joined = |i| {
        let r = two_gap_run(i);
        format!("{}{}{}", r[0], r[2], r[4])
    };
    let reported = alice_reported(two_gap_run, joined, joined);
    assert_eq!(reported.len(), TEXTS, "two-gap forwards excused");
}

/// `MIK-8205` control for the two-gap row: one gap (`p1 m`) is excused.
#[test]
fn one_gap_from_the_two_gap_run_is_not_a_relay() {
    let joined = |i| {
        let r = two_gap_run(i);
        format!("{}{}", r[0], r[2])
    };
    let reported = alice_reported(two_gap_run, joined, joined);
    assert!(
        reported.is_empty(),
        "one-gap forwards reported: {reported:?}"
    );
}

/// Text `i`'s first 72 chars, spaces as `_`: the T of the rearrangement row.
fn t72(i: usize) -> String {
    let t: String = text(i)
        .chars()
        .map(|c| if c == ' ' { '_' } else { c })
        .take(72)
        .collect();
    assert_eq!(t.chars().count(), 72, "premise: text {i} has 72 chars");
    t
}

/// `MIK-8205` residual R1 (design §6): gpt's overlapping triples
/// `[T[j..j+24], "~", T[j+24..j+48]]`, j = 0..24, in one run. Every window of
/// T is a one-gap stretch of that run (omit one "~"), so alice is excused for
/// T window by window, though no single ordered subsequence explains it.
/// She was delivered all of T. Dave, holding nothing, is still a relay.
#[test]
fn a_rearranged_forward_of_received_pieces_is_excused_window_by_window() {
    let fw = observing();
    let (mut alice, mut dave_missed) = (Vec::new(), Vec::new());
    for i in 0..TEXTS {
        let (tool, t) = (format!("read{i}"), t72(i));
        let run: Vec<String> = (0..=24)
            .flat_map(|j| {
                [
                    t[j..j + 24].to_owned(),
                    "~".to_owned(),
                    t[j + 24..j + 48].to_owned(),
                ]
            })
            .collect();
        deliver(&fw, "alice", &tool, &labelled_parts(&run));
        deliver(&fw, "carol", &tool, &flat(&t));
        if reported(&fw, "alice", &t) {
            alice.push(i);
        }
        if !reported(&fw, "dave", &t) {
            dave_missed.push(i);
        }
    }
    assert!(
        dave_missed.is_empty(),
        "control: dave not reported: {dave_missed:?}"
    );
    assert!(
        alice.is_empty(),
        "alice reported for a rearranged forward: {alice:?}"
    );
}

/// `MIK-8205` residual R2 (design §6): a subset forwarded inside its
/// original structure is matched through the all-values forms, whose k-grams
/// across the removed element are not key-path seams. Against carol's copy of
/// that structured subset it stays a relay; with no carol it is not.
#[test]
fn a_structured_subset_against_its_structured_copy_stays_a_relay() {
    let wrong: Vec<usize> = (0..TEXTS)
        .filter(|&i| {
            let tool = format!("read{i}");
            let p: Vec<String> = (0..3).map(|k| piece47(i, k)).collect();
            let subset = labelled_parts(&[p[0].clone(), p[2].clone()]);
            let params = json!({"name": "send", "arguments": {"body": subset}});
            let fw = observing();
            deliver(&fw, "alice", &tool, &labelled_parts(&p));
            let alone = relay_found(&fw, "alice", &params);
            deliver(&fw, "carol", &tool, &subset);
            alone || !relay_found(&fw, "alice", &params)
        })
        .collect();
    assert!(wrong.is_empty(), "structured subsets mishandled: {wrong:?}");
}

/// `MIK-8205`: the two-gap run with `p4` and `p5` given the first two chars
/// `start4` and `start5`. With equal starts, each window spanning both gaps of
/// `p1 m p5` equals a window of the legal one-gap text `p1 m p4 p5` (omit
/// `p2`): bytes alice received with one gap.
fn repeated_prefix_run(i: usize, start4: &str, start5: &str) -> Vec<String> {
    let mut run = two_gap_run(i);
    run[3] = format!("{start4}{}", &run[3][2..]);
    run[4] = format!("{start5}{}", &run[4][2..]);
    run
}

/// `MIK-8205`: why `piece47` tags each piece. If a two-gap window's text
/// equals a legal one-gap window's, the excuse covers exactly bytes alice
/// received, so no unreceived text is excused and she is not reported. Once
/// the starts differ, those windows hold bytes she never received, and they
/// still count: she is reported. Both halves on the same shape.
#[test]
fn a_two_gap_window_equal_to_a_one_gap_window_is_excused_and_no_other() {
    let joined = |run: &Vec<String>| format!("{}{}{}", run[0], run[2], run[4]);
    let shared = alice_reported(
        |i| repeated_prefix_run(i, "QQ", "QQ"),
        |i| joined(&repeated_prefix_run(i, "QQ", "QQ")),
        |i| joined(&repeated_prefix_run(i, "QQ", "QQ")),
    );
    assert!(shared.is_empty(), "received bytes reported: {shared:?}");
    let distinct = alice_reported(
        |i| repeated_prefix_run(i, "QQ", "ZZ"),
        |i| joined(&repeated_prefix_run(i, "QQ", "ZZ")),
        |i| joined(&repeated_prefix_run(i, "QQ", "ZZ")),
    );
    assert_eq!(distinct.len(), TEXTS, "unreceived bytes excused");
}

/// MIK-8290 (not `MIK-8205`): a holder forwarding the whole join it
/// was delivered, at `min_matches` = 1. Carol's content item records
/// "joined\ntext", so the window "the join's last 47 chars + separator" is
/// hers; alice's forward has a separator after the join too, but her own
/// delivery ends at the join, so that window is unexcused. Red until fixed.
#[test]
fn a_whole_join_forward_is_not_refused_for_a_trailing_separator() {
    let fw = Firewall::from_config(
        FirewallConfig {
            collusion: CollusionConfig {
                action: CollusionAction::Observe,
                sources: vec!["alpha:*".to_string()],
                min_matches: 1,
                ..CollusionConfig::default()
            },
            ..FirewallConfig::default()
        },
        None,
    )
    .keeping_every_kgram();
    let reported: Vec<usize> = (0..TEXTS)
        .filter(|&i| {
            let tool = format!("read{i}");
            let p: Vec<String> = (0..3).map(|k| piece47(i, k)).collect();
            let joined = p.concat();
            deliver(&fw, "alice", &tool, &labelled_parts(&p));
            deliver(&fw, "carol", &tool, &flat(&joined));
            reported(&fw, "alice", &joined)
        })
        .collect();
    assert!(
        reported.is_empty(),
        "whole-join forwards reported: {reported:?}"
    );
}

/// MIK-8290, the two-sided case at the default `min_matches` = 2: alice was
/// delivered the join as a single leaf (`{"note": joined}`), carol the join
/// between two other values. Alice forwards it with her own note field
/// before it, so her egress has a separator on both sides of the join; the
/// windows "separator + join head" and "join tail + separator" are carol's
/// and not hers: two unexcused windows.
#[test]
fn a_whole_join_forward_with_separators_on_both_sides_is_not_refused() {
    let fw = observing();
    let reported: Vec<usize> = (0..TEXTS)
        .filter(|&i| {
            let tool = format!("read{i}");
            let joined: String = (0..3).map(|k| piece47(i, k)).collect();
            deliver(&fw, "alice", &tool, &json!({"note": joined}));
            deliver(
                &fw,
                "carol",
                &tool,
                &json!({"a": "xx", "b": joined, "c": "yy"}),
            );
            let params = json!({"name": "send", "arguments": {"a_note": "x", "body": joined}});
            relay_found(&fw, "alice", &params)
        })
        .collect();
    assert!(
        reported.is_empty(),
        "two-sided forwards reported at the default: {reported:?}"
    );
}

/// `MIK-8205` (design §2, §8): seams come only from what a caller was
/// delivered. A plan step's staged receipt carries none, so a step's text the
/// answer drops can never be excused; a committed delivery of the same value
/// carries them.
#[test]
fn a_plan_steps_staged_receipt_carries_no_seams() {
    let fw = observing();
    let p: Vec<String> = (0..4).map(|k| piece47(0, k)).collect();
    let value = labelled_parts(&p);
    let staged = std::cell::Cell::new(0);
    let step = fw
        .receipt_digest("alpha", "read", &value, Some(&staged))
        .expect("staged");
    assert!(
        step.seam_excuses.is_none(),
        "a staged step receipt carries seams"
    );
    let delivered = fw
        .delivery_digest("alpha", "read", &value)
        .expect("recorded");
    assert!(
        delivered.seam_excuses.is_some(),
        "premise: the delivered value has seams"
    );
}

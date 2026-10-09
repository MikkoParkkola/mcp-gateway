// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! `MIK-8209`: a copy delivered split over one key path (content items, or
//! labelled parts) is its holder's own text when the pieces are re-joined
//! (design §14.1 shapes S2, S3b), while a caller who never received it is
//! still reported (the mid-word evasion stays caught).

use serde_json::{Value, json};

use super::super::{CollusionAction, CollusionConfig, RelayCaller};
use crate::security::firewall::{Firewall, FirewallConfig, ScanType};

/// Distinct texts per row.
const TEXTS: usize = 40;

fn observing() -> Firewall {
    Firewall::from_config(
        FirewallConfig {
            collusion: CollusionConfig {
                action: CollusionAction::Observe,
                sources: vec!["alpha:*".to_string()],
                ..CollusionConfig::default()
            },
            ..FirewallConfig::default()
        },
        None,
    )
    .keeping_every_kgram()
}

/// Text `i`: unique words, so no two texts share a k-gram.
fn text(i: usize) -> String {
    use std::fmt::Write as _;
    (0..60).fold(String::new(), |mut text, n| {
        let _ = write!(text, "x{i}y{} ", n * 7_919 % 10_007);
        text
    })
}

/// `text` cut mid-word into 20-byte pieces (ASCII), each shorter than a k-gram.
fn pieces(text: &str) -> Vec<String> {
    text.as_bytes()
        .chunks(20)
        .map(|c| String::from_utf8(c.to_vec()).expect("ascii"))
        .collect()
}

/// S2: MCP content items, one piece each.
fn content_items(pieces: &[String]) -> Value {
    let items: Vec<Value> = pieces
        .iter()
        .map(|p| json!({"type": "text", "text": p}))
        .collect();
    json!({ "content": items })
}

/// S3b: labelled parts, one piece each.
fn labelled_parts(pieces: &[String]) -> Value {
    let parts: Vec<Value> = pieces
        .iter()
        .map(|p| json!({"part": p, "kind": "chunk"}))
        .collect();
    json!({ "parts": parts })
}

/// S1: the text as one content item.
fn flat(text: &str) -> Value {
    json!({"content": [{"type": "text", "text": text}]})
}

fn deliver(fw: &Firewall, who: &str, tool: &str, result: &Value) {
    fw.record_delivery(RelayCaller::Keyed(who), "alpha", tool, result);
}

/// Whether `who` sending `text` as one string is reported as a relay.
fn reported(fw: &Firewall, who: &str, text: &str) -> bool {
    let params = json!({"name": "send", "arguments": {"body": text}});
    relay_found(fw, who, &params)
}

/// Whether `who` sending `params` is reported as a relay.
fn relay_found(fw: &Firewall, who: &str, params: &Value) -> bool {
    fw.check_relay(RelayCaller::Keyed(who), "alpha", "send", params, ("s", who))
        .findings
        .iter()
        .any(|f| f.scan_type == ScanType::CollusionRelay)
}

/// The texts whose holder, delivered them in `shape` from the tool another
/// caller read them flat from, is reported for re-joining the pieces.
fn holders_reported(shape: fn(&[String]) -> Value) -> Vec<usize> {
    let fw = observing();
    (0..TEXTS)
        .filter(|&i| {
            let (text, tool) = (text(i), format!("read{i}"));
            deliver(&fw, "alice", &tool, &flat(&text));
            deliver(&fw, "bob", &tool, &shape(&pieces(&text)));
            assert!(reported(&fw, "dave", &text), "control: text {i} is a relay");
            reported(&fw, "bob", &text)
        })
        .collect()
}

/// `CONTENT.1` (S2): content items re-joined by their holder are no relay.
#[test]
fn content_items_rejoined_by_their_holder_are_not_a_relay() {
    let refused = holders_reported(content_items);
    assert!(refused.is_empty(), "own copies reported: {refused:?}");
}

/// `CONTENT.1` (S3b): labelled parts re-joined by their holder are no relay.
#[test]
fn labelled_parts_rejoined_by_their_holder_are_not_a_relay() {
    let refused = holders_reported(labelled_parts);
    assert!(refused.is_empty(), "own copies reported: {refused:?}");
}

/// D1 (design §14.1 K4): content items are evidence. A caller who never
/// received the text is reported for forwarding it, whole or as split fields.
#[test]
fn content_items_are_evidence_against_a_non_holder() {
    let missed = non_holder_missed(|text| content_items(&pieces(text)));
    assert!(missed.is_empty(), "relays not reported: {missed:?}");
}

/// `CONTENT.1` guard (A3c, the mid-word evasion): with a flat delivery, a
/// caller who never received the text forwarding it split mid-word over
/// short fields is still reported, as egress runs forwarded values together.
#[test]
fn a_non_holder_splitting_a_flat_copy_is_still_reported() {
    let missed = non_holder_missed(flat);
    assert!(missed.is_empty(), "relays not reported: {missed:?}");
}

/// The texts that dave, who never received them, is not reported for
/// forwarding whole or as split fields, after alice was delivered them as
/// `shape` makes them.
fn non_holder_missed(shape: fn(&str) -> Value) -> Vec<usize> {
    let fw = observing();
    (0..TEXTS)
        .filter(|&i| {
            let (text, tool) = (text(i), format!("read{i}"));
            deliver(&fw, "alice", &tool, &shape(&text));
            let fields: serde_json::Map<String, Value> = pieces(&text)
                .into_iter()
                .enumerate()
                .map(|(k, p)| (format!("p{k:03}"), Value::String(p)))
                .collect();
            let params = json!({"name": "send", "arguments": fields});
            let split = relay_found(&fw, "dave", &params);
            !split || !reported(&fw, "dave", &text)
        })
        .collect()
}

/// `SUBSET` (design §14.1): a holder forwarding its pieces with a middle
/// one left out is not reported: every k-gram sits in a kept piece, a
/// delivered join of kept pieces, or across a seam no one was delivered.
#[test]
fn a_subset_of_whole_pieces_is_not_a_relay() {
    let fw = observing();
    let refused: Vec<usize> = (0..TEXTS)
        .filter(|&i| {
            let (text, tool) = (text(i), format!("read{i}"));
            let pieces = pieces(&text);
            deliver(&fw, "alice", &tool, &flat(&text));
            deliver(&fw, "bob", &tool, &content_items(&pieces));
            let middle = pieces.len() / 2;
            let subset: String = pieces
                .iter()
                .enumerate()
                .filter(|(k, _)| *k != middle)
                .map(|(_, p)| p.as_str())
                .collect();
            reported(&fw, "bob", &subset)
        })
        .collect();
    assert!(refused.is_empty(), "subset forwards reported: {refused:?}");
}

/// D1 (design §14.1 K4): a key path's join is evidence. A colluder who
/// never received the text relays one column of a two-column delivery,
/// re-joined; the holder of that column is excused.
#[test]
fn a_rejoined_column_is_evidence_and_its_holders_excuse() {
    let fw = observing();
    let wrong: Vec<usize> = (0..TEXTS)
        .filter(|&i| {
            let (text, tool) = (text(i), format!("read{i}"));
            let other = text.replace('x', "q");
            let rows: Vec<Value> = pieces(&text)
                .iter()
                .zip(pieces(&other))
                .map(|(a, b)| json!({"a": a, "b": b}))
                .collect();
            let result = json!({ "rows": rows });
            deliver(&fw, "alice", &tool, &result);
            deliver(&fw, "bob", &tool, &result);
            !reported(&fw, "dave", &text) || reported(&fw, "bob", &text)
        })
        .collect();
    assert!(wrong.is_empty(), "column join mishandled: {wrong:?}");
}

/// `CUT.1` (design §14.1, MIK-8066): one text over the record cap and the
/// per-delivery fingerprint bound, delivered flat to one holder and as
/// content items to another: each forwarding it whole is not reported while
/// a third caller holds a sensitive flat copy.
#[test]
fn flat_and_split_receipts_over_the_cap_both_excuse() {
    let fw = observing();
    let refused: Vec<usize> = (0..4)
        .filter(|&i| {
            let tool = format!("big{i}");
            let text: String = (0..24).map(|k| text(i * 100 + k)).collect();
            assert!(text.len() > 6 * 1024, "premise: over the record cap");
            deliver(&fw, "alice", &tool, &flat(&text));
            deliver(&fw, "bob", &tool, &flat(&text));
            deliver(&fw, "carol", &tool, &content_items(&pieces(&text)));
            assert!(reported(&fw, "dave", &text), "control: text {i} is a relay");
            reported(&fw, "bob", &text) || reported(&fw, "carol", &text)
        })
        .collect();
    assert!(refused.is_empty(), "over-cap holders reported: {refused:?}");
}

/// `CUT.1` budget guard (K2): joins have a budget of their own. A delivery of
/// ~3.6 KiB of distinct content items (joins take as much again) and then a
/// `tail` field, the walk's last leaf and in no join, keeps the tail as
/// evidence: a non-holder relaying it is reported. With one shared budget
/// the joins would push it out.
#[test]
fn joins_never_push_leaf_evidence_out() {
    let fw = observing();
    let missed: Vec<usize> = (0..TEXTS)
        .filter(|&i| {
            let tool = format!("read{i}");
            let items: Vec<String> = (0..60)
                .map(|k| text(i * 1_000 + k)[..60].to_owned())
                .collect();
            let tail = text(i * 1_000 + 999);
            let mut result = content_items(&items);
            result["tail"] = Value::String(tail.clone());
            deliver(&fw, "alice", &tool, &result);
            !reported(&fw, "dave", &tail)
        })
        .collect();
    assert!(missed.is_empty(), "the tail lost its evidence: {missed:?}");
}

/// A plan step through the design §14.6 path: staged, kept to `answer`,
/// capped and recorded for `who` from `alpha:{tool}`.
fn deliver_plan_step(fw: &Firewall, who: &str, tool: &str, step: &Value, answer: &Value) {
    let staged = fw
        .receipt_digest("alpha", tool, step, Some(&std::cell::Cell::new(0)))
        .expect("relay detection is on");
    let delivered = fw.delivered_for_plan(answer, None).expect("bounded");
    let kept = fw.cap_kept(fw.retain_delivered(staged, &delivered, None));
    fw.record_digest(RelayCaller::Keyed(who), "alpha", tool, &kept);
}

/// `pieces` as content items with a note item after the first piece.
fn interleaved(pieces: &[String]) -> Value {
    let mut items: Vec<Value> = pieces
        .iter()
        .map(|p| json!({"type": "text", "text": p}))
        .collect();
    items.insert(
        1,
        json!({"type": "text", "text": "a note another step put here"}),
    );
    json!({ "content": items })
}

/// The texts whose plan-step holder is reported for re-joining, after a step
/// delivered them as `step` and the plan's answer delivered `answer`.
fn plan_holders_reported(
    step: fn(&[String]) -> Value,
    answer: fn(&[String]) -> Value,
) -> Vec<usize> {
    let fw = observing();
    (0..TEXTS)
        .filter(|&i| {
            let (text, tool) = (text(i), format!("read{i}"));
            let pieces = pieces(&text);
            deliver(&fw, "alice", &tool, &flat(&text));
            deliver_plan_step(&fw, "bob", &tool, &step(&pieces), &answer(&pieces));
            assert!(reported(&fw, "dave", &text), "control: text {i} is a relay");
            reported(&fw, "bob", &text)
        })
        .collect()
}

/// `PLAN.1` (S2): a step's content items, delivered by the answer as they
/// came, keep their join: the holder re-joining them is not reported.
#[test]
fn a_plan_answer_of_content_items_keeps_the_steps_join() {
    let refused = plan_holders_reported(content_items, content_items);
    assert!(refused.is_empty(), "plan holders reported: {refused:?}");
}

/// `PLAN.1` (design r3.1, grok's r3 input): the answer interleaves the
/// step's under-K pieces with another leaf; each piece is still delivered
/// whole, so the step's join is kept.
#[test]
fn an_interleaved_step_join_of_under_k_pieces_is_kept() {
    let refused = plan_holders_reported(content_items, interleaved);
    assert!(refused.is_empty(), "plan holders reported: {refused:?}");
}

/// `PLAN.1` negative (gpt): an answer that left the middle piece out
/// breaks the step's run there, so the holder forwarding the whole text,
/// middle included, is reported.
#[test]
fn an_undelivered_middle_piece_breaks_the_steps_join() {
    fn without_middle(pieces: &[String]) -> Value {
        let mut kept = pieces.to_vec();
        kept.remove(pieces.len() / 2);
        content_items(&kept)
    }
    let excused = (0..TEXTS).count() - plan_holders_reported(content_items, without_middle).len();
    assert_eq!(excused, 0, "a missing middle piece was excused");
}

/// The value of `capacity_total{bound="record_text_cut"}`, 0 while absent.
#[cfg(feature = "metrics")]
fn text_cuts_exported() -> u64 {
    crate::metrics::install();
    let prefix = "mcp_gateway_collusion_capacity_total{bound=\"record_text_cut\"} ";
    crate::metrics::render()
        .lines()
        .find_map(|l| l.strip_prefix(prefix).and_then(|v| v.trim().parse().ok()))
        .unwrap_or(0)
}

/// `MIK-8201` VIS.1 residual, closed here: a delivery cut by either text
/// budget is exported as `record_text_cut`, once per delivery even when
/// both cut. (Joins never outgrow the leaves: each piece is in one key path,
/// so a join cut comes with a leaf cut, and is counted with it.)
#[cfg(feature = "metrics")]
#[test]
fn a_text_cut_is_counted_once_per_delivery() {
    let fw = observing();
    let big: String = (0..24).map(text).collect();
    assert!(big.len() > 6 * 1024, "premise: over the record cap");
    let exported = text_cuts_exported();
    let own = fw.relay_text_cuts();
    deliver(&fw, "alice", "big", &flat(&big));
    assert_eq!(fw.relay_text_cuts(), own + 1, "a leaf cut was not counted");
    // Both budgets cut: leaves over the cap, and their joins over theirs.
    let rows: Vec<Value> = pieces(&big[..3_000])
        .iter()
        .zip(pieces(&big[3_000..6_000]))
        .map(|(a, b)| json!({"a": a, "b": b, "c": format!("{a}{b}")}))
        .collect();
    deliver(&fw, "alice", "cols", &json!({ "rows": rows }));
    assert_eq!(fw.relay_text_cuts(), own + 2, "one cut per delivery");
    assert!(
        text_cuts_exported() >= exported + 2,
        "the cut was not exported"
    );
}

/// `PLAN.1` (residual 4, design K3): a step returned the text flat and the
/// plan's answer split it into content items. Only the answer's key-path
/// join matches the step's flat text, so the holder re-joining is excused.
#[test]
fn a_flat_step_split_by_the_answer_into_content_items_keeps_its_join() {
    let refused = plan_holders_reported(|p| flat(&p.concat()), content_items);
    assert!(refused.is_empty(), "plan holders reported: {refused:?}");
}

/// `PLAN.1` (S3a, design K3): a flat step whose answer splits it over short
/// object fields: only the answer's values run together match it.
#[test]
fn a_flat_step_split_by_the_answer_into_short_fields_keeps_its_form() {
    fn fields(pieces: &[String]) -> Value {
        let map: serde_json::Map<String, Value> = pieces
            .iter()
            .enumerate()
            .map(|(k, p)| (format!("p{k:03}"), Value::String(p.clone())))
            .collect();
        Value::Object(map)
    }
    let refused = plan_holders_reported(|p| flat(&p.concat()), fields);
    assert!(refused.is_empty(), "plan holders reported: {refused:?}");
}

/// D3 (design K2): the cut-delivery sketch holds each join alone. Bob was
/// delivered an over-cap two-column array; carol, the text where column a's
/// join meets column b's. Bob never received that boundary contiguously, so
/// relaying it is reported: his sketch must not run the joins together.
#[test]
fn a_join_boundary_is_never_excused_by_the_sketch() {
    let fw = observing();
    let excused: Vec<usize> = (0..4)
        .filter(|&i| {
            let tool = format!("cols{i}");
            let a: String = (0..8).map(|k| text(i * 100 + k)).collect();
            let b: String = (0..8)
                .map(|k| text(i * 100 + 50 + k))
                .collect::<String>()
                .replace('x', "q");
            let rows: Vec<Value> = pieces(&a)
                .iter()
                .zip(pieces(&b))
                .map(|(x, y)| json!({"a": x, "b": y}))
                .collect();
            let (ja, jb): (String, String) = (
                pieces(&a)
                    .iter()
                    .take(rows.len())
                    .map(String::as_str)
                    .collect(),
                pieces(&b)
                    .iter()
                    .take(rows.len())
                    .map(String::as_str)
                    .collect(),
            );
            assert!(
                ja.len() + jb.len() > 6 * 1024,
                "premise: over the record cap"
            );
            let boundary = format!("{}{}", &ja[ja.len() - 40..], &jb[..40]);
            deliver(&fw, "bob", &tool, &json!({ "rows": rows }));
            deliver(&fw, "carol", &tool, &flat(&boundary));
            !reported(&fw, "bob", &boundary)
        })
        .collect();
    assert!(
        excused.is_empty(),
        "a join boundary was excused: {excused:?}"
    );
}

/// `MIK-8209` K6 at the gate: a cross-step join's seams are read run
/// together only, so none comes from the newline-joined form alone.
#[test]
fn the_gate_reads_a_join_seam_run_together_only() {
    let fw = observing();
    let (a, b) = (text(1), text(2));
    let answer = json!({"rows": [{"t": a}, {"t": b}]});
    let step_of = |piece: &str| Some(u32::from(piece == b));
    let seams = fw.join_seam_fingerprints(&answer, &step_of);
    assert!(!seams.is_empty(), "premise: the two steps' pieces seam");
    let detector = fw.relay_detector().expect("relay detection on");
    let together: std::collections::HashSet<u64> = detector
        .fingerprints(&format!("{a}{b}"))
        .into_iter()
        .collect();
    assert!(
        seams.iter().all(|(fp, _)| together.contains(fp)),
        "a newline-form fingerprint in a join seam"
    );
}

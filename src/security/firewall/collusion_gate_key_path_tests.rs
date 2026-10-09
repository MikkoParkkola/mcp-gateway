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

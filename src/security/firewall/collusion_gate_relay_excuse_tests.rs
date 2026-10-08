// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8083: the same-source excuse holds wherever a copy sits. A copy sits
//! in different surroundings in each receipt and in the egress text, and the
//! process's hash seed varies; a selection that depended on surroundings (as
//! window minima did) failed for about 1 text in 70. So each row runs over
//! many distinct texts, and such a defect fails in nearly every run.

use serde_json::{Value, json};

use super::super::{CollusionAction, CollusionConfig, RelayCaller};
use crate::security::firewall::{Firewall, FirewallConfig, ScanType};

/// Distinct texts per row: about 1 in 70 hit the edge case before the fix.
const TEXTS: usize = 1_000;

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
}

/// Text `i`: unique words, so no two texts share a k-gram.
fn text(i: usize) -> String {
    use std::fmt::Write as _;
    (0..60).fold(String::new(), |mut text, n| {
        let _ = write!(text, "x{i}y{} ", n * 7_919 % 10_007);
        text
    })
}

/// `text` cut into 20-byte pieces (ASCII), under keys that sort in order.
fn pieces(text: &str) -> Value {
    let fields = text.as_bytes().chunks(20).enumerate().map(|(k, chunk)| {
        let piece = String::from_utf8(chunk.to_vec()).expect("ascii");
        (format!("p{k:03}"), Value::String(piece))
    });
    Value::Object(fields.collect())
}

/// Whether `who` forwarding `text`'s pieces is reported as a relay.
fn reported(fw: &Firewall, who: &str, text: &str) -> bool {
    let params = json!({
        "name": "send",
        "arguments": pieces(text),
        "_meta": {"io.modelcontextprotocol/protocolVersion": "2026-07-28"},
    });
    let verdict = fw.check_relay(
        RelayCaller::Keyed(who),
        "alpha",
        "send",
        &params,
        ("s", who),
    );
    verdict
        .findings
        .iter()
        .any(|f| f.scan_type == ScanType::CollusionRelay)
}

/// `who` delivered `text` from `alpha:{tool}`, flat or split over short fields.
fn deliver(fw: &Firewall, who: &str, tool: &str, text: &str, split: bool) {
    let result = if split {
        json!({"content": [{"type": "text", "text": "split copy"}], "structuredContent": pieces(text)})
    } else {
        json!({"content": [{"type": "text", "text": text}]})
    };
    fw.record_delivery(RelayCaller::Keyed(who), "alpha", tool, &result);
}

/// MIK-8083: B was delivered the copy split, from the same source A read it
/// flat from; B forwarding the pieces is its own copy, never a relay.
#[test]
fn a_callers_own_split_copy_is_never_a_relay() {
    let fw = observing();
    let refused: Vec<usize> = (0..TEXTS)
        .filter(|&i| {
            let (text, tool, a, b) = (
                text(i),
                format!("read{i}"),
                format!("a{i}"),
                format!("b{i}"),
            );
            deliver(&fw, &a, &tool, &text, false);
            deliver(&fw, &b, &tool, &text, true);
            // Control: the same text is a relay for a caller without it.
            assert!(
                reported(&fw, &format!("c{i}"), &text),
                "text {i} undetectable"
            );
            reported(&fw, &b, &text)
        })
        .collect();
    assert!(
        refused.is_empty(),
        "own copies reported as relays: {refused:?}"
    );
}

/// MIK-8083: B was delivered the copy after a short heading, so every k-gram
/// of the text sits at another offset than in A's copy; B forwarding the bare
/// text is still its own copy. A selection by position would keep different
/// k-grams for B than for the forward, and report it.
#[test]
fn a_callers_own_copy_at_another_offset_is_never_a_relay() {
    let fw = observing();
    let refused: Vec<usize> = (0..TEXTS)
        .filter(|&i| {
            let (text, tool, b) = (text(i), format!("read{i}"), format!("b{i}"));
            deliver(&fw, &format!("a{i}"), &tool, &text, false);
            deliver(&fw, &b, &tool, &format!("Note {i}: {text}"), false);
            assert!(
                reported(&fw, &format!("c{i}"), &text),
                "text {i} undetectable"
            );
            reported(&fw, &b, &text)
        })
        .collect();
    assert!(
        refused.is_empty(),
        "own copies reported as relays: {refused:?}"
    );
}

/// MIK-8083 controls: a caller holding nothing from the source, or only the
/// first half of the text, forwarding the whole text is still a relay.
#[test]
fn a_copy_the_caller_never_received_is_still_a_relay() {
    let fw = observing();
    let missed: Vec<usize> = (0..TEXTS / 10)
        .filter(|&i| {
            let (text, tool) = (text(i), format!("read{i}"));
            deliver(&fw, &format!("a{i}"), &tool, &text, false);
            deliver(&fw, &format!("h{i}"), &tool, &text[..text.len() / 2], false);
            !reported(&fw, &format!("c{i}"), &text) || !reported(&fw, &format!("h{i}"), &text)
        })
        .collect();
    assert!(missed.is_empty(), "relays not reported: {missed:?}");
}

/// MIK-8083: holding the start of a source's text excuses only that start: a
/// short unreceived suffix forwarded after it is still a relay (the hole a
/// proximity-based excuse would open).
#[test]
fn a_held_prefix_never_excuses_an_unreceived_suffix() {
    let fw = observing();
    let missed: Vec<usize> = (0..TEXTS / 10)
        .filter(|&i| {
            let (prefix, tool) = (text(i)[..200].to_string(), format!("read{i}"));
            let whole =
                format!("{prefix} s{i}k 7f3a9c1e5b2d8f4a6c0e9b7d3f1a5c8e2b4d6f0a9e1c3b5d7f");
            deliver(&fw, &format!("a{i}"), &tool, &whole, false);
            deliver(&fw, &format!("h{i}"), &tool, &prefix, false);
            !reported(&fw, &format!("h{i}"), &whole)
        })
        .collect();
    assert!(missed.is_empty(), "suffixes not reported: {missed:?}");
}

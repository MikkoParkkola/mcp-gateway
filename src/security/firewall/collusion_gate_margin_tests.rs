// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! `MIK-8290`: an egress window made of one long leaf's text plus a few chars
//! of glue (the gateway's separator, or a neighbouring field's edge char) is
//! not evidence. Such a window matches any copy with the same text beside
//! any other value. Only windows next to a leaf of at least 2K normalised
//! chars are dropped, so every relay keeps that leaf's interior windows.
//! Rows are judged with every k-gram kept: equal window sets mean equal
//! sampled matches under any sample key.

use std::collections::HashSet;

use serde_json::{Value, json};

use super::super::super::{CollusionAction, CollusionConfig};
use crate::security::firewall::{Firewall, FirewallConfig};

use super::{TEXTS, deliver, observing, pieces, relay_found, text};

/// [`observing`] at `min_matches`.
fn observing_at(min_matches: usize) -> Firewall {
    Firewall::from_config(
        FirewallConfig {
            collusion: CollusionConfig {
                action: CollusionAction::Observe,
                sources: vec!["alpha:*".to_string()],
                min_matches,
                ..CollusionConfig::default()
            },
            ..FirewallConfig::default()
        },
        None,
    )
    .keeping_every_kgram()
}

/// The fingerprints of `text`, normalised as the detector reads it.
fn fps(fw: &Firewall, text: &str) -> HashSet<u64> {
    let detector = fw.relay_detector().expect("relay detection on");
    detector.fingerprints(text).into_iter().collect()
}

/// What a delivery of `result` records.
fn recorded(fw: &Firewall, result: &Value) -> HashSet<u64> {
    let detector = fw.relay_detector().expect("relay detection on");
    fw.delivery_digest("alpha", "read", result)
        .expect("recorded")
        .fingerprints(detector)
        .into_iter()
        .collect()
}

/// The egress windows of `params`: every window of the egress text, and
/// those kept as evidence once glue windows are dropped.
fn egress(fw: &Firewall, params: &Value) -> (HashSet<u64>, HashSet<u64>) {
    let all = fps(fw, &super::super::super::egress_text(params));
    let detector = fw.relay_detector().expect("relay detection on");
    let kept: HashSet<u64> = detector
        .egress_fingerprints(&super::super::super::egress_parts(params))
        .into_iter()
        .collect();
    assert!(kept.is_subset(&all), "the filter added a window");
    (all, kept)
}

/// The windows of `kept` that carol's delivery holds and alice's does not:
/// the matches that refuse alice.
fn unexcused(fw: &Firewall, kept: &HashSet<u64>, carol: &Value, alice: &Value) -> HashSet<u64> {
    let (theirs, own) = (recorded(fw, carol), recorded(fw, alice));
    kept.iter()
        .filter(|f| theirs.contains(f) && !own.contains(f))
        .copied()
        .collect()
}

fn send(arguments: &Value) -> Value {
    json!({"name": "send", "arguments": arguments})
}

/// Text `i`'s first `n` chars.
fn head(i: usize, n: usize) -> String {
    text(i).chars().take(n).collect()
}

/// R1/R2 (window level): alice delivered T alone forwards it beside her own
/// field; carol holds T between other values. The glue windows are in
/// today's egress and unexcused, and none is kept.
#[test]
fn glue_windows_around_a_long_leaf_are_not_kept() {
    let fw = observing();
    for i in 0..TEXTS {
        let t = text(i);
        let alice = json!({ "note": t });
        let carol = json!({"a": "xx", "b": t, "c": "yy"});
        let params = send(&json!({"a_note": "x", "body": t}));
        let (all, kept) = egress(&fw, &params);
        assert!(
            !unexcused(&fw, &all, &carol, &alice).is_empty(),
            "premise: text {i} has unexcused glue windows today"
        );
        let left = unexcused(&fw, &kept, &carol, &alice);
        assert!(left.is_empty(), "text {i}: glue windows kept: {left:?}");
    }
}

/// R3: the borrowed edge char. Carol was delivered T between "Report:" and
/// "-- end"; alice, delivered T alone, forwards it between "Fwd:" and
/// "-- me". The keys sort so the walk reads prefix, body, suffix. ":" + head
/// and tail + "-" are carol's; with m = 4 they are glue (one char each).
/// Alice is not reported, even at `min_matches` = 1, and dave, delivered
/// nothing, is.
#[test]
fn a_borrowed_edge_char_is_not_a_relay() {
    let fw = observing_at(1);
    for i in 0..TEXTS {
        let (t, tool) = (text(i), format!("read{i}"));
        let carol = json!({"a_title": "Report:", "b_body": t, "c_footer": "-- end"});
        let alice = json!({ "note": t });
        deliver(&fw, "carol", &tool, &carol);
        deliver(&fw, "alice", &tool, &alice);
        let params = send(&json!({"a_subject": "Fwd:", "b_body": t, "c_sig": "-- me"}));
        let (all, kept) = egress(&fw, &params);
        assert!(
            !unexcused(&fw, &all, &carol, &alice).is_empty(),
            "premise: text {i} has borrowed-char windows today"
        );
        assert!(
            unexcused(&fw, &kept, &carol, &alice).is_empty(),
            "text {i}: a borrowed-char window was kept"
        );
        assert!(relay_found(&fw, "dave", &params), "control: dave, text {i}");
        assert!(
            !relay_found(&fw, "alice", &params),
            "text {i}: alice refused for a borrowed edge char"
        );
    }
}

/// G1: text split at spaces into short fields by a non-holder is reported.
/// Only the newline form puts the spaces back, so nothing may be dropped.
#[test]
fn a_word_boundary_split_by_a_non_holder_is_reported() {
    let fw = observing();
    for i in 0..TEXTS {
        let (t, tool) = (text(i), format!("read{i}"));
        deliver(&fw, "alice", &tool, &json!({ "note": t }));
        let words: serde_json::Map<String, Value> = t
            .split_whitespace()
            .enumerate()
            .map(|(k, w)| (format!("w{k:03}"), Value::String(w.to_owned())))
            .collect();
        let params = send(&Value::Object(words));
        let (all, kept) = egress(&fw, &params);
        assert_eq!(all, kept, "text {i}: a window of a fine split was dropped");
        assert!(relay_found(&fw, "dave", &params), "text {i} missed");
    }
}

/// G2/G3: a long field beside a short one keeps the long field's interior
/// windows, for a non-holder (dave) and for a sender holding only the long
/// field (bob).
#[test]
fn a_long_short_split_keeps_the_long_fields_evidence() {
    let fw = observing();
    for i in 0..TEXTS {
        let (t, tool) = (text(i), format!("read{i}"));
        let (long, short) = (
            head(i, 100),
            t.chars().skip(100).take(47).collect::<String>(),
        );
        deliver(&fw, "alice", &tool, &json!({ "note": t }));
        deliver(&fw, "bob", &tool, &json!({ "note": long }));
        let params = send(&json!({"a": long, "b": short}));
        let (all, kept) = egress(&fw, &params);
        let interior: HashSet<u64> = fps(&fw, &long).intersection(&all).copied().collect();
        assert!(
            interior.is_subset(&kept),
            "text {i}: an interior window dropped"
        );
        assert!(relay_found(&fw, "dave", &params), "text {i}: dave missed");
        assert!(relay_found(&fw, "bob", &params), "text {i}: bob missed");
    }
}

/// G4: text carried in long object keys by a non-holder is reported.
#[test]
fn text_in_long_keys_by_a_non_holder_is_reported() {
    let fw = observing();
    for i in 0..TEXTS {
        let (t, tool) = (text(i), format!("read{i}"));
        let alice = json!({ "note": t });
        deliver(&fw, "alice", &tool, &alice);
        let keys: serde_json::Map<String, Value> = t
            .chars()
            .collect::<Vec<_>>()
            .chunks(60)
            .map(|c| (c.iter().collect::<String>(), json!(0)))
            .collect();
        let params = send(&Value::Object(keys));
        let (all, _) = egress(&fw, &params);
        assert!(
            all.iter().any(|f| recorded(&fw, &alice).contains(f)),
            "premise: text {i}'s keys carry evidence today"
        );
        assert!(relay_found(&fw, "dave", &params), "text {i} missed");
    }
}

/// G10: the interior windows of a long prose field are all kept: spaces
/// inside a field are its own, not glue.
#[test]
fn prose_interior_windows_are_kept() {
    let fw = observing();
    for i in 0..TEXTS {
        let t = text(i);
        let (all, kept) = egress(&fw, &send(&json!({"a_note": "x", "b_body": t})));
        let interior: HashSet<u64> = fps(&fw, &t).intersection(&all).copied().collect();
        assert!(!interior.is_empty(), "premise: text {i} has windows");
        assert!(
            interior.is_subset(&kept),
            "text {i}: a prose interior window dropped"
        );
    }
}

/// G6 (gpt's r2 input) and G7 (grok's [48,4]): next to fields under 2K
/// nothing is dropped, so short texts keep every window, and a non-holder's
/// split is reported.
#[test]
fn short_text_splits_keep_every_window() {
    let fw = observing();
    let gpt = "01CDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxy";
    let grok: String = text(0).replace(' ', "_").chars().take(52).collect();
    for (t, cut) in [(gpt.to_owned(), 47), (grok, 48)] {
        let tool = format!("read{cut}");
        deliver(&fw, "alice", &tool, &json!({ "note": t }));
        let (a, b): (String, String) =
            (t.chars().take(cut).collect(), t.chars().skip(cut).collect());
        let params = send(&json!({"a": a, "b": b}));
        let (all, kept) = egress(&fw, &params);
        assert_eq!(all, kept, "split at {cut}: a window was dropped");
        assert!(relay_found(&fw, "dave", &params), "split at {cut} missed");
    }
}

/// G11: the 2K cut. A field of 95 normalised chars beside a note keeps every
/// window; at 96 the glue windows go.
#[test]
fn the_margin_starts_at_two_k() {
    let fw = observing();
    let body = |n: usize| -> String { text(1).replace(' ', "_").chars().take(n).collect() };
    let (all, kept) = egress(&fw, &send(&json!({"a_note": "x", "b_body": body(95)})));
    assert_eq!(all, kept, "a window dropped beside a 95-char field");
    let (all, kept) = egress(&fw, &send(&json!({"a_note": "x", "b_body": body(96)})));
    assert!(
        kept.len() < all.len(),
        "no glue window dropped beside a 96-char field"
    );
}

/// G5 (gpt's NFC input) and G9 (gpt's leaf-key input): a holder forwarding
/// its own delivery gains no unexcused window from the filter.
#[test]
fn seat_inputs_add_no_refusal_for_a_holder() {
    let m = "\u{30a}\u{301}";
    let nfc_parts =
        json!({"parts": ["a".repeat(48), format!("{m}{}", "b".repeat(23)), "c".repeat(24)]});
    let nfc_carol = json!({"text": format!("{m}{}{}", "b".repeat(23), "c".repeat(24))});
    let (a, b, k) = (
        "ABCDEFGHIJKLMNOPQRSTUVWX",
        "abcdefghijklmnopqrstuvw",
        "zabcdefghijklmnopqr",
    );
    let key_alice = json!({"a": a, "b": b, k: 0});
    let key_carol = json!({"text": format!("{a} {b} a b {k}")});
    for (name, alice, carol) in [("G5", nfc_parts, nfc_carol), ("G9", key_alice, key_carol)] {
        let fw = observing();
        deliver(&fw, "carol", "read", &carol);
        deliver(&fw, "alice", "read", &alice);
        let params = send(&alice);
        let _ = egress(&fw, &params);
        assert!(
            !relay_found(&fw, "alice", &params),
            "{name}: the holder was refused"
        );
    }
}

/// G8 (gpt's cap input): a held forward of combining marks past the
/// normaliser's piece cap, beside a note, is not refused.
#[test]
fn a_long_combining_run_adds_no_refusal() {
    let fw = observing();
    let tail = format!("\u{323}\u{327}\u{301}\u{301}10{}", "b".repeat(120));
    let held = format!("a{}{tail}", "\u{301}".repeat(128));
    let alice = json!({ "note": held });
    deliver(&fw, "carol", "read", &json!({ "text": tail }));
    deliver(&fw, "alice", "read", &alice);
    let params = send(&json!({"a_note": "x", "b_body": held}));
    let _ = egress(&fw, &params);
    assert!(
        !relay_found(&fw, "alice", &params),
        "the holder was refused"
    );
}

/// R4, a pinned residual (v4.0.1 follow-up, which names this row): a forward
/// made of short fields, beside the holder's own short fields, against a copy
/// whose neighbours share the touching chars, is still refused. No field is
/// 2K long, so no window is glue. The follow-up flips this row red-first.
#[test]
fn a_short_field_forward_beside_own_short_fields_is_still_refused() {
    let fw = observing();
    let mut refused = 0;
    for i in 0..TEXTS {
        let (p, tool) = (pieces(&text(i)), format!("read{i}"));
        deliver(
            &fw,
            "carol",
            &tool,
            &json!({"a_title": "Report:", "b_parts": p, "c_footer": "-- end"}),
        );
        deliver(&fw, "alice", &tool, &json!({ "parts": p }));
        let params = send(&json!({"a_subject": "Fwd:", "b_parts": p, "c_sig": "-- me"}));
        refused += usize::from(relay_found(&fw, "alice", &params));
    }
    assert_eq!(
        refused, TEXTS,
        "the residual changed: update the v4.0.1 follow-up"
    );
}

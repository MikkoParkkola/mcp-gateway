// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! `MIK-8066.BIG.3` and the EXCUSE.1 remainder: plan steps and answers past
//! the 1 MiB plan bound. A step staged once its plan holds the bound (P1),
//! a step over the bound (P2) and an answer over the bound (P3) keep no
//! sketch and no evidence today. Design r5.1 keeps exact and Bloom
//! fingerprint state for them in place of text.
//!
//! Production sampling (one k-gram in four); every relayed run is 2,000
//! chars of distinct k-grams (n = 1,953), so even at m = 16 a miss needs
//! fewer than 2 of 1,953 to survive (about 1e-12).

use std::cell::Cell;
use std::fmt::Write;

use serde_json::{Value, json};

use super::{CollusionAction, CollusionConfig, RelayCaller};
use crate::security::firewall::{Firewall, FirewallConfig, ScanType};

/// Relay detection on, observing, with production sampling.
fn firewall() -> Firewall {
    let config = FirewallConfig {
        collusion: CollusionConfig {
            action: CollusionAction::Observe,
            sources: vec!["alpha:*".to_string()],
            ..CollusionConfig::default()
        },
        ..FirewallConfig::default()
    };
    Firewall::from_config(config, None)
}

/// Distinct filler prose of about `chars` characters.
fn filler(seed: u64, chars: usize) -> String {
    let mut out = String::new();
    let mut i = seed;
    while out.len() < chars {
        i = i
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        let _ = write!(out, "row{:x} ", i >> 40);
    }
    out
}

fn deliver(fw: &Firewall, who: &str, text: &str) {
    let result = json!({"content": [{"type": "text", "text": text}]});
    fw.record_delivery(RelayCaller::Keyed(who), "alpha", "read", &result);
}

fn relays(fw: &Firewall, who: &str, text: &str) -> bool {
    let params = json!({"name": "send", "arguments": {"text": text}});
    fw.check_relay(
        RelayCaller::Keyed(who),
        "beta",
        "send",
        &params,
        ("direct:beta", who),
    )
    .findings
    .iter()
    .any(|f| f.scan_type == ScanType::CollusionRelay)
}

/// 2,000 chars of `text` from `at`.
fn run(text: &str, at: usize) -> &str {
    &text[at..at + 2_000]
}

/// Alice's plan step `step`, staged with `staged` already held by her plan,
/// kept to `answer` and recorded, as a plan's delivery does. `false` when
/// the answer was over the bound and the receipt was dropped.
fn deliver_step(fw: &Firewall, step: &Value, staged: usize, answer: &Value) -> bool {
    let staged = Cell::new(staged);
    let Some(digest) = fw.receipt_digest("alpha", "read", step, Some(&staged)) else {
        return false;
    };
    let Some(delivered) = fw.delivered_for_plan(answer, Some(&staged)) else {
        return false;
    };
    let kept = fw.cap_kept(fw.retain_delivered(digest, &delivered, None));
    fw.record_digest(RelayCaller::Keyed("alice"), "alpha", "read", &kept);
    true
}

/// `MIK-8066` T4b (P1): a 100 KiB step staged once its plan already holds
/// the 1 MiB bound, delivered whole by the answer. Its middle is evidence
/// against bob, and its holder alice is excused against carol's copy.
#[test]
fn a_step_staged_past_the_plan_bound_is_excused_and_evidence() {
    let fw = firewall();
    let text = filler(41, 100 * 1024);
    let relayed = run(&text, 40_000);
    let step = json!({"content": [{"type": "text", "text": text}]});
    let answer = json!({"whole": text});
    let bound = super::super::DELIVERED_SET_CAP;
    assert!(
        deliver_step(&fw, &step, bound, &answer),
        "premise: the answer is under the bound"
    );
    assert!(
        relays(&fw, "bob", relayed),
        "the P1 step's middle was never receipted"
    );
    deliver(&fw, "carol", relayed);
    assert!(
        !relays(&fw, "alice", relayed),
        "the P1 step's holder was refused"
    );
}

/// `MIK-8066` T7 (guard): a P1 step the answer leaves out was never
/// received, so it is neither excused nor evidence.
#[test]
fn a_step_staged_past_the_plan_bound_and_omitted_is_neither() {
    let fw = firewall();
    let text = filler(43, 100 * 1024);
    let relayed = run(&text, 40_000);
    let step = json!({"content": [{"type": "text", "text": text}]});
    let answer = json!({"other": filler(44, 50 * 1024)});
    let bound = super::super::DELIVERED_SET_CAP;
    assert!(
        deliver_step(&fw, &step, bound, &answer),
        "premise: under the bound"
    );
    assert!(!relays(&fw, "bob", relayed), "omitted text became evidence");
    deliver(&fw, "carol", relayed);
    assert!(relays(&fw, "alice", relayed), "omitted text was excused");
}

/// `MIK-8066` T4 (P2): one step over the bound (12 leaves of 100 KiB),
/// capped at staging; the answer delivers three of its leaves whole. The
/// middle of a delivered leaf is evidence, and alice is excused for it.
#[test]
fn a_step_over_the_plan_bound_is_excused_and_evidence_for_what_it_delivered() {
    let fw = firewall();
    let leaves: Vec<String> = (0..12).map(|i| filler(100 + i, 100 * 1024)).collect();
    let relayed = run(&leaves[4], 40_000).to_owned();
    let step = json!({ "parts": leaves });
    let answer = json!({"a": leaves[3], "b": leaves[4], "c": leaves[5]});
    assert!(
        deliver_step(&fw, &step, 0, &answer),
        "premise: the answer is under the bound"
    );
    assert!(
        relays(&fw, "bob", &relayed),
        "the P2 step's delivered middle was never receipted"
    );
    deliver(&fw, "carol", &relayed);
    assert!(
        !relays(&fw, "alice", &relayed),
        "the P2 step's holder was refused"
    );
}

/// `MIK-8066` T6 (P3): a 900 KiB step staged whole, delivered inside an
/// answer of 1.6 MiB. Today the over-bound answer drops every step receipt.
/// After BIG.3 the answer is read as a bounded fingerprint view: the step's
/// middle is evidence and its holder is excused.
#[test]
fn a_step_inside_an_answer_over_the_bound_is_excused_and_evidence() {
    let fw = firewall();
    let text = filler(51, 900 * 1024);
    let relayed = run(&text, 300_000);
    let step = json!({"content": [{"type": "text", "text": text}]});
    let answer = json!({"whole": text, "pad": filler(52, 700 * 1024)});
    assert!(
        deliver_step(&fw, &step, 0, &answer),
        "an answer over the bound dropped its step receipts"
    );
    assert!(
        relays(&fw, "bob", relayed),
        "the step's middle was never receipted"
    );
    deliver(&fw, "carol", relayed);
    assert!(
        !relays(&fw, "alice", relayed),
        "the step's holder was refused"
    );
}

/// `MIK-8066` T6, the join form (S3b): a step's labelled parts, each under
/// the 48-char k-gram, delivered inside an over-bound answer. Alice
/// forwarding the parts run together (the per-key-path join, MIK-8209) is
/// excused against carol's whole copy of that join.
#[test]
fn a_rejoined_step_inside_an_answer_over_the_bound_is_excused() {
    let fw = firewall();
    let parts: Vec<String> = (0..10)
        .map(|i| filler(60 + i, 40)[..40].to_owned())
        .collect();
    let items: Vec<Value> = parts
        .iter()
        .map(|p| json!({"kind": "chunk", "part": p}))
        .collect();
    let step = json!({ "items": items });
    let answer = json!({"items": items, "pad": filler(70, 1_200 * 1024)});
    let joined: String = parts.concat();
    assert!(
        deliver_step(&fw, &step, 0, &answer),
        "an answer over the bound dropped its step receipts"
    );
    deliver(&fw, "carol", &joined);
    assert!(
        relays(&fw, "bob", &joined),
        "control: bob without a copy is a relay"
    );
    assert!(
        !relays(&fw, "alice", &joined),
        "the re-joined parts were refused"
    );
}

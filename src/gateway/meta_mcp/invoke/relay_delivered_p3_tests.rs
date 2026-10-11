// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! `MIK-8066` PR 2b relay rows: subset-forward seams on an over-bound answer
//! are attributed by EXACT leaf hashes (D4), through the production
//! `keep_plan_receipts` (retention, seams, capping, subset seams). Test plan:
//! handoff/mutretro-8066-2b-testplan.md (T10, T11, T-seams-view).

use serde_json::{Value, json};

use crate::security::firewall::{
    CollusionAction, CollusionConfig, Firewall, FirewallConfig, PlanStaging, RelayCaller, ScanType,
};

use super::super::seams::with_plan_members;
use super::super::{Kind, Receipt};
use super::keep_plan_receipts;

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

/// A part under the 48-char k-gram, so only runs of parts carry k-grams.
/// Aperiodic (letters from a seeded LCG), so a strict prefix of a part ends
/// unlike the part itself: `p0[..40] + p2` is no substring of `p0 + p2`.
fn piece(k: usize) -> String {
    let mut s = 0x8066_2b00_u64 ^ (k as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15);
    let mut out = format!("p{k}:");
    while out.len() < 47 {
        s = s
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        out.push(char::from(b'a' + u8::try_from((s >> 33) % 26).unwrap_or(0)));
    }
    out
}

/// Distinct padding that pushes an answer past the 1 MiB bound.
/// `chars` of a short repeating unit: past the plan bound by text, but with
/// a handful of distinct k-grams, so the answer's view stays under the entry
/// cap A even when every k-gram is kept (`keeping_every_kgram`).
fn pad(chars: usize) -> String {
    "pad ".repeat(chars.div_ceil(4))
}

/// Where a step is staged: whole (a deferred step), or past the plan bound
/// (a P1 step, capped at staging with attachments).
#[derive(Clone, Copy)]
enum Staged {
    Whole,
    PastTheBound,
}

/// Key-a's plan of one step of labelled `parts` (step 0), kept by the
/// production path to an over-bound answer that carries them, then recorded.
fn keep_over_bound(fw: &Firewall, parts: &[String], staged: Staged) {
    keep_over_bound_beside(fw, parts, &[], staged);
}

/// [`keep_over_bound`] with `outside` parts after the step's in the same
/// answer array, produced by no step (unlabelled), so a run spans the step's
/// parts and parts outside every step.
fn keep_over_bound_beside(fw: &Firewall, parts: &[String], outside: &[String], staged: Staged) {
    let item = |p: &String| json!({"part": p, "kind": "chunk"});
    let items: Vec<Value> = parts.iter().map(item).collect();
    let answer_items: Vec<Value> = parts.iter().chain(outside).map(item).collect();
    let step = json!({ "parts": items });
    let staging = match staged {
        Staged::Whole => PlanStaging::default(),
        Staged::PastTheBound => PlanStaging::starting_at(1024 * 1024),
    };
    staging.set_caller("key-a");
    let digest = fw
        .receipt_digest("alpha", "read", &step, Some(&staging))
        .expect("staged");
    let mut receipts = vec![Receipt {
        key: "key-a".to_string(),
        keyed: true,
        server: "alpha".to_string(),
        tool: "read".to_string(),
        digest,
        in_plan: true,
        pending_retain: true,
        step: Some(0),
        kind: Kind::Delivered,
    }];
    let answer = json!({ "parts": answer_items, "pad": pad(1_200 * 1024) });
    let members = (0..parts.len())
        .map(|i| (format!("/parts/{i}"), 0))
        .collect();
    with_plan_members(members, || {
        keep_plan_receipts(fw, &mut receipts, &answer);
    });
    for r in &receipts {
        fw.record_digest(RelayCaller::Keyed("key-a"), &r.server, &r.tool, &r.digest);
    }
}

/// Whether `who` forwarding `text` is reported, after key-c (carol) was
/// delivered that same text by alpha.
fn reported_after_carol(fw: &Firewall, who: &str, text: &str) -> bool {
    fw.record_delivery(
        RelayCaller::Keyed("key-c"),
        "alpha",
        "read",
        &json!({ "note": text }),
    );
    let params = json!({"name": "send", "arguments": {"body": text}});
    fw.check_relay(
        RelayCaller::Keyed(who),
        "alpha",
        "send",
        &params,
        ("s", who),
    )
    .findings
    .iter()
    .any(|f| f.scan_type == ScanType::CollusionRelay)
}

/// `MIK-8066` T10 (D4): key-a forwards parts 0 and 2 run together, across
/// the omitted part 1, so the boundary k-grams are held only by carol and by
/// key-a's subset seams. On an over-bound answer the seams are attributed by
/// exact leaf hashes: key-a is not reported. Over a deferred AND a big step.
#[test]
fn a_subset_forward_of_an_over_bound_answer_is_excused_by_leaf_hashes() {
    for staged in [Staged::Whole, Staged::PastTheBound] {
        let fw = observing();
        let parts: Vec<String> = (0..3).map(piece).collect();
        keep_over_bound(&fw, &parts, staged);
        let joined = format!("{}{}", parts[0], parts[2]);
        assert!(
            !reported_after_carol(&fw, "key-a", &joined),
            "a subset forward of an over-bound answer was reported (step staged {})",
            match staged {
                Staged::Whole => "whole",
                Staged::PastTheBound => "past the bound",
            }
        );
    }
}

/// `MIK-8066` T11 (guard, D4): a forwarded piece that is a strict substring
/// of a step's leaf hashes differently, so it gets no seam: key-a is reported.
#[test]
fn a_substring_of_a_leaf_gets_no_seam_on_an_over_bound_answer() {
    for staged in [Staged::Whole, Staged::PastTheBound] {
        let fw = observing();
        let parts: Vec<String> = (0..3).map(piece).collect();
        keep_over_bound(&fw, &parts, staged);
        let joined = format!("{}{}", &parts[0][..40], parts[2]);
        assert!(
            reported_after_carol(&fw, "key-a", &joined),
            "a forward built from a leaf's substring was excused"
        );
    }
}

/// `MIK-8066` T-seams-view, first half (guard, B4s): a forward joining a
/// step's part to a part outside every step gets no excuse on an over-bound
/// answer. The answer carries all four parts in one array; the step produced
/// only the first two, so the run spans a step and text no step produced.
#[test]
fn a_forward_beyond_the_step_gets_no_seam_on_an_over_bound_answer() {
    let fw = observing();
    let parts: Vec<String> = (0..4).map(piece).collect();
    keep_over_bound_beside(&fw, &parts[..2], &parts[2..], Staged::Whole);
    let spanning = format!("{}{}", parts[1], parts[3]);
    assert!(
        reported_after_carol(&fw, "key-a", &spanning),
        "a forward spanning two steps was excused on an over-bound answer"
    );
}

/// Key-a's plan of several steps, each `(answer member, items)` labelled by
/// its index and staged whole, kept by the production path to one
/// over-bound answer carrying every member, then recorded.
fn keep_steps_over_bound(fw: &Firewall, steps: &[(&str, Vec<Value>)]) {
    let mut receipts = Vec::new();
    let mut members = Vec::new();
    let mut answer = serde_json::Map::new();
    for (label, (member, items)) in (0u32..).zip(steps) {
        let staging = PlanStaging::default();
        staging.set_caller("key-a");
        let step = json!({ *member: items });
        let digest = fw
            .receipt_digest("alpha", "read", &step, Some(&staging))
            .expect("staged");
        receipts.push(Receipt {
            key: "key-a".to_string(),
            keyed: true,
            server: "alpha".to_string(),
            tool: "read".to_string(),
            digest,
            in_plan: true,
            pending_retain: true,
            step: Some(label),
            kind: Kind::Delivered,
        });
        members.push((format!("/{member}"), label));
        answer.insert((*member).to_string(), Value::Array(items.clone()));
    }
    answer.insert("pad".to_string(), Value::String(pad(1_200 * 1024)));
    let answer = Value::Object(answer);
    with_plan_members(members, || keep_plan_receipts(fw, &mut receipts, &answer));
    for r in &receipts {
        fw.record_digest(RelayCaller::Keyed("key-a"), &r.server, &r.tool, &r.digest);
    }
}

fn chunks(parts: &[String]) -> Vec<Value> {
    parts
        .iter()
        .map(|p| json!({"part": p, "kind": "chunk"}))
        .collect()
}

/// `MIK-8066` T-seams-view, second half (guard, B4s): two steps, each with
/// its own receipt and label; a forward spanning step 0's last part and
/// step 1's first part gets no cross-step excuse on an over-bound answer.
/// Red proof: the mutant "cross-step seams formed on a view", KILLED.
#[test]
fn a_forward_spanning_two_steps_gets_no_seam_on_an_over_bound_answer() {
    let fw = observing();
    let parts: Vec<String> = (0..4).map(piece).collect();
    keep_steps_over_bound(
        &fw,
        &[
            ("first", chunks(&parts[..2])),
            ("second", chunks(&parts[2..])),
        ],
    );
    let spanning = format!("{}{}", parts[1], parts[2]);
    assert!(
        reported_after_carol(&fw, "key-a", &spanning),
        "a forward spanning two steps was excused on an over-bound answer"
    );
}

/// `MIK-8066` T11k (guard, D4): a step holds a string as a KEY; the answer
/// delivers it as a VALUE. Leaf hashes include `is_key`, so the piece is not
/// the step's, and a forward through it gets no seam. Red proof: the mutant
/// "`is_key` ignored in leaf hashes", KILLED.
#[test]
fn a_key_delivered_as_a_value_gets_no_seam_on_an_over_bound_answer() {
    let fw = observing();
    let parts: Vec<String> = (0..3).map(piece).collect();
    // The step carries part 0 as a key, the answer carries it as a value.
    let staged_items = vec![
        json!({ parts[0].clone(): "v", "kind": "chunk" }),
        json!({"part": parts[2], "kind": "chunk"}),
    ];
    let staging = PlanStaging::default();
    staging.set_caller("key-a");
    let digest = fw
        .receipt_digest(
            "alpha",
            "read",
            &json!({ "parts": staged_items }),
            Some(&staging),
        )
        .expect("staged");
    let mut receipts = vec![Receipt {
        key: "key-a".to_string(),
        keyed: true,
        server: "alpha".to_string(),
        tool: "read".to_string(),
        digest,
        in_plan: true,
        pending_retain: true,
        step: Some(0),
        kind: Kind::Delivered,
    }];
    let answer =
        json!({ "parts": chunks(&[parts[0].clone(), parts[2].clone()]), "pad": pad(1_200 * 1024) });
    with_plan_members(vec![("/parts".to_string(), 0)], || {
        keep_plan_receipts(&fw, &mut receipts, &answer);
    });
    for r in &receipts {
        fw.record_digest(RelayCaller::Keyed("key-a"), &r.server, &r.tool, &r.digest);
    }
    let joined = format!("{}{}", parts[0], parts[2]);
    assert!(
        reported_after_carol(&fw, "key-a", &joined),
        "a forward through a key delivered as a value was excused"
    );
}

/// `MIK-8066` T-rewritten (D7): a rewritten wrapper past the answer text cap
/// keeps its staged receipt (no clear) and fails closed: the receipt is
/// evidence under the unread holder, so a stranger's relay is refused.
#[test]
fn a_rewritten_answer_past_the_cap_keeps_its_receipt_and_fails_closed() {
    let fw = observing();
    fw.collusion_detector()
        .expect("relay detection on")
        .set_answer_text_cap(512 * 1024);
    // Over the 1 MiB bound, so today's path clears the receipt (fail-open);
    // past the 512 KiB cap, so 2b takes the unread path and keeps it.
    // A pretty-printed wrapper (the rewritten route's input) whose one
    // string literal is over the bound, so both readings are too big today.
    let text =
        serde_json::to_string_pretty(&json!({ "text": pad(1_200 * 1024) })).expect("serializes");
    let staging = PlanStaging::default();
    staging.set_caller("key-a");
    let digest = fw
        .receipt_digest("alpha", "read", &json!({ "text": text }), Some(&staging))
        .expect("staged");
    let mut receipts = vec![Receipt {
        key: "key-a".to_string(),
        keyed: true,
        server: "alpha".to_string(),
        tool: "read".to_string(),
        digest,
        in_plan: false,
        pending_retain: false,
        step: None,
        kind: Kind::Delivered,
    }];
    super::keep_to_rewritten(&fw, &mut receipts, &text);
    assert_eq!(
        receipts.len(),
        1,
        "a rewritten answer past the cap cleared its receipt (fail-open)"
    );
}

/// `MIK-8066` D6: an unread answer gets no label walk and no seam pass. With
/// the answer text cap lowered, key-a's over-bound answer is unread; keeping
/// its receipts walks nothing. Control: the same plan with the cap restored
/// is read, and keeping it walks the answer.
#[test]
fn an_unread_answer_gets_no_label_walk_or_seam_pass() {
    let walks_while_kept = |cap: Option<usize>| {
        let fw = observing();
        if let Some(cap) = cap {
            fw.collusion_detector()
                .expect("relay detection on")
                .set_answer_text_cap(cap);
        }
        let parts: Vec<String> = (0..3).map(piece).collect();
        let items: Vec<Value> = parts
            .iter()
            .map(|p| json!({"part": p, "kind": "chunk"}))
            .collect();
        let staging = PlanStaging::default();
        staging.set_caller("key-a");
        let digest = fw
            .receipt_digest("alpha", "read", &json!({ "parts": items }), Some(&staging))
            .expect("staged");
        let mut receipts = vec![Receipt {
            key: "key-a".to_string(),
            keyed: true,
            server: "alpha".to_string(),
            tool: "read".to_string(),
            digest,
            in_plan: true,
            pending_retain: true,
            step: Some(0),
            kind: Kind::Delivered,
        }];
        let answer = json!({ "parts": items, "pad": pad(1_200 * 1024) });
        let before = crate::security::firewall::walks_built();
        with_plan_members(vec![("/parts".to_string(), 0)], || {
            keep_plan_receipts(&fw, &mut receipts, &answer);
        });
        crate::security::firewall::walks_built() - before
    };
    assert!(
        walks_while_kept(None) > 0,
        "premise: keeping a read answer walked nothing"
    );
    assert_eq!(
        walks_while_kept(Some(512 * 1024)),
        0,
        "an unread answer was walked (label walk or seam pass)"
    );
}

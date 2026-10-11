// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! `MIK-8066` PR 2b relay rows: subset-forward seams on an over-bound answer
//! are attributed by EXACT leaf hashes (D4), through the production
//! `keep_plan_receipts` (retention, seams, capping, subset seams). Test plan:
//! handoff/mutretro-8066-2b-testplan.md (T10, T11, T-seams-view).

use std::fmt::Write;

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
fn piece(k: usize) -> String {
    format!("piece{k}-").repeat(10).chars().take(47).collect()
}

/// Distinct padding that pushes an answer past the 1 MiB bound.
fn pad(chars: usize) -> String {
    let mut out = String::with_capacity(chars + 16);
    let mut i = 0u64;
    while out.len() < chars {
        let _ = write!(out, "pad{i:x} ");
        i += 1;
    }
    out
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
    let items: Vec<Value> = parts
        .iter()
        .map(|p| json!({"part": p, "kind": "chunk"}))
        .collect();
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
    let answer = json!({ "parts": items, "pad": pad(1_200 * 1024) });
    with_plan_members(vec![("/parts".to_string(), 0)], || {
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
/// answer. (The two-receipt cross-step half lands with the implementation.)
#[test]
fn a_forward_beyond_the_step_gets_no_seam_on_an_over_bound_answer() {
    let fw = observing();
    let parts: Vec<String> = (0..4).map(piece).collect();
    keep_over_bound(&fw, &parts[..2], Staged::Whole);
    let spanning = format!("{}{}", parts[1], parts[3]);
    assert!(
        reported_after_carol(&fw, "key-a", &spanning),
        "a forward spanning two steps was excused on an over-bound answer"
    );
}

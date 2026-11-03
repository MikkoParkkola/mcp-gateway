// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A multi-contributor seam is judged per contributor under the lists and
//! flows in force when it is checked (ADR-029, amended, items 2 and 3), not
//! by the one combined bit and the flow masks fixed when it was recorded.
//!
//! The seams are built by the production path, `keep_plan_receipts` over a
//! plan whose answer joins adjacent steps' pieces (each under one k-gram, so
//! only a run across a boundary holds a seam fingerprint), then recorded for
//! alice under the generation current at delivery.

use serde_json::json;

use super::super::seams::with_plan_members;
use super::super::{Kind, Receipt};
use super::keep_plan_receipts;
use super::p3_tests::piece;
use crate::config_reload::Generation;
use crate::security::firewall::CollusionAction::Block;
use crate::security::firewall::collusion_live_rig::{Rig, config, flow};
use crate::security::firewall::{PlanStaging, RelayCaller};

/// One plan step: the `server:tool` it called, and whether its result
/// carries the gateway's own sensitive classification.
type Step = (&'static str, &'static str, bool);

/// Alice's plan of `steps` (step `i` delivers `piece(i)` as the answer's
/// member `/s{i}`), kept by the production path and recorded under `g`.
/// Returns the delivery's receipts.
fn deliver_plan(rig: &Rig, g: &Generation, steps: &[Step]) -> Vec<Receipt> {
    let (mut receipts, mut members, mut answer) = (Vec::new(), Vec::new(), serde_json::Map::new());
    for (label, (server, tool, inferred)) in (0_u32..).zip(steps) {
        let text = piece(usize::try_from(label).expect("small"));
        let result = if *inferred {
            json!({"v": text, "_context_integrity": {"classification": {"data_classes": ["personal_data"]}}})
        } else {
            json!({"v": text})
        };
        let staging = PlanStaging::default();
        staging.set_caller("alice");
        let digest = rig
            .firewall
            .receipt_digest(server, tool, &result, Some(&staging))
            .expect("staged");
        receipts.push(Receipt {
            key: "alice".to_string(),
            keyed: true,
            server: (*server).to_string(),
            tool: (*tool).to_string(),
            digest,
            in_plan: true,
            pending_retain: true,
            step: Some(label),
            kind: Kind::Delivered,
        });
        members.push((format!("/s{label}"), label));
        answer.insert(format!("s{label}"), json!(text));
    }
    let answer = serde_json::Value::Object(answer);
    with_plan_members(members, || {
        keep_plan_receipts(&rig.firewall, &mut receipts, &answer);
    });
    for r in &receipts {
        let caller = RelayCaller::Keyed("alice");
        rig.firewall
            .record_digest(caller, &r.server, &r.tool, &r.digest, g);
    }
    receipts
}

/// The seam run across steps `i` and `i + 1`, as bob would relay it.
fn seam_text(i: usize) -> String {
    format!("{}{}", piece(i), piece(i + 1))
}

/// Whether bob relaying seam `i` through `target` is refused under the
/// generation published now.
fn refused(rig: &Rig, i: usize, target: (&str, &str)) -> bool {
    let verdict = rig.relays("bob", target, &seam_text(i), &rig.generation());
    crate::security::firewall::collusion_live_rig::refused(&verdict)
}

const AB: [Step; 2] = [("alpha", "a", false), ("beta", "b", false)];

/// P8.7: a seam leaves only by a flow every contributor allows, judged by
/// the flows in force: adding the missing contributor's flow lets it out;
/// naming the composite does not. RED on base at the G1 "allowed": the
/// per-contributor masks were fixed at record.
#[test]
fn p8_7_a_seam_follows_the_flows_of_each_contributor() {
    let rig_for = || {
        let flows = vec![flow("alpha:a", "gamma:send")];
        Rig::new(config(Block, &["alpha:a", "beta:b"], flows))
    };
    let rig = rig_for();
    deliver_plan(&rig, &rig.generation(), &AB);
    assert!(
        refused(&rig, 0, ("gamma", "send")),
        "G0: beta:b has no flow"
    );
    rig.reload(|c| {
        let flows = &mut c.security.firewall.collusion.allowed_flows;
        flows.push(flow("beta:b", "gamma:send"));
    });
    assert!(
        !refused(&rig, 0, ("gamma", "send")),
        "P8.7: both contributors' flows do not let the seam out"
    );

    let control = rig_for();
    deliver_plan(&control, &control.generation(), &AB);
    control.reload(|c| {
        let flows = &mut c.security.firewall.collusion.allowed_flows;
        flows.push(flow("seam*", "gamma:send"));
    });
    assert!(
        refused(&control, 0, ("gamma", "send")),
        "control: the composite's name is no contributor"
    );
}

/// P8.10a: a contributor listed after the seam was recorded makes it
/// sensitive. RED on base: the seam bit was fixed by the OR at record.
#[test]
fn p8_10a_a_contributor_added_makes_the_seam_sensitive() {
    let rig = Rig::new(config(Block, &[], vec![]));
    deliver_plan(&rig, &rig.generation(), &AB);
    assert!(!refused(&rig, 0, ("gamma", "send")), "control: plain");
    rig.reload(|c| c.security.firewall.collusion.sources = vec!["beta:b".to_string()]);
    assert!(refused(&rig, 0, ("gamma", "send")), "P8.10a: still plain");
}

/// P8.10b: contributors removed from the lists one by one release the seam
/// when none is left. RED on base at the last assertion.
#[test]
fn p8_10b_contributors_removed_release_the_seam() {
    let rig = Rig::new(config(Block, &["alpha:a", "beta:b"], vec![]));
    deliver_plan(&rig, &rig.generation(), &AB);
    assert!(refused(&rig, 0, ("gamma", "send")), "control: sensitive");
    rig.reload(|c| c.security.firewall.collusion.sources = vec!["alpha:a".to_string()]);
    assert!(refused(&rig, 0, ("gamma", "send")), "one contributor left");
    rig.reload(|c| c.security.firewall.collusion.sources = vec![]);
    assert!(!refused(&rig, 0, ("gamma", "send")), "P8.10b: still held");
}

/// P8.10c: seams past the composite bound are judged by the lists in force,
/// not merged on the key they shared when recorded. Eighteen distinct
/// contributor sets (steps `t0..t18`, one seam per adjacent pair), recorded
/// in the lexical order of their members: `t7+t8` and `t8+t9` (seams 7 and
/// 8) come 17th and 18th and overflow the sixteen composites. `alpha:t7`
/// listed refuses seam 7 and not seam 8; removing it releases both. RED on
/// base at the G1 "refused": the reload is ignored.
#[test]
fn p8_10c_overflow_seams_follow_the_lists_in_force() {
    const TOOLS: [&str; 19] = [
        "t0", "t1", "t2", "t3", "t4", "t5", "t6", "t7", "t8", "t9", "t10", "t11", "t12", "t13",
        "t14", "t15", "t16", "t17", "t18",
    ];
    let steps: Vec<Step> = TOOLS.iter().map(|t| ("alpha", *t, false)).collect();
    let rig = Rig::new(config(Block, &[], vec![]));
    deliver_plan(&rig, &rig.generation(), &steps);
    rig.reload(|c| c.security.firewall.collusion.sources = vec!["alpha:t7".to_string()]);
    assert!(
        refused(&rig, 7, ("gamma", "send")),
        "P8.10c: the listed contributor's seam is not refused"
    );
    assert!(!refused(&rig, 8, ("gamma", "send")), "the other seam");
    rig.reload(|c| c.security.firewall.collusion.sources = vec![]);
    assert!(!refused(&rig, 7, ("gamma", "send")), "released");
    assert!(!refused(&rig, 8, ("gamma", "send")), "released");
}

/// P8.10d: each seam keeps its own contributors' exact facts. The first
/// step's result is classified (inferred); seam A joins it to a plain step,
/// seam B joins two plain steps. RED on base: one combined bit, so A's plain
/// contributor reads as inferred.
#[test]
fn p8_10d_a_seam_keeps_its_contributors_exact_facts() {
    let steps: [Step; 3] = [
        ("alpha", "a", true),
        ("beta", "b", false),
        ("gamma", "c", false),
    ];
    let rig = Rig::new(config(Block, &[], vec![]));
    let receipts = deliver_plan(&rig, &rig.generation(), &steps);
    let facts: Vec<_> = receipts
        .iter()
        .filter(|r| r.kind == Kind::Seam)
        .filter_map(|r| r.digest.contributor_facts_for_test())
        .map(|list| {
            list.into_iter()
                .map(|(n, f)| (n.to_string(), f))
                .collect::<Vec<_>>()
        })
        .collect();
    let pair =
        |a: &str, af: bool, b: &str, bf: bool| vec![(a.to_string(), af), (b.to_string(), bf)];
    assert!(
        facts.contains(&pair("alpha:a", true, "beta:b", false)),
        "P8.10d seam A: {facts:?}"
    );
    assert!(
        facts.contains(&pair("beta:b", false, "gamma:c", false)),
        "P8.10d seam B: {facts:?}"
    );
    assert!(refused(&rig, 0, ("gamma", "send")), "seam A refused");
    assert!(!refused(&rig, 1, ("gamma", "send")), "seam B allowed");
}

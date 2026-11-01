// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Relay detection follows the published configuration (ADR-029, amended,
//! items 2 and 3). A witness judges under the view of the generation its
//! request pinned, so a reload that removes a flow, adds a source, empties
//! `non_egress` or switches the action applies to the evidence already held.
//!
//! Alice receives from `alpha:read` and bob egresses through `alpha:send`
//! unless a row says otherwise. Each row holds its generations as the
//! requests would: G0 before the reload, G1 after.

use super::CollusionAction::{Block, Observe, Off};
use super::collusion_live_rig::{
    PROSE, Rig, Why, classified, config, flow, observed, plain, refused, why,
};

/// A second ordinary paragraph, unrelated to [`PROSE`].
const OTHER_PROSE: &str = "Minutes of the harbour committee: the dredging contract moves to the \
    spring tender, the ferry timetable keeps its Sunday gap, and the pilot boat needs a new \
    engine mount before the first autumn gale. Two residents asked about the lighting on the \
    east pier and were told the quote arrives after the council recess.";

const READ: (&str, &str) = ("alpha", "read");
const SEND: (&str, &str) = ("alpha", "send");

/// P8.1: a flow removed by a reload no longer excuses a held copy. The
/// removed entry is replaced, in the same position, by an unrelated source's
/// flow to the same egress. RED on base: the held mask and the startup flows
/// still allow it.
#[test]
fn p8_1_a_removed_flow_refuses_after_the_reload() {
    let rig = Rig::new(config(
        Block,
        &["alpha:read"],
        vec![flow("alpha:read", "alpha:send")],
    ));
    let g0 = rig.generation();
    rig.deliver("alice", READ, &plain(PROSE), &g0);
    assert!(
        !refused(&rig.relays("bob", SEND, PROSE, &g0)),
        "control: the flow allows it under G0"
    );
    rig.reload(|c| {
        c.security.firewall.collusion.allowed_flows = vec![flow("beta:read", "alpha:send")];
    });
    let g1 = rig.generation();
    assert_eq!(
        g1.collusion_view().source_flows("alpha:read"),
        0,
        "premise: the reload published"
    );
    let verdict = rig.relays("bob", SEND, PROSE, &g1);
    assert!(refused(&verdict), "P8.1: the removed flow still allows it");
    assert_eq!(
        why(&verdict),
        Some(Why::Relay),
        "P8.1: refused for a reason other than relay"
    );
}

/// P8.2a: an inferred (classified) delivery from a source no list names is
/// refused; a flow added by a reload allows it, and removing it refuses
/// again. RED on base at the G1 "allowed": the startup flows are empty.
#[test]
fn p8_2a_a_flow_added_then_removed_follows_the_reload() {
    let rig = Rig::new(config(Block, &[], vec![]));
    let g0 = rig.generation();
    rig.deliver("alice", READ, &classified(PROSE), &g0);
    assert!(
        refused(&rig.relays("bob", SEND, PROSE, &g0)),
        "control: an inferred copy is refused under G0"
    );
    rig.reload(|c| {
        c.security.firewall.collusion.allowed_flows = vec![flow("alpha:read", "alpha:send")];
    });
    let g1 = rig.generation();
    assert!(
        !refused(&rig.relays("bob", SEND, PROSE, &g1)),
        "P8.2a: the added flow does not allow the held copy"
    );
    rig.reload(|c| c.security.firewall.collusion.allowed_flows = vec![]);
    let g2 = rig.generation();
    let verdict = rig.relays("bob", SEND, PROSE, &g2);
    assert!(refused(&verdict), "P8.2a: the removed flow still allows it");
    assert_eq!(
        why(&verdict),
        Some(Why::Relay),
        "P8.2a: refused for a reason other than relay"
    );
}

/// P8.2b: a plain copy recorded under no list becomes sensitive when a
/// reload adds its source. RED on base: the witness reads the startup lists.
#[test]
fn p8_2b_a_source_added_makes_the_held_plain_copy_sensitive() {
    let rig = Rig::new(config(Block, &[], vec![]));
    let g0 = rig.generation();
    rig.deliver("alice", READ, &plain(PROSE), &g0);
    assert!(
        !refused(&rig.relays("bob", SEND, PROSE, &g0)),
        "control: a plain copy is allowed under G0"
    );
    rig.reload(|c| c.security.firewall.collusion.sources = vec!["alpha:read".to_string()]);
    let g1 = rig.generation();
    let verdict = rig.relays("bob", SEND, PROSE, &g1);
    assert!(refused(&verdict), "P8.2b: the added source does not apply");
    assert_eq!(
        why(&verdict),
        Some(Why::Relay),
        "P8.2b: refused for a reason other than relay"
    );
}

/// P8.3: reordering `allowed_flows` changes no verdict. GREEN pin on base
/// (the reload is ignored); the property is for the position-mask mutant.
#[test]
fn p8_3_reordered_flows_keep_every_verdict() {
    let (fa, fb) = (
        flow("alpha:read", "alpha:send"),
        flow("beta:read", "beta:send"),
    );
    let rig = Rig::new(config(
        Block,
        &["alpha:read", "beta:read"],
        vec![fa.clone(), fb.clone()],
    ));
    let g0 = rig.generation();
    rig.deliver("alice", READ, &plain(PROSE), &g0);
    rig.deliver("carol", ("beta", "read"), &plain(OTHER_PROSE), &g0);
    let verdicts = |g: &crate::config_reload::Generation| {
        [
            (PROSE, SEND),
            (PROSE, ("beta", "send")),
            (OTHER_PROSE, ("beta", "send")),
            (OTHER_PROSE, SEND),
        ]
        .map(|(text, target)| refused(&rig.relays("bob", target, text, g)))
    };
    let before = verdicts(&g0);
    assert_eq!(before, [false, true, false, true], "premise: G0 verdicts");
    rig.reload(|c| c.security.firewall.collusion.allowed_flows = vec![fb, fa]);
    assert_eq!(verdicts(&rig.generation()), before, "P8.3: a verdict moved");
}

/// P8.4: `non_egress` emptied by a reload checks the egress it exempted.
/// RED on base: the gate reads the startup `non_egress`.
#[test]
fn p8_4_an_emptied_non_egress_checks_the_egress_again() {
    let mut cfg = config(Block, &["alpha:read"], vec![]);
    cfg.security.firewall.collusion.non_egress = vec!["alpha:send".to_string()];
    let rig = Rig::new(cfg);
    let g0 = rig.generation();
    rig.deliver("alice", READ, &plain(PROSE), &g0);
    assert!(
        !refused(&rig.relays("bob", SEND, PROSE, &g0)),
        "control: a non-egress target is not checked under G0"
    );
    rig.reload(|c| c.security.firewall.collusion.non_egress = vec![]);
    let g1 = rig.generation();
    let verdict = rig.relays("bob", SEND, PROSE, &g1);
    assert!(
        refused(&verdict),
        "P8.4: the emptied non_egress still exempts it"
    );
    assert_eq!(
        why(&verdict),
        Some(Why::Relay),
        "P8.4: refused for a reason other than relay"
    );
}

/// P8.5a: relay detection switched on by a reload judges what is delivered
/// after the switch. RED on base: a startup `off` builds no detector.
#[test]
fn p8_5a_off_then_block_judges_the_delivery_after_the_switch() {
    let rig = Rig::new(config(Off, &["alpha:read"], vec![]));
    rig.reload(|c| c.security.firewall.collusion.action = Block);
    let g1 = rig.generation();
    rig.deliver("alice", READ, &plain(PROSE), &g1);
    let verdict = rig.relays("bob", SEND, PROSE, &g1);
    assert!(refused(&verdict), "P8.5a: nothing was recorded or checked");
    assert_eq!(
        why(&verdict),
        Some(Why::Relay),
        "P8.5a: refused for a reason other than relay"
    );
}

/// P8.6a: an activation that arrives with a detector parameter edit applies
/// nothing: the held view is kept and the edit waits for a restart. GREEN
/// pin on base (the startup action is `observe`).
#[test]
fn p8_6a_activation_with_a_detector_edit_applies_nothing() {
    let rig = Rig::new(config(Observe, &["alpha:read"], vec![]));
    let g0 = rig.generation();
    rig.deliver("alice", READ, &plain(PROSE), &g0);
    rig.reload(|c| {
        c.security.firewall.collusion.action = Block;
        c.security.firewall.collusion.window_secs = 601;
    });
    let g1 = rig.generation();
    assert_eq!(g1.collusion_view().action(), Observe, "control: held");
    assert!(
        rig.live.pending_restart_fields().contains(&"security"),
        "P8.6a: security is not restart-pending"
    );
    let verdict = rig.relays("bob", SEND, PROSE, &g1);
    assert!(observed(&verdict), "P8.6a: not observed: {verdict:?}");
}

/// P8.6b: a real action edit while the parameter edit is pending is held
/// too. GREEN pin on base.
#[test]
fn p8_6b_an_action_edit_beside_a_pending_edit_is_held() {
    let rig = Rig::new(config(Observe, &["alpha:read"], vec![]));
    let g0 = rig.generation();
    rig.deliver("alice", READ, &plain(PROSE), &g0);
    rig.reload(|c| {
        c.security.firewall.collusion.action = Block;
        c.security.firewall.collusion.window_secs = 601;
    });
    rig.reload(|c| c.security.firewall.collusion.action = Off);
    let g2 = rig.generation();
    assert_eq!(g2.collusion_view().action(), Observe, "control: held");
    assert!(
        rig.live.pending_restart_fields().contains(&"security"),
        "P8.6b: security is not restart-pending"
    );
    let verdict = rig.relays("bob", SEND, PROSE, &g2);
    assert!(observed(&verdict), "P8.6b: not observed: {verdict:?}");
}

/// P8.11: an effective `off` at the witness checks nothing, keyed or not.
/// RED on base: the gate reads the startup `block`.
#[test]
fn p8_11_an_effective_off_checks_nothing() {
    let dir = tempfile::tempdir().expect("tempdir");
    let log = dir.path().join("audit.ndjson");
    let mut cfg = config(Block, &["alpha:read"], vec![]);
    cfg.security.firewall.audit_log = Some(log.clone());
    let rig = Rig::new(cfg);
    let g0 = rig.generation();
    rig.deliver("alice", READ, &plain(PROSE), &g0);
    rig.reload(|c| c.security.firewall.collusion.action = Off);
    let g1 = rig.generation();
    let keyed = rig.relays("bob", SEND, PROSE, &g1);
    assert!(
        keyed.allowed && keyed.findings.is_empty(),
        "P8.11: {keyed:?}"
    );
    let params = serde_json::json!({"name": "send", "arguments": {"text": PROSE}});
    let unkeyed = rig.firewall.check_relay(
        g1.collusion_view(),
        super::RelayCaller::Unkeyed("direct:alpha"),
        "alpha",
        "send",
        &params,
        ("s", "x"),
    );
    assert!(
        unkeyed.allowed && unkeyed.findings.is_empty(),
        "P8.11: {unkeyed:?}"
    );
    let audited = std::fs::read_to_string(&log).unwrap_or_default();
    assert!(
        !audited.contains("collusion_relay"),
        "P8.11: audited: {audited}"
    );
}

/// P8.13: a live `block` applies, and a later detector edit keeps it
/// (the effective view falls back to the previous one, not the startup).
/// RED on base: the startup action is `observe`.
#[test]
fn p8_13_a_live_block_survives_a_later_detector_edit() {
    let rig = Rig::new(config(Observe, &["alpha:read"], vec![]));
    rig.reload(|c| c.security.firewall.collusion.action = Block);
    let g1 = rig.generation();
    rig.deliver("alice", READ, &plain(PROSE), &g1);
    rig.reload(|c| {
        c.security.firewall.collusion.action = Block;
        c.security.firewall.collusion.common_principals = 3;
    });
    let g2 = rig.generation();
    assert_eq!(
        g2.collusion_view().action(),
        Block,
        "control: held at block"
    );
    assert!(
        rig.live.pending_restart_fields().contains(&"security"),
        "P8.13: security is not restart-pending"
    );
    let verdict = rig.relays("bob", SEND, PROSE, &g2);
    assert!(refused(&verdict), "P8.13: not refused: {verdict:?}");
    assert_eq!(
        why(&verdict),
        Some(Why::Relay),
        "P8.13: refused for a reason other than relay"
    );
}

/// P8.14d: an inferred fact expires with its own delivery; a plain delivery
/// later does not extend it. GREEN pin on base.
#[test]
fn p8_14d_a_plain_delivery_does_not_extend_an_inferred_fact() {
    use std::time::{Duration, Instant};
    let rig = Rig::new(config(Block, &[], vec![]));
    let g = rig.generation();
    let view = g.collusion_view();
    let detector = rig.firewall.collusion_detector().expect("block runs one");
    let t0 = Instant::now();
    let t = |secs: u64| t0 + Duration::from_secs(secs);
    detector.record_delivery_under(view, ("alpha:read", true), "alice", PROSE, t0);
    detector.record_delivery_under(view, ("alpha:read", false), "alice", PROSE, t(300));
    detector.record_delivery_under(view, ("alpha:read", false), "alice", PROSE, t(500));
    let relayed = |at| {
        detector
            .check_egress_under(view, "bob", "alpha:send", PROSE, at)
            .is_some()
    };
    assert!(relayed(t(300)), "premise: refused inside the window");
    assert!(!relayed(t(601)), "P8.14d: the plain deliveries extended it");
}

/// SG1: a startup `off` still builds the detector, so a reload to `observe`
/// finds one. RED on base: `detector_for` returns `None` for `off`.
#[test]
fn sg1_a_startup_off_builds_the_detector() {
    let rig = Rig::new(config(Off, &["alpha:read"], vec![]));
    assert!(
        rig.firewall.collusion_detector().is_some(),
        "SG1: a startup `off` built no detector"
    );
    rig.reload(|c| c.security.firewall.collusion.action = Observe);
    let g1 = rig.generation();
    rig.deliver("alice", READ, &plain(PROSE), &g1);
    let verdict = rig.relays("bob", SEND, PROSE, &g1);
    assert!(observed(&verdict), "SG1: not observed: {verdict:?}");
}

/// A detector built with the default parameters (action `off`), every k-gram
/// kept, one match enough.
fn default_detector() -> super::collusion::CollusionDetector {
    let mut detector = super::collusion::CollusionDetector::new(super::collusion::RelayParams {
        min_matches: 1,
        ..super::collusion::RelayParams::default()
    });
    detector.keep_every_kgram();
    detector
}

/// SG2: the detector's record entry keeps no action of its own: a delivery
/// recorded under an `observe` view is kept. RED on base: the early return at
/// the top of `record_delivery_flows_at`.
#[test]
fn sg2_the_record_entry_has_no_action_gate() {
    let view_rig = Rig::new(config(Observe, &["alpha:read"], vec![]));
    let g1 = view_rig.generation();
    let detector = default_detector();
    detector.record_delivery_under(
        g1.collusion_view(),
        ("alpha:read", false),
        "alice",
        PROSE,
        std::time::Instant::now(),
    );
    assert!(
        detector.tracked_fingerprints() > 0,
        "SG2: nothing was recorded"
    );
}

/// SG3: the detector's egress entry has no action gate either. RED on base
/// at the finding (the record step and the egress step share the gate, so
/// the base cannot hold the evidence the check would read).
#[test]
fn sg3_the_egress_entry_has_no_action_gate() {
    let view_rig = Rig::new(config(Observe, &["alpha:read"], vec![]));
    let g1 = view_rig.generation();
    let detector = default_detector();
    let now = std::time::Instant::now();
    detector.record_delivery_under(
        g1.collusion_view(),
        ("alpha:read", false),
        "alice",
        PROSE,
        now,
    );
    let finding = detector.check_egress_under(g1.collusion_view(), "bob", "alpha:send", PROSE, now);
    assert!(finding.is_some(), "SG3: no finding");
}

/// SG4: a list-match delivery recorded after a reload from `off` to `observe`
/// is held. RED on base (no detector).
#[test]
fn sg4_a_delivery_recorded_after_off_to_observe_is_held() {
    let rig = Rig::new(config(Off, &["alpha:read"], vec![]));
    rig.reload(|c| c.security.firewall.collusion.action = Observe);
    let g1 = rig.generation();
    rig.deliver("alice", READ, &plain(PROSE), &g1);
    let verdict = rig.relays("bob", SEND, PROSE, &g1);
    assert!(observed(&verdict), "SG4: not observed: {verdict:?}");
}

/// SG6: the action at the witness is the view's, both ways. RED on base: the
/// startup action decides.
#[test]
fn sg6_the_witness_follows_the_view_action_both_ways() {
    let up = Rig::new(config(Observe, &["alpha:read"], vec![]));
    let g0 = up.generation();
    up.deliver("alice", READ, &plain(PROSE), &g0);
    up.reload(|c| c.security.firewall.collusion.action = Block);
    let verdict = up.relays("bob", SEND, PROSE, &up.generation());
    assert!(refused(&verdict), "SG6 observe->block: {verdict:?}");

    let down = Rig::new(config(Block, &["alpha:read"], vec![]));
    let g0 = down.generation();
    down.deliver("alice", READ, &plain(PROSE), &g0);
    down.reload(|c| c.security.firewall.collusion.action = Observe);
    let verdict = down.relays("bob", SEND, PROSE, &down.generation());
    assert!(observed(&verdict), "SG6 block->observe: {verdict:?}");
}

/// Alice's plan receipt of `alpha:read` delivering [`PROSE`], kept to the
/// plan's answer and snapshotted for replay.
fn plan_snapshot(rig: &Rig, text: &str) -> super::collusion_digest::ReplayReceipt {
    let staged = super::PlanStaging::default();
    staged.set_caller("alice");
    let step = serde_json::json!({"body": text});
    let digest = rig
        .firewall
        .receipt_digest("alpha", "read", &step, Some(&staged))
        .expect("relay detection is on: fixture");
    let delivered = rig
        .firewall
        .delivered_for_plan(&step, Some(&staged))
        .expect("the answer is under the bound: fixture");
    let kept = rig
        .firewall
        .cap_kept(rig.firewall.retain_delivered(digest, &delivered, None));
    kept.replay_snapshot(Some(0), "alpha", "read")
        .expect("a kept plan receipt snapshots: fixture")
}

/// Bob's verdict after alice's receipt lapses and its snapshot is replayed
/// to her under the generation published after `reload`.
fn replayed_verdict(reload: bool) -> crate::security::firewall::FirewallVerdict {
    let mut cfg = config(Block, &["alpha:*"], vec![]);
    cfg.security.firewall.collusion.window_secs = 1;
    let rig = Rig::new(cfg);
    let snapshot = plan_snapshot(&rig, PROSE);
    rig.lapse(std::time::Duration::from_secs(2));
    if reload {
        rig.reload(|c| c.security.firewall.collusion.sources = vec![]);
    }
    let g1 = rig.generation();
    let replayed = super::DeliveryDigest::of_replay_receipt(&snapshot);
    rig.firewall.record_digest(
        super::RelayCaller::Keyed("alice"),
        "alpha",
        "read",
        &replayed,
        &g1,
    );
    rig.relays("bob", SEND, PROSE, &g1)
}

/// P8.9a: a replayed receipt follows the current lists, not the combined bit
/// it was snapshotted with. Control: with no reload the replay is refused.
/// RED on base: the snapshot carries the list-or-inferred bit.
#[test]
fn p8_9a_a_replayed_receipt_follows_the_current_lists() {
    assert!(refused(&replayed_verdict(false)), "control: replay records");
    let verdict = replayed_verdict(true);
    assert!(
        !refused(&verdict),
        "P8.9a: the replay kept the old list match"
    );
    let single = plan_snapshot(&Rig::new(config(Block, &["alpha:*"], vec![])), PROSE);
    assert!(
        single.contributor_facts_for_test().is_none(),
        "a single-source receipt has no contributors"
    );
}

/// O5.2b: a replay re-decides retention under the current lists. Alice's plan
/// delivery of a one-fingerprint text from a listed source is snapshotted;
/// after the window and a reload that unlists the source, her cap is filled
/// and the snapshot replayed: the receipt is plain now, does not fit, and is
/// dropped, so bob relaying the text is allowed. RED on base: the snapshot's
/// stored bit overflows it, which refuses bob.
#[test]
fn o5_2b_a_replay_re_decides_retention_under_the_current_lists() {
    let text = super::collusion_live_rig::one_fp(1);
    let mut cfg = config(Block, &["alpha:*"], vec![flow("fill:*", "alpha:send")]);
    cfg.security.firewall.collusion.window_secs = 1;
    let rig = Rig::new(cfg);
    let snapshot = plan_snapshot(&rig, &text);
    rig.lapse(std::time::Duration::from_secs(2));
    rig.reload(|c| c.security.firewall.collusion.sources = vec!["fill:*".to_string()]);
    let g1 = rig.generation();
    for i in 0..64 {
        let tool = i.to_string();
        rig.deliver("alice", ("fill", &tool), &plain(&text), &g1);
    }
    let replayed = super::DeliveryDigest::of_replay_receipt(&snapshot);
    let alice = super::RelayCaller::Keyed("alice");
    let detector = rig.firewall.collusion_detector().expect("block runs one");
    let before = detector.capped();
    #[cfg(feature = "metrics")]
    let dropped = super::collusion_live_rig::bound_count("record_dropped");
    rig.firewall
        .record_digest(alice, "alpha", "read", &replayed, &g1);
    let verdict = rig.relays("bob", SEND, &text, &g1);
    assert!(
        !refused(&verdict),
        "O5.2b: the replay kept the stored class"
    );
    // The replayed receipt is plain under G1 and does not fit: dropped, so no
    // overflow pair names its source.
    let kept: Vec<_> = detector.overflow_pairs_of(&text, "alice");
    assert!(
        kept.iter().all(|(source, _)| &**source != "alpha:read"),
        "O5.2b: the replayed receipt was kept as an overflow pair: {kept:?}"
    );
    // `capped` counts drops and overflows together, so this is the one drop
    // the plan names as `record_dropped` +1; an overflow would move it by the
    // same amount, which the pairs assertion above separates.
    assert_eq!(
        detector.capped() - before,
        1,
        "O5.2b: one record not counted"
    );
}

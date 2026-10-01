// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! #1756: the firewall's anomaly detector learns from the calls it admits.
//!
//! Every fixture here starts from an EMPTY tracker, the way production builds
//! the firewall (`gateway/server/mod.rs`, both sites). Anything a test later
//! observes was learned through `check_request`, never trained by hand.

use std::sync::Arc;
use std::sync::mpsc;
use std::time::Duration;

use serde_json::json;

use super::{Firewall, FirewallAction, FirewallConfig, FirewallRule};
use crate::security::posture::SecurityPosture;
use crate::transition::TransitionTracker;

fn learning_firewall(threshold: f64, block: Option<f64>, rules: Vec<FirewallRule>) -> Firewall {
    let cfg = FirewallConfig {
        anomaly_detection: true,
        anomaly_threshold: threshold,
        anomaly_block_threshold: block,
        anomaly_min_observations: 20,
        rules,
        ..FirewallConfig::default()
    };
    Firewall::from_config(cfg, Some(Arc::new(TransitionTracker::new())))
}

fn call(fw: &Firewall, identity: &str, tool: &str) -> super::FirewallVerdict {
    fw.check_request(identity, "srv", tool, &json!({}), "caller", identity)
}

/// Alternate `tool_a` and `tool_b` for `rounds`, so `srv:tool_a` has `rounds`
/// recorded successors, all `srv:tool_b`.
fn teach(fw: &Firewall, identity: &str, rounds: usize) {
    for _ in 0..rounds {
        assert!(
            call(fw, identity, "tool_a").allowed,
            "teaching calls are admitted"
        );
        assert!(
            call(fw, identity, "tool_b").allowed,
            "teaching calls are admitted"
        );
    }
}

#[test]
fn admitted_calls_teach_the_detector() {
    // The issue's criterion at unit scale: no hand training, and after the
    // learning window a never-seen transition scores 1.0 and blocks.
    let fw = learning_firewall(0.7, Some(0.95), Vec::new());
    teach(&fw, "caller-1", 25);
    assert!(call(&fw, "caller-1", "tool_a").allowed);
    let verdict = call(&fw, "caller-1", "tool_c");
    assert_eq!(
        verdict.anomaly_score,
        Some(1.0),
        "a->c was never seen after 25 a->b"
    );
    assert!(!verdict.allowed && verdict.is_anomaly_block());
}

#[test]
fn blocked_call_is_not_learned() {
    // A blocked a->c moves nothing: the retry is scored against `a` again and
    // blocks again, and `c` never becomes a learned successor of `a`.
    let fw = learning_firewall(0.7, Some(0.95), Vec::new());
    teach(&fw, "caller-1", 25);
    assert!(call(&fw, "caller-1", "tool_a").allowed);
    assert!(
        !call(&fw, "caller-1", "tool_c").allowed,
        "first a->c blocks"
    );
    let retry = call(&fw, "caller-1", "tool_c");
    assert!(!retry.allowed, "the retry is still a->c, not a cold c->c");
    assert_eq!(retry.anomaly_score, Some(1.0));
}

fn allow_all() -> FirewallRule {
    FirewallRule {
        tool_match: "*".to_string(),
        action: FirewallAction::Allow,
        reason: Some("allow everything".to_string()),
        scan: Vec::new(),
    }
}

/// The firewall a `hardened` start builds: its config comes from a hardened
/// YAML through `Config::load` (block threshold, detection and warm-up all as
/// the posture leaves them), wired as `gateway/server/mod.rs` wires it.
fn hardened_firewall(rules: Vec<FirewallRule>) -> Firewall {
    use crate::security::posture::tests::{firewall_yaml, load};
    let mut cfg = load(&firewall_yaml("hardened", None)).security.firewall;
    cfg.rules = rules;
    Firewall::from_config(cfg, Some(Arc::new(TransitionTracker::new())))
        .with_posture(SecurityPosture::Hardened)
}

#[test]
fn anomaly_block_survives_allow_rule_standard() {
    // A rule may soften an ordinary finding. It may not soften a score at or
    // above the operator's block threshold: that operator asked for blocks.
    let fw = learning_firewall(0.7, Some(0.95), vec![allow_all()]);
    teach(&fw, "caller-1", 25);
    assert!(call(&fw, "caller-1", "tool_a").allowed);
    let verdict = call(&fw, "caller-1", "tool_c");
    assert!(
        !verdict.allowed,
        "an allow rule must not downgrade an anomaly block"
    );
    assert!(verdict.is_anomaly_block());
}

/// Design row 4c, hardened half: the block the posture forces at its default
/// threshold is not softened by an Allow rule either.
#[test]
fn anomaly_block_survives_allow_rule_hardened() {
    let fw = hardened_firewall(vec![allow_all()]);
    teach(&fw, "caller-1", 25);
    assert!(call(&fw, "caller-1", "tool_a").allowed);
    let verdict = call(&fw, "caller-1", "tool_c");
    assert_eq!(verdict.anomaly_score, Some(1.0), "a->c was never seen");
    assert!(
        !verdict.allowed,
        "an allow rule must not downgrade a hardened anomaly block"
    );
    assert!(verdict.is_anomaly_block());
}

/// Design row 3c: a warmed predecessor with 20 equally likely successors
/// scores each about 0.95. At the hardened default (1.0) none blocks; a 0.95
/// default would block every one.
#[test]
fn diverse_warm_predecessor_not_blocked_at_default() {
    let fw = hardened_firewall(Vec::new());
    let successors: Vec<String> = (0..20).map(|n| format!("tool_s{n}")).collect();
    // Round 1 warms `srv:tool_a`: its 20 transitions are learned while it has
    // fewer than the 20 observations scoring needs.
    for successor in &successors {
        assert!(call(&fw, "caller-1", "tool_a").allowed, "warm-up");
        assert!(call(&fw, "caller-1", successor).allowed, "warm-up");
    }
    // Round 2: every a->successor is scored, and none blocks.
    for successor in &successors {
        assert!(call(&fw, "caller-1", "tool_a").allowed);
        let verdict = call(&fw, "caller-1", successor);
        let score = verdict
            .anomaly_score
            .unwrap_or_else(|| panic!("a->{successor} must be scored, not warming up"));
        assert!(
            (0.95 - 1e-9..1.0).contains(&score),
            "a->{successor} is one of 20 equally likely successors: {score}"
        );
        assert!(
            verdict.allowed && !verdict.is_anomaly_block(),
            "a->{successor} (score {score}) blocked at the hardened default"
        );
    }
}

#[test]
fn warmup_has_no_score_and_is_counted() {
    // At a threshold just above the old neutral 0.5, a first call must carry
    // no score at all, raise no finding, and be counted as warming up.
    let fw = learning_firewall(0.51, None, Vec::new());
    let verdict = call(&fw, "caller-1", "tool_a");
    assert_eq!(verdict.anomaly_score, None, "warming up is not a score");
    assert!(verdict.findings.is_empty());
    let detector = fw.anomaly.as_ref().expect("detector on");
    assert_eq!(detector.warming_up_count(), 1);
}

#[test]
fn stripe_lock_serializes_one_identity() {
    // Deterministic: while the test holds caller-1's scoring lock, a call for
    // caller-1 on another thread must wait; released, it completes.
    let fw = Arc::new(learning_firewall(0.7, None, Vec::new()));
    let guard = fw
        .anomaly
        .as_ref()
        .expect("detector on")
        .hold_stripe("caller-1");
    let worker = Arc::clone(&fw);
    let (done, finished) = mpsc::channel();
    let (started, running) = mpsc::channel();
    let handle = std::thread::spawn(move || {
        let _ = started.send(());
        let _ = call(&worker, "caller-1", "tool_a");
        let _ = done.send(());
    });
    // Wait until the worker is about to call, so the window below measures
    // the lock and not thread start-up.
    running
        .recv_timeout(Duration::from_secs(5))
        .expect("worker started");
    let waited = finished.recv_timeout(Duration::from_millis(200));
    drop(guard);
    assert!(
        waited.is_err(),
        "the call must wait for the identity's scoring lock"
    );
    finished
        .recv_timeout(Duration::from_secs(5))
        .expect("released, the call completes");
    handle.join().expect("worker");
}

#[test]
fn committed_pairs_form_one_path() {
    // Four threads interleave calls for ONE identity. Serialized scoring means
    // every admitted call after the first is learned exactly once.
    let fw = Arc::new(learning_firewall(0.7, None, Vec::new()));
    let tools = ["tool_a", "tool_b", "tool_c"];
    let handles: Vec<_> = (0..4)
        .map(|t| {
            let fw = Arc::clone(&fw);
            std::thread::spawn(move || {
                for n in 0..50 {
                    let _ = call(&fw, "caller-1", tools[(t + n) % 3]);
                }
            })
        })
        .collect();
    for handle in handles {
        handle.join().expect("worker");
    }
    let learned: u64 = fw
        .anomaly
        .as_ref()
        .expect("detector on")
        .tracker_for_test()
        .total_transitions();
    assert_eq!(
        learned,
        4 * 50 - 1,
        "every call but the first is one learned transition"
    );
}

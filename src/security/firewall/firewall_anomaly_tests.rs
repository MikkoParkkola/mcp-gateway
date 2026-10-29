// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Unit tests of the unified firewall's anomaly blocking (OWASP ASI10).

use super::*;

// ── OWASP ASI10 anomaly blocking ──────────────────────────────────────────

/// Build a firewall with anomaly detection enabled and trained transition
/// data so that a never-seen transition scores 0.95.
fn anomaly_firewall(log_threshold: f64, block_threshold: Option<f64>) -> Firewall {
    use crate::transition::TransitionTracker;
    let tracker = Arc::new(TransitionTracker::new());
    // Train: tool_a → tool_b (10×) so predecessor data exists.
    for _ in 0..10 {
        tracker.record_transition("train", "srv:tool_a");
        tracker.record_transition("train", "srv:tool_b");
    }
    let cfg = FirewallConfig {
        anomaly_detection: true,
        anomaly_threshold: log_threshold,
        anomaly_block_threshold: block_threshold,
        anomaly_min_observations: 1,
        ..FirewallConfig::default()
    };
    Firewall::from_config(cfg, Some(tracker))
}

/// Prime the session so `tool_a` is recorded as the last tool.
fn prime_session(fw: &Firewall, session: &str) {
    fw.check_request(session, "srv", "tool_a", &json!({}), "caller", session);
}

#[test]
fn an_unscoreable_call_cannot_be_downgraded_by_a_rule() {
    // A rule may soften an ordinary finding. It must not soften this one:
    // an unscoreable call was never examined, so there is no judgement for
    // a rule to downgrade.
    use crate::transition::TransitionTracker;
    let cfg = FirewallConfig {
        anomaly_detection: true,
        anomaly_threshold: 0.7,
        anomaly_block_threshold: Some(0.9),
        rules: vec![FirewallRule {
            tool_match: "*".to_string(),
            action: FirewallAction::Allow,
            reason: Some("allow everything".to_string()),
            scan: Vec::new(),
        }],
        ..FirewallConfig::default()
    };
    let fw = Firewall::from_config(cfg, Some(Arc::new(TransitionTracker::new())));

    let args = json!({ "q": "ok" });
    let verdict = fw.check_request("", "srv", "tool", &args, "anonymous", "");

    assert!(
        !verdict.allowed,
        "an allow rule must not reach a call that was never scored"
    );
}

#[test]
fn an_anomaly_detector_with_no_identity_refuses_rather_than_passes() {
    // The failure shape that reads as success: the control still runs, still
    // logs, and stops deciding anything. A stateless caller has no session,
    // so if it is also unauthenticated there is nothing to key a sequence
    // on — and a sequence detector that cannot tell callers apart is not
    // detecting sequences.
    let fw = anomaly_firewall(0.7, Some(0.9));
    let args = json!({ "q": "ok" });

    let verdict = fw.check_request("", "srv", "tool", &args, "anonymous", "");

    assert!(
        !verdict.allowed,
        "an unscoreable call must be refused, not allowed unscored"
    );
}

#[test]
fn a_stateless_caller_is_keyed_on_its_principal() {
    // With no session, the authenticated principal is the identity. It is a
    // real one: two principals must not share a bucket, or one caller's
    // ordinary sequence makes another's unusual one look ordinary.
    let fw = anomaly_firewall(0.7, Some(0.9));
    let args = json!({ "q": "ok" });

    // A validated credential key, never the display name: two API keys may
    // share a name, and every anonymous caller presents the same one.
    // The first call only establishes a predecessor (warming up, #1756).
    fw.check_request("", "srv", "tool_a", &args, "alice", "credential:abc123");
    let verdict = fw.check_request("", "srv", "tool_b", &args, "alice", "credential:abc123");

    assert!(
        verdict.allowed,
        "an identified stateless caller must still be scored and served"
    );
    assert!(
        verdict.anomaly_score.is_some(),
        "the call must actually be scored, not merely permitted"
    );
}

#[test]
fn a_session_caller_is_still_keyed_on_its_session() {
    let fw = anomaly_firewall(0.7, Some(0.9));
    let args = json!({ "q": "ok" });

    fw.check_request("s1", "srv", "tool_a", &args, "anonymous", "s1");
    let verdict = fw.check_request("s1", "srv", "tool_b", &args, "anonymous", "s1");

    assert!(verdict.allowed);
    assert!(verdict.anomaly_score.is_some());
}

#[test]
fn anomaly_below_log_threshold_passes_silently() {
    // Cold-start score is 0.5; log_threshold is 0.7 → no finding at all.
    let fw = anomaly_firewall(0.7, None);
    let args = json!({});
    // First call is always cold-start (score 0.5).
    let verdict = fw.check_request("sess", "srv", "tool_a", &args, "caller", "sess");
    assert!(verdict.allowed);
    assert!(
        verdict.findings.is_empty(),
        "Cold-start score 0.5 must not produce a finding below log_threshold 0.7"
    );
}

#[test]
fn anomaly_above_log_threshold_logs_but_passes() {
    // Never-seen transition scores 0.95; log_threshold=0.7, no block_threshold.
    let fw = anomaly_firewall(0.7, None);
    prime_session(&fw, "sess");
    let verdict = fw.check_request(
        "sess",
        "srv",
        "never_seen_tool",
        &json!({}),
        "caller",
        "sess",
    );
    assert!(
        verdict.allowed,
        "Without block_threshold, anomaly findings must not block"
    );
    assert!(
        verdict
            .findings
            .iter()
            .any(|f| f.scan_type == ScanType::SequenceAnomaly && f.severity == Severity::Low),
        "Score 0.95 above log_threshold 0.7 must produce a Low SequenceAnomaly finding"
    );
    assert!(
        !verdict.is_anomaly_block(),
        "is_anomaly_block must be false when block_threshold is not set"
    );
}

#[test]
fn anomaly_above_block_threshold_is_rejected() {
    // Never-seen transition scores 0.95; block_threshold=0.9 → block.
    let fw = anomaly_firewall(0.7, Some(0.9));
    prime_session(&fw, "sess");
    let verdict = fw.check_request(
        "sess",
        "srv",
        "never_seen_tool",
        &json!({}),
        "caller",
        "sess",
    );
    assert!(
        !verdict.allowed,
        "Score 0.95 ≥ block_threshold 0.9 must be rejected"
    );
    assert_eq!(verdict.action, FirewallAction::Block);
    assert!(
        verdict
            .findings
            .iter()
            .any(|f| f.scan_type == ScanType::SequenceAnomaly && f.severity == Severity::High),
        "Blocked anomaly finding must be Severity::High"
    );
    assert!(
        verdict.is_anomaly_block(),
        "is_anomaly_block must be true when only anomaly findings are present"
    );
}

#[test]
fn anomaly_block_threshold_unset_preserves_backward_compatibility() {
    // block_threshold=None: even a score of 0.95 must never block.
    let fw = anomaly_firewall(0.7, None);
    prime_session(&fw, "sess");
    let verdict = fw.check_request(
        "sess",
        "srv",
        "never_seen_tool",
        &json!({}),
        "caller",
        "sess",
    );
    assert!(
        verdict.allowed,
        "With no block_threshold, all requests pass regardless of anomaly score"
    );
}

#[test]
fn anomaly_finding_is_high_severity_only_when_above_block_threshold() {
    // a->c seen once in ten scores 0.9: above log (0.7), below block
    // (0.99), so Low, not High.
    use crate::transition::TransitionTracker;
    let tracker = Arc::new(TransitionTracker::new());
    for n in 0..10 {
        let caller = format!("train-{n}");
        tracker.record_transition(&caller, "srv:tool_a");
        let next = if n == 0 {
            "srv:rare_tool"
        } else {
            "srv:tool_b"
        };
        tracker.record_transition(&caller, next);
    }
    let cfg = FirewallConfig {
        anomaly_detection: true,
        anomaly_block_threshold: Some(0.99),
        anomaly_min_observations: 1,
        ..FirewallConfig::default()
    };
    let fw = Firewall::from_config(cfg, Some(tracker));
    prime_session(&fw, "sess");
    let verdict = fw.check_request("sess", "srv", "rare_tool", &json!({}), "caller", "sess");
    assert!(
        verdict.allowed,
        "Score 0.9 < block_threshold 0.99 must pass"
    );
    assert!(
        verdict
            .findings
            .iter()
            .any(|f| f.scan_type == ScanType::SequenceAnomaly && f.severity == Severity::Low),
        "Finding must be Low (log-only) when score is below block_threshold"
    );
    assert!(
        !verdict.is_anomaly_block(),
        "is_anomaly_block must be false when score is below block_threshold"
    );
}

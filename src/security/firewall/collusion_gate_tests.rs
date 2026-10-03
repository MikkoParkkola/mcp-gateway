// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! COLLUDE.1 2a-i unit cases (test plan B1-B3).

use serde_json::json;

use super::{
    AllowedFlow, CollusionAction, CollusionConfig, RECORD_CAP, RelayCaller, Walk, capped, text_of,
};
use crate::config::Config;
use crate::security::firewall::{
    Finding, FindingLocation, Firewall, FirewallAction, FirewallConfig, FirewallVerdict, ScanType,
    Severity,
};

fn finding(scan_type: ScanType, severity: Severity) -> Finding {
    Finding {
        scan_type,
        severity,
        description: String::new(),
        matched: String::new(),
        location: FindingLocation::RequestArgs,
    }
}

fn blocked(findings: Vec<Finding>) -> FirewallVerdict {
    FirewallVerdict {
        allowed: false,
        action: FirewallAction::Block,
        findings,
        anomaly_score: None,
    }
}

/// B1: a relay block is an ASI10 block (`-32002`); a mix with any other
/// kind of finding is not.
#[test]
fn a_relay_block_is_an_anomaly_block_and_a_mixed_one_is_not() {
    let relay = || finding(ScanType::CollusionRelay, Severity::Medium);
    let anomaly = |s| finding(ScanType::SequenceAnomaly, s);
    assert!(blocked(vec![relay()]).is_asi10_block());
    assert!(blocked(vec![anomaly(Severity::High), relay()]).is_asi10_block());
    assert!(
        !blocked(vec![
            relay(),
            finding(ScanType::Credentials, Severity::High)
        ])
        .is_asi10_block()
    );
    assert!(!blocked(vec![anomaly(Severity::Medium)]).is_asi10_block());
    assert!(!blocked(Vec::new()).is_asi10_block());
    let mut allowed = blocked(vec![relay()]);
    allowed.allowed = true;
    assert!(!allowed.is_asi10_block());
    // The public check keeps its pre-relay meaning.
    assert!(!blocked(vec![relay()]).is_anomaly_block());
    assert!(blocked(vec![anomaly(Severity::High)]).is_anomaly_block());
}

fn load(firewall: &str) -> crate::Result<()> {
    let yaml = format!("security:\n  firewall:\n{firewall}");
    let config: Config = serde_yaml::from_str(&yaml).expect("the YAML parses");
    config.validate()
}

/// B2: every setting that cannot mean what it says is refused by name, with
/// anomaly detection off; `action: off` loads whatever the rest holds.
#[test]
fn collusion_settings_are_checked_at_load_and_off_loads_anything() {
    let cases = [
        (
            "    enabled: false\n    collusion:\n      action: observe\n",
            "collusion.action",
        ),
        (
            "    collusion:\n      action: block\n      min_matches: 0\n",
            "collusion.min_matches",
        ),
        (
            "    collusion:\n      action: observe\n      common_principals: 1\n",
            "collusion.common_principals",
        ),
        (
            "    collusion:\n      action: observe\n      common_principals: 10\n",
            "collusion.common_principals",
        ),
        (
            "    collusion:\n      action: observe\n      window_secs: 0\n",
            "collusion.window_secs",
        ),
        (
            "    collusion:\n      action: observe\n      sources: [\"a:[\"]\n",
            "collusion.sources",
        ),
        (
            "    collusion:\n      action: observe\n      non_egress: [\"a:[\"]\n",
            "collusion.non_egress",
        ),
    ];
    for (firewall, field) in cases {
        let err = load(firewall).expect_err(field).to_string();
        assert!(
            err.contains(&format!("security.firewall.{field}")),
            "{field}: {err}"
        );
    }
    for enabled in ["false", "true"] {
        let off = format!(
            "    enabled: {enabled}\n    collusion:\n      action: off\n      min_matches: 0\n      \
             common_principals: 1\n      window_secs: 0\n      sources: [\"a:[\"]\n      \
             non_egress: [\"b:[\"]\n"
        );
        load(&off).expect("action off loads whatever the other fields hold");
    }
    load("    collusion:\n      action: block\n").expect("the defaults are valid");
    load("    collusion:\n      action: observe\n      common_principals: 9\n")
        .expect("nine principals can still be reached before a fingerprint saturates");
}

/// B3: a delivery skips only the top-level `_context_integrity`, the
/// gateway's own verdict slot; a nested one, in any shape, is delivered
/// content. Values are read first, contiguous, so content split
/// over several short fields still matches; keys follow. Egress reads every
/// key (a key reaches the backend like a value); a delivery reads only keys
/// long enough to fingerprint alone, so short schema keys never make two
/// unrelated payloads alike.
#[test]
fn the_text_walker_reads_values_then_keys_and_skips_nothing() {
    let long_key = "k".repeat(48);
    let value = json!({
        "_context_integrity": {"note": "five"},
        "a": [{"text": "one"}],
        "b": {"_context_integrity": {"schema_version": "two"}},
        "c": {"_context_integrity": {"note": "three"}},
        "key four": 4,
        long_key.clone(): 5,
    });
    let delivered = text_of(&value, Walk::Delivery);
    assert!(delivered.starts_with("one\ntwo\nthree\n"), "{delivered:?}");
    assert!(delivered.contains(&long_key), "{delivered:?}");
    assert!(!delivered.contains("key four"), "{delivered:?}");
    let egress = text_of(&value, Walk::Egress);
    assert!(
        !delivered.contains("five"),
        "the gateway's own slot: {delivered:?}"
    );
    assert!(egress.contains("one\ntwo\nthree\n"), "{egress:?}");
    assert!(egress.contains("five"), "{egress:?}");
    for key in [
        "key four",
        "_context_integrity",
        "schema_version",
        long_key.as_str(),
    ] {
        assert!(egress.contains(key), "{key} missing: {egress:?}");
    }
}

/// B3: the adopted cap, pinned apart from the constant; at and below it the
/// text is kept whole, above it exactly the first and last half, each cut on
/// a char boundary, joined by one newline.
#[test]
fn an_over_cap_text_keeps_exact_head_and_tail_on_char_boundaries() {
    assert_eq!(RECORD_CAP, 6 * 1024, "the documented evasion bound");
    for len in [RECORD_CAP - 1, RECORD_CAP] {
        let text = "x".repeat(len);
        assert_eq!(capped(text.clone()), (text, false), "{len}");
    }
    let half = RECORD_CAP / 2;
    let plain: String = (b'a'..=b'z')
        .cycle()
        .take(RECORD_CAP + 1)
        .map(char::from)
        .collect();
    let (kept, cut) = capped(plain.clone());
    assert!(cut);
    assert_eq!(
        kept,
        format!("{}\n{}", &plain[..half], &plain[plain.len() - half..])
    );

    // A 4-byte char straddles both cut points: the head ends before it, the
    // tail starts after it.
    let text = format!(
        "{}{}{}",
        "a".repeat(half - 1),
        "\u{1D11E}".repeat(RECORD_CAP),
        "z"
    );
    let (kept, cut) = capped(text.clone());
    assert!(cut);
    let (head, tail) = kept.split_once('\n').expect("one separator");
    assert_eq!(head, "a".repeat(half - 1));
    assert!(tail.len() < half && tail.len() > half - 4, "{}", tail.len());
    assert!(text.ends_with(tail));
}

fn observing(extra: impl FnOnce(&mut CollusionConfig)) -> (Firewall, tempfile::TempDir) {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut collusion = CollusionConfig {
        action: CollusionAction::Observe,
        sources: vec!["alpha:*".to_string()],
        ..CollusionConfig::default()
    };
    extra(&mut collusion);
    let config = FirewallConfig {
        audit_log: Some(dir.path().join("audit.ndjson")),
        collusion,
        ..FirewallConfig::default()
    };
    (Firewall::from_config(config, None), dir)
}

const PROSE: &str = "The orchard ledger for the north slope records seven rows of late pears, \
    the grafting dates for each rootstock, the hours the drip lines ran during the dry weeks of \
    August, and which crew pruned the older trees after the second frost.";

fn delivered(fw: &Firewall, who: &str) {
    let result = json!({"content": [{"type": "text", "text": PROSE}]});
    fw.record_delivery(RelayCaller::Keyed(who), "alpha", "read", &result);
}

fn egress(fw: &Firewall, caller: RelayCaller<'_>) -> FirewallVerdict {
    let params = json!({"name": "send", "arguments": {"text": PROSE}});
    fw.check_relay(caller, "alpha", "send", &params, ("direct:alpha", "bob"))
}

/// B6: under `observe` a relay is a `Warn` verdict with one digest-only
/// `CollusionRelay` finding, audited; an unkeyed sender is checked too.
#[test]
fn observe_reports_a_relay_without_content_and_audits_it() {
    let (fw, dir) = observing(|_| {});
    delivered(&fw, "alice");
    for caller in [
        RelayCaller::Keyed("bob"),
        RelayCaller::Unkeyed("direct:alpha"),
    ] {
        let verdict = egress(&fw, caller);
        assert!(verdict.allowed, "{caller:?}");
        assert_eq!(verdict.action, FirewallAction::Warn, "{caller:?}");
        let [finding] = verdict.findings.as_slice() else {
            panic!("one finding: {:?}", verdict.findings);
        };
        assert_eq!(finding.scan_type, ScanType::CollusionRelay);
        assert_eq!(finding.severity, Severity::Medium);
        assert_eq!(finding.location, FindingLocation::RequestArgs);
        assert!(
            finding.matched.starts_with("source="),
            "{}",
            finding.matched
        );
        assert!(!finding.matched.contains("orchard"), "content leaked");
    }
    let audit = std::fs::read_to_string(dir.path().join("audit.ndjson")).expect("audited");
    assert_eq!(audit.matches("collusion_relay").count(), 2, "{audit}");
    // Neither side, nor the receiver itself, is a relay.
    assert!(egress(&fw, RelayCaller::Keyed("alice")).findings.is_empty());
}

/// B7: `min_matches` and `common_principals` reach the detector.
#[test]
fn the_configured_thresholds_reach_the_detector() {
    let (fw, _dir) = observing(|c| c.min_matches = 10_000);
    delivered(&fw, "alice");
    assert!(egress(&fw, RelayCaller::Keyed("bob")).findings.is_empty());

    let (fw, _dir) = observing(|c| c.common_principals = 2);
    delivered(&fw, "alice");
    delivered(&fw, "carol");
    assert!(
        egress(&fw, RelayCaller::Keyed("bob")).findings.is_empty(),
        "text two principals hold is common at common_principals: 2"
    );
}

fn flow(source: &str, egress: &str) -> AllowedFlow {
    AllowedFlow {
        source: source.to_string(),
        egress: egress.to_string(),
    }
}

/// An egress through `server:tool` carrying [`PROSE`], sent by `bob`.
fn egress_via(fw: &Firewall, (server, tool): (&str, &str)) -> FirewallVerdict {
    let params = json!({"name": tool, "arguments": {"text": PROSE}});
    fw.check_relay(
        RelayCaller::Keyed("bob"),
        server,
        tool,
        &params,
        ("s", "bob"),
    )
}

/// Row 13: an allowlisted flow passes under `observe` and `block`; the same
/// content through any other egress, or from any other source, is still a relay.
#[test]
fn allowed_flow_not_flagged() {
    for action in [CollusionAction::Observe, CollusionAction::Block] {
        let (fw, _dir) = observing(|c| {
            c.action = action;
            c.allowed_flows = vec![flow("alpha:read", "beta:send")];
        });
        delivered(&fw, "alice");
        let allowed = egress_via(&fw, ("beta", "send"));
        assert!(
            allowed.allowed && allowed.findings.is_empty(),
            "{action:?}: {allowed:?}"
        );
        let other = egress_via(&fw, ("alpha", "send"));
        assert_eq!(
            other.findings.len(),
            1,
            "{action:?}: another egress is a relay"
        );
        let (fw, _dir) = observing(|c| {
            c.action = action;
            c.allowed_flows = vec![flow("gamma:read", "beta:send")];
        });
        delivered(&fw, "alice");
        let other_source = egress_via(&fw, ("beta", "send"));
        assert_eq!(
            other_source.findings.len(),
            1,
            "{action:?}: another source is a relay"
        );
    }
}

/// Globs match: one entry covers every tool its patterns name.
#[test]
fn allowed_flow_globs_match() {
    let (fw, _dir) = observing(|c| c.allowed_flows = vec![flow("alpha:*", "b*:send_*")]);
    delivered(&fw, "alice");
    assert!(egress_via(&fw, ("beta", "send_doc")).findings.is_empty());
    assert_eq!(egress_via(&fw, ("beta", "post")).findings.len(), 1);
}

/// `allowed_flows` is checked at load like the other globs, and holds at most
/// 64 entries (one bit each).
#[test]
fn allowed_flows_are_checked_at_load() {
    let bad = "    collusion:\n      action: observe\n      allowed_flows:\n        - {source: \"a:[\", egress: \"b:*\"}\n";
    let err = load(bad).expect_err("bad source glob").to_string();
    assert!(
        err.contains("security.firewall.collusion.allowed_flows"),
        "{err}"
    );
    let bad = "    collusion:\n      action: observe\n      allowed_flows:\n        - {source: \"a:*\", egress: \"b:[\"}\n";
    assert!(load(bad).is_err(), "bad egress glob");
    let many: String = (0..65)
        .map(|i| format!("        - {{source: \"a:{i}\", egress: \"b:*\"}}\n"))
        .collect();
    let many = format!("    collusion:\n      action: observe\n      allowed_flows:\n{many}");
    assert!(load(&many).is_err(), "65 entries");
    let ok = "    collusion:\n      action: observe\n      allowed_flows:\n        - {source: \"a:*\", egress: \"b:*\"}\n";
    load(ok).expect("a valid entry loads");
    let off = "    collusion:\n      action: off\n      allowed_flows:\n        - {source: \"a:[\", egress: \"b:[\"}\n";
    load(off).expect("action off loads whatever the rest holds");
}

/// The metric: every reported relay increments
/// `mcp_gateway_collusion_relay_total` under its action label.
#[cfg(feature = "metrics")]
#[test]
fn a_reported_relay_increments_the_metric() {
    crate::metrics::install();
    let count = |action: &str| -> u64 {
        let line = format!("mcp_gateway_collusion_relay_total{{action=\"{action}\"}} ");
        crate::metrics::render()
            .lines()
            .find_map(|l| l.strip_prefix(&line).and_then(|v| v.trim().parse().ok()))
            .unwrap_or(0)
    };
    for (action, label) in [
        (CollusionAction::Observe, "observe"),
        (CollusionAction::Block, "block"),
    ] {
        let (fw, _dir) = observing(|c| c.action = action);
        delivered(&fw, "alice");
        let before = count(label);
        let _ = egress(&fw, RelayCaller::Keyed("bob"));
        assert!(count(label) > before, "{label}: not counted");
    }
}

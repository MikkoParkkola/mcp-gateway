// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! COLLUDE.1 2a-i unit cases (test plan B1-B3).

use serde_json::json;

use super::{
    AllowedFlow, CollusionAction, CollusionConfig, DeliveryDigest, RECORD_CAP, RelayCaller,
    delivery_leaves, egress_text,
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
    let delivered = delivery_leaves(&value).join("\n");
    assert!(delivered.starts_with("one\ntwo\nthree\n"), "{delivered:?}");
    assert!(delivered.contains(&long_key), "{delivered:?}");
    assert!(!delivered.contains("key four"), "{delivered:?}");
    let egress = egress_text(&value);
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
/// leaves are kept whole, above it the first and last half, a leaf cut on a
/// char boundary, with a seam between head and tail (MIK-7887.RECEIPT.2: no
/// fingerprint joins them).
#[test]
fn an_over_cap_text_keeps_exact_head_and_tail_on_char_boundaries() {
    assert_eq!(RECORD_CAP, 6 * 1024, "the documented evasion bound");
    for len in [RECORD_CAP - 1, RECORD_CAP] {
        let text = "x".repeat(len);
        let (digest, cut) = DeliveryDigest::of_leaves(&[&text], false);
        assert!(!cut, "{len}");
        assert_eq!(
            digest.segment_texts(),
            vec![(text.as_str(), false)],
            "{len}"
        );
    }
    let half = RECORD_CAP / 2;
    let plain: String = (b'a'..=b'z')
        .cycle()
        .take(RECORD_CAP + 1)
        .map(char::from)
        .collect();
    let (digest, cut) = DeliveryDigest::of_leaves(&[&plain], false);
    assert!(cut);
    assert_eq!(
        digest.segment_texts(),
        vec![
            (&plain[..half], false),
            (&plain[plain.len() - half..], true)
        ]
    );

    // A 4-byte char straddles both cut points: the head ends before it, the
    // tail starts after it.
    let text = format!(
        "{}{}{}",
        "a".repeat(half - 1),
        "\u{1D11E}".repeat(RECORD_CAP),
        "z"
    );
    let (digest, cut) = DeliveryDigest::of_leaves(&[&text], false);
    assert!(cut);
    let segments = digest.segment_texts();
    let [(head, false), (tail, true)] = segments.as_slice() else {
        panic!("head, seam, tail: {}", segments.len());
    };
    assert_eq!(*head, "a".repeat(half - 1));
    assert!(tail.len() < half && tail.len() > half - 4, "{}", tail.len());
    assert!(text.ends_with(tail));
}

/// MIK-7887.RECEIPT.2: a capped digest's fingerprints come from its head and
/// its tail apart, so none spans the cut, where joined text would have one.
#[test]
fn a_capped_digest_has_no_fingerprint_across_its_cut() {
    use std::collections::HashSet;

    use super::super::collusion::{CollusionDetector, RelayParams};
    let detector = CollusionDetector::new(RelayParams::default());
    let text = (0..2000)
        .map(|i| format!("w{i:05}"))
        .collect::<Vec<_>>()
        .join(" ");
    let (digest, cut) = DeliveryDigest::of_leaves(&[&text], false);
    assert!(cut);
    let segments = digest.segment_texts();
    let [(head, false), (tail, true)] = segments.as_slice() else {
        panic!("head, seam, tail: {}", segments.len());
    };
    let apart: HashSet<u64> = detector
        .fingerprints(head)
        .into_iter()
        .chain(detector.fingerprints(tail))
        .collect();
    let joined = detector.fingerprints(&format!("{head}\n{tail}"));
    assert!(
        joined.iter().any(|fp| !apart.contains(fp)),
        "premise: joined, the cut carries fingerprints of its own"
    );
    assert!(
        digest
            .fingerprints(&detector)
            .iter()
            .all(|fp| apart.contains(fp))
    );
}

/// MIK-7934.PLANRCPT.3: two whole leaves the cap keeps, with the leaf between
/// them dropped, record no fingerprint whose k-gram spans the two.
#[test]
fn a_dropped_middle_leaf_leaves_no_fingerprint_across_it() {
    use std::collections::HashSet;

    use super::super::collusion::{CollusionDetector, RelayParams};
    let detector = CollusionDetector::new(RelayParams::default());
    // Each outer leaf fills its half exactly, so the middle one is dropped whole.
    let half = RECORD_CAP / 2;
    let words = |tag: &str| {
        let mut text = (0..half)
            .map(|i| format!("{tag}{i:05}"))
            .collect::<Vec<_>>()
            .join(" ");
        text.truncate(half - 1);
        text
    };
    let (a, b) = (words("a"), words("b"));
    let (digest, cut) = DeliveryDigest::of_leaves(&[&a, "the middle leaf", &b], false);
    assert!(cut);
    let segments = digest.segment_texts();
    assert_eq!(
        segments,
        [(a.as_str(), false), (b.as_str(), true)],
        "A whole, the middle dropped, B whole behind a seam"
    );
    let apart: HashSet<u64> = detector
        .fingerprints(&a)
        .into_iter()
        .chain(detector.fingerprints(&b))
        .collect();
    let joined = detector.fingerprints(&format!("{a}\n{b}"));
    assert!(
        joined.iter().any(|fp| !apart.contains(fp)),
        "premise: joined, A|B carries fingerprints of its own"
    );
    assert!(
        digest
            .fingerprints(&detector)
            .iter()
            .all(|fp| apart.contains(fp))
    );
}

/// MIK-7887.RECEIPT.2: retention keeps exactly the source fingerprints whose
/// k-gram a delivered leaf holds, including one the delivered leaf's own
/// winnowing did not select, and drops every other.
#[test]
fn retaining_keeps_a_delivered_kgram_whichever_window_selected_it() {
    use std::collections::HashSet;

    use super::super::collusion::{CollusionDetector, RelayParams};
    use super::Delivered;
    let detector = CollusionDetector::new(RelayParams::default());
    let words = |tag: &str| {
        (0..60)
            .map(|i| format!("{tag}{i:04}"))
            .collect::<Vec<_>>()
            .join(" ")
    };
    let mut premise = false;
    for round in 0..20 {
        let (kept_part, gone) = (words(&format!("k{round}x")), words(&format!("g{round}x")));
        let source = format!("{kept_part} {gone}");
        let (digest, _) = DeliveryDigest::of_leaves(&[&source], false);
        let delivered = Delivered::of_leaves(vec![kept_part.as_str()]).expect("under the bound");
        let kept: HashSet<u64> = digest
            .retaining(&detector, &delivered)
            .fingerprints(&detector)
            .into_iter()
            .collect();
        let kgrams: HashSet<u64> = detector.kgram_hashes(&kept_part).into_iter().collect();
        let minima: HashSet<u64> = detector.fingerprints(&kept_part).into_iter().collect();
        for fp in detector.fingerprints(&source) {
            assert_eq!(kept.contains(&fp), kgrams.contains(&fp), "round {round}");
            premise |= kgrams.contains(&fp) && !minima.contains(&fp);
        }
    }
    assert!(
        premise,
        "premise: some kept fingerprint was not a delivered window minimum"
    );
}

/// Empty leaves past the cap add no segments: each walk stops once its half
/// is spent, so a digest stays bounded whatever the leaf count.
#[test]
fn empty_leaves_past_the_cap_add_no_segments() {
    // Each edge leaf spends its walk's half to zero; empties follow.
    let edge = "x".repeat(RECORD_CAP / 2 - 1);
    let big = "y".repeat(RECORD_CAP);
    let mut leaves = vec![edge.as_str()];
    leaves.extend(std::iter::repeat_n("", 32_768));
    leaves.push(big.as_str());
    leaves.extend(std::iter::repeat_n("", 32_768));
    leaves.push(edge.as_str());
    let (digest, cut) = DeliveryDigest::of_leaves(&leaves, false);
    assert!(cut);
    assert_eq!(digest.segment_texts().len(), 2, "the two edge leaves only");
}

/// MIK-7887.RECEIPT.2: removing a middle leaf splits its run, and the
/// neighbours re-winnowed can select other minima. Every fingerprint of the
/// original run whose k-gram is still delivered, inside one leaf or across
/// adjacent kept short fields, is kept, and no other: none of the removed
/// text, none across a seam.
#[test]
fn a_split_run_keeps_exactly_its_original_delivered_fingerprints() {
    use std::collections::HashSet;

    use super::super::collusion::{CollusionDetector, RelayParams};
    use super::Delivered;
    let detector = CollusionDetector::new(RelayParams::default());
    let fields = |tag: &str| (0..12).map(|i| format!("{tag} f{i}")).collect::<Vec<_>>();
    let mut moved = false;
    for round in 0..20 {
        let (left, right) = (fields(&format!("l{round}")), fields(&format!("r{round}")));
        let gone = format!("removed paragraph {round} ").repeat(8);
        let mut leaves: Vec<&str> = left.iter().map(String::as_str).collect();
        leaves.push(&gone);
        leaves.extend(right.iter().map(String::as_str));
        let (digest, _) = DeliveryDigest::of_leaves(&leaves, false);
        let original = digest.fingerprints(&detector);
        let mut shown: Vec<&str> = left.iter().map(String::as_str).collect();
        shown.extend(right.iter().map(String::as_str));
        let delivered = Delivered::of_leaves(shown).expect("bounded");
        let kept: HashSet<u64> = digest
            .retaining(&detector, &delivered)
            .fingerprints(&detector)
            .into_iter()
            .collect();
        let allowed: HashSet<u64> = [left.join("\n"), right.join("\n")]
            .iter()
            .flat_map(|run| detector.kgram_hashes(run))
            .collect();
        let alone: HashSet<u64> = [left.join("\n"), right.join("\n")]
            .iter()
            .flat_map(|run| detector.fingerprints(run))
            .collect();
        for fp in &original {
            assert_eq!(kept.contains(fp), allowed.contains(fp), "round {round}");
            moved |= allowed.contains(fp) && !alone.contains(fp);
        }
        assert!(
            kept.iter().all(|fp| allowed.contains(fp)),
            "round {round}: kept text never delivered"
        );
    }
    assert!(moved, "premise: a split moved some minimum");
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
    let many = "        - {source: \"a:*\", egress: \"b:*\"}\n".repeat(65);
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
    for (action, label) in [
        (CollusionAction::Observe, "observe"),
        (CollusionAction::Block, "block"),
    ] {
        let (fw, _dir) = observing(|c| c.action = action);
        delivered(&fw, "alice");
        let series = format!("mcp_gateway_collusion_relay_total{{action=\"{label}\"}}");
        let before = rendered_count(&series);
        let _ = egress(&fw, RelayCaller::Keyed("bob"));
        assert!(rendered_count(&series) > before, "{label}: not counted");
    }
}

/// The value of one rendered metric series, 0 while it is absent.
#[cfg(feature = "metrics")]
fn rendered_count(series: &str) -> u64 {
    crate::metrics::install();
    let prefix = format!("{series} ");
    crate::metrics::render()
        .lines()
        .find_map(|l| l.strip_prefix(&prefix).and_then(|v| v.trim().parse().ok()))
        .unwrap_or(0)
}

/// An egress checked without an authenticated caller is counted, by action.
#[cfg(feature = "metrics")]
#[test]
fn a_keyless_egress_increments_the_unkeyed_metric() {
    let series = "mcp_gateway_collusion_unkeyed_egress_total{action=\"observe\"}";
    let (fw, _dir) = observing(|_| {});
    let before = rendered_count(series);
    let _ = egress(&fw, RelayCaller::Unkeyed("direct:alpha"));
    assert!(rendered_count(series) > before, "not counted");
}

/// MIK-7873.RELAY.1: an unkeyed egress refused under `block` is a reported
/// relay, counted under `block` like a matched one.
#[cfg(feature = "metrics")]
#[test]
fn an_unkeyed_block_increments_the_relay_metric() {
    let series = "mcp_gateway_collusion_relay_total{action=\"block\"}";
    let (fw, _dir) = observing(|c| c.action = CollusionAction::Block);
    let before = rendered_count(series);
    let verdict = egress(&fw, RelayCaller::Unkeyed("direct:alpha"));
    assert!(!verdict.allowed, "premise: an unkeyed egress is refused");
    assert!(
        rendered_count(series) > before,
        "unkeyed block: not counted"
    );
}

/// MIK-7934.PLANRCPT.2: a plan whose answer is over the bound its receipts
/// are kept against is counted where an operator can read it.
#[cfg(feature = "metrics")]
#[test]
fn a_dropped_plan_receipt_increments_the_metric() {
    let series = "mcp_gateway_collusion_plan_receipts_dropped_total";
    let (fw, _dir) = observing(|_| {});
    let before = rendered_count(series);
    let text = "x".repeat(super::super::collusion_digest::DELIVERED_SET_CAP + 1);
    let answer = json!({"content": [{"type": "text", "text": text}]});
    assert!(
        fw.delivered_for_plan(&answer).is_none(),
        "premise: over the bound"
    );
    assert!(rendered_count(series) > before, "dropped plan: not counted");
}

/// The observed-relay warnings `check` logs, as parsed records.
fn observed_relay_warnings(
    fw: &Firewall,
    caller: &str,
    text: &str,
) -> (Option<String>, Vec<serde_json::Value>) {
    let params = json!({"name": "send", "arguments": {"text": text}});
    let mut message = None;
    let records = crate::test_log_capture::records(|| {
        message = fw.relay_block_message(
            RelayCaller::Keyed(caller),
            ("alpha", "send"),
            &params,
            ("direct:alpha", caller),
        );
    });
    let warnings = records
        .into_iter()
        .filter(|r| r["fields"]["message"] == "Firewall: relay observed")
        .collect();
    (message, warnings)
}

/// Under `observe` a relay goes through and is logged once, as a WARN whose
/// fields are exactly `server` and `tool`: the names an operator's alert rule
/// matches, the same on every route.
#[test]
fn an_observed_relay_warns_with_server_and_tool_fields() {
    let (fw, _dir) = observing(|_| {});
    delivered(&fw, "alice");
    let (message, warnings) = observed_relay_warnings(&fw, "bob", PROSE);
    assert_eq!(message, None, "observe lets the call go");
    let [warning] = warnings.as_slice() else {
        panic!("one relay warning, got: {warnings:?}");
    };
    assert_eq!(warning["level"], "WARN");
    let fields = warning["fields"].as_object().expect("fields");
    assert_eq!(fields["server"], "alpha", "{warning}");
    assert_eq!(fields["tool"], "send", "{warning}");
    assert_eq!(fields.len(), 3, "message, server, tool only: {warning}");
}

/// No relay, no warning; under `block` the call is refused, not warned about.
#[test]
fn a_clean_call_and_a_blocked_relay_log_no_observed_warning() {
    let (observe, _dir) = observing(|_| {});
    delivered(&observe, "alice");
    let (message, warnings) = observed_relay_warnings(&observe, "bob", "an unrelated short note");
    assert_eq!((message, warnings.len()), (None, 0));

    let (block, _dir) = observing(|c| c.action = CollusionAction::Block);
    delivered(&block, "alice");
    let (message, warnings) = observed_relay_warnings(&block, "bob", PROSE);
    let message = message.expect("block refuses the relay");
    assert!(
        message.starts_with("Relay detection blocked: "),
        "{message}"
    );
    assert!(warnings.is_empty(), "{warnings:?}");
}

/// MIK-7992: a plan step is staged whole and capped later exactly as a
/// delivery is capped now: the same head, seam and tail, char boundaries
/// included, and capped once.
#[test]
fn a_plan_step_digest_is_capped_later_as_a_delivery_is_now() {
    let half = RECORD_CAP / 2;
    let text = format!(
        "{}{}{}",
        "a".repeat(half - 1),
        "\u{1D11E}".repeat(RECORD_CAP),
        "z"
    );
    let leaves = ["short leaf", text.as_str(), "last leaf"];
    let (staged, cut) = DeliveryDigest::of_plan_step_leaves(&leaves, false);
    assert!(!cut && staged.is_deferred(), "staged whole, cap deferred");
    assert_eq!(staged.segment_texts().len(), 3, "every leaf whole");
    let (capped, cut) = staged.capped().expect("the cap is deferred");
    assert!(cut && !capped.is_deferred());
    let (now, _) = DeliveryDigest::of_leaves(&leaves, false);
    assert_eq!(capped.segment_texts(), now.segment_texts());
    assert!(capped.capped().is_none(), "a capped digest is capped once");
    let empty = vec![""; 1 << 16];
    let (many, _) = DeliveryDigest::of_plan_step_leaves(&empty, false);
    assert!(!many.is_deferred(), "each leaf costs a segment: capped now");
    let over = super::super::collusion_digest::Delivered::of_leaves(empty);
    assert!(over.is_none(), "each delivered leaf costs a segment too");
}

/// MIK-7992: a plan step's digest recorded without being kept to its plan's
/// answer is capped where it is recorded: the cut is counted and the middle
/// of an over-cap text is not recorded, as for any other delivery.
#[test]
fn a_deferred_digest_is_capped_where_it_is_recorded() {
    let (fw, _dir) = observing(|_| {});
    let pad = |tag: &str| {
        (0..700)
            .map(|i| format!("{tag}{i:05}"))
            .collect::<Vec<_>>()
            .join(" ")
    };
    let step = json!({"a": pad("head"), "body": PROSE, "z": pad("tail")});
    let digest = fw
        .plan_step_digest("alpha", "read", &step)
        .expect("relay detection is on");
    assert_eq!(fw.relay_text_cuts(), 0, "premise: staged whole");
    fw.record_digest(RelayCaller::Keyed("carol"), "alpha", "read", &digest);

    assert_eq!(fw.relay_text_cuts(), 1, "the cap applied at the sink");
    assert!(
        egress(&fw, RelayCaller::Keyed("bob")).findings.is_empty(),
        "the dropped middle was recorded"
    );
}

/// MIK-7992: a plan step kept to its answer can retain more fingerprints
/// than its text would record; the deferred cap bounds them too.
#[test]
fn a_capped_plan_step_retains_at_most_the_cap_of_fingerprints() {
    use super::super::collusion::{CollusionDetector, RelayParams};
    use super::super::collusion_digest::Delivered;
    let detector = CollusionDetector::new(RelayParams::default());
    let text = (0..25_000)
        .map(|i| format!("w{i:06}"))
        .collect::<Vec<_>>()
        .join(" ");
    let answer = format!("{text} as delivered");
    let (staged, _) = DeliveryDigest::of_plan_step_leaves(&[&text], false);
    let delivered = Delivered::of_leaves(vec![answer.as_str()]).expect("under the bound");
    let kept = staged.retaining(&detector, &delivered);
    assert!(
        kept.retained_len() > RECORD_CAP,
        "premise: retention alone passes the cap"
    );
    let (capped, cut) = kept.capped().expect("the cap is deferred");
    assert!(cut, "the truncation counts as a cut");
    assert_eq!(capped.retained_len(), RECORD_CAP);
}

/// MIK-7992: repeats of a changed leaf retain the same fingerprints; once
/// each, so the count cap keeps a later leaf's.
#[test]
fn repeated_changed_leaves_do_not_crowd_out_a_later_leafs_fingerprints() {
    use super::super::collusion::{CollusionDetector, RelayParams};
    use super::super::collusion_digest::Delivered;
    let detector = CollusionDetector::new(RelayParams::default());
    let words = |tag: &str, n: usize| (0..n).map(|i| format!("{tag}{i:05}")).collect::<Vec<_>>();
    let (copy, last) = (words("rep", 25).join(" "), PROSE.to_owned());
    let mut leaves = vec![copy.as_str(); 400];
    leaves.push(last.as_str());
    let (copy_sent, last_sent) = (format!("{copy} sent"), format!("{last} sent"));
    let (staged, _) = DeliveryDigest::of_plan_step_leaves(&leaves, false);
    let delivered = Delivered::of_leaves(vec![copy_sent.as_str(), last_sent.as_str()])
        .expect("under the bound");
    let (capped, _) = staged
        .retaining(&detector, &delivered)
        .capped()
        .expect("deferred");
    let kept: std::collections::HashSet<u64> = capped.fingerprints(&detector).into_iter().collect();
    assert!(
        detector
            .fingerprints(&last)
            .iter()
            .all(|fp| kept.contains(fp))
    );
}

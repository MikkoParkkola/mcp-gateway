// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! COLLUDE.1 2a-i unit cases (test plan B1-B3).

use serde_json::json;

use super::{RECORD_CAP, capped, text_of};
use crate::config::Config;
use crate::security::firewall::{
    Finding, FindingLocation, FirewallAction, FirewallVerdict, ScanType, Severity,
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
    assert!(blocked(vec![relay()]).is_anomaly_block());
    assert!(blocked(vec![anomaly(Severity::High), relay()]).is_anomaly_block());
    assert!(
        !blocked(vec![
            relay(),
            finding(ScanType::Credentials, Severity::High)
        ])
        .is_anomaly_block()
    );
    assert!(!blocked(vec![anomaly(Severity::Medium)]).is_anomaly_block());
    assert!(!blocked(Vec::new()).is_anomaly_block());
    let mut allowed = blocked(vec![relay()]);
    allowed.allowed = true;
    assert!(!allowed.is_anomaly_block());
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
    let off = "    enabled: false\n    collusion:\n      action: off\n      min_matches: 0\n      \
               common_principals: 1\n      window_secs: 0\n      sources: [\"a:[\"]\n";
    load(off).expect("action off loads whatever the other fields hold");
    load("    collusion:\n      action: block\n").expect("the defaults are valid");
}

/// B3: responses skip the gateway's `_context_integrity`; arguments keep a
/// caller-supplied one.
#[test]
fn the_text_walker_skips_only_the_gateways_own_metadata_on_responses() {
    let value =
        json!({"content": [{"text": "one"}], "_context_integrity": {"note": "two"}, "n": 3});
    assert_eq!(text_of(&value, true), "one");
    let mut all: Vec<String> = text_of(&value, false)
        .split('\n')
        .map(String::from)
        .collect();
    all.sort();
    assert_eq!(all, ["one", "two"]);
}

/// B3: over the cap, the head and tail halves are kept, each cut on a char
/// boundary, and the cut is reported.
#[test]
fn an_over_cap_text_keeps_head_and_tail_on_char_boundaries() {
    let short = "x".repeat(RECORD_CAP);
    assert_eq!(capped(short.clone()), (short, false));

    // A 4-byte char straddles both cut points.
    let text = format!(
        "{}{}{}",
        "a".repeat(RECORD_CAP / 2 - 1),
        "𝄞".repeat(RECORD_CAP),
        "z"
    );
    let (kept, cut) = capped(text.clone());
    assert!(cut);
    assert!(kept.len() <= RECORD_CAP + 1, "{}", kept.len());
    assert!(kept.starts_with('a') && kept.ends_with('z'));
    assert!(text.ends_with(kept.rsplit('\n').next().unwrap()));
}

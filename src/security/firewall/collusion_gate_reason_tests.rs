// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! `MIK-8201`, `MIK-8206`: every relay refusal names why, and every capacity
//! bound is counted where an operator can read it (design §14.2, §14.3 B2).

use serde_json::json;

use super::{CollusionAction, CollusionConfig, RelayCaller};
use crate::security::firewall::{Firewall, FirewallConfig, ScanType};

/// Text every row relays: long enough for several k-grams.
const P: &str = "The quarterly reconciliation moves the vendor holdback into the escrow ledger \
    before the audit window opens, and the controller signs the variance memo by Friday.";

/// Observe mode, every `alpha:*` tool sensitive, every k-gram kept.
fn firewall() -> Firewall {
    let config = FirewallConfig {
        collusion: CollusionConfig {
            action: CollusionAction::Observe,
            sources: vec!["alpha:*".to_string()],
            ..CollusionConfig::default()
        },
        ..FirewallConfig::default()
    };
    Firewall::from_config(config, None).keeping_every_kgram()
}

fn deliver(fw: &Firewall, who: &str, tool: &str, text: &str) {
    let result = json!({"content": [{"type": "text", "text": text}]});
    fw.record_delivery(RelayCaller::Keyed(who), "alpha", tool, &result);
}

/// The relay finding `who` sending `text` raises, if any.
fn relay_description(fw: &Firewall, who: &str, text: &str) -> Option<String> {
    let params = json!({"name": "send", "arguments": {"text": text}});
    fw.check_relay(
        RelayCaller::Keyed(who),
        "beta",
        "send",
        &params,
        ("direct:beta", who),
    )
    .findings
    .into_iter()
    .find(|f| f.scan_type == ScanType::CollusionRelay)
    .map(|f| f.description)
}

/// `MIK-8206`: a caller holding the text from another tool of the same
/// server is refused under the per-source rule, and the refusal says so.
#[test]
fn an_other_tool_copy_is_named_in_the_refusal() {
    let fw = firewall();
    deliver(&fw, "carol", "docs", P);
    deliver(&fw, "alice", "notes", P);
    let description = relay_description(&fw, "alice", P).expect("premise: still a relay");
    assert!(
        description.contains("recorded as reaching you from a different tool"),
        "not named: {description}"
    );
}

/// `MIK-8201.VIS.2`: a refusal whose only evidence is an overflow record
/// (carol's sixty-fifth source for P could not be stored) names capacity.
/// Bob holds P from carol's first 64 sources, so only the overflow refuses.
#[test]
fn an_overflow_refusal_names_capacity() {
    let fw = firewall();
    for i in 0..65 {
        deliver(&fw, "carol", &format!("read{i}"), P);
    }
    for i in 0..64 {
        deliver(&fw, "bob", &format!("read{i}"), P);
    }
    let description = relay_description(&fw, "bob", P).expect("premise: overflow refuses");
    assert!(
        description.contains("past the relay detector's capacity"),
        "not named: {description}"
    );
}

/// A finding with one plainly unheld match is a relay whatever else it
/// holds: dave holds nothing, so his refusal reads as ordinary detection.
#[test]
fn plain_detection_keeps_the_relay_description() {
    let fw = firewall();
    deliver(&fw, "carol", "docs", P);
    let description = relay_description(&fw, "dave", P).expect("a relay");
    assert!(
        description.contains("content delivered to another caller"),
        "relabelled: {description}"
    );
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

/// `MIK-8201.VIS.1`: a refusal is counted under its reason.
#[cfg(feature = "metrics")]
#[test]
fn a_refusal_is_counted_under_its_reason() {
    let series = "mcp_gateway_collusion_relay_total{action=\"observe\",reason=\"other_source\"}";
    let fw = firewall();
    deliver(&fw, "carol", "docs", P);
    deliver(&fw, "alice", "notes", P);
    let before = rendered_count(series);
    assert!(relay_description(&fw, "alice", P).is_some());
    assert!(
        rendered_count(series) > before,
        "not counted under its reason"
    );
}

/// `MIK-8201.VIS.1`: an overflowed record is counted as a capacity bound.
#[cfg(feature = "metrics")]
#[test]
fn an_overflowed_record_is_counted() {
    let series = "mcp_gateway_collusion_capacity_total{bound=\"record_overflow\"}";
    let fw = firewall();
    let before = rendered_count(series);
    for i in 0..65 {
        deliver(&fw, "erin", &format!("read{i}"), P);
    }
    assert!(
        rendered_count(series) > before,
        "the overflow was not counted"
    );
}

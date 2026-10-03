// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-7116.MIN.4: the cross-tenant read verdict's false-positive measurement
//! over a labelled fixture corpus (design §5).
//!
//! Each corpus line is one outbound frame, run through the writer's own judge
//! (`outbound::delivered` / `outbound::admit`) on a history whose clock the
//! test advances to the line's `t_secs`, and committed as a sink would.
//! Labels come from the generating pattern
//! (`tests/fixtures/gen_tenant_reads_corpus.py`), never from the guard. The
//! unit is the principal-session: a session is flagged when any of its frames
//! is.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::time::Duration;

use serde_json::Value;

use crate::gateway::outbound::{Admission, Payload, admit, attribute, delivered};
use crate::protocol::{JsonRpcNotification, JsonRpcResponse};
use crate::security::firewall::tenant_guard::{CrossTenantReads, TenantGuardConfig};
use crate::security::firewall::{Firewall, FirewallConfig};
use crate::security::tenant_reads::{ReadHistory, ReadVerdict};

const CORPUS: &str = include_str!("../../tests/fixtures/tenant-reads-corpus.jsonl");

/// Patterns a single tenant reader produces: gate 1, zero flags.
const LEGITIMATE: &[&str] = &[
    "single_tenant",
    "retry_same_tenant",
    "mixed_workload",
    "opaque_only",
    "support_handoff_slow",
    "window_boundary",
];
/// Legitimate, flagged by construction: excluded from gate 1, counted in the
/// pinned false-positive number.
const KNOWN_FALSE_POSITIVE: &[&str] = &[
    "opaque_only_multi",
    "support_handoff_fast",
    "admin_sweep",
    "large_single_tenant",
];

fn firewall(window_secs: u64, reads: &Arc<ReadHistory>) -> Firewall {
    Firewall::from_config(
        FirewallConfig {
            tenant_guard: TenantGuardConfig {
                enabled: false,
                window_secs,
                arg_keys: vec!["customer_id".to_string()],
                cross_tenant_reads: CrossTenantReads::Observe,
                ..TenantGuardConfig::default()
            },
            ..FirewallConfig::default()
        },
        None,
    )
    .with_reads(Arc::clone(reads))
}

/// Judge and commit one corpus frame; whether it was flagged.
fn flagged(fw: &Firewall, key: &str, row: &Value) -> bool {
    let frame = row["frame"].clone();
    let verdict = match row["kind"].as_str().expect("kind") {
        "response" => {
            let response: JsonRpcResponse = serde_json::from_value(frame).expect("response");
            let request = row.get("request");
            let judged = delivered(fw, Some(key), Payload::Response(response), request, None);
            judged.commit_for_test();
            judged.verdict()
        }
        kind => {
            let hidden = row.get("raw").map(|raw| attribute(fw, raw));
            let payload = match kind {
                "notification" => Payload::Notification(
                    serde_json::from_value::<JsonRpcNotification>(frame).expect("notification"),
                ),
                "request" => Payload::Request(frame),
                "event" => Payload::Event(frame),
                "callback" => Payload::Callback(frame),
                other => panic!("unknown kind {other}"),
            };
            match admit(fw, Some(key), payload, hidden.as_ref()) {
                Admission::Admitted(judged) => {
                    judged.commit_for_test();
                    judged.verdict()
                }
                Admission::Blocked(evidence) => Some(evidence.verdict),
            }
        }
    };
    matches!(verdict, Some(ReadVerdict::Flagged | ReadVerdict::Blocked))
}

/// The corpus's units: frames grouped by principal-session, in file order.
fn units(rows: &[Value]) -> BTreeMap<String, Vec<&Value>> {
    let mut by_unit: BTreeMap<String, Vec<&Value>> = BTreeMap::new();
    for row in rows {
        let unit = row
            .get("principal_session")
            .or_else(|| row.get("session"))
            .and_then(Value::as_str)
            .expect("session");
        by_unit.entry(unit.to_owned()).or_default().push(row);
    }
    by_unit
}

#[test]
fn tenant_read_corpus_fp_measurement() {
    let mut lines = CORPUS.lines();
    let header: Value = serde_json::from_str(lines.next().expect("header")).expect("header JSON");
    let window = header["window_secs"].as_u64().expect("window");
    let declared: BTreeMap<String, usize> =
        serde_json::from_value(header["sessions"].clone()).expect("session counts");
    let rows: Vec<Value> = lines
        .map(|l| serde_json::from_str(l).expect("row"))
        .collect();

    let reads = ReadHistory::shared();
    let fw = firewall(window, &reads);
    let mut seen: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    let mut hit: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for (unit, frames) in units(&rows) {
        let mut at = 0;
        for row in frames {
            let t = row["t_secs"].as_u64().expect("t_secs");
            reads.advance_for_test(Duration::from_secs(t - at));
            at = t;
            let pattern = row["pattern"].as_str().expect("pattern").to_owned();
            seen.entry(pattern.clone())
                .or_default()
                .insert(unit.clone());
            if flagged(&fw, row["caller_key"].as_str().expect("key"), row) {
                hit.entry(pattern).or_default().insert(unit.clone());
            }
        }
        // Units are independent: let this one's history expire.
        reads.advance_for_test(Duration::from_secs(window + 1));
    }

    let count = |p: &str| seen.get(p).map_or(0, BTreeSet::len);
    let flags = |p: &str| hit.get(p).map_or(0, BTreeSet::len);
    for (pattern, n) in &declared {
        assert_eq!(count(pattern), *n, "{pattern}: the header's session count");
    }
    // Gate 1: zero flags on the legitimate patterns.
    for pattern in LEGITIMATE {
        assert_eq!(
            flags(pattern),
            0,
            "{pattern}: a legitimate session was flagged"
        );
    }
    // Gate 2: every cross-tenant session is flagged.
    let cross: Vec<&str> = declared
        .keys()
        .map(String::as_str)
        .filter(|p| !LEGITIMATE.contains(p) && !KNOWN_FALSE_POSITIVE.contains(p))
        .collect();
    for pattern in &cross {
        assert_eq!(
            flags(pattern),
            count(pattern),
            "{pattern}: a cross-tenant session passed"
        );
    }
    // Gate 3: pinned counts and the false-positive rate, in the shape of
    // tests/provenance_eval_binary.rs.
    let legit: usize = LEGITIMATE
        .iter()
        .chain(KNOWN_FALSE_POSITIVE)
        .map(|p| count(p))
        .sum();
    let false_positives: usize = KNOWN_FALSE_POSITIVE.iter().map(|p| flags(p)).sum();
    let true_positives: usize = cross.iter().map(|p| flags(p)).sum();
    let cross_sessions: usize = cross.iter().map(|p| count(p)).sum();
    eprintln!(
        "corpus: legitimate sessions {legit}, false positives {false_positives}, \
         cross-tenant sessions {cross_sessions}, flagged {true_positives}"
    );
    assert_eq!(
        (legit, false_positives, cross_sessions, true_positives),
        (PINNED_LEGIT, PINNED_FP, PINNED_CROSS, PINNED_CROSS),
        "pinned corpus counts"
    );
}

/// Pinned from the corpus generator's session counts.
const PINNED_LEGIT: usize = 71;
const PINNED_FP: usize = 16;
const PINNED_CROSS: usize = 55;

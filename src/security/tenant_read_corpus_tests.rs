// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-7116.MIN.4: the cross-tenant read verdict's false-positive measurement
//! over a labelled fixture corpus (design §5).
//!
//! Each corpus line is one outbound frame, run through the writer's own judge
//! (`outbound::delivered` / `outbound::admit`, or for a webhook event the
//! session-stream judge, `SessionJudge`) on a history whose clock the test
//! advances to the line's `t_secs`, and committed as a sink would.
//! Labels come from the generating pattern
//! (`tests/fixtures/gen_tenant_reads_corpus.py`), never from the guard. The
//! unit is the principal-session: a session is flagged when any of its frames
//! is.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::time::Duration;

use serde_json::Value;

use crate::gateway::outbound::{
    Admission, Payload, RejectionAudit, SessionJudge, admit, attribute, delivered,
};
use crate::gateway::streaming::TaggedNotification;
use crate::protocol::{JsonRpcNotification, JsonRpcResponse};
use crate::security::TransparencyLogger;
use crate::security::audit::AuditFailurePolicy;
use crate::security::firewall::tenant_guard::{CrossTenantReads, TenantGuardConfig};
use crate::security::firewall::{Firewall, FirewallConfig};
use crate::security::tenant_reads::{ReadHistory, ReadVerdict};
use crate::security::transparency_log::TransparencyLogConfig;

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

/// The production session-stream judge over `fw`, recording to `log`: the
/// stream records a written item's verdict there, so the test reads it back.
struct Stream {
    judge: SessionJudge,
    log: std::path::PathBuf,
}

impl Stream {
    fn new(fw: &Arc<Firewall>, dir: &std::path::Path) -> Self {
        let log = dir.join("audit.jsonl");
        let logger = TransparencyLogger::open(Arc::new(TransparencyLogConfig {
            enabled: true,
            path: log.display().to_string(),
            key_id: "corpus".to_string(),
            ..TransparencyLogConfig::default()
        }))
        .expect("log")
        // A failed record then fails `written`, not the verdict read back.
        .with_failure_policy(AuditFailurePolicy::FailClosed);
        let judge = SessionJudge::new(
            Some(Arc::clone(fw)),
            Arc::new(RejectionAudit::new(None, 1)),
            Some(Arc::new(logger)),
        )
        .expect("the guard judges");
        Self { judge, log }
    }

    fn records(&self) -> Vec<Value> {
        std::fs::read_to_string(&self.log)
            .unwrap_or_default()
            .lines()
            .map(|line| serde_json::from_str(line).expect("log line is JSON"))
            .collect()
    }

    /// A webhook event as `broadcast_to_backend_raw` delivers it: a
    /// non-message item judged for the session's caller with its raw body's
    /// attribution, then written (recorded and committed) by the stream.
    async fn flagged(&self, key: &str, row: &Value) -> bool {
        let note = TaggedNotification {
            source: "corpus".to_string(),
            event_type: "webhook.corpus.row".to_string(),
            data: row["frame"].clone(),
            event_id: None,
        };
        let hidden = row.get("raw").and_then(|raw| self.judge.raw(raw));
        // Observe mode delivers a flagged item; a withheld one is a fault.
        let mark = self
            .judge
            .judge(Some(key), &note, hidden.as_ref())
            .expect("observe mode withholds nothing");
        let Some(mark) = mark else {
            return false;
        };
        let before = self.records().len();
        assert!(
            mark.written(Some(&self.judge)).await,
            "the stream writes it"
        );
        self.records()[before..].iter().any(|r| {
            r["event"] == "tenant_read"
                && matches!(r["cross_tenant_read"].as_str(), Some("flagged" | "blocked"))
        })
    }
}

/// Judge and commit one corpus frame; whether it was flagged.
async fn flagged(fw: &Firewall, stream: &Stream, key: &str, row: &Value) -> bool {
    let frame = row["frame"].clone();
    let verdict = match row["kind"].as_str().expect("kind") {
        "event" => return stream.flagged(key, row).await,
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

#[tokio::test]
async fn tenant_read_corpus_fp_measurement() {
    let mut lines = CORPUS.lines();
    let header: Value = serde_json::from_str(lines.next().expect("header")).expect("header JSON");
    let window = header["window_secs"].as_u64().expect("window");
    let declared: BTreeMap<String, usize> =
        serde_json::from_value(header["sessions"].clone()).expect("session counts");
    let rows: Vec<Value> = lines
        .map(|l| serde_json::from_str(l).expect("row"))
        .collect();

    let reads = ReadHistory::shared();
    let fw = Arc::new(firewall(window, &reads));
    let dir = tempfile::tempdir().expect("tempdir");
    // One firewall, so the stream judge shares the frames' read history.
    let stream = Stream::new(&fw, dir.path());
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
            if flagged(&fw, &stream, row["caller_key"].as_str().expect("key"), row).await {
                hit.entry(pattern).or_default().insert(unit.clone());
            }
        }
        // Units are independent: let this one's history expire.
        reads.advance_for_test(Duration::from_secs(window + 1));
    }

    let count = |p: &str| seen.get(p).map_or(0, BTreeSet::len);
    let flags = |p: &str| hit.get(p).map_or(0, BTreeSet::len);
    // Every pattern the rows carry is declared, and every declared one
    // occurs: an undeclared pattern would skip every gate below.
    assert_eq!(
        seen.keys().collect::<Vec<_>>(),
        declared.keys().collect::<Vec<_>>(),
        "the rows' patterns are the header's"
    );
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
    let cross: Vec<&str> = seen
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

// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The identity audit record, read back from a real subscriber.
//!
//! The criterion's last clause is that "the audit record carries both so a
//! proved-A-claimed-B mismatch is detectable". The rows in the sibling file
//! stop at the `IdentityAudit` value `validate_agent_identity` returns; none
//! of them sees the record `log_agent_identity` writes. These rows capture that
//! record as JSON and assert on its level and fields, so dropping either
//! identity from it, or demoting the mismatch to `debug`, turns them red.

use std::sync::{Arc, Mutex};

use super::tests::{cfg, proven};
use super::*;

/// The target every audit record carries: the parent module, not this one.
const AUDIT_TARGET: &str = "mcp_gateway::security::agent_identity";

const PROVEN_A: &str = "spiffe://cluster/ns/agents/sa/runner";
const DECLARED_B: &str = "runner";

#[derive(Clone, Default)]
struct Sink(Arc<Mutex<Vec<u8>>>);

impl std::io::Write for Sink {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// The audit records `run` emits, one parsed JSON object per event.
///
/// The subscriber is thread-local and `run` is synchronous, so a parallel
/// test cannot write into this capture. The process-wide TRACE registry is the
/// idiom from the Open `WebUI` adapter tests: it keeps every callsite's cached
/// interest and the global max level open, so a record is never filtered out
/// before the scoped subscriber sees it.
fn audit_records(run: impl FnOnce()) -> Vec<serde_json::Value> {
    use tracing_subscriber::prelude::*;
    static INTEREST: std::sync::Once = std::sync::Once::new();
    INTEREST.call_once(|| {
        let _ = tracing::subscriber::set_global_default(
            tracing_subscriber::Registry::default()
                .with(tracing::level_filters::LevelFilter::TRACE),
        );
    });
    let sink = Sink::default();
    let writer = sink.clone();
    let subscriber = tracing_subscriber::fmt()
        .json()
        .without_time()
        .with_ansi(false)
        .with_max_level(tracing::Level::TRACE)
        .with_writer(move || writer.clone())
        .finish();
    tracing::subscriber::with_default(subscriber, run);
    let bytes = sink.0.lock().unwrap().clone();
    String::from_utf8(bytes)
        .expect("utf-8 log output")
        .lines()
        .map(|line| {
            serde_json::from_str::<serde_json::Value>(line).expect("one JSON object per line")
        })
        .filter(|record| record["target"] == AUDIT_TARGET)
        .collect()
}

/// The single audit record `log_agent_identity` wrote for one request.
fn the_record(
    identity: &AgentIdentity,
    audit: IdentityAudit,
    refusal: Option<&str>,
) -> serde_json::Value {
    let mut records = audit_records(|| log_agent_identity(identity, audit, refusal));
    assert_eq!(
        records.len(),
        1,
        "expected exactly one identity audit record, got {records:#?}"
    );
    records.remove(0)
}

fn proved_a_declared(label: &str, proof: ProofSource, proven_id: &str) -> AgentIdentity {
    let mut identity = proven(proven_id, proof);
    identity.declared = Some(DeclaredLabel {
        id: label.to_string(),
        source: DeclaredSource::Header,
    });
    identity
}

/// Anchor: the criterion's "audit record carries both". A waived mTLS
/// mismatch is accepted, so this record is the only trace the mismatch
/// leaves; it must name the proven principal AND the declared label, at a
/// level an operator alerts on.
#[test]
fn a_waived_mismatch_audit_record_carries_both_identities_at_warn() {
    let mut config = cfg(true, true, &[]);
    config.incomparable_proof_sources = vec![ProofSource::MutualTls];
    let identity = proved_a_declared(DECLARED_B, ProofSource::MutualTls, PROVEN_A);
    let audit = validate_agent_identity(&identity, &config).expect("a waived mismatch was refused");
    assert_eq!(audit, IdentityAudit::DeclaredLabelMismatch);

    let record = the_record(&identity, audit, None);

    assert_eq!(record["level"], "WARN", "{record:#}");
    let fields = &record["fields"];
    assert_eq!(
        fields["agent_proven"], PROVEN_A,
        "proven id missing: {record:#}"
    );
    assert_eq!(fields["agent_proof"], "mtls", "{record:#}");
    assert_eq!(
        fields["agent_declared"], DECLARED_B,
        "declared id missing: {record:#}"
    );
    assert_eq!(fields["agent_declared_source"], "header", "{record:#}");
    assert_eq!(fields["declared_label_mismatch"], true, "{record:#}");
}

/// Anchor: the refusal half. An unwaived contradiction is refused, and both
/// dispatch routes pass the refusal string into the audit record
/// (`handlers.rs`, `backend_handlers.rs`), so the string and the record must
/// each name both identities.
#[test]
fn a_contradiction_refusal_names_both_ids_and_is_audited_at_warn() {
    let identity = proved_a_declared(DECLARED_B, ProofSource::MutualTls, PROVEN_A);
    let reason = validate_agent_identity(&identity, &cfg(true, true, &[]))
        .expect_err("an unwaived mismatch was accepted");
    assert!(
        reason.contains("contradicts the proven principal"),
        "not the contradiction refusal: {reason}"
    );
    assert!(
        reason.contains(&format!("'{PROVEN_A}'")),
        "proven id missing: {reason}"
    );
    assert!(
        reason.contains(&format!("'{DECLARED_B}'")),
        "declared id missing: {reason}"
    );

    // What both call sites pass on the refusal arm.
    let record = the_record(&identity, IdentityAudit::Clean, Some(&reason));

    assert_eq!(record["level"], "WARN", "{record:#}");
    let fields = &record["fields"];
    assert_eq!(
        fields["agent_proven"], PROVEN_A,
        "proven id missing: {record:#}"
    );
    assert_eq!(
        fields["agent_declared"], DECLARED_B,
        "declared id missing: {record:#}"
    );
    assert_eq!(fields["agent_proof"], "mtls", "{record:#}");
    assert_eq!(fields["agent_declared_source"], "header", "{record:#}");
    assert_eq!(fields["refused"], true, "{record:#}");
    assert_eq!(fields["reason"], reason.as_str(), "{record:#}");
}

/// Control for the level assertions above: a principal declaring its own name
/// is recorded at DEBUG and not as a mismatch. Without it, a capture that
/// labelled every record WARN would pass both rows.
#[test]
fn a_matching_identity_is_recorded_at_debug_not_as_a_mismatch() {
    let identity = proved_a_declared("svc-a", ProofSource::VerifiedJwtSubject, "svc-a");
    let audit = validate_agent_identity(&identity, &cfg(true, true, &[]))
        .expect("a principal declaring its own name was refused");
    assert_eq!(audit, IdentityAudit::Clean);

    let record = the_record(&identity, audit, None);

    assert_eq!(record["level"], "DEBUG", "{record:#}");
    assert_eq!(
        record["fields"]["declared_label_mismatch"], false,
        "{record:#}"
    );
    assert_eq!(record["fields"]["agent_proven"], "svc-a", "{record:#}");
    assert_eq!(record["fields"]["agent_declared"], "svc-a", "{record:#}");
}

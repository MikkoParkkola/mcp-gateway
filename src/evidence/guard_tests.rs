//! Tests for the render guard: non-bypassability (structural), drop/downgrade
//! behavior, and mandatory self-citation.

use super::*;

fn hit(id: &str) -> EvidenceState {
    EvidenceState::CheckedHit { source: SourceId::new(id), detail: None }
}
fn no_hit(id: &str) -> EvidenceState {
    EvidenceState::CheckedNoHit { source: SourceId::new(id), detail: None }
}
fn failed(id: &str) -> EvidenceState {
    EvidenceState::Failed { source: SourceId::new(id), detail: None }
}
fn skipped(id: &str) -> EvidenceState {
    EvidenceState::SkippedNotApplicable { source: SourceId::new(id), detail: None }
}

#[test]
fn backed_claim_is_emitted_with_verdict_and_citations() {
    let claims = vec![RawClaim::new("X is listed", vec![hit("registry")])];
    let out = render_guard(claims);
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].text(), "X is listed");
    assert_eq!(out[0].verdict(), Verdict::Clean);
    assert_eq!(out[0].citations(), &[SourceId::new("registry")]);
}

#[test]
fn unbacked_claim_is_dropped() {
    // GIVEN a claim with no evidence at all.
    // THEN the guard drops it entirely (no EmittableClaim is produced).
    let out = render_guard(vec![RawClaim::new("trust me", vec![])]);
    assert!(out.is_empty());
}

#[test]
fn only_not_applicable_backing_is_dropped() {
    // GIVEN a claim whose only backing is a not-applicable state.
    // THEN it has no relevant citations and is dropped.
    let out = render_guard(vec![RawClaim::new("n/a claim", vec![skipped("s")])]);
    assert!(out.is_empty());
}

#[test]
fn adverse_claim_is_emitted_not_dropped() {
    // An authoritative negative is a finding, not an absence — it is emitted
    // (tagged Adverse), not suppressed.
    let out = render_guard(vec![RawClaim::new("X not on list", vec![no_hit("registry")])]);
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].verdict(), Verdict::Adverse);
}

#[test]
fn disclaimer_claim_is_emitted_with_tag_not_dropped() {
    // A could-not-check claim is downgraded via its verdict tag (Disclaimer),
    // NOT dropped — so the experiment can observe abstention.
    let out = render_guard(vec![RawClaim::new("X status unknown", vec![failed("registry")])]);
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].verdict(), Verdict::Disclaimer);
    // Still self-citing: the could-not-check source is named.
    assert_eq!(out[0].citations(), &[SourceId::new("registry")]);
}

#[test]
fn every_emitted_claim_carries_nonempty_citations() {
    let claims = vec![
        RawClaim::new("a", vec![hit("s1")]),
        RawClaim::new("b", vec![no_hit("s2"), failed("s3")]),
        RawClaim::new("c", vec![failed("s4")]),
    ];
    let out = render_guard(claims);
    assert_eq!(out.len(), 3);
    for claim in &out {
        assert!(
            !claim.citations().is_empty(),
            "emitted claim {:?} must cite at least one source",
            claim.text()
        );
    }
}

#[test]
fn not_applicable_states_are_excluded_from_citations() {
    // GIVEN a claim backed by a real hit plus a not-applicable state.
    // THEN only the relevant source appears in citations.
    let out = render_guard(vec![RawClaim::new("x", vec![hit("real"), skipped("noise")])]);
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].citations(), &[SourceId::new("real")]);
    assert_eq!(out[0].verdict(), Verdict::Clean);
}

#[test]
fn guard_preserves_order_and_count_of_surviving_claims() {
    let claims = vec![
        RawClaim::new("first", vec![hit("s1")]),
        RawClaim::new("dropped", vec![]),
        RawClaim::new("second", vec![no_hit("s2")]),
    ];
    let out = render_guard(claims);
    assert_eq!(out.len(), 2);
    assert_eq!(out[0].text(), "first");
    assert_eq!(out[1].text(), "second");
}

// --- Non-bypassability (structural invariant) -------------------------------
//
// The strongest guarantee is enforced by the type system at COMPILE time:
// `EmittableClaim` has only private fields and no public constructor, so the
// following are impossible to write outside this module and would not compile:
//
//     EmittableClaim { text: ..., verdict: ..., citations: ... } // E0451 private fields
//     EmittableClaim::new(...)                                   // no such fn
//
// We do not use a compile-fail harness (trybuild) for a spike; instead we assert
// the runtime contract that proves the only path is the guard.

#[test]
fn emittable_claim_only_obtainable_via_guard() {
    // The ONLY way to get an EmittableClaim is render_guard. This test documents
    // and exercises that path; the absence of any other constructor is enforced
    // by the private fields (see module-level note above).
    let out = render_guard(vec![RawClaim::new("only path", vec![hit("s")])]);
    let claim: &EmittableClaim = &out[0];
    // Read-only accessors exist; no mutator or constructor is exposed.
    assert_eq!(claim.text(), "only path");
}

//! Tests for the state→verdict mapping, with emphasis on the load-bearing
//! [`Verdict::Adverse`]-vs-[`Verdict::Disclaimer`] distinction.

use super::*;
use crate::evidence::state::SourceId;

fn src(id: &str) -> SourceId {
    SourceId::new(id)
}

fn hit(id: &str) -> EvidenceState {
    EvidenceState::CheckedHit { source: src(id), detail: None }
}
fn no_hit(id: &str) -> EvidenceState {
    EvidenceState::CheckedNoHit { source: src(id), detail: None }
}
fn failed(id: &str) -> EvidenceState {
    EvidenceState::Failed { source: src(id), detail: None }
}
fn timeout(id: &str) -> EvidenceState {
    EvidenceState::Timeout { source: src(id), detail: None }
}
fn not_configured(id: &str) -> EvidenceState {
    EvidenceState::NotConfigured { source: src(id), detail: None }
}
fn not_authorized(id: &str) -> EvidenceState {
    EvidenceState::NotAuthorized { source: src(id), detail: None }
}
fn stale(id: &str) -> EvidenceState {
    EvidenceState::Stale { source: src(id), detail: None }
}
fn skipped(id: &str) -> EvidenceState {
    EvidenceState::SkippedNotApplicable { source: src(id), detail: None }
}

// --- Clean -----------------------------------------------------------------

#[test]
fn single_checked_hit_maps_to_clean() {
    // GIVEN one authoritative positive and nothing else.
    // WHEN classified.
    // THEN the verdict is Clean.
    assert_eq!(classify(&[hit("registry")]), Verdict::Clean);
}

#[test]
fn multiple_checked_hits_map_to_clean() {
    assert_eq!(classify(&[hit("a"), hit("b"), hit("c")]), Verdict::Clean);
}

// --- Adverse vs Disclaimer: the load-bearing distinction --------------------

#[test]
fn checked_no_hit_is_adverse_not_disclaimer() {
    // GIVEN a source queried that authoritatively returned no match.
    // WHEN classified.
    // THEN the verdict is Adverse (a trustworthy negative), NOT Disclaimer.
    let v = classify(&[no_hit("directory")]);
    assert_eq!(v, Verdict::Adverse);
    assert_ne!(v, Verdict::Disclaimer);
}

#[test]
fn multiple_checked_no_hits_are_adverse() {
    let v = classify(&[no_hit("a"), no_hit("b")]);
    assert_eq!(v, Verdict::Adverse);
    assert_ne!(v, Verdict::Disclaimer);
}

#[test]
fn failed_only_is_disclaimer_not_adverse() {
    // GIVEN the only outcome is a failure to check.
    // WHEN classified.
    // THEN the verdict is Disclaimer (we could not check), NOT Adverse.
    let v = classify(&[failed("directory")]);
    assert_eq!(v, Verdict::Disclaimer);
    assert_ne!(v, Verdict::Adverse);
}

#[test]
fn each_could_not_check_variant_alone_is_disclaimer() {
    for state in [failed("s"), timeout("s"), not_configured("s"), not_authorized("s")] {
        assert_eq!(
            classify(&[state.clone()]),
            Verdict::Disclaimer,
            "could-not-check state {state:?} must map to Disclaimer",
        );
    }
}

#[test]
fn any_mix_of_could_not_check_is_disclaimer() {
    // GIVEN only could-not-check states (no conclusive evidence).
    let v = classify(&[failed("a"), timeout("b"), not_configured("c"), not_authorized("d")]);
    assert_eq!(v, Verdict::Disclaimer);
    assert_ne!(v, Verdict::Adverse);
}

#[test]
fn disclaimer_and_adverse_never_collapse_across_inputs() {
    // The defining property: a pure could-not-check input and a pure
    // authoritative-negative input must yield DIFFERENT verdicts.
    let could_not_check = classify(&[failed("s"), timeout("s")]);
    let authoritative_negative = classify(&[no_hit("s")]);
    assert_ne!(could_not_check, authoritative_negative);
    assert_eq!(could_not_check, Verdict::Disclaimer);
    assert_eq!(authoritative_negative, Verdict::Adverse);
}

// --- Qualified --------------------------------------------------------------

#[test]
fn hit_plus_could_not_check_is_qualified() {
    // GIVEN sufficient (a hit) mixed with insufficient (a failure).
    // THEN the verdict is Qualified.
    assert_eq!(classify(&[hit("a"), failed("b")]), Verdict::Qualified);
}

#[test]
fn hit_plus_no_hit_contradiction_is_qualified() {
    // GIVEN one source says hit and another says no-hit (contradiction).
    // THEN the verdict is Qualified — NOT Clean (there IS contradicting
    // evidence) and NOT Adverse (there is a positive).
    let v = classify(&[hit("a"), no_hit("b")]);
    assert_eq!(v, Verdict::Qualified);
    assert_ne!(v, Verdict::Clean);
    assert_ne!(v, Verdict::Adverse);
}

#[test]
fn stale_degrades_clean_to_qualified() {
    // GIVEN a conclusive positive degraded by a stale state.
    // THEN the otherwise-Clean verdict becomes Qualified.
    assert_eq!(classify(&[hit("a"), stale("b")]), Verdict::Qualified);
}

// --- SkippedNotApplicable: neutral (advisor-flagged blind spot) -------------

#[test]
fn skipped_not_applicable_alone_is_disclaimer() {
    // GIVEN only a not-applicable state (no relevant evidence).
    // THEN the verdict is Disclaimer.
    assert_eq!(classify(&[skipped("s")]), Verdict::Disclaimer);
}

#[test]
fn skipped_not_applicable_does_not_degrade_clean() {
    // GIVEN a conclusive positive plus a not-applicable state.
    // THEN the not-applicable state is filtered out and the verdict stays Clean.
    // (If it were wrongly bucketed with could-not-check this would be Qualified.)
    assert_eq!(classify(&[hit("a"), skipped("b")]), Verdict::Clean);
}

#[test]
fn skipped_not_applicable_does_not_turn_adverse_into_disclaimer() {
    // GIVEN an authoritative negative plus a not-applicable state.
    // THEN the verdict remains Adverse.
    assert_eq!(classify(&[no_hit("a"), skipped("b")]), Verdict::Adverse);
}

// --- Empty / edge ----------------------------------------------------------

#[test]
fn empty_evidence_is_disclaimer() {
    assert_eq!(classify(&[]), Verdict::Disclaimer);
}

#[test]
fn stale_only_is_disclaimer() {
    // GIVEN only stale data with nothing conclusive to modify.
    // THEN the verdict is Disclaimer.
    assert_eq!(classify(&[stale("a"), stale("b")]), Verdict::Disclaimer);
}

#[test]
fn classify_is_order_independent() {
    let a = classify(&[hit("x"), failed("y"), stale("z")]);
    let b = classify(&[stale("z"), hit("x"), failed("y")]);
    let c = classify(&[failed("y"), stale("z"), hit("x")]);
    assert_eq!(a, b);
    assert_eq!(b, c);
}

#[test]
fn verdict_ordering_reflects_support_level() {
    // Clean is the most-supported, Disclaimer the least.
    assert!(Verdict::Clean < Verdict::Qualified);
    assert!(Verdict::Qualified < Verdict::Adverse);
    assert!(Verdict::Adverse < Verdict::Disclaimer);
}

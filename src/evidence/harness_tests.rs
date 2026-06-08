//! Tests for the experiment harness: ground-truth/verdict alignment, the
//! no-partial-credit scorer, and the three strategies over synthetic cases.

use super::*;
use crate::evidence::state::EvidenceState;

fn sid(id: &str) -> SourceId {
    SourceId::new(id)
}
fn hit(id: &str) -> EvidenceState {
    EvidenceState::CheckedHit { source: sid(id), detail: None }
}
fn no_hit(id: &str) -> EvidenceState {
    EvidenceState::CheckedNoHit { source: sid(id), detail: None }
}
fn failed(id: &str) -> EvidenceState {
    EvidenceState::Failed { source: sid(id), detail: None }
}
fn stale(id: &str) -> EvidenceState {
    EvidenceState::Stale { source: sid(id), detail: None }
}

/// The canonical four discriminating cases.
fn discriminating_cases() -> Vec<GroundTruthCase> {
    vec![
        GroundTruthCase::new(
            "should-abstain",
            RawClaim::new("status of X unknown", vec![failed("primary"), failed("secondary")]),
            GroundTruth::ShouldAbstain,
        ),
        GroundTruthCase::new(
            "source-authoritatively-empty",
            RawClaim::new("X not on list", vec![no_hit("list")]),
            GroundTruth::SourceAuthoritativelyEmpty,
        ),
        GroundTruthCase::new(
            "source-unavailable-failed",
            RawClaim::new("could not verify X", vec![failed("list")]),
            GroundTruth::SourceUnavailableFailed,
        ),
        GroundTruthCase::new(
            "source-stale",
            RawClaim::new("X was clear (stale)", vec![hit("list"), stale("list")]),
            GroundTruth::SourceStale,
        ),
    ]
}

#[test]
fn ground_truth_maps_to_expected_verdicts() {
    assert_eq!(GroundTruth::ShouldAbstain.expected_verdict(), Verdict::Disclaimer);
    assert_eq!(GroundTruth::SourceUnavailableFailed.expected_verdict(), Verdict::Disclaimer);
    assert_eq!(
        GroundTruth::SourceAuthoritativelyEmpty.expected_verdict(),
        Verdict::Adverse
    );
    assert_eq!(GroundTruth::SourceStale.expected_verdict(), Verdict::Qualified);
}

// --- No-partial-credit scorer ----------------------------------------------

#[test]
fn scorer_gives_no_credit_for_wrong_verdict() {
    // Raw passthrough always emits Clean. Against a case whose truth is Adverse,
    // "Clean" is wrong and earns ZERO — no partial credit for emitting *a*
    // verdict.
    let case = GroundTruthCase::new(
        "empty",
        RawClaim::new("x", vec![no_hit("l")]),
        GroundTruth::SourceAuthoritativelyEmpty,
    );
    assert_eq!(score_strategy(&RawPassthrough, std::slice::from_ref(&case)), 0);
}

#[test]
fn scorer_gives_no_credit_for_suppression() {
    // A strategy that suppresses everything scores zero even on a should-abstain
    // case (the expected verdict is Disclaimer *emitted*, not silence).
    struct AlwaysSuppress;
    impl Strategy for AlwaysSuppress {
        fn name(&self) -> &'static str {
            "always-suppress"
        }
        fn decide(&self, _case: &GroundTruthCase) -> StrategyOutput {
            StrategyOutput::Suppressed
        }
    }
    let cases = discriminating_cases();
    assert_eq!(score_strategy(&AlwaysSuppress, &cases), 0);
}

#[test]
fn scorer_gives_no_partial_credit_for_close_verdict() {
    // Emitting Qualified when Adverse is required is WRONG, not half-right.
    struct AlwaysQualified;
    impl Strategy for AlwaysQualified {
        fn name(&self) -> &'static str {
            "always-qualified"
        }
        fn decide(&self, _case: &GroundTruthCase) -> StrategyOutput {
            StrategyOutput::Emitted(Verdict::Qualified)
        }
    }
    let case = GroundTruthCase::new(
        "empty",
        RawClaim::new("x", vec![no_hit("l")]),
        GroundTruth::SourceAuthoritativelyEmpty,
    );
    assert_eq!(score_strategy(&AlwaysQualified, std::slice::from_ref(&case)), 0);
}

// --- Strategy behavior over the discriminating set --------------------------

#[test]
fn render_guard_scores_perfectly_on_discriminating_cases() {
    // The render guard's verdict mapping is built to match the ground truth on
    // exactly these four cases.
    let cases = discriminating_cases();
    assert_eq!(score_strategy(&RenderGuardStrategy, &cases), cases.len());
}

#[test]
fn raw_passthrough_only_scores_when_truth_happens_to_be_clean() {
    // Baseline always says Clean — none of the four discriminating cases is
    // Clean, so it scores zero. This is the headline contrast the spike wants.
    let cases = discriminating_cases();
    assert_eq!(score_strategy(&RawPassthrough, &cases), 0);
}

#[test]
fn reliability_weighted_vote_distinguishes_adverse_from_disclaimer() {
    let weights = HashMap::from([(sid("list"), 1.0)]);
    let voter = ReliabilityWeightedVote::new(weights, 1.0);

    let empty = GroundTruthCase::new(
        "empty",
        RawClaim::new("x", vec![no_hit("list")]),
        GroundTruth::SourceAuthoritativelyEmpty,
    );
    let failed_case = GroundTruthCase::new(
        "failed",
        RawClaim::new("x", vec![failed("list")]),
        GroundTruth::SourceUnavailableFailed,
    );

    assert_eq!(voter.decide(&empty), StrategyOutput::Emitted(Verdict::Adverse));
    assert_eq!(voter.decide(&failed_case), StrategyOutput::Emitted(Verdict::Disclaimer));
}

#[test]
fn reliability_weighting_lets_trusted_source_win() {
    // A high-weight authoritative-negative source outvotes a low-weight
    // could-not-check source.
    let weights = HashMap::from([(sid("trusted"), 10.0), (sid("flaky"), 1.0)]);
    let voter = ReliabilityWeightedVote::new(weights, 1.0);
    let case = GroundTruthCase::new(
        "mixed",
        RawClaim::new("x", vec![no_hit("trusted"), failed("flaky")]),
        GroundTruth::SourceAuthoritativelyEmpty,
    );
    assert_eq!(voter.decide(&case), StrategyOutput::Emitted(Verdict::Adverse));
}

#[test]
fn reliability_vote_with_no_relevant_evidence_is_suppressed() {
    let voter = ReliabilityWeightedVote::new(HashMap::new(), 1.0);
    let case = GroundTruthCase::new(
        "none",
        RawClaim::new("x", vec![]),
        GroundTruth::ShouldAbstain,
    );
    assert_eq!(voter.decide(&case), StrategyOutput::Suppressed);
}

// --- Comparison table -------------------------------------------------------

#[test]
fn compare_strategies_produces_one_row_per_strategy_in_order() {
    let cases = discriminating_cases();
    let weights = HashMap::from([(sid("list"), 1.0), (sid("primary"), 1.0), (sid("secondary"), 1.0)]);
    let voter = ReliabilityWeightedVote::new(weights, 1.0);
    let strategies: Vec<&dyn Strategy> =
        vec![&RawPassthrough, &RenderGuardStrategy, &voter];

    let rows = compare_strategies(&strategies, &cases);

    assert_eq!(rows.len(), 3);
    assert_eq!(rows[0].strategy, "raw-passthrough");
    assert_eq!(rows[1].strategy, "render-guard");
    assert_eq!(rows[2].strategy, "reliability-weighted-vote");
    for row in &rows {
        assert_eq!(row.total, cases.len());
    }
    // Headline measurement: the guard beats the raw baseline.
    assert!(rows[1].correct > rows[0].correct);
}

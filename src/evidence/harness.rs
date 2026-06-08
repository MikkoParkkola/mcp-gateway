//! Experiment harness (EVGUARD.3 / EVGUARD.4).
//!
//! This module scaffolds the measurement: it defines the discriminating ground
//! truth cases, a trait-stubbed agent invocation boundary, and a strict
//! no-partial-credit scorer that compares three strategies:
//!
//! - **raw passthrough** ([`RawPassthrough`]) — the baseline: emit whatever the
//!   agent claimed, ungated.
//! - **render guard** ([`RenderGuardStrategy`]) — route claims through
//!   [`crate::evidence::render_guard`] and report the resulting verdict.
//! - **reliability-weighted majority vote** ([`ReliabilityWeightedVote`]) — the
//!   only weighting scheme permitted by the spike: each source carries a scalar
//!   reliability weight and the winning expected-answer is the weighted
//!   plurality. No probabilistic fusion, no calibration.
//!
//! The agent / LLM call itself is stubbed behind the [`Strategy`] trait so the
//! pure scoring and strategy logic compile and are unit-tested with synthetic
//! cases. Wiring a real agent is a later phase.

use std::collections::HashMap;

use crate::evidence::guard::{RawClaim, render_guard};
use crate::evidence::state::{EvidenceState, SourceId};
use crate::evidence::verdict::Verdict;

/// The four discriminating ground-truth situations the experiment must separate.
///
/// These map one-to-one onto the verdicts a correct strategy should produce, and
/// crucially keep *abstain* ([`Self::ShouldAbstain`]) distinct from
/// *authoritative empty* ([`Self::SourceAuthoritativelyEmpty`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum GroundTruth {
    /// The correct behavior is to abstain — no source can settle the claim
    /// (could-not-check). Correct verdict: [`Verdict::Disclaimer`].
    ShouldAbstain,
    /// A source was queried and authoritatively returned no match. Correct
    /// verdict: [`Verdict::Adverse`].
    SourceAuthoritativelyEmpty,
    /// A source was unavailable / errored. Correct verdict:
    /// [`Verdict::Disclaimer`] (we could not check).
    SourceUnavailableFailed,
    /// A source answered, but from stale data. Correct behavior is a caveated
    /// answer. Correct verdict: [`Verdict::Qualified`].
    SourceStale,
}

impl GroundTruth {
    /// The verdict a fully-correct strategy must report for this case.
    #[must_use]
    pub fn expected_verdict(self) -> Verdict {
        match self {
            Self::ShouldAbstain | Self::SourceUnavailableFailed => Verdict::Disclaimer,
            Self::SourceAuthoritativelyEmpty => Verdict::Adverse,
            Self::SourceStale => Verdict::Qualified,
        }
    }
}

/// A single labelled experiment case.
#[derive(Debug, Clone)]
pub struct GroundTruthCase {
    /// Human-readable case name (for reporting).
    pub name: String,
    /// The candidate claim and its backing evidence, as the agent produced it.
    pub claim: RawClaim,
    /// The correct situation this case represents.
    pub truth: GroundTruth,
}

impl GroundTruthCase {
    /// Construct a labelled case.
    pub fn new(name: impl Into<String>, claim: RawClaim, truth: GroundTruth) -> Self {
        Self { name: name.into(), claim, truth }
    }
}

/// The verdict a strategy reports for a case (or that it emitted nothing).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StrategyOutput {
    /// The strategy emitted a claim tagged with this verdict.
    Emitted(Verdict),
    /// The strategy emitted nothing for this case (the claim was dropped).
    Suppressed,
}

/// The agent-invocation boundary, stubbed for the spike.
///
/// A real implementation would call an LLM / agent to decide what to emit for a
/// case. Here it is a trait so the pure scoring logic compiles and is testable
/// with deterministic synthetic strategies.
pub trait Strategy {
    /// A short, stable name for reporting.
    fn name(&self) -> &'static str;

    /// Decide what (if anything) to emit for one case.
    fn decide(&self, case: &GroundTruthCase) -> StrategyOutput;
}

/// Baseline: emit the agent's claim verbatim with no evidence gating.
///
/// Models "raw tool output" — it always asserts a clean answer regardless of the
/// backing evidence, which is exactly the unsupported-claim behavior the spike
/// measures against.
#[derive(Debug, Default, Clone, Copy)]
pub struct RawPassthrough;

impl Strategy for RawPassthrough {
    fn name(&self) -> &'static str {
        "raw-passthrough"
    }

    fn decide(&self, _case: &GroundTruthCase) -> StrategyOutput {
        // Ungated: every claim is asserted as if clean.
        StrategyOutput::Emitted(Verdict::Clean)
    }
}

/// Route the claim through the non-bypassable [`render_guard`] and report the
/// resulting verdict (or suppression when the claim is dropped).
#[derive(Debug, Default, Clone, Copy)]
pub struct RenderGuardStrategy;

impl Strategy for RenderGuardStrategy {
    fn name(&self) -> &'static str {
        "render-guard"
    }

    fn decide(&self, case: &GroundTruthCase) -> StrategyOutput {
        let emitted = render_guard(vec![case.claim.clone()]);
        emitted
            .first()
            .map_or(StrategyOutput::Suppressed, |claim| StrategyOutput::Emitted(claim.verdict()))
    }
}

/// Reliability-weighted majority vote over the per-source outcomes.
///
/// Each source id carries a scalar reliability weight. Every backing
/// evidence-state casts a weighted vote for the verdict it would imply *on its
/// own*; the verdict with the greatest total weight wins. This is the **only**
/// weighting scheme permitted by the spike — deliberately a plain weighted
/// plurality, with no probabilistic fusion or calibration.
#[derive(Debug, Clone)]
pub struct ReliabilityWeightedVote {
    weights: HashMap<SourceId, f64>,
    default_weight: f64,
}

impl ReliabilityWeightedVote {
    /// Construct with per-source weights and a fallback weight for unknown
    /// sources.
    #[must_use]
    pub fn new(weights: HashMap<SourceId, f64>, default_weight: f64) -> Self {
        Self { weights, default_weight }
    }

    /// The reliability weight for a source, falling back to the default.
    fn weight_for(&self, source: &SourceId) -> f64 {
        self.weights.get(source).copied().unwrap_or(self.default_weight)
    }

    /// The verdict a single evidence-state would imply on its own.
    ///
    /// Not-applicable states are filtered out by [`Strategy::decide`] before this
    /// is called, so they never reach the tally; they share the
    /// [`Verdict::Disclaimer`] arm here only for totality.
    fn per_state_verdict(state: &EvidenceState) -> Verdict {
        match state {
            EvidenceState::CheckedHit { .. } => Verdict::Clean,
            EvidenceState::CheckedNoHit { .. } => Verdict::Adverse,
            EvidenceState::Stale { .. } => Verdict::Qualified,
            EvidenceState::Failed { .. }
            | EvidenceState::Timeout { .. }
            | EvidenceState::NotConfigured { .. }
            | EvidenceState::NotAuthorized { .. }
            | EvidenceState::SkippedNotApplicable { .. } => Verdict::Disclaimer,
        }
    }
}

impl Strategy for ReliabilityWeightedVote {
    fn name(&self) -> &'static str {
        "reliability-weighted-vote"
    }

    fn decide(&self, case: &GroundTruthCase) -> StrategyOutput {
        let mut tally: HashMap<Verdict, f64> = HashMap::new();
        for state in &case.claim.evidence {
            if matches!(state, EvidenceState::SkippedNotApplicable { .. }) {
                continue;
            }
            let verdict = Self::per_state_verdict(state);
            *tally.entry(verdict).or_insert(0.0) += self.weight_for(state.source());
        }

        // No relevant votes → suppressed (nothing to emit).
        // Deterministic tie-break: the most-supported verdict (Ord) wins, so
        // equal weights resolve toward Clean < Qualified < Adverse < Disclaimer.
        tally
            .into_iter()
            .max_by(|(va, wa), (vb, wb)| {
                wa.partial_cmp(wb).unwrap_or(std::cmp::Ordering::Equal).then(vb.cmp(va))
            })
            .map_or(StrategyOutput::Suppressed, |(verdict, _)| StrategyOutput::Emitted(verdict))
    }
}

/// Score a strategy over a case set with **no partial credit**.
///
/// A case is correct **iff** the strategy emits a claim whose verdict equals the
/// case's [`GroundTruth::expected_verdict`]. Suppression, a wrong verdict, or any
/// mismatch all score zero for that case — there is no graded reward for being
/// "close" (e.g. emitting Qualified when Adverse was required).
///
/// Returns the number of fully-correct cases.
///
/// # Examples
///
/// ```
/// use mcp_gateway::evidence::harness::{
///     GroundTruth, GroundTruthCase, RenderGuardStrategy, score_strategy,
/// };
/// use mcp_gateway::evidence::{EvidenceState, RawClaim, SourceId};
///
/// let case = GroundTruthCase::new(
///     "empty",
///     RawClaim::new(
///         "X not listed",
///         vec![EvidenceState::CheckedNoHit { source: SourceId::new("l"), detail: None }],
///     ),
///     GroundTruth::SourceAuthoritativelyEmpty,
/// );
/// assert_eq!(score_strategy(&RenderGuardStrategy, &[case]), 1);
/// ```
#[must_use]
pub fn score_strategy<S: Strategy + ?Sized>(strategy: &S, cases: &[GroundTruthCase]) -> usize {
    cases
        .iter()
        .filter(|case| {
            matches!(
                strategy.decide(case),
                StrategyOutput::Emitted(v) if v == case.truth.expected_verdict()
            )
        })
        .count()
}

/// One strategy's score line over a case set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScoreRow {
    /// The strategy name.
    pub strategy: String,
    /// Number of fully-correct cases.
    pub correct: usize,
    /// Total number of cases scored.
    pub total: usize,
}

/// Score every strategy in `strategies` over the same `cases`, returning one
/// [`ScoreRow`] per strategy in input order.
///
/// This is the comparison table for EVGUARD.3 / EVGUARD.4.
#[must_use]
pub fn compare_strategies(
    strategies: &[&dyn Strategy],
    cases: &[GroundTruthCase],
) -> Vec<ScoreRow> {
    strategies
        .iter()
        .map(|s| ScoreRow {
            strategy: s.name().to_string(),
            correct: score_strategy(*s, cases),
            total: cases.len(),
        })
        .collect()
}

#[cfg(test)]
#[path = "harness_tests.rs"]
mod tests;

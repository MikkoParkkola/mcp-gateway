//! Four-valued verdict and the pure state→verdict mapping.
//!
//! [`classify`] is the deterministic core of the apparatus. Given the set of
//! [`EvidenceState`]s backing a single claim, it returns exactly one
//! [`Verdict`]. The mapping is total, side-effect-free, and order-independent.
//!
//! # The load-bearing distinction
//!
//! [`Verdict::Adverse`] and [`Verdict::Disclaimer`] are categorically different
//! and must never be confused:
//!
//! - **[`Verdict::Adverse`]** — a source was queried and authoritatively
//!   returned *no match* ([`EvidenceState::CheckedNoHit`]). This is a trustworthy
//!   negative finding.
//! - **[`Verdict::Disclaimer`]** — *no* conclusive evidence is available; the
//!   source(s) could not be checked (failed / timed out / not configured / not
//!   authorized) or only stale data exists. We are silent on the truth, not
//!   asserting a negative.
//!
//! Collapsing these two would let "we couldn't check" masquerade as "we checked
//! and it's clear", which is exactly the unsupported-claim failure this spike
//! measures.

use crate::evidence::state::{EvidenceClass, EvidenceState};

/// The four possible verdicts for a claim, ordered from most to least supported.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Verdict {
    /// Fully supported: conclusive positive evidence, no contradiction, no
    /// confidence-degrading factors.
    Clean,
    /// Supported but with caveats: a mix of sufficient and insufficient
    /// evidence, an internal contradiction, or a stale-degraded positive.
    Qualified,
    /// An authoritative negative finding: a source was queried and returned no
    /// match. Categorically distinct from [`Verdict::Disclaimer`].
    Adverse,
    /// We could not determine the truth: no conclusive evidence is available.
    /// Categorically distinct from [`Verdict::Adverse`].
    Disclaimer,
}

/// Map the set of evidence-states backing a claim to a single [`Verdict`].
///
/// The mapping is a decision tree keyed on [`EvidenceClass`]:
///
/// 1. [`EvidenceClass::NotApplicable`] states are **filtered out first** — they
///    neither support nor undermine the claim.
/// 2. If nothing remains → [`Verdict::Disclaimer`] (no backing at all).
/// 3. If there is **no conclusive evidence** (only could-not-check and/or stale)
///    → [`Verdict::Disclaimer`].
/// 4. With conclusive evidence present:
///    - both a positive *and* a negative (contradiction) → [`Verdict::Qualified`];
///    - only negative(s) → [`Verdict::Adverse`];
///    - only positive(s): if any could-not-check **or** any stale state is also
///      present → [`Verdict::Qualified`]; otherwise → [`Verdict::Clean`].
///
/// This satisfies every rule in the spike spec:
/// - ≥1 [`CheckedHit`](EvidenceState::CheckedHit) with no contradiction → toward Clean.
/// - [`CheckedNoHit`](EvidenceState::CheckedNoHit) → [`Verdict::Adverse`], not Disclaimer.
/// - only could-not-check states → [`Verdict::Disclaimer`].
/// - mixed sufficient + insufficient → [`Verdict::Qualified`].
/// - [`Stale`](EvidenceState::Stale) degrades Clean → [`Verdict::Qualified`].
///
/// # Examples
///
/// ```
/// use mcp_gateway::evidence::{EvidenceState, SourceId, Verdict, classify};
///
/// let hit = EvidenceState::CheckedHit { source: SourceId::new("s"), detail: None };
/// assert_eq!(classify(&[hit]), Verdict::Clean);
///
/// let empty = EvidenceState::CheckedNoHit { source: SourceId::new("s"), detail: None };
/// assert_eq!(classify(&[empty]), Verdict::Adverse);
///
/// let failed = EvidenceState::Failed { source: SourceId::new("s"), detail: None };
/// assert_eq!(classify(&[failed]), Verdict::Disclaimer);
/// ```
#[must_use]
pub fn classify(states: &[EvidenceState]) -> Verdict {
    let mut has_positive = false;
    let mut has_negative = false;
    let mut has_could_not_check = false;
    let mut has_stale = false;
    let mut any_relevant = false;

    for state in states {
        match state.class() {
            // Rule 1: not-applicable is filtered out (neutral).
            EvidenceClass::NotApplicable => continue,
            EvidenceClass::ConclusivePositive => has_positive = true,
            EvidenceClass::ConclusiveNegative => has_negative = true,
            EvidenceClass::CouldNotCheck => has_could_not_check = true,
            EvidenceClass::Stale => has_stale = true,
        }
        any_relevant = true;
    }

    // Rule 2: nothing relevant remains.
    if !any_relevant {
        return Verdict::Disclaimer;
    }

    // Rule 3: no conclusive evidence at all (only could-not-check and/or stale).
    if !has_positive && !has_negative {
        return Verdict::Disclaimer;
    }

    // Rule 4: conclusive evidence is present.
    match (has_positive, has_negative) {
        // Contradiction: queried both ways with opposite authoritative answers.
        (true, true) => Verdict::Qualified,
        // Only authoritative negatives — a trustworthy adverse finding.
        (false, true) => Verdict::Adverse,
        // Only authoritative positives.
        (true, false) => {
            if has_could_not_check || has_stale {
                // Mixed sufficient + insufficient, or stale-degraded → caveat.
                Verdict::Qualified
            } else {
                Verdict::Clean
            }
        }
        // Unreachable: covered by Rule 3 above, but kept total for clarity.
        (false, false) => Verdict::Disclaimer,
    }
}

#[cfg(test)]
#[path = "verdict_tests.rs"]
mod tests;

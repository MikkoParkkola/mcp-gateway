//! Non-bypassable render guard.
//!
//! The guard enforces a structural invariant: **a claim cannot be emitted
//! without passing through [`render_guard`]**. This is achieved with the
//! *sealed-constructor* pattern — [`EmittableClaim`] has only private fields and
//! no public constructor, so the only way to obtain one is the [`render_guard`]
//! function (the sole `pub` item that returns it). Downstream code can read an
//! [`EmittableClaim`] via its accessors but can never fabricate one that skipped
//! the guard.
//!
//! Each surviving claim is tagged with its [`Verdict`] and carries the
//! [`SourceId`]s of the evidence-states that justify it, so every emitted claim
//! is self-citing.
//!
//! # Drop vs downgrade policy
//!
//! - A claim with **no relevant backing** (empty, or only
//!   [`EvidenceState::SkippedNotApplicable`]) is **dropped** — it never produces
//!   an [`EmittableClaim`].
//! - A claim with relevant backing is **emitted with its verdict tag**,
//!   including [`Verdict::Disclaimer`] and [`Verdict::Adverse`]. Downgrading is
//!   expressed through the verdict, not through suppression, so the experiment
//!   can measure abstention ([`Verdict::Disclaimer`]) distinctly from an
//!   authoritative negative ([`Verdict::Adverse`]).

use crate::evidence::state::{EvidenceState, SourceId};
use crate::evidence::verdict::{Verdict, classify};

/// An unguarded, candidate claim plus the evidence-states backing it.
///
/// This is the *input* to the guard. It is freely constructible — it carries no
/// authority. Only [`render_guard`] can turn it into an [`EmittableClaim`].
#[derive(Debug, Clone)]
pub struct RawClaim {
    /// The proposition the agent wants to emit (free text).
    pub text: String,
    /// The evidence-states consulted in support of this claim.
    pub evidence: Vec<EvidenceState>,
}

impl RawClaim {
    /// Construct a raw candidate claim.
    pub fn new(text: impl Into<String>, evidence: Vec<EvidenceState>) -> Self {
        Self {
            text: text.into(),
            evidence,
        }
    }
}

/// A claim that has passed the render guard and is permitted to be emitted.
///
/// # Invariant
///
/// **The only constructor is [`render_guard`].** All fields are private and there
/// is no public `new`/`From`/`Default`, so an [`EmittableClaim`] is *proof* that
/// the claim was classified by the guard. This makes "emit a claim without
/// guarding it" unrepresentable in the type system rather than merely
/// discouraged.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EmittableClaim {
    text: String,
    verdict: Verdict,
    citations: Vec<SourceId>,
}

impl EmittableClaim {
    /// The claim text.
    #[must_use]
    pub fn text(&self) -> &str {
        &self.text
    }

    /// The verdict the guard assigned to this claim.
    #[must_use]
    pub fn verdict(&self) -> Verdict {
        self.verdict
    }

    /// The evidence-source ids that justify this claim's verdict.
    ///
    /// Guaranteed non-empty: a claim with no relevant backing is dropped by the
    /// guard rather than emitted.
    #[must_use]
    pub fn citations(&self) -> &[SourceId] {
        &self.citations
    }
}

/// The non-bypassable render guard.
///
/// Filters a batch of candidate [`RawClaim`]s into the [`EmittableClaim`]s that
/// are permitted to surface. For each candidate:
///
/// 1. Compute its [`Verdict`] via [`classify`].
/// 2. Collect the citing [`SourceId`]s — every relevant (non-not-applicable)
///    evidence-state's source.
/// 3. If there are **no** relevant evidence-states, **drop** the claim.
/// 4. Otherwise emit an [`EmittableClaim`] tagged with the verdict and
///    citations.
///
/// Because [`EmittableClaim`] is sealed, this function is the single chokepoint
/// through which any claim must pass before it can be rendered.
///
/// # Examples
///
/// ```
/// use mcp_gateway::evidence::{EvidenceState, RawClaim, SourceId, Verdict, render_guard};
///
/// let backed = RawClaim::new(
///     "entity X is on the list",
///     vec![EvidenceState::CheckedHit { source: SourceId::new("list"), detail: None }],
/// );
/// let unbacked = RawClaim::new("entity Y is fine", vec![]);
///
/// let emitted = render_guard(vec![backed, unbacked]);
/// assert_eq!(emitted.len(), 1); // the unbacked claim was dropped
/// assert_eq!(emitted[0].verdict(), Verdict::Clean);
/// assert_eq!(emitted[0].citations(), &[SourceId::new("list")]);
/// ```
#[must_use]
pub fn render_guard(claims: Vec<RawClaim>) -> Vec<EmittableClaim> {
    claims
        .into_iter()
        .filter_map(|claim| {
            let verdict = classify(&claim.evidence);
            let citations: Vec<SourceId> = claim
                .evidence
                .iter()
                .filter(|state| !is_not_applicable(state))
                .map(|state| state.source().clone())
                .collect();

            // Drop claims with no relevant backing — never emit an
            // uncited claim.
            if citations.is_empty() {
                return None;
            }

            Some(EmittableClaim {
                text: claim.text,
                verdict,
                citations,
            })
        })
        .collect()
}

/// Whether a state is a not-applicable (neutral) state, excluded from citations.
fn is_not_applicable(state: &EvidenceState) -> bool {
    matches!(state, EvidenceState::SkippedNotApplicable { .. })
}

#[cfg(test)]
#[path = "guard_tests.rs"]
mod tests;

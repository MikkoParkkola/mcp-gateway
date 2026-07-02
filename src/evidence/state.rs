//! Evidence-state model: the eight outcomes of consulting a backing source.
//!
//! [`EvidenceState`] is exhaustive by construction. Every way a source check can
//! resolve — including the "could not check" and "not applicable" cases — is a
//! named variant carrying minimal metadata, rather than being smuggled through an
//! `Option` or a sentinel value. This is what lets the verdict mapping
//! ([`crate::evidence::verdict`]) distinguish an *authoritative negative*
//! ([`EvidenceState::CheckedNoHit`]) from a *failure to check*
//! ([`EvidenceState::Failed`] and friends).

use std::fmt;

/// Identifier of a backing source (e.g. a tool, dataset, or check name).
///
/// A newtype over `String` so that source ids are not interchangeable with
/// arbitrary text and so the type reads clearly in signatures.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct SourceId(pub String);

impl SourceId {
    /// Construct a [`SourceId`] from anything string-like.
    ///
    /// # Examples
    ///
    /// ```
    /// use mcp_gateway::evidence::SourceId;
    /// let id = SourceId::new("registry-v2");
    /// assert_eq!(id.as_str(), "registry-v2");
    /// ```
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }

    /// Borrow the underlying id as a string slice.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for SourceId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// The outcome of consulting one backing source for a claim.
///
/// Each variant carries the [`SourceId`] that produced it plus an optional
/// human-readable `detail` for diagnostics. The variants partition into three
/// evidential classes, which the verdict mapping keys on:
///
/// | Class | Variants | Meaning |
/// |-------|----------|---------|
/// | **Conclusive** | [`CheckedHit`](Self::CheckedHit), [`CheckedNoHit`](Self::CheckedNoHit) | The source was queried and gave an authoritative answer. |
/// | **Could-not-check** | [`Failed`](Self::Failed), [`Timeout`](Self::Timeout), [`NotConfigured`](Self::NotConfigured), [`NotAuthorized`](Self::NotAuthorized) | The source could not produce an authoritative answer. |
/// | **Modifier / neutral** | [`Stale`](Self::Stale), [`SkippedNotApplicable`](Self::SkippedNotApplicable) | Degrades confidence, or is irrelevant to this claim. |
///
/// The class taxonomy is expressed once in code via [`EvidenceState::class`] so
/// the mapping logic never re-derives it ad hoc.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EvidenceState {
    /// The source was queried and returned a positive, authoritative match.
    CheckedHit {
        /// The source that produced this outcome.
        source: SourceId,
        /// Optional diagnostic detail.
        detail: Option<String>,
    },
    /// The source was queried and authoritatively returned *no* match.
    ///
    /// This is a **trustworthy negative**, not an absence of evidence: the
    /// source was reachable, authorized, and current. It is the basis for an
    /// [`crate::evidence::Verdict::Adverse`] verdict.
    CheckedNoHit {
        /// The source that produced this outcome.
        source: SourceId,
        /// Optional diagnostic detail.
        detail: Option<String>,
    },
    /// The source returned an error and could not produce an answer.
    Failed {
        /// The source that produced this outcome.
        source: SourceId,
        /// Optional diagnostic detail.
        detail: Option<String>,
    },
    /// The source did not respond within the deadline.
    Timeout {
        /// The source that produced this outcome.
        source: SourceId,
        /// Optional diagnostic detail.
        detail: Option<String>,
    },
    /// The source is not configured in this deployment.
    NotConfigured {
        /// The source that produced this outcome.
        source: SourceId,
        /// Optional diagnostic detail.
        detail: Option<String>,
    },
    /// The caller is not authorized to query this source.
    NotAuthorized {
        /// The source that produced this outcome.
        source: SourceId,
        /// Optional diagnostic detail.
        detail: Option<String>,
    },
    /// The source answered, but from data old enough to degrade confidence.
    ///
    /// Stale is a *modifier*: it pushes an otherwise-clean verdict toward
    /// [`crate::evidence::Verdict::Qualified`]. On its own (with no conclusive
    /// evidence to modify) it cannot support a claim.
    Stale {
        /// The source that produced this outcome.
        source: SourceId,
        /// Optional diagnostic detail.
        detail: Option<String>,
    },
    /// The source was deliberately skipped as not applicable to this claim.
    ///
    /// Neutral: it neither supports nor undermines the claim and is filtered out
    /// before the verdict mapping runs.
    SkippedNotApplicable {
        /// The source that produced this outcome.
        source: SourceId,
        /// Optional diagnostic detail.
        detail: Option<String>,
    },
}

/// The evidential class of an [`EvidenceState`].
///
/// Computed once from the variant so the verdict mapping keys on a small, total
/// taxonomy instead of re-matching the eight variants in multiple places.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EvidenceClass {
    /// An authoritative positive answer ([`EvidenceState::CheckedHit`]).
    ConclusivePositive,
    /// An authoritative negative answer ([`EvidenceState::CheckedNoHit`]).
    ConclusiveNegative,
    /// The source could not produce an authoritative answer.
    CouldNotCheck,
    /// The source answered but from stale data (a confidence modifier).
    Stale,
    /// The source is not applicable to this claim (neutral).
    NotApplicable,
}

impl EvidenceState {
    /// The [`SourceId`] that produced this state.
    #[must_use]
    pub fn source(&self) -> &SourceId {
        match self {
            Self::CheckedHit { source, .. }
            | Self::CheckedNoHit { source, .. }
            | Self::Failed { source, .. }
            | Self::Timeout { source, .. }
            | Self::NotConfigured { source, .. }
            | Self::NotAuthorized { source, .. }
            | Self::Stale { source, .. }
            | Self::SkippedNotApplicable { source, .. } => source,
        }
    }

    /// The optional diagnostic detail attached to this state.
    #[must_use]
    pub fn detail(&self) -> Option<&str> {
        match self {
            Self::CheckedHit { detail, .. }
            | Self::CheckedNoHit { detail, .. }
            | Self::Failed { detail, .. }
            | Self::Timeout { detail, .. }
            | Self::NotConfigured { detail, .. }
            | Self::NotAuthorized { detail, .. }
            | Self::Stale { detail, .. }
            | Self::SkippedNotApplicable { detail, .. } => detail.as_deref(),
        }
    }

    /// The evidential [`EvidenceClass`] of this state.
    ///
    /// This is the single source of truth for the conclusive / could-not-check /
    /// modifier taxonomy that the verdict mapping depends on.
    #[must_use]
    pub fn class(&self) -> EvidenceClass {
        match self {
            Self::CheckedHit { .. } => EvidenceClass::ConclusivePositive,
            Self::CheckedNoHit { .. } => EvidenceClass::ConclusiveNegative,
            Self::Failed { .. }
            | Self::Timeout { .. }
            | Self::NotConfigured { .. }
            | Self::NotAuthorized { .. } => EvidenceClass::CouldNotCheck,
            Self::Stale { .. } => EvidenceClass::Stale,
            Self::SkippedNotApplicable { .. } => EvidenceClass::NotApplicable,
        }
    }
}

#[cfg(test)]
#[path = "state_tests.rs"]
mod tests;

// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A delivery digest's facts as a record holds them: the source identity it
//! was taken from and the inferred fact, per contributor for a seam.

use super::DeliveryDigest;

impl DeliveryDigest {
    /// The source identity and inferred fact this digest stages (tests
    /// only).
    #[cfg(test)]
    pub(crate) fn facts_for_test(&self) -> (Option<std::sync::Arc<str>>, bool) {
        (self.source.clone(), self.inferred)
    }

    /// Each contributing source with its inferred fact (tests only).
    #[cfg(test)]
    pub(crate) fn contributor_facts_for_test(&self) -> Option<Vec<(std::sync::Arc<str>, bool)>> {
        contributor_facts(
            self.seam_sources.as_deref()?,
            self.seam_inferred.as_deref(),
            self.inferred,
        )
    }

    /// This seam's contributors' own inferred facts, in its sources' order;
    /// the seam is inferred when any is.
    #[must_use]
    pub(crate) fn with_contributor_facts(mut self, inferred: Box<[bool]>) -> Self {
        self.inferred = inferred.iter().any(|f| *f);
        self.sensitive |= self.inferred;
        self.seam_inferred = Some(inferred);
        self
    }

    /// Whether the result itself was classified sensitive (the inferred
    /// fact), apart from any list match.
    pub(crate) const fn is_inferred(&self) -> bool {
        self.inferred
    }

    /// Set the `server:tool` this digest's result came from.
    pub(crate) fn set_source(&mut self, source: &str) {
        self.source = Some(std::sync::Arc::from(source));
    }
}

/// Each of `sources` with its own inferred fact, else the seam's one fact
/// (a digest built before facts were kept apart).
#[cfg(test)]
pub(super) fn contributor_facts(
    sources: &[String],
    inferred: Option<&[bool]>,
    seam: bool,
) -> Option<Vec<(std::sync::Arc<str>, bool)>> {
    Some(
        sources
            .iter()
            .enumerate()
            .map(|(i, s)| {
                let fact = inferred.and_then(|f| f.get(i).copied()).unwrap_or(seam);
                (std::sync::Arc::from(s.as_str()), fact)
            })
            .collect(),
    )
}

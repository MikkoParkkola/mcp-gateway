// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Where a held copy came from, judged at witness against the lists in force
//! (ADR-029, amended, item 2): a record keeps its source identity, never a
//! verdict on it, so a reload that adds or removes a source or a flow applies
//! to every copy already held.

use std::collections::HashSet;
use std::sync::{Arc, LazyLock};

use super::super::CollusionView;

/// The source identity a record holds: one `server:tool`, or the
/// contributors of a seam between plan steps, which leaves only
/// by a flow every contributor has.
#[derive(Clone, PartialEq, Eq)]
pub(super) enum Origin {
    One(Arc<str>),
    Each(Arc<[Arc<str>]>),
}

impl Origin {
    /// Whether `view` lists this origin as sensitive: the source, or any
    /// contributor of a seam.
    pub(super) fn listed(&self, view: &CollusionView) -> bool {
        let lists = |name: &str| view.sources.iter().any(|p| p.matches(name));
        match self {
            Self::One(name) => lists(name),
            Self::Each(names) => names.iter().any(|n| lists(n)),
        }
    }

    /// Whether a current `allowed_flows` entry lets this copy leave through
    /// `egress`: for a seam, every contributor needs one. The composite seam
    /// name is never matched.
    pub(super) fn flows_to(&self, view: &CollusionView, egress: &str) -> bool {
        let covered = |name: &str| {
            view.flows
                .iter()
                .any(|(source, out)| source.matches(name) && out.matches(egress))
        };
        match self {
            Self::One(name) => covered(name),
            Self::Each(names) => !names.is_empty() && names.iter().all(|n| covered(n)),
        }
    }
}

/// A view with no lists and no flows: what the bool-only entries judge by,
/// so their `sensitive` is an inferred fact no reload changes.
pub(crate) fn no_lists() -> &'static CollusionView {
    static NONE: LazyLock<CollusionView> =
        LazyLock::new(|| CollusionView::compile(&super::super::CollusionConfig::default()));
    &NONE
}

/// Source names shared by every record that holds them (lead ruling B2): an
/// interned name is freed when its last holder is.
#[derive(Default)]
pub(super) struct Interned(HashSet<Arc<str>>);

impl Interned {
    /// The shared copy of `name`.
    pub(super) fn get(&mut self, name: &str) -> Arc<str> {
        if let Some(held) = self.0.get(name) {
            return Arc::clone(held);
        }
        let held: Arc<str> = Arc::from(name);
        self.0.insert(Arc::clone(&held));
        held
    }

    /// Forget names only this table still holds.
    pub(super) fn release(&mut self) {
        self.0.retain(|name| Arc::strong_count(name) > 1);
    }

    /// Names some record still holds.
    #[cfg(test)]
    pub(super) fn len(&self) -> usize {
        self.0.iter().filter(|n| Arc::strong_count(n) > 1).count()
    }
}

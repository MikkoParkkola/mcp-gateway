// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Test-only readers for the live-relay rows: the overflow pairs, the
//! unattributed mark, the overflow bytes and the interned names.

use super::{CollusionDetector, Entry, Holders};

impl CollusionDetector {
    /// Allow `n` bytes of overflow pairs in all (tests only).
    pub(super) fn set_overflow_bytes_total(&mut self, n: usize) {
        self.state.get_mut().budget.limit = n;
    }

    /// The distinct overflow pairs `(source, inferred)` `caller` holds for
    /// the fingerprints of `text` (tests only).
    pub(crate) fn overflow_pairs_of(
        &self,
        text: &str,
        caller: &str,
    ) -> Vec<(std::sync::Arc<str>, bool)> {
        let mut pairs: Vec<_> = self
            .overflow_pairs_by_fingerprint(text, caller)
            .into_iter()
            .flatten()
            .collect();
        pairs.sort_unstable();
        pairs.dedup();
        pairs
    }

    /// `caller`'s overflow pairs on each fingerprint of `text`, in
    /// fingerprint order, each sorted; empty for a fingerprint without a
    /// tracked entry (tests only).
    pub(crate) fn overflow_pairs_by_fingerprint(
        &self,
        text: &str,
        caller: &str,
    ) -> Vec<Vec<(std::sync::Arc<str>, bool)>> {
        let principal = self.digest(caller);
        let state = self.state.lock();
        self.fingerprints(text)
            .iter()
            .map(|fp| match state.entries.get(fp) {
                Some(Entry {
                    holders: Holders::Tracked(t),
                    ..
                }) => {
                    let mut pairs = t.pairs_of(principal);
                    pairs.sort_unstable();
                    pairs
                }
                _ => Vec::new(),
            })
            .collect()
    }

    /// Whether `caller`'s overflow for a fingerprint of `text` is marked
    /// unattributed (tests only).
    pub(crate) fn overflow_unattributed(&self, text: &str, caller: &str) -> bool {
        let principal = self.digest(caller);
        let state = self.state.lock();
        self.fingerprints(text).iter().any(|fp| {
            matches!(
                state.entries.get(fp),
                Some(Entry { holders: Holders::Tracked(t), .. }) if t.unattributed(principal)
            )
        })
    }

    /// The overflow bytes `(per caller maximum, total)` held now (tests
    /// only).
    pub(crate) fn overflow_bytes(&self) -> (usize, usize) {
        let state = self.state.lock();
        let most = state
            .entries
            .values()
            .filter_map(|e| match &e.holders {
                Holders::Tracked(t) => Some(t.max_caller_bytes()),
                Holders::Common => None,
            })
            .max()
            .unwrap_or(0);
        (most, state.budget.total)
    }

    /// Whether the intern table still holds `source` (tests only).
    pub(crate) fn interns_for_test(&self, source: &str) -> bool {
        self.state.lock().interned.holds(source)
    }
}

/// The view an old bit-mask row meant: `recorded` is each source with the
/// `allowed_flows` entries (bit each) it matched, `egress` the egress with
/// its own. An entry both match becomes a flow from that source to the
/// egress, so a copy is allowed exactly when its mask and the egress's share
/// a bit (tests only).
pub(super) fn masked(
    recorded: &[(&str, u64)],
    (egress, mask): (&str, u64),
) -> crate::security::firewall::CollusionView {
    let allowed_flows = recorded
        .iter()
        .filter(|(_, m)| m & mask != 0)
        .map(|(source, _)| crate::security::firewall::AllowedFlow {
            source: (*source).to_string(),
            egress: egress.to_string(),
        })
        .collect();
    crate::security::firewall::CollusionView::compile(&crate::security::firewall::CollusionConfig {
        allowed_flows,
        ..crate::security::firewall::CollusionConfig::default()
    })
}

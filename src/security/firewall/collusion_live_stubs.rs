// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Test-only entry points and readers for the live-relay rows: the detector
//! entries that take a source identity, an inferred fact and a view, and the
//! overflow and interning readers. Each returns today's facts until the fix
//! gives it meaning.

use std::time::Instant;

use super::{CollusionDetector, Entry, Holders, RelayFinding};

impl CollusionDetector {
    /// Record a result delivered to `principal` from `source` under `view`:
    /// the source identity and the inferred fact (a classification marker
    /// on the result), from which the list match and the flows follow. The
    /// stub derives today's `(sensitive, flows)` as the gate does now.
    #[cfg(test)]
    pub(crate) fn record_delivery_under(
        &self,
        view: &super::super::CollusionView,
        (source, inferred): (&str, bool),
        principal: &str,
        text: &str,
        now: Instant,
    ) {
        let sensitive = view.lists(source) || inferred;
        self.record_delivery_flows_at(
            source,
            principal,
            (sensitive, view.source_flows(source)),
            text,
            now,
        );
    }

    /// Check an egress through `target` by `principal` under `view`. The stub
    /// derives today's egress flow mask as the gate does now.
    #[cfg(test)]
    pub(crate) fn check_egress_under(
        &self,
        view: &super::super::CollusionView,
        principal: &str,
        target: &str,
        args: &str,
        now: Instant,
    ) -> Option<RelayFinding> {
        self.check_egress_fingerprints_at(
            principal,
            (target, view.egress_flows(target)),
            self.fingerprints(args),
            now,
        )
    }

    /// Allow `n` bytes of overflow pairs in all (tests only). The stub keeps
    /// no pairs yet.
    #[cfg(test)]
    #[expect(clippy::unused_self, reason = "the fix reads the detector")]
    pub(super) fn set_overflow_bytes_total(&mut self, n: usize) {
        let _ = n; // used by the fix
    }

    /// The overflow pairs `(source, inferred)` `caller` holds for the one
    /// fingerprint of `text` (tests only). The stub holds none.
    #[cfg(test)]
    #[expect(clippy::unused_self, reason = "the fix reads the detector")]
    pub(crate) fn overflow_pairs_of(
        &self,
        text: &str,
        caller: &str,
    ) -> Vec<(std::sync::Arc<str>, bool)> {
        let _ = (text, caller); // used by the fix
        Vec::new()
    }

    /// Whether `caller`'s overflow for the fingerprint of `text` is held
    /// without a source (tests only). Today every overflow is.
    #[cfg(test)]
    pub(crate) fn overflow_unattributed(&self, text: &str, caller: &str) -> bool {
        let principal = self.digest(caller);
        let state = self.state.lock();
        self.fingerprints(text).iter().any(|fp| {
            matches!(
                state.entries.get(fp),
                Some(Entry { holders: Holders::Tracked(t), .. }) if t.has_overflow(principal)
            )
        })
    }

    /// The overflow bytes `(per caller maximum, total)` held now (tests
    /// only). The stub counts none.
    #[cfg(test)]
    #[expect(clippy::unused_self, reason = "the fix reads the detector")]
    pub(crate) fn overflow_bytes(&self) -> (usize, usize) {
        (0, 0)
    }

    /// Source names interned now (tests only). The stub interns none.
    #[cfg(test)]
    #[expect(clippy::unused_self, reason = "the fix reads the detector")]
    pub(crate) fn interned_sources_for_test(&self) -> usize {
        0
    }
}

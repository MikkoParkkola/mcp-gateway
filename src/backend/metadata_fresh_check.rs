// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! What `tools_for_check` reads from a tools slot, beside it so `tools_slot`
//! stays private (MIK-8014 PERF.12). A fresh slot is answered here, before any
//! fill machinery: no fetch runs, so it needs no pool lease, abandon hook,
//! boxed fill or deadline. A stale or empty slot takes the fill path, whose
//! lease keeps the transport open for the fetch (MIK-7334.CATALOGUE.1 R3).

use std::sync::Arc;
use std::sync::atomic::Ordering;

use super::{Backend, Completeness};
use crate::protocol::Tool;

impl Backend {
    /// The list a fresh `binding` slot holds and its completeness, read under
    /// one cache guard: read apart, a list stored between them could pair one
    /// list with another's truncation flag. `None` when the slot is stale or
    /// holds nothing.
    pub(super) fn fresh_tools_for_check(
        &self,
        binding: Option<&str>,
    ) -> Option<(Arc<Vec<Tool>>, Completeness)> {
        let slot = self.tools_slot(binding);
        slot.tools_cache
            .with_cached_populated_fresh(self.cache_ttl, |held, _populated, fresh| {
                held.filter(|_| fresh).map(|held| {
                    let truncated = slot.tools_truncated.load(Ordering::SeqCst);
                    (Arc::clone(held), Completeness::held(truncated))
                })
            })
    }

    /// `tools`' completeness: `Complete` or `Truncated` only while `binding`'s
    /// slot still holds that very list (`Arc::ptr_eq`, read under its guard),
    /// so a voided store is `Unknown`.
    pub(super) fn held_completeness(
        &self,
        binding: Option<&str>,
        tools: &Arc<Vec<Tool>>,
    ) -> Completeness {
        let slot = self.tools_slot(binding);
        slot.tools_cache.with_cached(|current| match current {
            Some(held) if Arc::ptr_eq(held, tools) => {
                Completeness::held(slot.tools_truncated.load(Ordering::SeqCst))
            }
            _ => Completeness::Unknown,
        })
    }
}

// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The gate's fill marks: whether a named backend's catalogue filled while
//! a judgement was being made, read against the registry's membership
//! epoch so a replaced instance cannot pass for the one marked.

use crate::gateway::meta_mcp::MetaMcp;
use crate::gateway::meta_mcp::scoped_backends::Unscoped;

impl MetaMcp {
    /// Each named backend's fill count plus the registry's membership epoch,
    /// for [`Self::filled_since`], read in one call under the registry's
    /// membership lock. No instance is held: the lock serializes the marks
    /// against every add, replace or remove, so an unmoved epoch means every
    /// target is the same instance as at the mark and its count compares
    /// soundly.
    pub(super) fn fill_marks<'s>(
        &self,
        servers: impl Iterator<Item = &'s str>,
    ) -> (u64, Vec<Option<u64>>) {
        self.backends
            .membership_for(Unscoped::Discovery, |membership| {
                let fills = servers
                    .map(|server| {
                        self.backends
                            .get_for(Unscoped::Discovery, server)
                            .map(|backend| backend.list_fills())
                    })
                    .collect();
                (membership, fills)
            })
    }

    /// Whether a named backend filled since `marks`: any count changed OR
    /// the epoch changed counts as a fill, so the nonce stays spent. The
    /// counts and the epoch are read in one call under the registry's
    /// membership lock, so the snapshot and the final read agree with the
    /// map; only reloads pay this, and equal marks prove nothing acted.
    pub(super) fn filled_since<'s>(
        &self,
        (membership, marks): &(u64, Vec<Option<u64>>),
        servers: impl Iterator<Item = &'s str>,
    ) -> bool {
        self.backends.membership_for(Unscoped::Discovery, |epoch| {
            let counts_changed = marks.iter().zip(servers).any(|(mark, server)| {
                self.backends
                    .get_for(Unscoped::Discovery, server)
                    .map(|backend| backend.list_fills())
                    != *mark
            });
            counts_changed || epoch != *membership
        })
    }
}

// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Which tools the response cache may answer for (MIK-8393, from #3773).

use super::Backend;

impl Backend {
    /// Whether `binding`'s slot declared `tool` read-only, as of its last
    /// `tools/list`: the only thing that lets the response cache store or
    /// serve its result (MIK-8393). The same slot resolution the dispatch
    /// uses, as a lookup: a cold slot answers `false`.
    #[must_use]
    pub(crate) fn is_read_only_for(&self, binding: Option<&str>, tool: &str) -> bool {
        self.tools_slot(binding)
            .read_only_declared
            .read()
            .contains(tool)
    }

    /// An accepted fill's own derived state: its resend and read-only sets,
    /// and its descriptor verdicts. Written only from the store callback, so
    /// a fill voided by a mid-fill invalidation writes none of it (F13,
    /// #1441, MIK-8393).
    pub(super) fn store_prepared(
        &self,
        entry: &crate::backend::pool::PooledEntry,
        identity_key: Option<&str>,
        truncated: bool,
        prepared: crate::backend::annotations::PreparedTools,
    ) {
        *entry.resend_permitted.write() = prepared.resend_permitted;
        *entry.read_only_declared.write() = prepared.read_only_declared;
        let listing = if truncated {
            crate::backend::Listing::Truncated
        } else {
            crate::backend::Listing::Complete
        };
        self.commit_verdicts(identity_key.unwrap_or(""), listing, prepared.verdicts);
    }

    /// Seed the shared slot's read-only set, for fixtures whose subject is the
    /// cache's keying rather than how a declaration is read.
    #[cfg(test)]
    pub(crate) fn set_read_only_declared_for_test(&self, tools: &[&str]) {
        *self.shared_entry().read_only_declared.write() =
            tools.iter().map(|tool| (*tool).to_string()).collect();
    }

    /// A page that is not stored (truncated, or fetched under a caller's own
    /// credential into the shared slot) may still revoke (MIK-8393 r5-r7).
    /// When it lists a tool without declaring it read-only, and the slot
    /// either admits that tool or has a fill on the wire, the slot's tool list
    /// is invalidated and its admission cleared.
    ///
    /// Invalidating rather than narrowing moves the cache generation, so a
    /// fill already on the wire cannot land afterwards and re-admit the tool
    /// (`store_if_current`); the next accepted fill re-admits what the backend
    /// still declares. The slot is looked up, never created (#2300). A page
    /// that revokes nothing costs nothing.
    pub(in crate::backend) fn revoke_read_only_from_page<'a>(
        &self,
        key: &super::PoolKey,
        listed: impl Iterator<Item = &'a str>,
        declared: &std::collections::HashSet<String>,
    ) {
        let Some(slot) = self
            .pool
            .get(key)
            .map(|slot| std::sync::Arc::clone(slot.value()))
        else {
            return;
        };
        // In flight FIRST (MIK-8393 r7): a fill stores its set before it
        // clears the mark, so with no fill in flight the admission read below
        // sees whatever the last fill stored.
        let in_flight = slot.tools_cache.fill_in_flight();
        let mut writes = listed.filter(|tool| !declared.contains(*tool)).peekable();
        let revokes = writes.peek().is_some() && {
            let admitted = slot.read_only_declared.read();
            in_flight || writes.any(|tool| admitted.contains(tool))
        };
        if revokes {
            slot.tools_cache.invalidate_then(|| {
                slot.resend_permitted.write().clear();
                slot.read_only_declared.write().clear();
            });
        }
    }
}

#[cfg(test)]
#[path = "read_only_revoke_tests.rs"]
mod revoke_tests;

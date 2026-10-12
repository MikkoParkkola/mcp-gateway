// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A stored task read's view of a slot's catalogue (MIK-8392).

use std::sync::Arc;
use std::sync::atomic::Ordering;

use crate::protocol::Tool;

use super::super::Backend;

impl Backend {
    /// The slot's tools, truncated flag and whether it was ever populated,
    /// all under one read guard (MIK-8392, R2-5): a stored read judges "the
    /// complete catalogue lacks the tool" from one snapshot, never from
    /// membership and completeness read apart.
    #[must_use]
    pub(crate) fn cached_tools_view(&self, binding: Option<&str>) -> (Arc<Vec<Tool>>, bool, bool) {
        let slot = self.tools_slot(binding);
        let (tools, truncated, populated) =
            slot.tools_cache
                .with_cached_and_populated(|tools, populated| {
                    (
                        tools.map_or_else(|| Arc::new(Vec::new()), Arc::clone),
                        slot.tools_truncated.load(Ordering::SeqCst),
                        populated,
                    )
                });
        (self.without_blocked(tools), truncated, populated)
    }
}

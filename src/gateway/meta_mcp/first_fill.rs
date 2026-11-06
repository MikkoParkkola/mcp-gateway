// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A modern stdio client's first `tools/list` waits for the surfaced
//! backends' first fill.
//!
//! A surfaced tool whose backend's shared catalogue was never filled is left
//! out of `tools/list`. A legacy stdio session is told when the fill lands; a
//! modern one cannot be (that needs stdio `subscriptions/listen`), so its
//! first list waits, bounded, for the fills instead of caching a list
//! without them.

use std::sync::Arc;

use tracing::warn;

use super::MetaMcp;
use super::listing_warm::LISTING_DEADLINE_CAP;
use super::scoped_backends::Unscoped;
use crate::backend::Backend;
use crate::gateway::health_metrics::clock::carried;

impl MetaMcp {
    /// Wait for each surfaced tool's backend whose shared catalogue was never
    /// filled, joining the fill already running (warm-up's) or leading one,
    /// until all land or the deadline: the longest fill bound among them,
    /// capped at [`LISTING_DEADLINE_CAP`] from now.
    ///
    /// Each fill runs as its own task, so a list cancelled or cut short here
    /// never aborts it: the cache still fills, and a later list shows it. A
    /// backend refusing a shared session is `warm_listing_views`' to warm.
    /// Only a tool this caller would be shown is waited for: the routing
    /// profile and the listing predicate, in `resolve_surfaced_tool`'s order.
    pub(crate) async fn wait_surfaced_first_fill(
        &self,
        scope: super::InvokeScope<'_>,
        session_id: Option<&str>,
    ) {
        // Code Mode lists no surfaced tools: nothing to wait for.
        if self.code_mode_enabled {
            return;
        }
        let profile = self.active_profile(session_id);
        let mut cold: Vec<Arc<Backend>> = Vec::new();
        for surfaced in &self.surfaced_state().tools {
            if profile.check(&surfaced.server, &surfaced.tool).is_err()
                || !self.listing_names(
                    &surfaced.server,
                    &surfaced.tool,
                    scope,
                    session_id,
                    super::listing_view::ColdRule::SharedView,
                )
            {
                continue;
            }
            let Some(backend) = self
                .backends
                .get_for(Unscoped::Visibility, &surfaced.server)
            else {
                continue;
            };
            if !backend.shared_slot_refused()
                && !backend.cached_tools_known()
                && !cold.iter().any(|seen| seen.name == backend.name)
            {
                cold.push(backend);
            }
        }
        let Some(bound) = cold.iter().map(|backend| backend.tools_fill_bound()).max() else {
            return;
        };
        let deadline = tokio::time::Instant::now() + bound.min(LISTING_DEADLINE_CAP);
        let fills: Vec<_> = cold
            .iter()
            .map(|backend| {
                let backend = Arc::clone(backend);
                tokio::spawn(carried(
                    async move { drop(backend.get_tools_shared().await) },
                ))
            })
            .collect();
        if tokio::time::timeout_at(deadline, futures::future::join_all(fills))
            .await
            .is_err()
        {
            let unfilled: Vec<&str> = cold
                .iter()
                .filter(|backend| !backend.cached_tools_known())
                .map(|backend| backend.name.as_str())
                .collect();
            warn!(
                ?unfilled,
                "first tools/list: surfaced backends not filled by the deadline; \
                 their tools are left out of this list"
            );
        }
    }
}

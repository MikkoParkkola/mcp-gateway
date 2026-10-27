// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A listing's warm of a caller's cold per-user views (MIK-8962 SHARED.5).
//!
//! A backend that never opens a shared session has no shared catalogue to
//! show a caller whose own view is cold. Before `tools/list` is built, that
//! caller's own view of each such backend with a surfaced tool is
//! re-established through the checks a stored read runs, in the same order:
//! the account pre-pass and `claim_caller_view`, both through the caller's own
//! backend grant, before any credential is resolved or any backend is reached.

use super::MetaMcp;
use super::account_outcome::AccountWrites;
use super::scoped_backends::Unscoped;
use super::visibility::InvokeScope;

impl MetaMcp {
    /// Warm the caller's cold views of the surfaced tools' backends that
    /// refuse a shared session, and wait for each before the list is built.
    /// A won claim's fill runs as its own task, bounded by its backend's own
    /// fill bound; a view another reader's lease is filling is waited on, up
    /// to the same bound, and served from that fill. The listing waits for
    /// every fill to end, so none publishes after this response: a backend
    /// past its own bound is cut off and absent, with no later
    /// `tools/list_changed` from here. The claims themselves (the pre-pass
    /// and the credential resolution) are bounded by the longest fill bound;
    /// a claim cut there spawned no fill, and its lease lapses.
    pub(crate) async fn warm_listing_views(
        &self,
        scope: InvokeScope<'_>,
        session_id: Option<&str>,
    ) {
        let surfaced = self.surfaced_state();
        // A config read only: which backends refuse a shared session. Whether
        // this caller may reach one is decided by the scoped checks below.
        let refused: Vec<_> = surfaced
            .tools
            .iter()
            .filter_map(|surfaced| {
                let backend = self
                    .backends
                    .get_for(Unscoped::Visibility, &surfaced.server)?;
                backend
                    .shared_slot_refused()
                    .then(|| ((surfaced.server.as_str(), surfaced.tool.as_str()), backend))
            })
            .collect();
        let Some(claims_bound) = refused
            .iter()
            .map(|(_, backend)| backend.tools_fill_bound())
            .max()
        else {
            return;
        };
        let targets: Vec<(&str, &str)> = refused.iter().map(|(target, _)| *target).collect();
        let mut fills = Vec::new();
        let mut leased = Vec::new();
        let claim = async {
            // A listing is not a call: a busy custody writes no transient
            // refusal record here.
            self.account_prepass(&targets, scope, session_id, AccountWrites::PermanentOnly)
                .await;
            for &(server, tool) in &targets {
                match self
                    .claim_caller_view(server, tool, scope, session_id)
                    .await
                {
                    Some(fill) => fills.push(tokio::spawn(fill.run())),
                    None => leased.extend(self.running_cold_lease(server, scope)),
                }
            }
        };
        let _ = tokio::time::timeout(claims_bound, claim).await;
        let waits = leased.iter().map(|(backend, id)| async move {
            let _ =
                tokio::time::timeout(backend.tools_fill_bound(), backend.wait_cold_lease(id)).await;
        });
        futures::future::join(
            futures::future::join_all(fills),
            futures::future::join_all(waits),
        )
        .await;
    }

    /// The caller's cold lease on `server` another reader holds, if one
    /// runs, through the caller's own backend grant.
    fn running_cold_lease(
        &self,
        server: &str,
        scope: InvokeScope<'_>,
    ) -> Option<(std::sync::Arc<crate::backend::Backend>, String)> {
        let backend = self
            .scoped(scope.authorizer.backend_grant())
            .scoped_get(server)?;
        let id = self
            .principal_for(&backend, scope.caller)?
            .stable_actor_id();
        backend.cold_lease_remaining(&id)?;
        Some((backend, id))
    }
}

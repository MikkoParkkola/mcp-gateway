// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A listing's warm of a caller's cold per-user views (SHARED.5).
//!
//! A backend that never opens a shared session has no shared catalogue to
//! show a caller whose own view is cold. Before `tools/list` is built, that
//! caller's own view of each such backend with a surfaced tool is
//! re-established through the checks a stored read runs, in the same order:
//! the account pre-pass and `claim_caller_view`, both through the caller's own
//! backend grant, before any credential is resolved or any backend is reached.

use std::sync::Arc;

use super::MetaMcp;
use super::account_outcome::AccountWrites;
use super::scoped_backends::Unscoped;
use super::visibility::InvokeScope;
use crate::gateway::health_metrics::clock::{backend_wait, carried};

/// The longest a listing waits for the fills it starts or finds: half the
/// MCP TypeScript SDK's default request timeout (60 s), so a cold listing
/// answers well before a client gives up.
/// Nothing on the gateway bounds an inbound request: `server.request_timeout`
/// was never enforced and is gone in 4.0.
pub(crate) const LISTING_DEADLINE_CAP: std::time::Duration = std::time::Duration::from_secs(30);

impl MetaMcp {
    /// Warm the caller's cold views of the surfaced tools' backends that
    /// refuse a shared session, every claim at once, and wait for them under
    /// one deadline from here: the longest fill bound among the backends this
    /// listing fills or waits on, capped at [`LISTING_DEADLINE_CAP`]. A won
    /// claim's fill runs as its own task, bounded by its backend's own fill
    /// bound; a view another reader's lease is filling is waited on and served
    /// from that fill, and a view filled under a grant that rotated since
    /// reads as cold. A fill still running at the deadline is left out of this
    /// listing and finishes on its own lease; when its slot stores,
    /// `tools_nudge` sends the caller `tools/list_changed`.
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
                    .then_some(((surfaced.server.as_str(), surfaced.tool.as_str()), backend))
            })
            .collect();
        // Every surfaced tool claims: a policy that refuses one tool must not
        // keep its allowed sibling on the same backend cold. A second claim on
        // one backend finds the first's lease and waits on it.
        let targets: Vec<(&str, &str)> = refused.iter().map(|(target, _)| *target).collect();
        let Some(ceiling) = refused
            .iter()
            .map(|(_, backend)| backend.tools_fill_bound())
            .max()
        else {
            return;
        };
        let started = tokio::time::Instant::now();
        // One deadline for the whole step: the claims and the waits both end
        // by it.
        let ceiling = started + ceiling.min(LISTING_DEADLINE_CAP);
        let claims = async {
            #[cfg(test)]
            for (_, backend) in &refused {
                backend.before_listing_prepass.pause().await;
            }
            // A listing is not a call: a busy custody writes no transient
            // refusal record here.
            self.account_prepass(&targets, scope, session_id, AccountWrites::PermanentOnly)
                .await;
            // Concurrent, so a slow resolution on one backend does not eat
            // another's share of the deadline.
            futures::future::join_all(refused.iter().map(|((server, tool), backend)| async move {
                if let Some(fill) = self
                    .claim_caller_view(server, tool, scope, session_id)
                    .await
                {
                    Some(Pending::Fill(
                        fill.backend_bound(),
                        tokio::spawn(carried(fill.run())),
                    ))
                } else {
                    #[cfg(test)]
                    backend.before_lease_lookup.pause().await;
                    #[cfg(not(test))]
                    let _ = backend;
                    self.running_cold_lease(server, scope)
                        .map(|(backend, id)| Pending::Leased(backend, id))
                }
            }))
            .await
        };
        let Ok(pending) = tokio::time::timeout_at(ceiling, claims).await else {
            // Cut short, the pre-pass may not have read a target's account:
            // fail closed, so no held view of it is shown unchecked.
            for (_, backend) in &refused {
                if let Some(account) = backend.account_descriptor_id() {
                    super::visible::memo::record_account_unchecked(
                        &backend.name,
                        &super::visible::memo::DescriptorId(account.to_owned()),
                    );
                }
            }
            return;
        };
        let pending: Vec<Pending> = pending.into_iter().flatten().collect();
        // The deadline covers only the backends this listing fills or waits
        // on, from the step's start.
        let Some(bound) = pending.iter().map(Pending::bound).max() else {
            return;
        };
        let waits = pending.into_iter().map(|pending| async move {
            match pending {
                Pending::Fill(_, fill) => {
                    let _ = fill.await;
                }
                // Another reader's fill on a backend: waiting on it is backend wait.
                Pending::Leased(backend, id) => {
                    backend_wait(backend.wait_cold_lease(&id)).await;
                }
            }
        });
        let deadline = ceiling.min(started + bound.min(LISTING_DEADLINE_CAP));
        let _ = tokio::time::timeout_at(deadline, futures::future::join_all(waits)).await;
    }

    /// The caller's cold lease on `server` another reader holds, if its
    /// lookup or fill still runs, through the caller's own backend grant. A
    /// settled lease (a failed attempt's retry backoff) has nothing to wait
    /// for.
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
        backend.cold_fill_remaining(&id)?;
        Some((backend, id))
    }
}

/// What a listing's claim on one backend left it to wait for.
enum Pending {
    /// This listing won the claim; its fill runs as its own task.
    Fill(std::time::Duration, tokio::task::JoinHandle<()>),
    /// Another reader's lease is filling the caller's view; a view it filled
    /// under a grant that rotated since reads as cold when the list is built.
    Leased(Arc<crate::backend::Backend>, String),
}

impl Pending {
    /// The backend's fill bound.
    fn bound(&self) -> std::time::Duration {
        match self {
            Self::Fill(bound, _) => *bound,
            Self::Leased(backend, _) => backend.tools_fill_bound(),
        }
    }
}

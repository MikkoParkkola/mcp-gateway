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

/// The longest a listing waits for the fills it starts or finds: half the
/// MCP TypeScript SDK's default request timeout (60 s), so a cold listing
/// answers well before a client gives up.
/// Nothing on the gateway bounds an inbound request: `server.request_timeout`
/// was never enforced and is gone in 4.0.
pub(crate) const LISTING_DEADLINE_CAP: std::time::Duration = std::time::Duration::from_secs(30);

impl MetaMcp {
    /// Warm the caller's cold views of the surfaced tools' backends that
    /// refuse a shared session, one claim per backend, all at once, and wait
    /// for them under one deadline from here: the longest fill bound among
    /// the backends this listing fills or waits on, capped at
    /// [`LISTING_DEADLINE_CAP`]. A won claim's fill runs as its own task,
    /// bounded by its backend's own fill bound; a view another reader's lease
    /// is filling is waited on and served from that fill, unless the caller's
    /// grant rotated meanwhile. A fill still running at the deadline is left
    /// out of this listing and finishes on its own lease; when its slot
    /// stores, `tools_nudge` sends the caller `tools/list_changed`.
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
        // One claim per backend: several surfaced tools of one backend share
        // the caller's one slot there.
        let mut seen = std::collections::HashSet::new();
        let targets: Vec<(&str, &str)> = refused
            .iter()
            .map(|(target, _)| *target)
            .filter(|(server, _)| seen.insert(*server))
            .collect();
        let started = tokio::time::Instant::now();
        let claims = async {
            // A listing is not a call: a busy custody writes no transient
            // refusal record here.
            self.account_prepass(&targets, scope, session_id, AccountWrites::PermanentOnly)
                .await;
            // Concurrent, so a slow resolution on one backend does not eat
            // another's share of the deadline.
            futures::future::join_all(targets.iter().map(|&(server, tool)| async move {
                match self
                    .claim_caller_view(server, tool, scope, session_id)
                    .await
                {
                    Some(fill) => Some(Pending::Fill(
                        fill.backend_bound(),
                        tokio::spawn(fill.run()),
                    )),
                    None => self
                        .running_cold_lease(server, scope)
                        .map(|(backend, id)| Pending::Leased((server, tool), backend, id)),
                }
            }))
            .await
        };
        let Ok(pending) = tokio::time::timeout(LISTING_DEADLINE_CAP, claims).await else {
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
                Pending::Leased(target, backend, id) => {
                    backend.wait_cold_lease(&id).await;
                    self.forget_if_rotated(target, scope, &backend, &id);
                }
            }
        });
        let deadline = started + bound.min(LISTING_DEADLINE_CAP);
        let _ = tokio::time::timeout_at(deadline, futures::future::join_all(waits)).await;
    }

    /// A view another reader's lease filled is kept only while it is still
    /// the caller's current grant's: a lease claimed before a rotation
    /// publishes the old grant's slot, and that view is forgotten here, as a
    /// warm view's revalidation forgets it.
    fn forget_if_rotated(
        &self,
        (server, tool): (&str, &str),
        scope: InvokeScope<'_>,
        backend: &crate::backend::Backend,
        id: &str,
    ) {
        let Some(held) = backend.caller_slot_held(id) else {
            return;
        };
        let current = self
            .target_account(&self.scoped(scope.authorizer.backend_grant()), server, tool)
            .and_then(|account| super::visible::memo::account_binding(server, &account));
        if !current.is_none_or(|current| current == held.binding()) {
            backend.forget_caller_held(id, &held);
        }
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

/// What a listing's claim on one backend left it to wait for.
enum Pending<'a> {
    /// This listing won the claim; its fill runs as its own task.
    Fill(std::time::Duration, tokio::task::JoinHandle<()>),
    /// Another reader's lease is filling the caller's view.
    Leased((&'a str, &'a str), Arc<crate::backend::Backend>, String),
}

impl Pending<'_> {
    /// The backend's fill bound.
    fn bound(&self) -> std::time::Duration {
        match self {
            Self::Fill(bound, _) => *bound,
            Self::Leased(_, backend, _) => backend.tools_fill_bound(),
        }
    }
}

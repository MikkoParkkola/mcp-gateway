// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! What a listener run listens on, chosen once at its start (MIK-8835): the
//! transport's own session or the transport itself, the era it speaks, the
//! flavour it started on, and the ledger cleanup an own session's end runs.

use std::sync::{Arc, Weak};

use tracing::debug;

use crate::backend::Backend;
use crate::backend::listen::ListenTarget;
use crate::events::upstream_listener::Shared;
use crate::events::upstream_session::ToolsDebt;
use crate::protocol::era::PeerEra;
use crate::transport::upstream_tap::{ListenerCredential, UpstreamListen};

/// What a run listens on, chosen once at its start.
pub(super) struct Run {
    /// Keeps the idle reaper off the shared slot while the run lasts; a
    /// per-user run holds none.
    _lease: Option<crate::backend::listen::ListenLease>,
    /// The shared slot's transport: a replaced one ends the run. `None` for a
    /// per-user run, which listens on a transport of its own and ends when
    /// its backend is replaced.
    pub(super) transport: Option<Weak<dyn UpstreamListen>>,
    /// What the run's calls go to: an own session, or `transport` itself.
    pub(super) handle: Weak<dyn UpstreamListen>,
    /// An own session speaks the legacy transport whatever the slot's cached
    /// era says (B12).
    pub(super) era: PeerEra,
    /// The transport flavour the run starts on: a recovery that switches it
    /// in place keeps the same transport, so only this read sees it (B2).
    pub(super) flavour: Option<bool>,
    /// An own session, kept alive for the run.
    _own: Option<Arc<dyn UpstreamListen>>,
    /// A per-user run's own transport, which its session holds only weakly.
    _own_transport: Option<Arc<crate::transport::HttpTransport>>,
    /// An own session's subscriptions end with it, however the run ends; any
    /// `release` runs first, inside the run (B14').
    _retire: Option<RetireOnEnd>,
    /// A minted per-user run's fence: its binding stamps what it emits, and a
    /// moved grant ends it. `None` for a shared or leased run.
    pub(super) fence: Option<Arc<crate::events::listener_credential::RunFence>>,
}

/// Start a run: reach the backend and choose its session. A shared key
/// listens on the shared slot with the gateway's own credential; a per-user
/// key on a transport of its own with its subscriber's. `None`: the backend
/// is not reachable, or a per-user key has no credential or session to be
/// had and the run fails closed.
pub(super) async fn begin_run(
    shared: &Arc<Shared>,
    backend: &Backend,
    hub: &Weak<crate::events::EventsHub>,
) -> Option<Run> {
    shared.refresh_ledger();
    if shared.key.obs.is_some() {
        return begin_per_user_run(shared, backend, hub).await;
    }
    let lease = backend.listen_lease();
    let target: ListenTarget = match backend.listen_target().await {
        Ok(target) => target,
        Err(error) => {
            debug!(backend = %shared.name, error = %shared.error_text(&error), "upstream listener: backend not reachable");
            return None;
        }
    };
    let flavour = backend.connected_streamable();
    let (own, handle) = pick_session(&target.handle, ListenerCredential::shared())?;
    // An SSE own session speaks the legacy handshake.
    let era = if runs_modern(own.is_some(), target.era) {
        PeerEra::Modern
    } else {
        PeerEra::Legacy
    };
    Some(Run {
        _lease: Some(lease),
        transport: Some(target.handle),
        handle,
        era,
        flavour,
        _retire: own.is_some().then(|| RetireOnEnd(Arc::clone(shared))),
        _own: own,
        _own_transport: None,
        fence: None,
    })
}

/// A per-user key's run: its own unstarted transport, whose session makes
/// every request, its era probe and `initialize` included, with the
/// subscriber's credential. The shared slot is never started or read, so a
/// backend that refuses the gateway's credential still serves the
/// subscriber's own.
async fn begin_per_user_run(
    shared: &Arc<Shared>,
    backend: &Backend,
    hub: &Weak<crate::events::EventsHub>,
) -> Option<Run> {
    let Some((credential, fence)) = crate::events::listener_credential::for_key(&shared.key, hub)
    else {
        debug!(backend = %shared.name, "upstream listener: no credential for a per-user key");
        return None;
    };
    let transport = match backend.listener_transport() {
        Ok(transport) => transport,
        Err(error) => {
            debug!(backend = %shared.name, error = %shared.error_text(&error), "upstream listener: no transport for a per-user key");
            return None;
        }
    };
    let Some((own, era)) = transport.per_user_session(&shared.name, credential).await else {
        debug!(backend = %shared.name, "upstream listener: an identity credential has no session of its own");
        return None;
    };
    // Its session's first mint has fixed the run's grant by now.
    if let Some(run) = &fence {
        forget_foreign_debt(&mut shared.tools.lock(), run.binding());
    }
    Some(Run {
        _lease: None,
        transport: None,
        handle: Arc::downgrade(&own),
        era,
        flavour: None,
        _retire: Some(RetireOnEnd(Arc::clone(shared))),
        _own: Some(own),
        _own_transport: Some(transport),
        fence,
    })
}

/// A tools notice an earlier run left pending was heard under that run's
/// grant: a run fixed on another grant (`binding`) never announces it.
fn forget_foreign_debt(debt: &mut ToolsDebt, binding: Option<String>) {
    if debt.fence != binding {
        *debt = ToolsDebt::default();
    }
}

/// Whether a run speaks the modern transport: never on an own session, which
/// is the legacy SSE handshake whatever the slot's cached era (design B12).
pub(super) fn runs_modern(own_session: bool, era: PeerEra) -> bool {
    !own_session && era == PeerEra::Modern
}

/// Retires the run's ledger holder when an own session's run ends.
struct RetireOnEnd(Arc<Shared>);

impl Drop for RetireOnEnd {
    fn drop(&mut self) {
        self.0.ledger().lock().retire_holder();
    }
}

/// An own session (kept alive for the run), and the handle the run upgrades.
type Picked = (Option<Arc<dyn UpstreamListen>>, Weak<dyn UpstreamListen>);

/// The session a run listens on: the transport's own session when it offers
/// one (the SSE handshake), the transport itself otherwise. `None` when
/// `credential` names an identity and there is no own session: the run must
/// never fall back to the shared transport and its gateway credential
/// (MIK-8835.SSE.4, design B6). The `Arc` keeps an own session alive for the
/// run; the `Weak` is what the run's calls upgrade.
pub(super) fn pick_session(
    transport: &Weak<dyn UpstreamListen>,
    credential: ListenerCredential,
) -> Option<Picked> {
    let identity = credential.source.is_some();
    let own = transport.upgrade().and_then(|t| t.own_session(credential));
    match own {
        Some(own) => {
            let handle = Arc::downgrade(&own);
            Some((Some(own), handle))
        }
        None if identity => None,
        None => Some((None, transport.clone())),
    }
}

#[cfg(test)]
#[path = "upstream_session_run_tests.rs"]
mod tests;

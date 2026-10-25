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
use crate::protocol::era::PeerEra;
use crate::transport::upstream_tap::{ListenerCredential, UpstreamListen};

/// What a run listens on, chosen once at its start.
pub(super) struct Run {
    /// Keeps the idle reaper off the shared slot while the run lasts.
    _lease: crate::backend::listen::ListenLease,
    /// The shared slot's transport: a replaced one ends the run.
    pub(super) transport: Weak<dyn UpstreamListen>,
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
    /// An own session's subscriptions end with it, however the run ends; any
    /// `release` runs first, inside the run (B14').
    _retire: Option<RetireOnEnd>,
}

/// Start a run: reach the backend and choose its session. P3 listens with
/// the gateway's own credential; MIK-8833 passes the key's. `None`: the
/// backend is not reachable, or an identity credential has no session of its
/// own and the run fails closed.
pub(super) async fn begin_run(
    shared: &Arc<Shared>,
    backend: &Backend,
    hub: &Weak<crate::events::EventsHub>,
) -> Option<Run> {
    shared.refresh_ledger();
    let lease = backend.listen_lease();
    let target: ListenTarget = match backend.listen_target().await {
        Ok(target) => target,
        Err(error) => {
            debug!(backend = %shared.name, error = %shared.error_text(&error), "upstream listener: backend not reachable");
            return None;
        }
    };
    let flavour = backend.connected_streamable();
    // A per-user key listens only as its subscriber, never as the gateway:
    // with no credential to be had it does not run.
    let Some(credential) = crate::events::listener_credential::for_key(&shared.key, hub) else {
        debug!(backend = %shared.name, "upstream listener: no credential for a per-user key");
        return None;
    };
    let Some((own, handle)) = pick_session(&target.handle, credential) else {
        debug!(backend = %shared.name, "upstream listener: an identity credential has no session of its own");
        return None;
    };
    // An SSE own session speaks the legacy handshake; a Streamable HTTP one
    // (a per-user listener's) the era the slot detected.
    let sse_own = own
        .as_ref()
        .is_some_and(|o| o.detected_streamable() != Some(true));
    let era = if runs_modern(sse_own, target.era) {
        PeerEra::Modern
    } else {
        PeerEra::Legacy
    };
    Some(Run {
        _lease: lease,
        transport: target.handle,
        handle,
        era,
        flavour,
        _retire: own.is_some().then(|| RetireOnEnd(Arc::clone(shared))),
        _own: own,
    })
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

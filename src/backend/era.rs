// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Protocol-era probing for one backend (MIK-7217, DISCOVER.4).
//!
//! A peer's era is a property of the *process* on the other end of the
//! transport, so it is resolved once per start and cached on the backend
//! rather than re-derived per request.

use std::sync::Arc;
use std::time::Duration;

use super::Backend;
use crate::protocol::JsonRpcResponse;
use crate::protocol::era::{Era, EraObservation, ProbeOutcome, classify};
use crate::transport::Transport;

/// Method a modern peer answers with its discovery document.
const DISCOVER_METHOD: &str = "server/discover";

/// Upper bound on how long a start waits for the probe to come back.
///
/// A peer that ignores `server/discover` entirely must not hold the start path
/// open for the full request timeout. Bounding it is safe because silence is
/// never cached: a probe cut short here is retried on the next start, not
/// remembered as a verdict.
const PROBE_TIMEOUT: Duration = Duration::from_secs(2);

/// Send one `server/discover` and describe what came back.
///
/// Every failure is [`ProbeOutcome::NoAnswer`] rather than an error, so a probe
/// can never fail a start: the era is an optimisation, the connection is not.
async fn probe(transport: &Arc<dyn Transport>, timeout: Duration) -> ProbeOutcome {
    match tokio::time::timeout(timeout, transport.request(DISCOVER_METHOD, None)).await {
        Ok(Ok(response)) => outcome_of(response),
        Ok(Err(_)) | Err(_) => ProbeOutcome::NoAnswer,
    }
}

/// Map one probe response onto a [`ProbeOutcome`]; `classify` decides the era.
fn outcome_of(response: JsonRpcResponse) -> ProbeOutcome {
    if let Some(error) = response.error {
        return ProbeOutcome::Error(error.code);
    }
    response
        .result
        .map_or(ProbeOutcome::NoAnswer, ProbeOutcome::Result)
}

/// Whether an ordinary request's error answer is itself proof of a modern peer.
///
/// Read through [`classify`] rather than re-listing the codes, so the set of
/// modern-only errors lives in exactly one place.
fn contradicts_legacy(code: i32) -> bool {
    classify(&ProbeOutcome::Error(code)) == Era::Modern
}

impl Backend {
    /// The era this backend's peer was last observed to speak, if it has been
    /// resolved. Never probes: a caller asking what is known must not change
    /// what is known.
    pub async fn cached_era(&self) -> Option<Era> {
        self.era.cached().await
    }

    /// Everything an operator can see about this backend's era, for
    /// `gateway_list_servers`. Never probes.
    pub async fn era_observation(&self) -> EraObservation {
        self.era.observation().await
    }

    /// Resolve the era of a freshly started peer, probing at most once.
    ///
    /// Awaited on the start path so the first request already knows which
    /// dialect to speak.
    ///
    /// NOTE (lock order): callers hold the slot's `start_lock`, so this takes
    /// `start_lock` -> era mutex. Anything holding the era mutex must therefore
    /// use a transport handle it already owns and must never call back into
    /// `ensure_entry_started`, which would invert the order.
    pub(super) async fn resolve_era(&self, transport: &Arc<dyn Transport>) {
        let timeout = self.probe_timeout();
        // A start hands over a transport to a process that has only just come
        // up. Any era already determined describes the peer that came before
        // it, which an upgrade or a downgrade may have replaced, so carrying
        // the verdict across the swap asserts something never observed about
        // the peer now on the wire. Guarded on a determination existing so a
        // cold start does not emit a discard record for a belief it never had.
        if self.era.cached().await.is_some() {
            self.era.invalidate_because("restart").await;
        }
        self.era.resolve_with(|| probe(transport, timeout)).await;
    }

    /// Re-probe when an ordinary response contradicts a cached `Legacy` verdict.
    ///
    /// A peer that answers a normal call with a 2026-only error code is modern
    /// however its probe went, so the stale verdict is dropped and one fresh
    /// probe is run. Detached: the request that noticed must not pay for it.
    pub(super) async fn reprobe_if_contradicted(
        &self,
        response: &JsonRpcResponse,
        transport: &Arc<dyn Transport>,
    ) {
        let Some(error) = response.error.as_ref() else {
            return;
        };
        if !contradicts_legacy(error.code) || self.cached_era().await != Some(Era::Legacy) {
            return;
        }

        let era = Arc::clone(&self.era);
        let transport = Arc::clone(transport);
        let timeout = self.probe_timeout();
        tokio::spawn(async move {
            era.invalidate().await;
            era.reprobe_with(|| probe(&transport, timeout)).await;
        });
    }

    /// Probe deadline: never longer than the backend's own request timeout.
    fn probe_timeout(&self) -> Duration {
        self.config.timeout.min(PROBE_TIMEOUT)
    }
}

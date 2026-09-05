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
use crate::protocol::era::{Era, EraObservation, METHOD_NOT_FOUND_CODE, ProbeOutcome, classify};
use crate::protocol::meta::ADDED_IN_2026_07_28;
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

/// Whether an ordinary request's error answer disproves a cached `Modern` verdict.
///
/// Narrow on purpose, and the narrowness is the design: only `method not found`, and only against
/// a method that exists solely in the modern revision. A modern peer may reject any other method
/// for reasons of its own, and a transport fault or a refused credential is a failure to surface
/// rather than evidence about which dialect the peer speaks. Widening this to a family of codes
/// would file real faults as a benign "peer is older than we thought".
///
/// The modern-only set is read from [`ADDED_IN_2026_07_28`] rather than re-listed here, so a
/// method added to the revision is covered by this check without a second edit — a second list
/// would go stale silently, and the failure would be a re-probe that never fires.
fn contradicts_modern(method: &str, code: i32) -> bool {
    code == METHOD_NOT_FOUND_CODE
        && (method == DISCOVER_METHOD || ADDED_IN_2026_07_28.contains(&method))
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
        // the peer now on the wire. Discard and probe are one locked step: a
        // detached re-probe of the old peer must not be able to land between them.
        self.era.restart_with(|| probe(transport, timeout)).await;
    }

    /// Re-probe when an ordinary response contradicts the cached verdict.
    ///
    /// The clause is symmetric, so both directions are read. A peer that answers
    /// a normal call with a 2026-only error code is modern however its probe
    /// went; a peer that answers a 2026-only method `method not found` is not
    /// modern however its probe went. Either way the stale verdict is dropped
    /// and one fresh probe is run, detached: the request that noticed must not
    /// pay for it.
    pub(super) async fn reprobe_if_contradicted(
        &self,
        method: &str,
        response: &JsonRpcResponse,
        transport: &Arc<dyn Transport>,
    ) {
        let Some(error) = response.error.as_ref() else {
            return;
        };
        // Judging the verdict and dropping it are one locked step, and only the task that
        // dropped it probes. Reading the era and clearing it separately would let two answers
        // arriving at once both find the stale verdict and each fan out a detached probe.
        let discarded = self
            .era
            .discard_if(|era| match era {
                Era::Legacy => contradicts_legacy(error.code),
                Era::Modern => contradicts_modern(method, error.code),
            })
            .await;
        if !discarded {
            return;
        }

        let era = Arc::clone(&self.era);
        let transport = Arc::clone(transport);
        let timeout = self.probe_timeout();
        tokio::spawn(async move {
            era.reprobe_with(|| probe(&transport, timeout)).await;
        });
    }

    /// Probe deadline: never longer than the backend's own request timeout.
    fn probe_timeout(&self) -> Duration {
        self.config.timeout.min(PROBE_TIMEOUT)
    }
}

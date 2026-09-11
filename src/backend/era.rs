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
use crate::Result;
use crate::error::Error;
use crate::protocol::JsonRpcResponse;
use crate::protocol::era::{Era, EraObservation, METHOD_NOT_FOUND_CODE, ProbeOutcome, classify};
use crate::transport::Transport;

/// Method a modern peer answers with its discovery document.
const DISCOVER_METHOD: &str = "server/discover";

/// Liveness method of every revision before 2026-07-28, removed by that one.
const PING_METHOD: &str = "ping";

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

/// The JSON-RPC error code in an answer, whichever way the peer carried it.
///
/// A refusal is a refusal whether it arrives in-band, as an error object in a
/// 200 response, or status-carried, as a non-2xx whose body the HTTP transport
/// parsed into [`Error::JsonRpc`]. The two carriages are one wire fact and the
/// probe must judge them the same, or a peer that declines over HTTP is torn
/// down while the same peer over stdio is left alone. `None` means the answer
/// is not a refusal: either the peer served it, or the transport itself broke.
pub(super) fn refusal_code(answer: &Result<JsonRpcResponse>) -> Option<i32> {
    match answer {
        Ok(response) => response.error.as_ref().map(|error| error.code),
        Err(Error::JsonRpc { code, .. }) => Some(*code),
        Err(_) => None,
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
/// The set is exactly [`DISCOVER_METHOD`], named rather than listed. The revision's other
/// additions — the `tasks/*` and `subscriptions/listen` extension methods — are optional and
/// capability-gated, so a peer that fully speaks 2026-07-28 may answer them `method not found`
/// for the ordinary reason that it does not implement that extension. Reading those answers as
/// evidence would downgrade a modern peer for declining an option the revision lets it decline.
/// Discovery is the one method the revision requires of every peer, which is what makes its
/// absence say something about the peer's era rather than about its feature set.
fn contradicts_modern(method: &str, code: i32) -> bool {
    code == METHOD_NOT_FOUND_CODE && method == DISCOVER_METHOD
}

impl Backend {
    /// The era this backend's peer was last observed to speak, if it has been
    /// resolved. Never probes: a caller asking what is known must not change
    /// what is known.
    pub async fn cached_era(&self) -> Option<Era> {
        self.era.cached().await
    }

    /// Which liveness method this peer's era answers.
    ///
    /// `ping` was removed in the 2026-07-28 revision, so a peer known to speak
    /// it is asked for its discovery document instead. Every other state -
    /// legacy, or an era never resolved - keeps `ping`: silence is not evidence
    /// of modernity, so an unresolved peer must not be sent a method only a
    /// modern peer answers.
    pub(super) async fn liveness_method(&self) -> &'static str {
        match self.cached_era().await {
            Some(Era::Modern) => DISCOVER_METHOD,
            Some(Era::Legacy) | None => PING_METHOD,
        }
    }

    /// Everything an operator can see about this backend's era, for
    /// `gateway_list_servers`. Never probes.
    pub async fn era_observation(&self) -> EraObservation {
        self.era.observation().await
    }

    /// Test-only reach-through to [`Backend::resolve_era`] for rows that live
    /// outside `crate::backend`: the section 4 gate rows exercise gateway call
    /// sites and still need a peer whose era came from its own answer rather
    /// than from a setter. A `#[cfg(test)]` wrapper rather than widening
    /// `resolve_era` itself, so the production visibility stays `pub(super)`.
    #[cfg(test)]
    pub(crate) async fn resolve_era_for_test(&self, transport: &Arc<dyn Transport>) {
        self.resolve_era(transport).await;
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
        self.reprobe_if_code_contradicts(method, error.code, transport)
            .await;
    }

    /// [`Self::reprobe_if_contradicted`] keyed on the code alone, for callers
    /// that hold a refusal which never arrived as a [`JsonRpcResponse`] - a
    /// status-carried error from the HTTP transport reaches its caller as
    /// [`Error::JsonRpc`], with the same code and the same evidentiary weight.
    pub(super) async fn reprobe_if_code_contradicts(
        &self,
        method: &str,
        code: i32,
        transport: &Arc<dyn Transport>,
    ) {
        // Judging the verdict and dropping it are one locked step, and only the task that
        // dropped it probes. Reading the era and clearing it separately would let two answers
        // arriving at once both find the stale verdict and each fan out a detached probe.
        let discarded = self
            .era
            .discard_if(|era| match era {
                Era::Legacy => contradicts_legacy(code),
                Era::Modern => contradicts_modern(method, code),
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::era::UNSUPPORTED_PROTOCOL_VERSION;
    use crate::protocol::meta::ADDED_IN_2026_07_28;

    /// An optional extension the peer declined is not evidence about its era.
    ///
    /// The revision adds these methods and lets a peer omit them, so their `method not found`
    /// answer is a statement about implemented features. Only discovery, which every peer of
    /// this revision must answer, disproves a modern verdict.
    #[test]
    fn declining_an_optional_extension_does_not_disprove_a_modern_peer() {
        for method in ADDED_IN_2026_07_28 {
            assert!(
                !contradicts_modern(method, METHOD_NOT_FOUND_CODE),
                "{method} is optional in this revision, so refusing it says nothing about era"
            );
        }
        assert!(contradicts_modern(DISCOVER_METHOD, METHOD_NOT_FOUND_CODE));
        assert!(!contradicts_modern(
            DISCOVER_METHOD,
            UNSUPPORTED_PROTOCOL_VERSION
        ));
    }

    /// Whichever method the probe chooses for an era, HTTP session recovery
    /// must be allowed to resend it. The recovery path re-initializes the
    /// session and then asks [`resend_permission`] whether it may repeat the
    /// request; a `Denied` there hands the caller back the original error, and
    /// the probe reads that as a fault and rebuilds a working backend's
    /// transport. `ping` was on the allowlist, so swapping the modern probe to
    /// `server/discover` silently took that recovery away from exactly the
    /// peers OUTBOUND.1 was written for (MIK-7217, OUTBOUND.1).
    #[test]
    fn every_liveness_method_survives_a_session_resend() {
        use crate::transport::{ResendPermission, resend_permission};
        let no_tools = std::collections::HashSet::<String>::new();
        for method in [PING_METHOD, DISCOVER_METHOD] {
            assert_eq!(
                resend_permission(method, None, &no_tools),
                ResendPermission::Permitted,
                "the probe sends {method}, so session recovery must be able to resend it"
            );
        }
    }
}

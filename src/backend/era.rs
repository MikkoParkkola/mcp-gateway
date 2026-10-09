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
use super::PooledEntry;
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

/// Whether `entry` is serving exactly `transport`, by identity.
fn holds(entry: &PooledEntry, transport: &Arc<dyn Transport>) -> bool {
    entry
        .transport
        .read()
        .as_ref()
        .is_some_and(|held| same(held, transport))
}

/// Identity, not equality: the address of the transport, ignoring the vtable half of the
/// fat pointer, which may legitimately differ between codegen units.
fn same(a: &Arc<dyn Transport>, b: &Arc<dyn Transport>) -> bool {
    std::ptr::addr_eq(Arc::as_ptr(a), Arc::as_ptr(b))
}

/// Run `store` if `entry` still serves `transport`, holding the slot's read guard through
/// it: a replacement takes the write guard, so it either happened before this check (the
/// answer is refused) or waits for the write (the answer was about the peer then in service).
/// Both halves are synchronous, which is what makes check and write one step.
///
/// Serving means pooled as well as holding it: a removed busy entry keeps its transport, and
/// the pool marks it retired under that same write guard before it leaves the map (MIK-7643).
pub(super) fn with_serving(
    entry: &PooledEntry,
    transport: &Arc<dyn Transport>,
    store: &mut dyn FnMut(),
) -> bool {
    let slot = entry.transport.read();
    let held = !entry.retired.load(std::sync::atomic::Ordering::SeqCst)
        && slot.as_ref().is_some_and(|held| same(held, transport));
    if held {
        store();
    }
    held
}

/// Run `step` unless the pool has retired `entry`, holding the slot's read guard through
/// it, as [`with_serving`] does. For the start path, whose transport the entry may not
/// hold yet (an HTTP start probes before it publishes), so membership is the whole test.
pub(super) fn unless_retired(entry: &PooledEntry, step: &mut dyn FnMut()) -> bool {
    let _slot = entry.transport.read();
    let live = !entry.retired.load(std::sync::atomic::Ordering::SeqCst);
    if live {
        step();
    }
    live
}

/// The JSON-RPC error code in an answer, whichever way the peer carried it.
///
/// A refusal is a refusal whether it arrives in-band, as an error object in a
/// 200 response, or status-carried, as a non-2xx whose body the HTTP transport
/// parsed into [`Error::JsonRpc`] -- or, when the status also says "ask again",
/// into [`Error::JsonRpcRetryable`], which keeps the code the retry would
/// otherwise have flattened away. The carriages are one wire fact and the
/// probe must judge them the same, or a peer that declines over HTTP is torn
/// down while the same peer over stdio is left alone. `None` means the answer
/// is not a refusal: either the peer served it, or the transport itself broke.
pub(super) fn refusal_code(answer: &Result<JsonRpcResponse>) -> Option<i32> {
    match answer {
        Ok(response) => response.error.as_ref().map(|error| error.code),
        Err(Error::JsonRpc { code, .. } | Error::JsonRpcRetryable { code, .. }) => Some(*code),
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
    /// The era the Shared slot's peer was last observed to speak, if it has
    /// been resolved: the backend-level view (liveness, `gateway_list_servers`).
    /// A request routed to a per-user slot is shaped by that slot's own era
    /// instead (MIK-8186). Never probes: a caller asking what is known must not
    /// change what is known.
    pub async fn cached_era(&self) -> Option<Era> {
        self.shared_entry().era.cached().await
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

    /// Start `entry` as the dispatch does, then refuse a method the 2026-07-28
    /// revision removed when the started slot's peer speaks that revision,
    /// before anything reaches the wire (MIK-7217 OUTBOUND.1). Sending one
    /// anyway is not harmless: a modern peer answers `method not found`, which
    /// cannot be told from a peer missing a feature. An unresolved or legacy
    /// era forwards: silence is not evidence of modernity. Judged after the slot
    /// is admitted and started, on the slot actually used: another slot's peer may speak a different revision, and a cold
    /// slot has a verdict only once its own start has probed (MIK-7217
    /// OUTBOUND.1, MIK-8186).
    pub(super) async fn start_judged(
        &self,
        key: &super::pool::PoolKey,
        entry: &PooledEntry,
        started_at: std::time::Instant,
        method: &str,
    ) -> crate::Result<Arc<dyn Transport>> {
        let transport = self.start_recorded(key, entry, started_at).await?;
        if !crate::protocol::meta::REMOVED_IN_2026_07_28.contains(&method) {
            return Ok(transport);
        }
        // The start may have replaced the claimed entry (an eviction or a
        // revocation in between): judge by the slot that holds the transport
        // the request will be sent on. The era is read first and the holding
        // re-checked after, so a restart in between cannot pair one peer's
        // transport with its replacement's verdict; then the request is refused
        // before the wire as a start that must be retried.
        let replacement = if holds(entry, &transport) {
            None
        } else {
            self.pool
                .get(key)
                .filter(|current| holds(current.value(), &transport))
                .map(|current| Arc::clone(current.value()))
        };
        let holder = replacement.as_deref().unwrap_or(entry);
        let verdict = holder.era.cached().await;
        if !holds(holder, &transport) {
            return Err(super::lifecycle::pre_send_start_error(
                &self.name,
                crate::Error::BackendUnavailable(
                    "the slot was replaced while it started; retry the request".to_string(),
                ),
            ));
        }
        if verdict == Some(Era::Modern) {
            note_removed_method_refused(&self.name, method);
            return Err(removed_method_refusal(method));
        }
        Ok(transport)
    }

    /// Everything an operator can see about this backend's era, for
    /// `gateway_list_servers`. Never probes.
    pub async fn era_observation(&self) -> EraObservation {
        self.shared_entry().era.observation().await
    }

    /// Test-only reach-through to [`Backend::resolve_era`] for rows that live
    /// outside `crate::backend`: the section 4 gate rows exercise gateway call
    /// sites and still need a peer whose era came from its own answer rather
    /// than from a setter. A `#[cfg(test)]` wrapper rather than widening
    /// `resolve_era` itself, so the production visibility stays `pub(super)`.
    #[cfg(test)]
    pub(crate) async fn resolve_era_for_test(&self, transport: &Arc<dyn Transport>) {
        let shared = self.shared_entry();
        self.resolve_era(transport, &shared).await;
    }

    /// Test-only: the start path's era step for the slot `entry` (MIK-7643),
    /// which the pool may have retired while the start ran.
    #[cfg(test)]
    pub(crate) async fn resolve_era_for_entry_test(
        &self,
        transport: &Arc<dyn Transport>,
        entry: &PooledEntry,
    ) {
        self.resolve_era(transport, entry).await;
    }

    /// Resolve the era of a freshly started peer, probing at most once.
    ///
    /// Awaited on the start path so the first request already knows which
    /// dialect to speak. Returns the era this start's own probe decided, for
    /// its handshake: the shared cache may already hold another slot's verdict
    /// by the time the caller reads it (MIK-8056).
    ///
    /// NOTE (lock order): callers hold the slot's `start_lock`, so this takes
    /// `start_lock` -> era mutex. Anything holding the era mutex must therefore
    /// use a transport handle it already owns and must never call back into
    /// `ensure_entry_started`, which would invert the order.
    pub(super) async fn resolve_era(
        &self,
        transport: &Arc<dyn Transport>,
        entry: &PooledEntry,
    ) -> crate::protocol::era::Era {
        let timeout = self.probe_timeout();
        // A start hands over a transport to a process that has only just come
        // up. Any era already determined describes the peer that came before
        // it, which an upgrade or a downgrade may have replaced, so carrying
        // the verdict across the swap asserts something never observed about
        // the peer now on the wire. Discard and probe are one locked step: a
        // detached re-probe of the old peer must not be able to land between them.
        // A revocation removes a per-user slot without its start lock, so the slot this
        // start serves may be retired before the discard or before the install (MIK-7643).
        entry
            .era
            .restart_while_serving(
                || probe(transport, timeout),
                |step| unless_retired(entry, step),
            )
            .await
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
        // The slot this transport serves, found first: an answer that arrived over a transport
        // no slot holds any more is evidence about a peer that has been replaced, and must
        // neither drop the current verdict nor start a probe of it.
        let Some(entry) = self
            .pool
            .iter()
            .find_map(|slot| holds(slot.value(), transport).then(|| Arc::clone(slot.value())))
        else {
            return;
        };
        #[cfg(test)]
        self.after_reprobe_lookup.pause().await;
        // Judging the verdict and dropping it are one locked step, and only the task that
        // dropped it probes. Reading the era and clearing it separately would let two answers
        // arriving at once both find the stale verdict and each fan out a detached probe.
        let discarded = entry
            .era
            .discard_if_serving(
                |era| match era {
                    Era::Legacy => contradicts_legacy(code),
                    Era::Modern => contradicts_modern(method, code),
                },
                // Re-checked under the era lock, and held through the clear: a restart may have
                // installed and resolved a new peer since the lookup above, or the pool removed
                // the slot, and a contradiction from the old one must not erase the verdict.
                |clear| with_serving(&entry, transport, clear),
            )
            .await;
        if !discarded {
            return;
        }

        let era = Arc::clone(&entry.era);
        let transport = Arc::clone(transport);
        let timeout = self.probe_timeout();
        tokio::spawn(async move {
            era.reprobe_with(
                || probe(&transport, timeout),
                |store| with_serving(&entry, &transport, store),
            )
            .await;
        });
    }

    /// Probe deadline: never longer than the backend's own request timeout.
    fn probe_timeout(&self) -> Duration {
        self.config.timeout.min(probe_cap())
    }
}

/// The probe's cap. Debug builds let a test widen it (#2425): a shell-script
/// peer on a stalled runner can answer later than [`PROBE_TIMEOUT`]. Release
/// builds compile the override out, and the release job greps for its name.
#[cfg(debug_assertions)]
fn probe_cap() -> Duration {
    std::env::var("MCP_GATEWAY_TEST_ERA_PROBE_CAP_MS")
        .ok()
        .and_then(|ms| ms.parse().ok())
        .map_or(PROBE_TIMEOUT, Duration::from_millis)
}

#[cfg(not(debug_assertions))]
fn probe_cap() -> Duration {
    PROBE_TIMEOUT
}

/// What a refusal of a method the 2026-07-28 revision removed carries, so the
/// route that answers the caller can tell it from a peer's own error.
const REMOVED_METHOD_MARK: &str = "removedInRevision";

/// The error a dispatch returns instead of sending `method` to a peer whose
/// era removed it (MIK-7217 OUTBOUND.1). Nothing reached the wire.
fn removed_method_refusal(method: &str) -> crate::Error {
    crate::Error::JsonRpc {
        code: METHOD_NOT_FOUND_CODE,
        message: format!("{method} was removed in protocol revision 2026-07-28"),
        data: Some(serde_json::json!({ REMOVED_METHOD_MARK: "2026-07-28" })),
    }
}

/// The message of a [`removed_method_refusal`], or `None` for any other error.
pub(crate) fn removed_method_refusal_message(error: &crate::Error) -> Option<&str> {
    match error {
        crate::Error::JsonRpc {
            code,
            message,
            data: Some(data),
        } if *code == METHOD_NOT_FOUND_CODE && data.get(REMOVED_METHOD_MARK).is_some() => {
            Some(message)
        }
        _ => None,
    }
}

/// Record one refused removed method. `debug!`, not `warn!`: the refusal is
/// triggered by whatever method a client asks for, so at `warn!` a client
/// polling a removed method sets the gateway's log volume. The counter carries
/// the same event at a volume an operator controls.
fn note_removed_method_refused(backend: &str, method: &str) {
    tracing::debug!(
        backend,
        method,
        "Refusing a method the backend's protocol revision removed"
    );
    telemetry_metrics::counter!(
        "mcp_gateway_removed_method_refused_total",
        "backend" => backend.to_string(),
        "method" => method.to_string(),
        "era" => "modern"
    )
    .increment(1);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::era::UNSUPPORTED_PROTOCOL_VERSION;
    use crate::protocol::meta::ADDED_IN_2026_07_28;

    /// Both carriages of a refusal must reach the probe as the same code.
    ///
    /// `row_16g` pins the transport end -- a 5xx carrying a JSON-RPC error
    /// keeps the peer's code -- and `row_6b` pins the scoring end, but `row_6b`
    /// fabricates an `Error::JsonRpc` directly and so never reaches this
    /// function with the variant the HTTP path actually produces. Dropping the
    /// `JsonRpcRetryable` arm below would leave both rows green while the probe
    /// scored a 5xx-carried refusal as a transport fault again.
    #[test]
    fn a_refusal_is_the_same_code_whichever_carriage_brings_it() {
        let in_band = Err(Error::JsonRpc {
            code: METHOD_NOT_FOUND_CODE,
            message: "method not found".into(),
            data: None,
        });
        let on_a_status = Err(Error::JsonRpcRetryable {
            code: METHOD_NOT_FOUND_CODE,
            message: "method not found".into(),
            status: 503,
            data: None,
        });
        assert_eq!(refusal_code(&in_band), Some(METHOD_NOT_FOUND_CODE));
        assert_eq!(refusal_code(&on_a_status), Some(METHOD_NOT_FOUND_CODE));
    }

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

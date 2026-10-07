// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! F13 (MIK-7586): the catalogue fill R2's check runs on a cold slot.
//!
//! A check-site fill is the ordinary single-flight tools fill with a
//! `CallTimeout` bound. Before it touches the wire it asks the slot's breaker,
//! then the failure cooldown, then the limiter (Amendment 1, Revision 1a), and
//! it reports its outcome to the breaker as a dispatch does. Every tools fill,
//! whatever its bound, carries a [`FillGuard`] that stamps the cooldown when
//! the fill ends without storing, and never on a caller cancellation.

use std::sync::Arc;
use std::time::Duration;

use super::LIST_MAX_PAGES;
use super::pool::PooledEntry;
use crate::failsafe::CircuitState;
use crate::trust::closed_keys::{count, count_reason};
use crate::{Error, Result};

/// After a tools fill ends without storing, fills of that slot fail fast for
/// this long instead of each taking a `tools/list` of their own.
pub(crate) const LIST_FILL_COOLDOWN: Duration = Duration::from_secs(10);

/// How much longer than `timeout` a check-site caller waits on another
/// caller's fill, so the leader's own inner timeout always fires first.
pub(crate) const LIST_FILL_WAIT_GRACE: Duration = Duration::from_secs(1);

/// What bounds one fill's drain (design §2 step 2, Revision 3).
#[derive(Clone, Copy, Debug)]
pub(crate) enum FillBound {
    /// Discovery, `gateway_search` and every other request-triggered fill:
    /// the drain's own structural stop (`CACHE_LIST_DRAIN_BUDGET`), gated on
    /// and recorded against the slot's failsafe (#1300).
    DrainBudget,
    /// A check-site fill: the drain is abandoned after this long, and the
    /// fill is gated on and recorded against the slot's failsafe.
    CallTimeout(Duration),
    /// Startup warm-up (#1300): not admitted (no caller to charge, and its
    /// own retry loop must not see the refusals it caused), but recorded.
    Warmup,
}

/// Whether the list a check-site fill returned is the slot's whole catalogue.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Completeness {
    /// The slot holds this list and its drain ran to the end.
    Complete,
    /// The slot holds this list, but its drain stopped structurally.
    Truncated,
    /// The slot does not hold this list (a voided store, or the slot moved
    /// on): absence from it proves nothing.
    Unknown,
}

impl Completeness {
    /// A list the slot holds, by the slot's truncated mark.
    pub(crate) fn held(truncated: bool) -> Self {
        if truncated {
            Self::Truncated
        } else {
            Self::Complete
        }
    }
}

/// A transport failure of a tools fill, kept so a check-site call inside the
/// cooldown answers with the same variant, message and budget treatment (a
/// rate-limit text stays one) as the failure it stands in for (A3).
#[derive(Clone, Debug)]
pub(crate) enum Replay {
    /// A message-carrying variant, rebuilt as is.
    Message(fn(String) -> Error, String),
    /// A protocol-version rejection and the versions the backend named.
    VersionRejected(Vec<String>),
}

impl Replay {
    /// `Some` for a transport failure that can be rebuilt exactly. `Http`,
    /// `Io` and `Tls` carry sources that cannot be cloned, so they get `None`
    /// and their fill stamps no cooldown ([`FillEnd::Unreplayable`]): the
    /// next call lists again and gets the backend's own error, bounded by
    /// the breaker.
    pub(crate) fn of(error: &Error) -> Option<Self> {
        let (variant, message): (fn(String) -> Error, String) = match error {
            Error::BackendTimeout(m) => (Error::BackendTimeout, m.clone()),
            Error::BackendUnavailable(m) => (Error::BackendUnavailable, m.clone()),
            Error::Transport(m) => (Error::Transport, m.clone()),
            Error::TransportPermanent(m) => (Error::TransportPermanent, m.clone()),
            Error::TransportConnect(m) => (Error::TransportConnect, m.clone()),
            Error::Protocol(m) => (Error::Protocol, m.clone()),
            Error::Config(m) => (Error::Config, m.clone()),
            Error::ConfigValidation(m) => (Error::ConfigValidation, m.clone()),
            Error::OAuth(m) => (Error::OAuth, m.clone()),
            Error::ProtocolVersionRejected { supported } => {
                return Some(Self::VersionRejected(supported.clone()));
            }
            _ => return None,
        };
        Some(Self::Message(variant, message))
    }

    fn error(&self) -> Error {
        match self {
            Self::Message(variant, message) => variant(message.clone()),
            Self::VersionRejected(supported) => Error::ProtocolVersionRejected {
                supported: supported.clone(),
            },
        }
    }
}

/// How a tools fill ended, as its guard sees it on drop.
#[derive(Clone, Debug)]
pub(crate) enum FillEnd {
    /// Still draining: a drop here is a caller cancellation.
    Pending,
    /// The drain, parse, start or inner timeout returned an error;
    /// `transport` is its [`Replay`] when it was a transport failure (A3).
    Failed { transport: Option<Replay> },
    /// A transport failure no [`Replay`] can rebuild exactly: counted, but
    /// stamps no cooldown, so no later call answers with a lookalike.
    Unreplayable,
    /// Drained; reaching drop in this state means the store was voided.
    Drained,
    /// The store was accepted.
    Stored,
}

/// Armed once a tools fill is admitted, carried in the fill's side value, and
/// moved to `Stored` only by `on_stored`. `Failed` and `Drained` stamp the
/// cooldown on drop; `Stored` clears it; `Pending` stamps nothing.
pub(crate) struct FillGuard {
    entry: Arc<PooledEntry>,
    end: FillEnd,
}

impl FillGuard {
    pub(super) fn arm(entry: Arc<PooledEntry>) -> Self {
        Self {
            entry,
            end: FillEnd::Pending,
        }
    }

    pub(super) fn end(&mut self, end: FillEnd) {
        self.end = end;
    }
}

impl Drop for FillGuard {
    // Runs under the cache's write guard when `on_stored` ran, so it touches
    // only the stamp mutex and the counters, never the cache.
    fn drop(&mut self) {
        let stamp = &self.entry.tools_fill_failed_at;
        match std::mem::replace(&mut self.end, FillEnd::Pending) {
            FillEnd::Pending => count("input_schema_fill_cancelled"),
            FillEnd::Failed { transport } => {
                *stamp.lock() = Some((tokio::time::Instant::now(), transport));
                count("input_schema_fetch_failed");
            }
            FillEnd::Unreplayable => count("input_schema_fetch_failed"),
            FillEnd::Drained => {
                // Voided. Stamp only if the slot is still empty (an
                // invalidation). A newer list already stored ended the
                // cooldown. Checked and stamped under the cache's read guard,
                // so a direct list (which stores and clears the stamp under
                // the write guard) lands wholly before or after.
                self.entry.tools_cache.with_cached(|held| {
                    if held.is_none() {
                        *stamp.lock() = Some((tokio::time::Instant::now(), None));
                    }
                });
                count("input_schema_fetched");
            }
            FillEnd::Stored => {
                // A newer list ends both hold-offs, as a direct list does.
                *stamp.lock() = None;
                *self.entry.tools_refresh_failed_at.lock() = None;
                count("input_schema_fetched");
            }
        }
    }
}

/// Steps 1-3 of a fill closure, before its guard is armed: the breaker, the
/// cooldown (tools only), the limiter token. Every fill but warm-up is
/// admitted (#1300). A refusal here stamps nothing.
pub(super) fn admit_fill(
    entry: &PooledEntry,
    backend: &str,
    bound: FillBound,
    tools: bool,
) -> Result<()> {
    // Written as "not warm-up" so a new bound inherits the gate, not a bypass.
    let admitted = !matches!(bound, FillBound::Warmup);
    // The cooldown's replayed error stays the check site's alone.
    let gated = matches!(bound, FillBound::CallTimeout(_));
    if admitted {
        entry.failsafe.check_circuit(backend).inspect_err(|_| {
            if gated {
                count_reason("input_schema_fill_refused", "circuit");
            }
        })?;
    }
    let cooling = if tools {
        entry
            .tools_fill_failed_at
            .lock()
            .clone()
            .filter(|(at, _)| at.elapsed() < LIST_FILL_COOLDOWN)
    } else {
        None
    };
    if let Some((_, replay)) = cooling {
        count("input_schema_fill_cooldown");
        let fast_fail = format!(
            "{backend}: tools/list failed within the last {}s",
            LIST_FILL_COOLDOWN.as_secs()
        );
        // A check-site call answers as the failure it stands in for, carried
        // in the error so no later read of the stamp can reclass it: the
        // transport failure, or an unreadable list (not transport-class, so
        // text U). Any other caller keeps the generic fast-fail.
        return Err(match replay {
            Some(replay) if gated => replay.error(),
            None if gated => Error::json_rpc(-32603, fast_fail),
            _ => Error::BackendUnavailable(fast_fail),
        });
    }
    if admitted {
        entry.failsafe.take_token(backend).inspect_err(|_| {
            if gated {
                count_reason("input_schema_fill_refused", "rate");
            }
        })?;
    }
    Ok(())
}

/// Run a fill's drain under its bound (the call timeout for a check-site
/// fill only), and record its outcome on the slot's failsafe (#1300).
pub(super) async fn run_bounded<T>(
    entry: &PooledEntry,
    backend: &str,
    bound: FillBound,
    drain: impl Future<Output = Result<T>>,
) -> Result<T> {
    let started = tokio::time::Instant::now();
    let result =
        match bound {
            FillBound::CallTimeout(limit) => tokio::time::timeout(limit, drain)
                .await
                .unwrap_or_else(|_| {
                    Err(crate::oauth::login_gate::Provenance::expired(
                        backend,
                        list_timeout(backend, limit),
                    ))
                }),
            FillBound::DrainBudget | FillBound::Warmup => drain.await,
        };
    record_fill(
        entry,
        backend,
        bound,
        result.as_ref().err(),
        started.elapsed(),
    );
    result
}

/// One fill's outcome, as the breaker means it: reachability (amended AC2).
/// A transport failure counts against it; a throttle counts as neither; an
/// answer the gateway cannot use is reachable, logged and counted.
fn record_fill(
    entry: &PooledEntry,
    backend: &str,
    bound: FillBound,
    error: Option<&Error>,
    latency: Duration,
) {
    let warmup = matches!(bound, FillBound::Warmup);
    let Some(error) = error else {
        record_reachable(entry, warmup, latency);
        return;
    };
    // A person still logging in is neither a failure nor reachability: the
    // backend was never asked (MIK-7982).
    if error.is_authorization_wait() {
        return;
    }
    let reason = error.to_string();
    if is_transport_failure(error) {
        if warmup {
            // A warm-up's own failure: counted, but it marks nothing, so a
            // later warm-up success may undo the trip.
            let _guard = entry.request_failed_since_close.lock();
            entry.failsafe.record_dispatch_failure(&reason, latency);
        } else {
            record_request_failure(entry, &reason, latency);
        }
    } else if crate::gateway::recovery::is_rate_limited(&reason) {
        entry.failsafe.record_rate_limited(&reason, latency);
        count_fill(backend, "rate_limited");
    } else {
        tracing::warn!(backend, error = %reason, "list fill answered but unusable");
        count_fill(backend, "list_unusable");
        record_reachable(entry, warmup, latency);
    }
}

/// A reachable answer. A warm-up success resets an Open breaker only when
/// no request failure was recorded since it last closed: warm-up may undo
/// its own trips, never one requests caused (maintainer ruling on #1300).
/// The check, the reset and the success are one step under the flag's lock.
fn record_reachable(entry: &PooledEntry, warmup: bool, latency: Duration) {
    let mut request_failed = entry.request_failed_since_close.lock();
    let open = entry.failsafe.circuit_breaker.stats().state == CircuitState::Open;
    if warmup && open && !*request_failed {
        entry.failsafe.circuit_breaker.reset();
    }
    success_under(entry, &mut request_failed, latency);
}

/// A request's success on the slot (dispatch path).
pub(super) fn record_request_success(entry: &PooledEntry, latency: Duration) {
    let mut request_failed = entry.request_failed_since_close.lock();
    success_under(entry, &mut request_failed, latency);
}

/// Record a success; once the breaker is Closed no failure since the close
/// remains, so the provenance flag clears.
fn success_under(entry: &PooledEntry, request_failed: &mut bool, latency: Duration) {
    entry.failsafe.record_success(latency);
    if entry.failsafe.circuit_breaker.stats().state == CircuitState::Closed {
        *request_failed = false;
    }
}

/// A request's (or request-triggered fill's) failure, recorded and flagged
/// under one lock. Returns `true` for a throttle, which is not a failure and
/// flags nothing.
pub(super) fn record_request_failure(entry: &PooledEntry, reason: &str, latency: Duration) -> bool {
    let mut request_failed = entry.request_failed_since_close.lock();
    let throttled = entry.failsafe.record_dispatch_failure(reason, latency);
    if !throttled {
        *request_failed = true;
    }
    throttled
}

fn count_fill(backend: &str, status: &'static str) {
    telemetry_metrics::counter!(
        "mcp_backend_requests_total",
        "backend" => backend.to_string(),
        "status" => status
    )
    .increment(1);
}

/// A fill error that says the backend could not be reached or did not answer
/// in time, as opposed to one that answered with a list the gateway cannot
/// read (A3). Under `closed` the call then gets the error a failed dispatch
/// gets, not text U. `Http` is here because a dispatch to the same endpoint
/// fails the same way.
pub(crate) fn is_transport_failure(error: &Error) -> bool {
    matches!(
        error,
        Error::BackendUnavailable(_)
            | Error::BackendTimeout(_)
            | Error::Transport(_)
            | Error::TransportPermanent(_)
            | Error::TransportConnect(_)
            | Error::Http(_)
            | Error::Io(_)
            | Error::Tls(_)
            // The handshake failed (initialize refused, a framing fault): a
            // dispatch would get the same error.
            | Error::Protocol(_)
            | Error::ProtocolVersionRejected { .. }
            // The backend could not be started as this caller: the dispatch
            // would fail with the same error, so the call gets it too.
            | Error::Config(_)
            | Error::ConfigValidation(_)
            | Error::OAuth(_)
    )
}

/// The cold tools/list fill ran out of time. Only the read-only tools/list was
/// sent, never the tools/call it was checking for, so this is a pre-send
/// refusal that frees the caller's idempotency key (MIK-7979).
pub(super) fn list_timeout(backend: &str, limit: Duration) -> Error {
    Error::BackendUnavailable(format!(
        "{backend}: tools/list did not finish within {}ms",
        limit.as_millis()
    ))
}

/// Text U: the schema could not be read.
pub(crate) const TEXT_UNAVAILABLE: &str = "the gateway could not read this tool's input schema for you; list the backend's tools and retry";

/// Text P: the tool is not in the part of a truncated list the gateway read.
/// Names no config key: the remedy is the operator's, documented in UPGRADING.
pub(crate) fn text_partial() -> String {
    format!(
        "the gateway could not read this backend's whole tool list (it stopped at the \
         {LIST_MAX_PAGES}-page cap, at a repeated page cursor, or at the list time budget), \
         and this tool is not in the part it read, so its input schema cannot be checked"
    )
}

/// Text A: a fresh, complete list does not hold the tool. No retry advice:
/// the same name fails the same way.
pub(crate) fn text_absent(tool: &str) -> String {
    format!("the backend does not list a tool named `{tool}`")
}

#[cfg(test)]
mod tests {
    use super::{LIST_FILL_COOLDOWN, LIST_MAX_PAGES};

    /// MIK-7979: a cold tools/list fill that runs out of time has not sent the
    /// tools/call it was checking for, so it is a pre-send refusal.
    #[test]
    fn a_list_timeout_is_a_pre_send_refusal() {
        let error = super::list_timeout("svc", std::time::Duration::from_millis(5));
        assert!(
            matches!(error, crate::Error::BackendUnavailable(_)),
            "{error:?}"
        );
    }

    /// Design §6: the numbers UPGRADING §59 prints are the constants' values,
    /// so a changed constant fails the build until the text follows (M6e's
    /// second pin).
    #[test]
    fn upgrading_section_59_quotes_the_constants() {
        let doc = include_str!("../../docs/UPGRADING-4.0.md");
        let start = doc.find("## 59.").expect("section 59");
        let section = &doc[start..];
        let section = &section[..section[3..].find("\n## ").map_or(section.len(), |e| e + 3)];
        // Whitespace-normalised: a Windows checkout reads the doc with CRLF.
        let section = section.split_whitespace().collect::<Vec<_>>().join(" ");
        let secs = LIST_FILL_COOLDOWN.as_secs();
        for quoted in [
            format!("{LIST_MAX_PAGES}-page cap"),
            format!("{secs} s."),
            format!("The {LIST_MAX_PAGES} pages and the {secs} s above"),
            // A3: both answers to a failed list are described.
            "the same error a failed tool call to that backend gets".to_owned(),
            "not counted as a backend failure".to_owned(),
        ] {
            assert!(section.contains(&quoted), "UPGRADING §59 lacks {quoted:?}");
        }
    }
}

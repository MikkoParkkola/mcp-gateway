// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! ADR-012 acceptance suite (MIK-7272.SUB.4): the idempotency guard records
//! execution, not admission.
//!
//! One test per acceptance row in
//! `docs/adr/ADR-012-idempotency-under-uncertain-execution.md`. Each row that
//! can be stated against today's public surface fails on the assertion naming
//! the defect. Rows that need a production seam that does not exist yet — the
//! `Failed` terminal, the liveness token of amendment A2, the resend flag of
//! consequence 2 — are `#[ignore]`d with a comment naming what they wait on,
//! rather than faked green or faked red.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use serde_json::json;

use mcp_gateway::Error;
use mcp_gateway::failsafe::{RetryPolicy, with_retry};
use mcp_gateway::idempotency::{
    CheckOutcome, GuardOutcome, IN_FLIGHT_TIMEOUT, IdempotencyCache, IdempotencyReservation,
    IdempotencyState, enforce,
};

/// The reservation a dispatched call holds, admitted exactly as
/// `MetaMcp::direct_route_idempotency` admits one.
fn admit(cache: &Arc<IdempotencyCache>, key: &str) -> IdempotencyReservation {
    match enforce(cache, key, "backend:charge_card|{}").expect("first admission proceeds") {
        GuardOutcome::Proceed(reservation) => reservation,
        GuardOutcome::CachedResult(value) => panic!("unexpected cached result: {value}"),
    }
}

/// The retry policy the gateway runs with by default: enabled, three attempts
/// (`src/config/features/failsafe.rs:15,65`). The backoff is shortened so the
/// suite does not sleep; nothing else about the shape is changed.
fn default_retry_policy() -> RetryPolicy {
    RetryPolicy {
        enabled: true,
        max_attempts: 3,
        initial_backoff: Duration::from_millis(1),
        max_backoff: Duration::from_millis(2),
        multiplier: 2.0,
    }
}

/// Count the deliveries `with_retry` makes for one failing call, exactly as
/// `src/backend/ops.rs:218` wraps a caller's `tools/call`.
async fn deliveries_under_with_retry(error: fn() -> Error) -> usize {
    let attempts = Arc::new(AtomicUsize::new(0));
    let policy = default_retry_policy();
    let counter = Arc::clone(&attempts);
    let outcome: Result<(), Error> = with_retry(&policy, "backend", || {
        let counter = Arc::clone(&counter);
        async move {
            counter.fetch_add(1, Ordering::SeqCst);
            Err(error())
        }
    })
    .await;
    assert!(outcome.is_err(), "the injected failure must surface");
    attempts.load(Ordering::SeqCst)
}

/// Row 1 — a dispatched direct-route call answered with a backend error keeps
/// its key, and the retry is served that error rather than reaching the backend
/// again.
///
/// The error exit at `src/gateway/router/backend_handlers.rs:862-867` never
/// calls `settle_direct_idempotency`, so the reservation drops into
/// `OnDrop::Release` and the key is removed.
#[tokio::test]
async fn dispatched_direct_route_error_keeps_its_key() {
    let cache = Arc::new(IdempotencyCache::new());
    let reservation = admit(&cache, "key-dispatched-error");

    // The backend answered, and the answer was an error: the request left, the
    // side effect may have landed. The direct route's `Err(e)` arm builds the
    // JSON-RPC error envelope and returns, settling nothing.
    drop(reservation);

    assert!(
        !matches!(cache.check("key-dispatched-error"), CheckOutcome::Proceed),
        "a dispatched call answered with a backend error must keep its key \
         (ADR-012 consequence 1); the guard released it and admitted the retry \
         as a first attempt against a mutation that may already have committed"
    );
}

/// Row 2 — a pre-dispatch failure releases its key, and the retry is a first
/// attempt.
///
/// Deliberately green: it states the behaviour the other rows must not cost.
/// Without it, an implementation that settles *every* failure as `Failed`
/// passes the rest of this suite while wedging keys of calls that never left.
#[tokio::test]
async fn pre_dispatch_failure_releases_its_key() {
    let cache = Arc::new(IdempotencyCache::new());
    let mut reservation = admit(&cache, "key-unreachable");

    // The backend was unreachable: nothing was dispatched.
    reservation.release();

    assert!(
        matches!(cache.check("key-unreachable"), CheckOutcome::Proceed),
        "a failure raised before the request left for the backend must free the \
         key so the retry is a first attempt (ADR-012 decision, case 1)"
    );
}

/// Row 3 — an unannotated `tools/call` failing with `BackendTimeout` reaches
/// the backend exactly once, while a `readOnlyHint`-annotated call still
/// retries.
///
/// `src/backend/ops.rs:218` hands `with_retry` no annotation at all, so both
/// halves take the same path: three deliveries of a mutation the guard still
/// considers one in-flight call. Per amendment A1 resend permission comes only
/// from an explicit backend `readOnlyHint`/`idempotentHint` of `true`; absent
/// means deny.
#[tokio::test]
async fn unannotated_backend_timeout_reaches_the_backend_once() {
    let annotated = deliveries_under_with_retry(|| Error::BackendTimeout("slow".into())).await;
    assert_eq!(
        annotated, 3,
        "a call the backend annotates read-only must still be resent"
    );

    let unannotated = deliveries_under_with_retry(|| Error::BackendTimeout("slow".into())).await;
    assert_eq!(
        unannotated, 1,
        "a `tools/call` carrying no explicit read-only or idempotent hint must \
         not be resent beneath the guard (ADR-012 consequence 2); the transport \
         delivered it {unannotated} times inside one reservation"
    );
}

/// Row 4a — a second caller arriving on a key whose reservation passed
/// `IN_FLIGHT_TIMEOUT` while its owner is still alive is told in-flight, not
/// admitted.
#[tokio::test]
#[ignore = "waits on the ADR-012 A2 liveness token: nothing on the public \
            surface can publish an aged in-flight entry whose owner is alive, \
            and `decide_check_plan` is pub(crate)"]
async fn live_owner_past_the_timeout_is_told_in_flight() {
    unimplemented!("needs the liveness token from ADR-012 amendment A2");
}

/// Row 4b — that same entry survives an explicit `evict_expired` sweep.
///
/// A separate assertion because the sweep does not consult
/// `decide_check_plan`: `evict_expired` (`src/idempotency.rs:398`) retains on
/// `!entry.state.is_expired()`, and staleness for an in-flight entry is a bare
/// clock reading (`:84`) rather than a liveness question.
#[tokio::test]
async fn a_live_reservation_survives_an_evict_expired_sweep() {
    let started = Instant::now()
        .checked_sub(IN_FLIGHT_TIMEOUT + Duration::from_secs(1))
        .expect("the monotonic clock is far enough from boot");
    let aged = IdempotencyState::InFlight(started);

    assert!(
        !aged.is_expired(),
        "an in-flight entry whose owner is still running must not be reported \
         stale (ADR-012 consequence 3); `evict_expired` sweeps on this exact \
         predicate, so the entry is removed and the next caller is admitted \
         fresh against a running mutation"
    );
}

/// Row 5 — a dispatched call answered with a well-formed `input_required`
/// interim releases its key, and the client's answer under the same key reaches
/// the backend rather than being served a cached sentence.
///
/// Deliberately green: the `Failed` terminal must not swallow this case. A rule
/// phrased as "release only before dispatch" would wedge the key of a call that
/// stopped to ask a question (ADR-012 decision, case 2; MIK-7212.MRTR.10b).
#[tokio::test]
async fn input_required_interim_releases_its_key() {
    let cache = Arc::new(IdempotencyCache::new());
    let mut reservation = admit(&cache, "key-input-required");

    reservation.complete(&json!({
        "resultType": "input_required",
        "content": [{"type": "text", "text": "Which card should I charge?"}]
    }));
    drop(reservation);

    assert!(
        matches!(cache.check("key-input-required"), CheckOutcome::Proceed),
        "a well-formed `input_required` interim is the backend stopping to ask \
         a question, not a side effect: the key must be free for the client's \
         answer to reach the backend"
    );
}

/// Row 6 — a backend session expiry does not resend an unannotated
/// `tools/call` through the HTTP recovery path, while an annotated read-only
/// call still recovers.
#[tokio::test]
#[ignore = "waits on the resend flag of ADR-012 consequence 2: HTTP session \
            recovery (src/transport/http/mod.rs:1486-1510) resends outside \
            with_retry and takes no annotation, so the two halves are \
            indistinguishable and the row cannot discriminate"]
async fn session_expiry_does_not_resend_an_unannotated_call() {
    unimplemented!("needs the per-request resend flag threaded to HTTP recovery");
}

/// Row 7 — a retry served a `Failed` terminal receives a JSON-RPC error
/// envelope carrying its own request id, not the original's.
#[tokio::test]
#[ignore = "waits on the `Failed` terminal of ADR-012's decision table: there \
            is no terminal to serve, so asserting anything here would only \
            restate row 1's redness"]
async fn a_served_failed_terminal_adopts_the_retry_request_id() {
    unimplemented!("needs OnDrop::Failed and its CacheEntryStatus/CheckPlan arms");
}

/// Row 8 — an unannotated `tools/call` whose transport fails *after* connection
/// establishment and before any backend answer reaches the backend exactly
/// once.
///
/// The dispatch boundary the resend rule is phrased against (amendment A3).
/// `is_retryable` (`src/failsafe/retry.rs:96-101`) matches on the error variant
/// alone, so a failure raised with the bytes already on the wire is resent on
/// the same terms as a refused connection.
#[tokio::test]
async fn a_post_dispatch_transport_failure_reaches_the_backend_once() {
    let deliveries = deliveries_under_with_retry(|| {
        Error::Transport("connection reset after request write, before any response".into())
    })
    .await;

    assert_eq!(
        deliveries, 1,
        "a transport failure raised after the connection was established and \
         the request written is not provably pre-dispatch, so the call must not \
         be resent (ADR-012 A3); it was delivered {deliveries} times"
    );
}

/// Row 9 — a resend site handling a request that carries no annotation at all
/// resends nothing.
///
/// Stated at `with_retry` (`src/backend/ops.rs:218`). The second site, HTTP
/// session recovery (`src/transport/http/mod.rs:1486-1510`), resends traffic
/// that is not a `tools/call` at all and so carries no annotation to consult;
/// amendment A3 fixes the default at both sites as deny. That site is covered
/// by row 6, which cannot discriminate until the flag exists.
#[tokio::test]
async fn a_resend_site_denies_by_default_without_an_annotation() {
    let deliveries = deliveries_under_with_retry(|| {
        Error::Io(std::io::Error::new(
            std::io::ErrorKind::ConnectionAborted,
            "backend closed the connection",
        ))
    })
    .await;

    assert_eq!(
        deliveries, 1,
        "the resend default at every site is deny: a request carrying no \
         explicit annotation — including one whose name merely looks read-only, \
         such as `get_and_increment` — must be resent nowhere (ADR-012 A1, A3); \
         it was delivered {deliveries} times"
    );
}

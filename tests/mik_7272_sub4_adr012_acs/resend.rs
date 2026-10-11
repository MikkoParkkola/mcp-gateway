// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Resend rows: an interim releases its key, session expiry, failed-terminal adoption and the resend deny-by-default.

use super::*;

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
/// `tools/call`.
///
/// The second resend site. HTTP session recovery
/// (`src/transport/http/mod.rs:1486-1510`) re-handshakes and replays the
/// original request once, outside `with_retry` and without consulting any
/// annotation, so amendment A3's deny default has to be applied there too or
/// the row below stays red however row 3 is fixed.
#[tokio::test]
async fn session_expiry_does_not_resend_an_unannotated_call() {
    let delivered = deliveries(Fault::SessionExpired, MUTATION).await;

    assert_eq!(
        delivered, 1,
        "an expired backend session is a reason to re-handshake, not permission \
         to replay a mutation the backend may already have run (ADR-012 A3); \
         the recovery path delivered it {delivered} times"
    );
}

/// Row 6b — the permission half of row 6: recovery still replays a call the
/// backend annotates read-only.
///
/// Row 6 alone is satisfiable by refusing to replay anything, which would
/// retire the session recovery MIK-5982 added. This row is what stops that:
/// the recovery path must read the same permission the retry path does, so
/// `resend_permission` is threaded to it rather than duplicated beside it.
#[tokio::test]
async fn session_expiry_still_recovers_an_explicitly_read_only_call() {
    let delivered = deliveries(Fault::SessionExpired, ANNOTATED_READ).await;

    assert!(
        delivered > 1,
        "an expired session must still be re-handshaked and the call replayed \
         when the backend annotates it `readOnlyHint: true` (ADR-012 A1); it \
         was delivered {delivered} time(s), so the deny default reached a call \
         that granted permission"
    );
}

/// Row 7 — a retry served a `Failed` terminal receives a JSON-RPC error
/// envelope carrying its own request id, not the original's.
///
/// The criterion is about a call re-issued *with a new request id*, so the id
/// on the served answer is the half a client uses to correlate it at all. An
/// envelope carrying the first call's id is a reply to a request this client
/// never sent, and every correlating client drops it — which is the same
/// outcome as the hang the guard exists to prevent.
///
/// Message equality is asserted alongside because an id that matched on a
/// freshly executed second call would satisfy the id claim while breaking the
/// criterion; the delivery count settles which of the two happened.
#[tokio::test]
async fn a_served_failed_terminal_adopts_the_retry_request_id() {
    let (url, mock) = start_mock(Fault::Refused).await;
    let (state, _store_dir) = route_state().await;
    register_route_backend(&state, &url, ForwardArm::Sanitized);

    let (_, first) = post_direct(&state, keyed_call(1, "key-served-terminal")).await;
    let (status, second) = post_direct(&state, keyed_call(7, "key-served-terminal")).await;

    assert_eq!(
        mock.lock().expect("mock mutex poisoned").calls.len(),
        1,
        "the retry of a dispatched call the backend refused must be served the \
         stored terminal, not delivered again; first={first}, second={second}"
    );
    assert_eq!(
        second.get("id").and_then(Value::as_u64),
        Some(7),
        "a served `Failed` terminal must adopt the retry's request id, exactly \
         as a served `Completed` does (ADR-012, \"The `Failed` state, \
         enumerated\"); the answer was: {second}"
    );
    assert_ne!(
        second.get("id"),
        first.get("id"),
        "the served envelope kept the original call's id, which is a reply to a \
         request the retrying client never sent"
    );
    assert_eq!(
        second.pointer("/error/message"),
        first.pointer("/error/message"),
        "the retry must be served the stored error rather than a fresh one"
    );
    assert_eq!(
        status,
        StatusCode::OK,
        "a replayed terminal is an answer, not a live failure: {second}"
    );
}

/// Row 8 — an unannotated `tools/call` whose transport fails *after* the
/// request was written and before any backend answer reaches the backend
/// exactly once.
///
/// The dispatch boundary the resend rule is phrased against (amendment A3).
/// `is_retryable` (`src/failsafe/retry.rs:96-101`) matches on the error variant
/// alone, so a failure raised with the bytes already on the wire is resent on
/// the same terms as a refused connection.
#[tokio::test]
async fn a_post_dispatch_transport_failure_reaches_the_backend_once() {
    let delivered = deliveries(Fault::BrokenResponse, MUTATION).await;

    assert_eq!(
        delivered, 1,
        "a transport failure raised after the connection was established and \
         the request written is not provably pre-dispatch, so the call must not \
         be resent (ADR-012 A3); the backend received it {delivered} times"
    );
}

/// Row 9 — a name that reads like a query grants no resend permission.
///
/// The row amendment A1 is phrased for. `get_and_increment` is a mutation
/// whose name invites the inference the ADR forbids, and it carries no
/// annotation, so every resend site must deny it.
#[tokio::test]
async fn a_resend_site_denies_by_default_without_an_annotation() {
    let delivered = deliveries(Fault::Silence, READ_LOOKING_MUTATION).await;

    assert_eq!(
        delivered, 1,
        "the resend default at every site is deny: a request carrying no \
         explicit annotation — including one whose name merely looks read-only, \
         such as `{READ_LOOKING_MUTATION}` — must be resent nowhere (ADR-012 A1, \
         A3); the backend received it {delivered} times"
    );
}

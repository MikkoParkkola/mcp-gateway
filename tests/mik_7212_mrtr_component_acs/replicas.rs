// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MRTR.6 replica routing and MRTR.5d single use across replicas.

use super::*;

// ---------------------------------------------------------------------------
// MRTR.6 — a retry reaches the replica holding the exchange, or fails
// ---------------------------------------------------------------------------
//
// The criterion offers two arms and the accepted design took the second:
// `docs/design/2026-08-30-shared-continuation-state.md:116` forecloses affinity
// and `:103-104` prices the consequence. `6e744936` deleted `Routing::Elsewhere`
// accordingly, so "reach the holder" is not a behaviour this gateway can be
// tested for. What remains testable is the half the criterion actually forbids:
// **it MUST NOT silently start a second exchange.**
//
// That is why both cases below assert on the *fixture backend's recorder* and
// not only on the refusal. A refusal-only assertion is green today against the
// blanket `-32602`, green tomorrow against a correct implementation, and green
// against the one implementation MRTR.6 exists to forbid — one that answers the
// client with an error after having already opened a second exchange with the
// backend. The recorder is the only witness that separates those three.
//
// Can these fail for the wrong reason? Today, yes in one direction and it is
// stated rather than hidden: the recorder is empty because *nothing* dispatches,
// so the "no backend call" half passes vacuously and the red comes from the
// vocabulary half. `fixture_control_a_valid_retry_reaches_the_backend` is what
// stops that vacuity being permanent — it is the same route these cases drive,
// so once it is green an empty recorder here means a refusal that dispatched
// nothing rather than a route that cannot dispatch at all. The fresh-call
// control proves only that the recorder records.

/// GIVEN an exchange one replica holds, WHEN the retry arrives at a different
/// replica, THEN that replica refuses it and opens nothing with the backend.
///
/// Two whole `AppState`s, because that is what two replicas are. A single
/// process with a hand-swapped key proves AES key separation; it does not prove
/// that the production constructor builds a distinct key per process, which is
/// the property the whole cross-replica claim rests on.
///
/// The origin is asserted afterwards to still hold the handle unspent — the
/// neighbour's refusal must be the neighbour not knowing, never the attempt
/// having consumed a token the origin was still owed.
#[tokio::test]
async fn ac_mrtr_6_a_retry_at_another_replica_is_refused_and_opens_no_exchange() {
    // GIVEN: replica A minted the handle; replica B has a backend to dispatch to.
    let (origin, _origin_store_dir) = app_state().await;
    let (neighbour, _neighbour_store_dir) = app_state().await;
    let (url, received) = spawn_fixture_backend().await;
    register_fixture_backend(&origin, &url);
    register_fixture_backend(&neighbour, &url);
    let args = arguments();
    let handle = mint_for(&origin, &received, CALLER_A, TOOL_INTERIM, &args).await;
    // The exchange the origin is holding: the one its own mint opened, named by
    // the hold key sealed inside this handle. Read rather than staged — a hold
    // taken here would be a *second* exchange of the same shape, and the
    // closing assertion would then pass against a gateway that ended the wrong
    // one.
    let held = origin
        .continuation
        .keyring()
        .open(&handle, now_secs())
        .expect("a handle the origin just minted must open")
        .hold_key;

    // WHEN: the retry lands on B, as a round-robin balancer will send it.
    let (_status, response) = post(&neighbour, &retry_body(1, TOOL_INTERIM, &args, &handle)).await;

    // THEN: refused in the continuation vocabulary — an explicit failure, which
    // is the arm this design took.
    assert_refused_by_the_continuation_guard(&response, "a neighbour replica's handle");

    // AND: nothing was opened with the backend. This is the half MRTR.6 forbids
    // by name, and the half a refusal-only assertion cannot see.
    let calls = received.lock().expect("recorder").clone();
    assert!(
        calls.is_empty(),
        "a replica that does not hold the exchange must not start a second one; \
         the fixture backend recorded {calls:?}"
    );

    // AND: the origin still holds it, in both senses. `open` answers only
    // authenticity — it verifies the seal and the deadline and never consults
    // the ledger — so on its own it would stay green through exactly the
    // cross-replica consumption this case exists to forbid. The ledger is what
    // says unspent; `open` is here so that an empty ledger cannot be satisfied
    // by a handle that was never real.
    assert!(
        origin
            .continuation
            .keyring()
            .open(&handle, now_secs())
            .is_ok(),
        "the handle must still be authentic, or what follows proves nothing"
    );
    assert_eq!(
        origin.continuation.ledger().len().await,
        0,
        "the neighbour's refusal must not consume the handle the origin still owes"
    );
    assert_eq!(
        origin.continuation.in_flight().len(now_secs()).await,
        1,
        "the neighbour's refusal must not end an exchange the origin is holding"
    );
    assert!(
        origin
            .continuation
            .in_flight()
            .complete(&held, now_secs())
            .await,
        "the origin must still hold the exchange *this handle names*, not merely \
         one of the same shape"
    );
}

/// GIVEN a handle the origin minted for an exchange it no longer holds — the
/// deadline passed, or the backend connection dropped — WHEN the client retries
/// on that same origin, THEN it is refused rather than dispatched.
///
/// This is the one MRTR.6 outcome that survives on the *origin*, and the only
/// one no key-separation property can cover: the token opens, the ledger has it
/// unspent, and every check except the in-flight pin says yes. Without that pin
/// the gateway opens a second exchange with a legacy backend, which is exactly
/// what the criterion names.
///
/// The exchange is staged and then ended, never merely absent. An empty table
/// is the *never existed* state, and a gateway that refuses every exchange it
/// does not recognise satisfies that without one ever having existed — the
/// criterion is about an exchange this origin **no longer** holds, which only a
/// table that once held it can present. `complete` ends it rather than `reap`,
/// so the case turns on the exchange being gone and not on deadline timing.
///
/// The exchange that ends is the handle's own. `Payload::hold_key` names the
/// in-flight entry the mint opened, so "the hold for *this* handle" is
/// constructible and the case does not have to settle for the weaker statement
/// that some exchange against this backend has ended. That weaker staging would
/// pass against a gateway that admits a retry whenever *any* exchange for the
/// backend is open — an honest concurrent one belonging to another caller.
#[tokio::test]
async fn ac_mrtr_6_a_retry_whose_exchange_the_origin_no_longer_holds_is_refused() {
    // GIVEN: a handle this replica minted, and no exchange open for it.
    let (state, _store_dir) = app_state().await;
    let (url, received) = spawn_fixture_backend().await;
    register_fixture_backend(&state, &url);
    let args = arguments();
    let handle = mint_for(&state, &received, CALLER_A, TOOL_INTERIM, &args).await;
    let payload = state
        .continuation
        .keyring()
        .open(&handle, now_secs())
        .expect("a handle this replica just minted must open");
    let held = payload.hold_key.clone();
    assert!(
        state
            .continuation
            .in_flight()
            .complete(&held, now_secs())
            .await,
        "the exchange that ends must be the one this handle names, or the state \
         under test is not the one this case names"
    );
    // A stranger's exchange, open on the same backend across the retry. Without
    // it the table is empty, and *the exchange this handle continues is gone*
    // and *no exchange is open at all* are the same assertion — so a gateway
    // asking the weaker, backend-scoped question passes the very case that
    // exists to catch it. With it, only a gateway that routes on the key this
    // handle carries can refuse.
    let stranger = state
        .continuation
        .in_flight()
        .hold(
            &payload.backend_id,
            &mcp_gateway::protocol::continuation::QuotaKey::new(
                mcp_gateway::protocol::continuation::QuotaSource::KeyName("test"),
            ),
            now_secs() + 60,
            now_secs(),
        )
        .await
        .expect("the table has room for one honest concurrent exchange");
    assert_ne!(
        stranger, held,
        "the stranger must be a second exchange, not the one just ended"
    );
    assert_eq!(
        state.continuation.in_flight().len(now_secs()).await,
        1,
        "the exchange this handle continues must be gone and a stranger's must \
         remain, or the case is not the one it names"
    );

    // WHEN: the client retries on the replica that minted it.
    let (_status, response) = post(&state, &retry_body(1, TOOL_INTERIM, &args, &handle)).await;

    // THEN: refused, and nothing was opened. The backend assertion carries the
    // criterion; the vocabulary assertion only says which guard answered.
    let calls = received.lock().expect("recorder").clone();
    assert!(
        calls.is_empty(),
        "a retry for an exchange that is gone must not silently start a second \
         one; the fixture backend recorded {calls:?}"
    );
    assert_refused_by_the_continuation_guard(&response, "a handle whose exchange is gone");
}

// ---------------------------------------------------------------------------
// MRTR.5d — single-use holds across replicas, under concurrency
// ---------------------------------------------------------------------------

/// GIVEN one handle, WHEN it is retried at two replicas at the same moment,
/// THEN exactly one backend call is made in total.
///
/// `ac_mrtr_5c_two_racing_redemptions_yield_exactly_one_success` races two
/// retries inside one process, where a shared ledger decides the winner.
/// `ac_mrtr_5d_a_handle_minted_by_another_process_is_refused` presents a foreign
/// handle sequentially. Neither reaches the implementation this row exists to
/// forbid: one that shares key material across replicas to make cross-replica
/// redemption *work*, and then has two independent ledgers that never consult
/// each other. That build passes 5c (one process, one ledger) and passes 5d in
/// the direction 5d asserts, while double-spending here.
///
/// Counted across both recorders rather than asserted per replica, because
/// which replica wins is not a property — only that the pair yields one.
#[tokio::test]
async fn ac_mrtr_5d_one_handle_retried_at_two_replicas_yields_one_backend_call() {
    let (origin, _origin_store_dir) = app_state().await;
    let (neighbour, _neighbour_store_dir) = app_state().await;
    let (origin_url, origin_calls) = spawn_fixture_backend().await;
    let (neighbour_url, neighbour_calls) = spawn_fixture_backend().await;
    register_fixture_backend(&origin, &origin_url);
    register_fixture_backend(&neighbour, &neighbour_url);
    let args = arguments();
    let handle = mint_for(&origin, &origin_calls, CALLER_A, TOOL_INTERIM, &args).await;

    // WHEN: both land together. `join` rather than sequential posts, so a
    // check-then-insert ledger has the window it needs to be wrong in.
    let here = retry_body(1, TOOL_INTERIM, &args, &handle);
    let there = retry_body(2, TOOL_INTERIM, &args, &handle);
    let (_a, _b) = tokio::join!(post(&origin, &here), post(&neighbour, &there));

    let total = origin_calls.lock().expect("recorder").len()
        + neighbour_calls.lock().expect("recorder").len();
    assert_eq!(
        total, 1,
        "one handle must buy exactly one backend call however many replicas see \
         it; the two fixture backends recorded {total} between them"
    );
}

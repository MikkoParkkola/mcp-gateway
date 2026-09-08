// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-7377.SIGNING.5, first checkpoint: a nonce refused at the signing
//! boundary consumes no response cache and no execution admission.
//!
//! "Nothing happened" is also satisfied by a gateway where nothing *could*
//! happen, so every negative is paired with a positive control on the SAME
//! fixture proving both mechanisms are live: a real `ResponseCache` that misses
//! cold and hits warm, and the real `ExecutionAdmission` probing, reserving,
//! settling, replaying and abandoning.
//!
//! Wire tests are production wiring throughout — gateway built by
//! `Gateway::build_meta_mcp` via `build_meta_mcp_for_test`, real TCP backend,
//! real HTTP router. Counters are `cfg(test)` observations written AT the real
//! map operations (`entries.get`, `insert`, the status write, `remove`), never
//! inferred from a returned enum and never a harness stand-in.
//!
//! One test is explicitly a COMPONENT control: it drives the real
//! `ExecutionAdmission` directly, because in-flight, mismatch and abandonment
//! are not all reachable from one successful wire call, and a counter no test
//! ever moves is a counter nobody has checked.
//!
//! SCOPE: not a row-39 claim — this is the cache and admission half. Rows 40-42
//! are separate increments. The large nested arguments exist so the refusal path
//! runs against a real payload; NO allocation or clone-count claim is made.

use super::*;
// Explicit: the glob above and the standard prelude both offer `assert_eq`,
// which is E0659 ambiguous in a child module until one of them is named.
use super::signing_nonce_cache_admission_support::{
    CLOCK_EPOCH, EchoBackend, Reading, TOOL, gateway, invoke, read, send,
};
use crate::idempotency::admission::observer::Observed;
use crate::idempotency::admission::{Admission, ExecutionAdmission, Mode, Request, Settlement};
use pretty_assertions::assert_eq;

fn assert_completed(status: StatusCode, body: &Value) {
    assert_eq!(status, StatusCode::OK);
    assert!(
        body.get("error").is_none() || body["error"].is_null(),
        "a completed call must not carry a json-rpc error: {body}"
    );
    assert!(
        body.get("result").is_some() && !body["result"].is_null(),
        "a completed call must carry a result: {body}"
    );
}

/// The exact refusal, not merely "an error": a nonce refused for the wrong
/// reason would satisfy every counter assertion in this file.
fn assert_refused(status: StatusCode, body: &Value, code: i64, message: &str) {
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"]["code"], json!(code), "refusal code: {body}");
    assert_eq!(
        body["error"]["message"],
        json!(message),
        "refusal message: {body}"
    );
    assert!(
        body.get("result").is_none() || body["result"].is_null(),
        "a refusal must carry no result: {body}"
    );
}

/// One accepted call, so the store the negatives run against is warm: a live
/// cache entry, a settled admission entry and a registered nonce.
async fn warm(state: &Arc<AppState>, backend: &EchoBackend) {
    let (status, body) = send(state, invoke("warm", "warm-key", Some(json!("warm-nonce")))).await;
    assert_completed(status, &body);
    assert_eq!(
        backend.tools_call_count(),
        1,
        "the warming call must dispatch"
    );
}

// ── Component control: every counter is written at a real operation ──────────

/// COMPONENT control, not a wire test: the real `ExecutionAdmission` driven
/// through each map operation in turn, which is the only way to reach
/// in-flight, mismatch and abandonment deterministically.
///
/// The step that matters most is the mismatch — a refusal is NOT "touched no
/// entry". It probes twice and refuses on what it found.
/// One sync admission request. A free function rather than a closure: the
/// returned `Request` borrows its arguments, and a closure cannot express that
/// relation without a higher-ranked bound.
fn sync_request<'a>(operation: &'a Value, representation: &'a Value) -> Request<'a> {
    Request {
        principal: "component-principal",
        key: "component-key",
        operation,
        representation,
        mode: Mode::Sync,
    }
}

#[test]
fn component_control_counts_each_real_admission_operation() {
    let owner = ExecutionAdmission::new(Arc::new(|| CLOCK_EPOCH));
    let operation = json!({"kind": "backend", "tool": TOOL});
    let other_operation = json!({"kind": "backend", "tool": "a-different-tool"});
    let representation = json!({"meta": "component-control"});
    let request = || sync_request(&operation, &representation);
    let other_request = || sync_request(&other_operation, &representation);

    // 1. A cold admission READS the map twice — the expiry probe and the
    //    ownership probe — and both MISS, before it writes anything.
    let lease = match owner.admit(request()) {
        Ok(Admission::Owned(lease)) => lease,
        other => panic!("a cold admission must be owned: {other:?}"),
    };
    assert_eq!(
        owner.observed(),
        Observed {
            admit_attempts: 1,
            lookups: 2,
            lookup_misses: 2,
            reservations: 1,
            ..Observed::default()
        },
        "a cold store is read before it is written, twice, and both reads miss"
    );
    assert_eq!(owner.snapshot().entries, 1);

    // 2. The same key while the lease is held: two probes that HIT, answered as
    //    in-flight, and no reservation.
    assert!(matches!(owner.admit(request()), Ok(Admission::InFlight)));
    let held = owner.observed();
    assert_eq!(held.in_flight_served, 1);
    assert_eq!(held.lookup_hits, 2, "both probes found the held entry");
    assert_eq!(held.reservations, 1, "an in-flight answer reserves nothing");

    // 3. The same key for a DIFFERENT operation: refused — and the refusal
    //    performed two real lookups on the way. This is the case an
    //    outcome-derived counter reports as "touched no entry".
    assert!(owner.admit(other_request()).is_err());
    let mismatched = owner.observed();
    assert_eq!(mismatched.mismatch_refusals, 1);
    assert_eq!(
        mismatched.lookups,
        held.lookups + 2,
        "a mismatch refusal probes the map twice before refusing"
    );
    assert_eq!(mismatched.reservations, 1);

    // 4. Dropped before dispatch: one probe and one real removal.
    drop(lease);
    assert_eq!(
        owner.observed(),
        Observed {
            admit_attempts: 3,
            lookups: 7,
            lookup_hits: 5,
            lookup_misses: 2,
            reservations: 1,
            in_flight_served: 1,
            mismatch_refusals: 1,
            abandon_attempts: 1,
            abandon_removals: 1,
            ..Observed::default()
        },
        "an undispatched drop releases the slot through a real removal"
    );
    assert_eq!(owner.snapshot().entries, 0);

    // 5. Re-admit, dispatch, settle: a real completion mutation with retention.
    let mut lease = match owner.admit(request()) {
        Ok(Admission::Owned(lease)) => lease,
        other => panic!("the released key must be admissible again: {other:?}"),
    };
    lease.mark_dispatched();
    assert_eq!(
        lease.complete_secured(&json!({"content": [{"type": "text", "text": "ok"}]})),
        Settlement::Retained
    );
    let settled = owner.observed();
    assert_eq!(settled.settlement_attempts, 1);
    assert_eq!(settled.settlement_mutations, 1);
    assert_eq!(settled.reservations, 2);
    assert!(
        owner.snapshot().result_bytes > 0,
        "a retained settlement stores its bytes"
    );

    // 6. The same key once more: two probes that hit, answered as a replay.
    assert!(matches!(owner.admit(request()), Ok(Admission::Replay(_))));
    let replayed = owner.observed();
    assert_eq!(replayed.replays_served, 1);
    assert_eq!(
        replayed.reservations, settled.reservations,
        "a replay reserves nothing"
    );
    assert_eq!(replayed.lookup_hits, settled.lookup_hits + 2);

    // 7. Nothing has expired under the fixed clock, so reclamation removes
    //    nothing — and says so. Expiry and capacity reclamation belong to the
    //    bounds row, not to this checkpoint.
    assert_eq!(owner.reclaim_completed(), 0);
    assert_eq!(owner.observed().reclaimed_entries, 0);
    assert_eq!(owner.observed().expiry_removals, 0);
}

// ── Positive controls at the wire: both mechanisms are live ──────────────────

#[tokio::test]
async fn a_valid_nonce_misses_the_cold_cache_and_the_next_call_hits_it() {
    let backend = EchoBackend::start().await;
    let (state, _owner) = gateway(&backend.url).await;
    let before = read(&state, &backend);
    assert_eq!(
        before,
        Reading {
            cache_hits: 0,
            cache_misses: 0,
            cache_entries: 0,
            admission: crate::idempotency::admission::Snapshot::default(),
            observed: Observed::default(),
            backend_calls: 0,
        },
        "the fixture must start cold, or 'unchanged' below proves nothing"
    );

    let (status, body) = send(&state, invoke("cold", "key-a", Some(json!("nonce-a")))).await;
    assert_completed(status, &body);

    let cold = read(&state, &backend);
    assert_eq!(cold.cache_misses, 1, "a cold read is a read, and it misses");
    assert_eq!(cold.cache_hits, 0);
    assert_eq!(cold.cache_entries, 1, "the answer must be stored");
    assert_eq!(cold.backend_calls, 1);
    assert_eq!(cold.observed.admit_attempts, 1);
    assert_eq!(
        cold.observed.lookup_misses, 2,
        "a cold admission probes twice and misses twice"
    );
    assert_eq!(cold.observed.reservations, 1);
    assert_eq!(
        cold.observed.settlement_mutations, 1,
        "a dispatched call settles through a real status write"
    );
    assert_eq!(cold.observed.replays_served, 0);
    assert_eq!(cold.admission.entries, 1);
    assert!(
        cold.admission.result_bytes > 0,
        "a settled sync execution retains its secured result: {:?}",
        cold.admission
    );

    // A distinct key and a distinct nonce, so neither the nonce store nor
    // admission can answer this one: only the response cache can. The arguments
    // are identical, which is what makes the cache key identical.
    let (status, body) = send(&state, invoke("warm", "key-b", Some(json!("nonce-b")))).await;
    assert_completed(status, &body);

    let warmed = read(&state, &backend);
    assert_eq!(warmed.cache_hits, 1, "the second call must hit the cache");
    assert_eq!(warmed.cache_misses, 1, "and must not add a miss");
    assert_eq!(
        warmed.backend_calls, 1,
        "a cache hit must not reach the backend again"
    );
    assert_eq!(
        warmed.observed.reservations, 2,
        "a new key reserves its own slot"
    );
    assert_eq!(warmed.observed.replays_served, 0);
    // The cache hit returns before dispatch, so that lease was never marked
    // dispatched and releases its slot: a real abandonment on the wire path.
    assert_eq!(warmed.observed.abandon_removals, 1);
    assert_eq!(warmed.admission.entries, 1);
}

#[tokio::test]
async fn a_repeated_key_replays_from_admission_before_the_cache_is_read() {
    // The lookup half at the wire, and a second ordering oracle: a replay is
    // answered by the execution owner and returns before dispatch, so the
    // response cache must show no read at all.
    let backend = EchoBackend::start().await;
    let (state, _owner) = gateway(&backend.url).await;
    warm(&state, &backend).await;
    let before = read(&state, &backend);

    // The warming call's idempotency key, a fresh nonce, the same target and
    // the same arguments: the operation and representation match, so this is
    // the same logical execution and admission owns the answer.
    let (status, body) = send(
        &state,
        invoke("repeat", "warm-key", Some(json!("fresh-nonce"))),
    )
    .await;
    assert_completed(status, &body);

    let after = read(&state, &backend);
    assert_eq!(
        after.observed.admit_attempts,
        before.observed.admit_attempts + 1,
        "the call must reach admission"
    );
    assert_eq!(after.observed.replays_served, 1, "and be answered as one");
    assert_eq!(
        after.observed.lookup_hits,
        before.observed.lookup_hits + 2,
        "both probes hit the retained entry"
    );
    assert_eq!(
        after.observed.reservations, before.observed.reservations,
        "a replay reserves nothing"
    );
    assert_eq!(
        after.cache_hits, before.cache_hits,
        "a replay returns before the response cache is consulted"
    );
    assert_eq!(after.cache_misses, before.cache_misses);
    assert_eq!(after.backend_calls, before.backend_calls);
    assert_eq!(after.admission.entries, before.admission.entries);
}

#[tokio::test]
async fn a_256_byte_nonce_is_accepted_and_a_257_byte_one_is_refused() {
    let backend = EchoBackend::start().await;
    let (state, _owner) = gateway(&backend.url).await;

    // 64 four-byte characters: 256 bytes, and only 64 characters — the bound is
    // on bytes, so a character count would admit the 260-byte case below.
    let at_bound = "😀".repeat(64);
    assert_eq!(at_bound.len(), 256);
    let (status, body) = send(&state, invoke("at", "key-at", Some(json!(at_bound)))).await;
    assert_completed(status, &body);

    let accepted = read(&state, &backend);

    let over = "a".repeat(257);
    let (status, body) = send(&state, invoke("over", "key-over", Some(json!(over)))).await;
    assert_refused(status, &body, -32602, "Invalid signing nonce");
    assert_eq!(
        read(&state, &backend),
        accepted,
        "one byte over the bound must consume nothing"
    );

    // 65 four-byte characters: 260 bytes. Refused despite being 65 characters.
    let over_unicode = "😀".repeat(65);
    assert_eq!(over_unicode.len(), 260);
    let (status, body) = send(
        &state,
        invoke("over-unicode", "key-over-u", Some(json!(over_unicode))),
    )
    .await;
    assert_refused(status, &body, -32602, "Invalid signing nonce");
    assert_eq!(read(&state, &backend), accepted);
}

// ── The negatives ────────────────────────────────────────────────────────────

#[tokio::test]
async fn a_missing_required_nonce_refuses_before_the_cache_and_admission() {
    let backend = EchoBackend::start().await;
    let (state, _owner) = gateway(&backend.url).await;

    // Cold. Not "a cold store cannot be read" — it can, and a read would show
    // as a cache MISS and as two admission lookup misses. That those counters
    // stay at zero is precisely the claim.
    let cold = read(&state, &backend);
    let (status, body) = send(&state, invoke("cold-missing", "key-cold", None)).await;
    assert_refused(
        status,
        &body,
        -32001,
        "Nonce required when message signing is enforced",
    );
    assert_eq!(read(&state, &backend), cold, "cold store must be untouched");

    // Warm: a live cache entry and a live admission entry exist and could be
    // read. The refusal must still probe neither.
    warm(&state, &backend).await;
    let warmed = read(&state, &backend);
    assert!(
        warmed.cache_entries > 0,
        "the warming call must leave a cache entry to be read: {warmed:?}"
    );
    assert!(
        warmed.admission.entries > 0,
        "the warming call must leave a settled entry to be replayed: {warmed:?}"
    );

    let (status, body) = send(&state, invoke("warm-missing", "warm-key", None)).await;
    assert_refused(
        status,
        &body,
        -32001,
        "Nonce required when message signing is enforced",
    );
    assert_eq!(
        read(&state, &backend),
        warmed,
        "a refusal must not read the cache, and must not probe the key it \
         reuses — either would show as a lookup or a hit"
    );
}

#[tokio::test]
async fn malformed_nonce_shapes_refuse_before_the_cache_and_admission() {
    let backend = EchoBackend::start().await;
    let (state, _owner) = gateway(&backend.url).await;

    // Every shape a client can send that never becomes a usable nonce. A table
    // because the assertion is identical and only the value varies.
    let malformed = [
        ("null", Value::Null),
        ("non-string", json!(42)),
        ("boolean", json!(true)),
        ("object", json!({"nonce": "nested"})),
        ("empty", json!("")),
        ("oversized-ascii", json!("a".repeat(257))),
    ];

    for warmed_store in [false, true] {
        if warmed_store {
            warm(&state, &backend).await;
        }
        let before = read(&state, &backend);
        for (label, nonce) in &malformed {
            let id = format!("{label}-{warmed_store}");
            let (status, body) = send(
                &state,
                // The same idempotency key the warming call used: if the
                // refusal ran after admission it would be served that call's
                // retained result, and `replays_served` would say so.
                invoke(&id, "warm-key", Some(nonce.clone())),
            )
            .await;
            assert_refused(status, &body, -32602, "Invalid signing nonce");
            assert_eq!(
                read(&state, &backend),
                before,
                "{label} (warm={warmed_store}) must consume no cache and no admission"
            );
        }
    }
}

#[tokio::test]
async fn a_replayed_nonce_refuses_before_the_cache_and_admission() {
    let backend = EchoBackend::start().await;
    let (state, _owner) = gateway(&backend.url).await;
    warm(&state, &backend).await;
    let before = read(&state, &backend);

    // The nonce the warming call registered, under a different idempotency key
    // and a different request id: only the nonce is reused.
    let (status, body) = send(
        &state,
        invoke("replay", "replay-key", Some(json!("warm-nonce"))),
    )
    .await;
    assert_refused(status, &body, -32001, "Nonce replay detected");
    assert_eq!(
        read(&state, &backend),
        before,
        "a replayed nonce is refused at the store, before any execution owner \
         probes the map for it"
    );

    // The store is still usable afterwards: a refusal must not wedge it.
    let (status, body) = send(
        &state,
        invoke("after", "after-key", Some(json!("after-nonce"))),
    )
    .await;
    assert_completed(status, &body);
    assert_eq!(
        read(&state, &backend).observed.reservations,
        before.observed.reservations + 1
    );
}

// ── What this route does NOT reach ───────────────────────────────────────────

#[tokio::test]
async fn the_legacy_idempotency_cache_is_not_wired_on_this_route() {
    // Recorded rather than instrumented. `MetaMcp::build` sets this to `None`
    // and `Gateway::build_meta_mcp` never sets it, so `idempotency_key_for`
    // returns `None` for every call and `enforce` is unreachable from a built
    // gateway. Counters inside `crate::idempotency::IdempotencyCache` would
    // therefore have proved nothing about this route — which is why this file
    // observes `ExecutionAdmission` and states the gap instead of dressing an
    // unreachable path as evidence.
    let backend = EchoBackend::start().await;
    let (state, _owner) = gateway(&backend.url).await;
    assert!(
        state.meta_mcp.idempotency_cache.is_none(),
        "if this ever becomes Some, the legacy guard is on the route and needs \
         its own observers before any 'no idempotency work' claim holds"
    );
}

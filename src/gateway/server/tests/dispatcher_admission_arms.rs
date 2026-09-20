// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The stdio dispatcher's four admission arms, observed at the dispatcher
//! rather than at the gate that produces them.
//!
//! Design and review: `docs/release/v4.0.0-dispatcher-regression-design.md`.
//!
//! `src/gateway/meta_mcp/admission_tests.rs` already pins what `admit` decides.
//! What nothing pinned until now is what the dispatcher DOES with each of the
//! four decisions — and two of those arms are early breaks, so a regression
//! turning either into a fallthrough would still return a well-formed answer
//! while silently re-running a mutation.
//!
//! The instrument is the fixture's own `tools_call_count()`, which derives the
//! count from the requests the backend actually received. No second tally is
//! kept: a counter maintained beside the record can disagree with it, and then
//! neither number is evidence.
//!
//! Every row uses its own idempotency key, so the record one row stores cannot
//! reach another row's setup and each failure stays attributable to one row.

use serde_json::{Value, json};

use super::signing_nonce_allocations_support::{Fixture, SESSION, error_of, invoke};

/// The production stdio entry point, called exactly as `run_stdio` calls it.
async fn dispatch(fixture: &Fixture, request: Value) -> Value {
    super::super::Gateway::dispatch_single_with_sink(
        &fixture.meta,
        &fixture.tool_policy,
        &fixture.mtls_policy,
        request,
        super::super::StdioClient {
            session_id: SESSION,
            channel: &crate::gateway::input_bridge::NoClientChannel,
            handshake_capabilities: crate::protocol::meta::Declared::NONE,
        },
        &super::super::StdioTelemetry::default(),
    )
    .await
    .expect("a request carrying an id must produce a response")
}

/// `invoke` with an idempotency key in `_meta`, which is where
/// `RetryFields::from_params` reads it from.
fn keyed(id: &str, key: &str, arguments: Value) -> Value {
    let mut request = invoke(id, None, arguments);
    request["params"]["_meta"]
        .as_object_mut()
        .expect("the invoke builder must produce a _meta object")
        .insert(
            crate::protocol::mrtr::IDEMPOTENCY_KEY_META.to_string(),
            json!(key),
        );
    request
}

fn assert_ok(phase: &str, response: &Value) {
    assert!(
        response.get("error").is_none(),
        "{phase} must succeed, got {response}"
    );
}

// ── Unprotected ──────────────────────────────────────────────────────────────

/// An unkeyed call against an operator-declared read-only target is
/// `Unprotected`: it dispatches.
///
/// Without this row the `Unprotected` arm has no dispatcher coverage at all —
/// the other three rows all carry a key. The arm's other obligation, that it
/// holds no lease, is NOT asserted here: `dispatch_single_with_sink` does not
/// return the `Option<SyncLease>` that `dispatch_tools_call` produces, so the
/// lease is unobservable from the production entry point. See D24/D26 in
/// `docs/release/v4.0.0-dispatcher-regression-design.md`.
#[tokio::test]
async fn an_unkeyed_read_only_call_dispatches_exactly_once() {
    let fixture = Fixture::start(false).await;

    let response = dispatch(&fixture, invoke("u1", None, json!({}))).await;

    assert_ok("an unkeyed read-only call", &response);
    assert_eq!(
        fixture.backend.tools_call_count(),
        1,
        "the unkeyed call must reach the backend exactly once"
    );
}

// ── Owned ────────────────────────────────────────────────────────────────────

/// A keyed call against a mutating target is `Owned`: it dispatches once.
///
/// The control for the replay row below. Without it, "the second call did not
/// reach the backend" is also satisfied by a dispatcher that never reached it
/// on the first call either.
#[tokio::test]
async fn a_keyed_mutation_dispatches_exactly_once() {
    let fixture = Fixture::start_mutating().await;

    let response = dispatch(&fixture, keyed("o1", "key-owned", json!({}))).await;

    assert_ok("a keyed mutating call", &response);
    assert_eq!(
        fixture.backend.tools_call_count(),
        1,
        "a keyed mutation must reach the backend exactly once"
    );
}

// ── Replay ───────────────────────────────────────────────────────────────────

/// The same key twice returns the stored result without re-running it.
///
/// The `result` is compared, not the whole envelope: `admission.rs:190`
/// deliberately rewrites `response.id` to the current request, so an
/// envelope-equality assertion would fail against correct code. Asserting the
/// second id is what proves the replay was correlated to THIS request rather
/// than handed back verbatim.
///
/// The count assertion is the load-bearing half. Equality alone is satisfied by
/// a dispatcher that re-ran an idempotent backend and got the same answer.
#[tokio::test]
async fn a_replayed_key_returns_the_stored_result_without_re_running_it() {
    let fixture = Fixture::start_mutating().await;
    let arguments = json!({"note": "charge-once"});

    let first = dispatch(&fixture, keyed("r1", "key-replay", arguments.clone())).await;
    assert_ok("the first keyed call", &first);
    assert_eq!(
        fixture.backend.tools_call_count(),
        1,
        "the first keyed call must reach the backend"
    );

    let second = dispatch(&fixture, keyed("r2", "key-replay", arguments)).await;

    assert_ok("the replayed call", &second);
    // `content`, not the whole `result`: the replayed response is re-signed,
    // because the signature covers the id that `admission.rs:190` has just
    // rewritten to this request. Comparing `result` wholesale fails against
    // correct code — which is how this assertion found its own scope.
    assert_eq!(
        second["result"]["content"], first["result"]["content"],
        "the replay must return the stored content: {second}"
    );
    assert_eq!(
        second["result"]["isError"], first["result"]["isError"],
        "the replay must return the stored error flag: {second}"
    );
    assert_ne!(
        second["result"]["_signature"]["sig"], first["result"]["_signature"]["sig"],
        "the replay must be re-signed for this request, not handed back verbatim: {second}"
    );
    assert_eq!(
        second.get("id"),
        Some(&json!("r2")),
        "the replay must be correlated to the second request: {second}"
    );
    assert_eq!(
        fixture.backend.tools_call_count(),
        1,
        "the replay must not reach the backend a second time"
    );
}

// ── Err ──────────────────────────────────────────────────────────────────────

/// A key reused with different arguments is refused, and the refusal happens
/// BEFORE dispatch.
///
/// The count assertion is what separates a refusal before dispatch from one
/// after: a dispatcher that ran the mutation and then refused to return its
/// result would satisfy the error-code assertion alone.
#[tokio::test]
async fn a_conflicting_key_is_refused_before_the_backend_is_reached() {
    let fixture = Fixture::start_mutating().await;

    let first = dispatch(&fixture, keyed("c1", "key-conflict", json!({"amount": 1}))).await;
    assert_ok("the first keyed call", &first);
    assert_eq!(fixture.backend.tools_call_count(), 1);

    let conflict = dispatch(
        &fixture,
        keyed("c2", "key-conflict", json!({"amount": 999})),
    )
    .await;

    let (code, message) = error_of(&conflict);
    assert_eq!(
        code, 409,
        "a reused key with different arguments must be refused: {conflict} ({message})"
    );
    // The code alone does not attribute the refusal. `backend_handlers.rs:824`
    // runs a SECOND idempotency guard downstream of this arm, and
    // `idempotency.rs:842` answers a mismatched key with its own 409 before the
    // backend — so a dispatcher that fell through this arm would still produce
    // 409 with a count of 1. The message is what separates the two producers.
    // Substring, not equality: `Error::json_rpc` renders as
    // `JSON-RPC error 409: <text>`, so pinning the whole string would pin the
    // wrapper's formatting alongside the identity of the refuser.
    assert!(
        message.contains("belongs to another execution or representation"),
        "the refusal must come from the dispatcher's admission arm \
         (`meta_mcp/admission.rs:200`), not the downstream guard: {conflict}"
    );
    assert_eq!(
        fixture.backend.tools_call_count(),
        1,
        "the refused call must not have reached the backend"
    );
}

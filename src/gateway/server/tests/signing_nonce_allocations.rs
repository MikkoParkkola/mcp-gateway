// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-7377.SIGNING.5, row 40, first checkpoint: a nonce refusal on the OWNED
//! stdio dispatcher must not pay for the payload it refuses.
//!
//! What is measured: every real allocation made on this thread while
//! `Gateway::dispatch_single_with_sink` — the exact function `run_stdio` calls,
//! not a duplicate validator — runs to completion on a prepared 1 MiB or 3 MiB
//! request. Runtime, gateway, backend, payload and expectations are built
//! before the scope opens; every assertion and every formatted message happens
//! after it closes.
//!
//! COLD and WARM mean what they say here. A refusal populates nothing — the
//! qualified-observer gate already established that refusals leave the nonce
//! store, the response cache and the admission owner untouched — so measuring
//! two refusals in a row would have measured cold twice. Between the two
//! readings the fixture serves one UNMETERED valid call that reaches the real
//! backend, which warms the response cache and the nonce store. It does NOT
//! warm a durable admission record: stdio has no authenticated identity, so the
//! call travels unkeyed against a configured read-only target and takes
//! `SyncAdmission::Unprotected`, which owns no lease. Admission-observer
//! evidence is row 39's, already proved there under its own qualified fixture,
//! and is not claimed from this one. The call is also the policy control: it
//! proves the refusals below refuse something that otherwise works.
//!
//! What is NOT measured here, and is the next artifact rather than a gap
//! silently left open: the HTTP path's body parse, sanitiser, request scanner
//! and maximum-body rejection; retry siblings; multiple batch items; the
//! metadata-ownership table. Row 40 is not done when this file is green.
//!
//! Two controls sit under the SAME meter, because a byte counter that is blind
//! proves nothing by reporting a small number:
//! * positive — a forced deep clone of the prepared tree must cost at least
//!   the payload's own size;
//! * negative — one known-size allocation must be reported at its known size.

use serde_json::{Value, json};

use super::alloc_meter::{LARGE_BYTES, Measured, measure, measure_async};
use super::signing_nonce_allocations_support::{
    Fixture, ONE_MIB, SESSION, THREE_MIB, error_of, invoke, isolate, nested_arguments, runtime,
};

/// What a refused dispatch may allocate, run as the serve loop runs it
/// (MIK-8400). Two populations, each with its own cap, split at
/// `alloc_meter::LARGE_BYTES` (2 KiB):
///
/// - Small allocations are what the refusal itself does (records, strings,
///   tables): at most [`SMALL_BUDGET`] bytes. A payload-sized copy or new
///   per-refusal churn breaks it.
/// - Large allocations store dispatch futures: the serve loop's box of the
///   whole dispatch (`stdio_loop.rs`) and the `tools/call` dispatch's own box
///   (`Box::pin(Self::dispatch_tools_call(..))` in `stdio_dispatch.rs`, inside
///   `slot_rpc`), where a missing or replayed nonce is refused after the
///   policy. At most [`LARGE_ALLOCATIONS`] of them and [`LARGE_BUDGET`] bytes
///   in all: an extra boxed dispatch or a growing dispatch state breaks it.
///   No lint bounds them: `clippy::large_futures` does not see a future behind
///   `Box::pin`, and `dispatch_single_staged` allows it.
///
/// #3841 boxed the whole stdio dispatch a third time, inside the visibility
/// memo; it is pinned in place since.
const SMALL_BUDGET: u64 = 8 * 1024;
const LARGE_ALLOCATIONS: u64 = 2;
const LARGE_BUDGET: u64 = 12 * 1024;

/// The three refusal errors are settled production controls, pinned exactly.
/// `wire_error_message` preserves each text.
const MISSING_NONCE: (i64, &str) = (-32001, "Nonce required when message signing is enforced");
const MALFORMED_NONCE: (i64, &str) = (-32602, "Invalid signing nonce");
const REPLAYED_NONCE: (i64, &str) = (-32001, "Nonce replay detected");

/// A libtest filter names a test from the crate ROOT's children down —
/// `gateway::server::…` — while `module_path!()` prefixes the crate itself.
/// Stripping exactly the first component keeps the filter correct through a
/// module rename; a hand-written literal would not, and a filter that matches
/// nothing exits zero with every control unrun.
///
/// MUST stay in the same module as the tests that call it. `module_path!()`
/// expands where it is written, so moving this helper into the meter or the
/// support file would aim every filter at the wrong module and match nothing —
/// the exact failure it exists to prevent.
fn test_path(name: &str) -> String {
    let module = module_path!();
    let module = module
        .split_once("::")
        .map_or(module, |(_crate, rest)| rest);
    format!("{module}::{name}")
}

/// The stdio client every call in this file is, the session `SESSION`.
fn client() -> super::super::StdioClient<'static> {
    super::super::StdioClient {
        session_id: SESSION,
        channel: &crate::gateway::input_bridge::NoClientChannel,
        handshake_capabilities: crate::protocol::meta::Declared::NONE,
        tasks: None,
        serving: crate::gateway::server::stdio_single::ModernServing::Enabled,
        discover: crate::gateway::server::stdio_single::DiscoverListing::Configured,
        sanitize: crate::gateway::server::stdio_single::InputSanitizing::Off,
    }
}

/// The production stdio dispatcher, called as `run_stdio` calls it (owned
/// `Value` moved in, no sink, the stdio session id), unmetered calls only;
/// the measured ones go through [`dispatch_as_served`].
async fn dispatch(fixture: &Fixture, request: Value) -> Value {
    super::super::Gateway::dispatch_single_with_sink(
        &fixture.meta,
        &fixture.tool_policy,
        &fixture.mtls_policy,
        request,
        client(),
        &super::super::StdioTelemetry::default(),
    )
    .await
    .expect("a request carrying an id must produce a response")
}

/// The dispatch as the serve loop runs it (`stdio_loop.rs`):
/// `dispatch_single_staged` boxed whole, then its answer settled as
/// `dispatch_single_with_sink` settles it (no frame judge in this fixture).
async fn dispatch_as_served(fixture: &Fixture, request: Value) -> Value {
    let (answer, staged) = Box::pin(super::super::Gateway::dispatch_single_staged(
        &fixture.meta,
        &fixture.tool_policy,
        &fixture.mtls_policy,
        request,
        client(),
        &super::super::StdioTelemetry::default(),
    ))
    .await;
    let answer = answer.expect("a request carrying an id must produce a response");
    let frame = answer.delivered_unjudged(&fixture.meta, SESSION).await;
    staged.commit(frame.delivers_result());
    frame
        .stdio_value()
        .map(std::borrow::Cow::into_owned)
        .expect("a refusal is delivered as a frame")
}

fn assert_refusal(phase: &str, response: &Value, expected: (i64, &str)) {
    let (code, message) = error_of(response);
    assert_eq!(
        (code, message.as_str()),
        expected,
        "{phase} refusal changed its wire error: {response}"
    );
}

fn assert_within_budget(phase: &str, payload_bytes: usize, measured: Measured) {
    let small_bytes = measured.bytes - measured.large_bytes;
    assert!(
        small_bytes <= SMALL_BUDGET,
        "{phase} refusal of a {payload_bytes}-byte payload allocated {measured}: \
         {small_bytes} bytes under {LARGE_BYTES} each, above the {SMALL_BUDGET}-byte cap"
    );
    assert!(
        measured.large <= LARGE_ALLOCATIONS && measured.large_bytes <= LARGE_BUDGET,
        "{phase} refusal of a {payload_bytes}-byte payload allocated {measured}: \
         {} bytes in large allocations, above {LARGE_ALLOCATIONS} or {LARGE_BUDGET} bytes \
         (another boxed dispatch, or a dispatch state that grew?)",
        measured.large_bytes
    );
}

/// One refusal measured on a fixture that has never served anything, and the
/// same refusal measured again after one real call has warmed the gateway.
///
/// Every large tree is prepared before its own meter opens — constructing one
/// costs more than the whole budget.
fn refusal_cold_and_warm(payload_bytes: usize, nonce: Option<Value>, expected: (i64, &str)) {
    runtime().block_on(async move {
        let fixture = Fixture::start(true).await;
        let cold_request = invoke("cold", nonce.clone(), nested_arguments(payload_bytes));
        // A distinguishable payload, so a warm refusal could not be answered
        // from the warming call's response-cache entry even if the nonce check
        // stopped preceding admission. The budget must not depend on an
        // ordering another row is what asserts.
        let mut warming_arguments = nested_arguments(payload_bytes);
        warming_arguments["label"] = json!("stdio-allocation-warming");
        let warming_request = invoke(
            "warming",
            Some(json!("stdio-allocation-warming-nonce-0001")),
            warming_arguments,
        );
        let warm_request = invoke("warm", nonce, nested_arguments(payload_bytes));
        assert_eq!(
            fixture.backend.tools_call_count(),
            0,
            "the fixture must serve the cold reading first"
        );

        let (cold_response, cold) =
            measure_async(|| dispatch_as_served(&fixture, cold_request)).await;
        assert_refusal("cold", &cold_response, expected);
        assert_eq!(
            fixture.backend.tools_call_count(),
            0,
            "the cold refusal reached the backend"
        );

        // Unmetered, and the reason the next reading is warm: this is the call
        // that populates the nonce store and the response cache. It leaves no
        // durable admission record — unkeyed against a configured read-only
        // target is `SyncAdmission::Unprotected` — so nothing here stands in
        // for row 39's admission-observer evidence. It is also the control that
        // the policy admits real traffic.
        let warming_response = dispatch(&fixture, warming_request).await;
        assert!(
            warming_response.get("error").is_none(),
            "a valid nonce must be admitted: {warming_response}"
        );
        assert_eq!(
            fixture.backend.tools_call_count(),
            1,
            "the admitted call must have reached the real backend"
        );

        let (warm_response, warm) =
            measure_async(|| dispatch_as_served(&fixture, warm_request)).await;
        assert_refusal("warm", &warm_response, expected);
        assert_eq!(
            fixture.backend.tools_call_count(),
            1,
            "the warm refusal reached the backend"
        );

        assert_within_budget("cold", payload_bytes, cold);
        assert_within_budget("warm", payload_bytes, warm);
    });
}

/// A nonce accepted once on a fresh fixture, then replayed. The first call is
/// unmetered and reaches the real backend; only the replay is measured.
fn replay_under_budget(payload_bytes: usize) {
    runtime().block_on(async move {
        let fixture = Fixture::start(true).await;
        let nonce = json!("stdio-allocation-checkpoint-nonce-0001");
        let accepted_request = invoke(
            "accepted",
            Some(nonce.clone()),
            nested_arguments(payload_bytes),
        );
        let replay_request = invoke("replay", Some(nonce), nested_arguments(payload_bytes));

        let accepted = dispatch(&fixture, accepted_request).await;
        assert!(
            accepted.get("error").is_none(),
            "a valid nonce must be admitted: {accepted}"
        );
        assert_eq!(
            fixture.backend.tools_call_count(),
            1,
            "the admitted call must have reached the real backend"
        );

        let (response, measured) =
            measure_async(|| dispatch_as_served(&fixture, replay_request)).await;

        assert_refusal("replay", &response, REPLAYED_NONCE);
        assert_eq!(
            fixture.backend.tools_call_count(),
            1,
            "a replayed nonce reached the backend a second time"
        );
        assert_within_budget("replay", payload_bytes, measured);
    });
}

// ── The checkpoint ───────────────────────────────────────────────────────────

#[test]
fn stdio_missing_nonce_refusal_1mib_stays_under_budget() {
    if isolate(&test_path(
        "stdio_missing_nonce_refusal_1mib_stays_under_budget",
    )) {
        return;
    }
    refusal_cold_and_warm(ONE_MIB, None, MISSING_NONCE);
}

#[test]
fn stdio_missing_nonce_refusal_3mib_stays_under_budget() {
    if isolate(&test_path(
        "stdio_missing_nonce_refusal_3mib_stays_under_budget",
    )) {
        return;
    }
    refusal_cold_and_warm(THREE_MIB, None, MISSING_NONCE);
}

/// A present nonce that never was a string: refused by `delivery()` before the
/// store sees it, so it must cost even less than the missing one.
#[test]
fn stdio_malformed_nonce_refusal_1mib_stays_under_budget() {
    if isolate(&test_path(
        "stdio_malformed_nonce_refusal_1mib_stays_under_budget",
    )) {
        return;
    }
    refusal_cold_and_warm(ONE_MIB, Some(json!(42)), MALFORMED_NONCE);
}

#[test]
fn stdio_malformed_nonce_refusal_3mib_stays_under_budget() {
    if isolate(&test_path(
        "stdio_malformed_nonce_refusal_3mib_stays_under_budget",
    )) {
        return;
    }
    refusal_cold_and_warm(THREE_MIB, Some(json!(42)), MALFORMED_NONCE);
}

#[test]
fn stdio_replayed_nonce_refusal_1mib_stays_under_budget() {
    if isolate(&test_path(
        "stdio_replayed_nonce_refusal_1mib_stays_under_budget",
    )) {
        return;
    }
    replay_under_budget(ONE_MIB);
}

#[test]
fn stdio_replayed_nonce_refusal_3mib_stays_under_budget() {
    if isolate(&test_path(
        "stdio_replayed_nonce_refusal_3mib_stays_under_budget",
    )) {
        return;
    }
    replay_under_budget(THREE_MIB);
}

// ── Controls on the meter itself ─────────────────────────────────────────────

/// Positive control. The PREPARED tree — the same value a dispatch is handed —
/// is deep-cloned inside an open scope. Construction happens outside, so what
/// is counted is the copying and nothing else. A counter that cannot see this
/// cannot see a clone inside the dispatcher either, and every budget above
/// would be vacuous.
#[test]
fn forced_whole_tree_clone_costs_at_least_the_payload() {
    if isolate(&test_path(
        "forced_whole_tree_clone_costs_at_least_the_payload",
    )) {
        return;
    }
    for payload_bytes in [ONE_MIB, THREE_MIB] {
        let prepared = nested_arguments(payload_bytes);
        let serialised = serde_json::to_vec(&prepared)
            .expect("prepared serialises")
            .len();
        let (clone, measured) = measure(|| std::hint::black_box(prepared.clone()));
        // `assert!`, not `assert_eq!`: on failure the latter formats both
        // multi-megabyte trees into the panic message, which reads as a hang.
        assert!(clone == prepared, "the control must clone the whole tree");
        assert!(
            measured.bytes >= serialised as u64,
            "cloning a {serialised}-byte tree reported only {measured}: the meter is blind"
        );
    }
}

/// Negative control with a KNOWN floor, not merely "greater than zero" — a
/// counter that saw exactly one allocation ever would pass `> 0`.
#[test]
fn known_size_allocation_is_reported_at_its_known_size() {
    const SIZE: usize = 4096;
    if isolate(&test_path(
        "known_size_allocation_is_reported_at_its_known_size",
    )) {
        return;
    }
    let (buffer, measured) = measure(|| std::hint::black_box(Vec::<u8>::with_capacity(SIZE)));
    assert_eq!(buffer.capacity(), SIZE);
    // Ranges, not equality. The floor is what kills a blind counter; an exact
    // number would also fail on allocator rounding or one incidental
    // allocation, producing "the meter is broken" ahead of the real RED.
    assert!(
        (1..=2).contains(&measured.calls),
        "one reservation must be about one allocator call, not {measured}"
    );
    assert!(
        measured.bytes >= SIZE as u64 && measured.bytes < (SIZE * 2) as u64,
        "a {SIZE}-byte reservation was reported as {measured}"
    );
}

/// MIK-8400 control: the large-allocation count and the largest single
/// allocation sit on the exact `LARGE_BYTES` boundary. A counter that never
/// counted would let every refusal row pass its bound.
#[test]
fn the_large_allocation_count_starts_at_its_boundary() {
    if isolate(&test_path(
        "the_large_allocation_count_starts_at_its_boundary",
    )) {
        return;
    }
    let ((below, at), measured) = measure(|| {
        (
            std::hint::black_box(Vec::<u8>::with_capacity(LARGE_BYTES - 1)),
            std::hint::black_box(Vec::<u8>::with_capacity(LARGE_BYTES)),
        )
    });
    assert_eq!(
        (below.capacity(), at.capacity()),
        (LARGE_BYTES - 1, LARGE_BYTES)
    );
    assert_eq!(
        measured.large, 1,
        "only the {LARGE_BYTES}-byte one is large: {measured}"
    );
    assert_eq!(measured.largest, LARGE_BYTES as u64, "{measured}");
    assert_eq!(measured.large_bytes, LARGE_BYTES as u64, "{measured}");
}

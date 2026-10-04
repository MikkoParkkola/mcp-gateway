// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MRTR.3 forged handles, MRTR.5d foreign processes and MRTR.8 slots.

use super::*;

// ---------------------------------------------------------------------------
// MRTR.3 — a client-presented handle is attacker-controlled (wire half)
// ---------------------------------------------------------------------------
//
// The plan's original oracle — four presentations "each refused with a distinct
// reason" — is not satisfiable here and must not be faked. `client_message()`
// answers one constant for every variant
// (`src/protocol/continuation.rs:234-236`); the per-variant text exists only in
// `Display` (`:239-253`) and never reaches a client. So:
//
//   * distinctness is proved at unit level, on the `ContinuationError` variant;
//   * the wire proves the constant, and nothing more.
//
// The gap between those two is a finding about the requirement, not a hole in
// this file: "each refused with a distinct reason" is unobservable at the wire
// by design, and nobody should later read these cases as covering it. The
// collapse is treated as the specification — a verifier that tells an attacker
// whether a forgery failed for want of a signature, a known key, or an intact
// tag tells them which to fix next.
//
// Four identical refusals cannot fail against a verifier that refuses
// everything, which is exactly what this build does today. The positive control
// is therefore not decoration; it is the only case at this level that
// discriminates a correct verifier from a blanket one.

/// A handle minted by a *different* gateway process.
///
/// `ContinuationState::new()` draws its own key material, so this is the
/// arrangement the accepted design deploys — independent keys per process, no
/// shared store (`docs/design/2026-08-30-shared-continuation-state.md:107-120`).
/// The payload is identical in every field; only the minting key differs.
fn mint_on_a_foreign_process(tool: &str, args: &Value) -> String {
    let foreign = ContinuationState::new();
    let payload = Payload::mint(
        BACKEND.to_string(),
        Some(SEALED_STATE.to_string()),
        fingerprint_of(CALLER_A),
        original_request_digest(BACKEND, tool, args),
        foreign.replica().to_string(),
        // The foreign process's table is not this one's, so no key sealed here
        // could name an exchange this gateway holds. Named rather than empty:
        // the refusal under test is the signature, and a payload that is
        // implausible in a second way makes it ambiguous which guard fired.
        format!("{BACKEND}:foreign-exchange"),
        now_secs(),
    );
    foreign
        .keyring()
        .mint(&payload)
        .expect("the foreign keyring must mint")
}

/// Flip one character in the middle of an envelope, leaving its length intact.
///
/// The tampered byte lands in the sealed body, so the envelope stays
/// well-formed and only its authentication can catch it.
fn tamper(handle: &str) -> String {
    let mut chars: Vec<char> = handle.chars().collect();
    let middle = chars.len() / 2;
    chars[middle] = if chars[middle] == 'A' { 'B' } else { 'A' };
    chars.into_iter().collect()
}

#[tokio::test]
async fn ac_mrtr_3_every_forged_presentation_is_refused_by_the_continuation_guard() {
    // GIVEN: a genuine handle, and four ways a client can present something else.
    let (state, received, _store_dir) = state_with_fixture().await;
    let args = arguments();
    let genuine = mint_for(&state, &received, CALLER_A, TOOL_INTERIM, &args).await;

    let presentations = [
        (
            "in the clear, with no envelope at all",
            json!({
                "backend": BACKEND,
                "principal": fingerprint_of(CALLER_A),
                "backend_request_state": SEALED_STATE
            })
            .to_string(),
        ),
        (
            "minted by a process with independent key material",
            mint_on_a_foreign_process(TOOL, &args),
        ),
        (
            "truncated envelope",
            genuine[..genuine.len() - 8].to_string(),
        ),
        ("tampered body, envelope otherwise intact", tamper(&genuine)),
    ];

    // Every row is driven before anything is asserted, so one failing
    // presentation cannot hide the colour of the three behind it.
    let mut offenders: Vec<String> = Vec::new();
    for (index, (case, handle)) in presentations.iter().enumerate() {
        // WHEN: it is presented on the retry path.
        let (_, response) = post(&state, &retry_body(index as u64 + 1, TOOL, &args, handle)).await;

        // THEN: refused in the continuation vocabulary — the same sentence for
        // all four, which is what the wire specifies. The HTTP status is not
        // asserted: a 400 and a 200-with-error are both refusals, and pinning
        // one would fail a case for a reason that is not its criterion.
        let message = error_message(&response)
            .unwrap_or_else(|| format!("not refused at all, response was {response}"));
        if !message.contains(ContinuationError::Malformed.client_message()) {
            offenders.push(format!("{case}: got {message:?}"));
        }
    }
    assert!(
        offenders.is_empty(),
        "every forged presentation must be refused by the continuation guard; these were not: \
         {offenders:#?}"
    );
}

#[tokio::test]
async fn ac_mrtr_3_a_genuine_handle_is_still_accepted() {
    // GIVEN: the handle this gateway minted, for this principal and this call.
    let (state, received, _store_dir) = state_with_fixture().await;
    let args = arguments();
    let genuine = mint_for(&state, &received, CALLER_A, TOOL_INTERIM, &args).await;

    // WHEN: presented unaltered.
    let (_, response) = post(&state, &retry_body(1, TOOL_INTERIM, &args, &genuine)).await;

    // THEN: the guard did not stop it. Without this half, refusing every
    // presentation passes all four negatives above.
    assert_not_refused_by_the_continuation_guard(&response, "a genuine handle");
}

// ---------------------------------------------------------------------------
// MRTR.5d — a handle does not travel between processes
// ---------------------------------------------------------------------------
//
// The plan files this at `integration`, on the reading that a second process is
// needed. What the criterion actually asserts is that key material is per
// process and a foreign envelope cannot be opened — and two `ContinuationState`
// values already have independent key material, because that is what
// `ContinuationState::new()` does. A second OS process would add a port and a
// binary, not a stronger assertion: the envelope is refused for the same reason
// either way, and this level can observe the refusal's vocabulary, which a
// process boundary would only make harder to read.
//
// Recorded as a plan-vs-code disagreement rather than silently re-levelled. If
// the operator wants the process boundary itself proved, that is a different
// criterion — about deployment, not about continuations.

#[tokio::test]
async fn ac_mrtr_5d_a_handle_minted_by_another_process_is_refused() {
    // GIVEN: a handle minted under key material this process never held.
    let (state, _store_dir) = app_state().await;
    let args = arguments();
    let foreign = mint_on_a_foreign_process(TOOL, &args);

    // WHEN: presented to this process.
    let (_, response) = post(&state, &retry_body(1, TOOL, &args, &foreign)).await;

    // THEN: refused explicitly, in the continuation vocabulary — never silently
    // treated as a fresh call, which is the failure mode a status-only
    // assertion would miss.
    assert_refused_by_the_continuation_guard(&response, "a foreign process's handle");
}

// ---------------------------------------------------------------------------
// MRTR.8 — the bounded table is the gateway's, not just the type's
// ---------------------------------------------------------------------------

/// An exchange the gateway opened must occupy a slot in the bounded table.
///
/// Both bounds MRTR.8 names are already held at `unit` against the type, and
/// held well: `tests/mik_7212_acs/inflight.rs:60` refuses at capacity rather
/// than growing, and `:78` reclaims an abandoned exchange *and* asserts its slot
/// comes back, which is the non-vacuous form the test plan asks for. Neither
/// says anything about the gateway: they drive the table directly, and the
/// criterion is about the *request path* putting an entry in it. That half is
/// what this case carries, and it is the half no unit case can reach.
///
/// `ContinuationState::begin_exchange` is what makes it reachable — it takes
/// the slot and seals its key into the handle in one step, so the count bound
/// and the lifetime bound finally have a subject.
///
/// A green here says the interim path minted *and* held. It says nothing about
/// the MRTR.7 bridge: the fixture backend returns an interim result of its own,
/// where a legacy backend would need the bridge to produce one. Stated so a
/// future reader does not read this green as proof of that.
#[tokio::test]
async fn ac_mrtr_8_an_exchange_the_gateway_opened_occupies_a_slot() {
    let (state, _store_dir) = app_state().await;
    let (url, _received) = spawn_fixture_backend().await;
    register_fixture_backend(&state, &url);

    let (_status, response) = post(&state, &fresh_body(1, TOOL_INTERIM, &arguments())).await;

    assert_eq!(
        state.continuation.in_flight().len(now_secs()).await,
        1,
        "a backend that asked for input leaves an exchange open, and an open \
         exchange must occupy a slot in the bounded table; the table holds \
         nothing, and the gateway answered {response}"
    );
}

/// The discriminator for the case above: a call that finished holds no slot.
///
/// The table is written now, so this is no longer green by vacancy: it says the
/// gateway holds a slot for an exchange that stayed open and for nothing else.
/// Without it, an implementation that holds a slot for *every* call satisfies
/// the positive above while leaking one per request, which is the exhaustion
/// the bound exists to prevent.
#[tokio::test]
async fn ac_mrtr_8_a_call_that_finished_holds_no_slot() {
    let (state, _store_dir) = app_state().await;
    let (url, _received) = spawn_fixture_backend().await;
    register_fixture_backend(&state, &url);

    let (_status, response) = post(&state, &fresh_body(1, TOOL, &arguments())).await;

    assert_eq!(
        state.continuation.in_flight().len(now_secs()).await,
        0,
        "a call the backend answered outright opened no exchange, so it must \
         hold no slot; the gateway answered {response}"
    );
}

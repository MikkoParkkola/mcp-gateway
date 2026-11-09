// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MRTR.4 principal binding and MRTR.5a-c single use, expiry and atomicity.

use super::*;

// ---------------------------------------------------------------------------
// MRTR.4 — a continuation is bound to its principal and its original request
// ---------------------------------------------------------------------------
//
// Both halves are expressible, because the handle comes from the production
// mint path and the request carries an identity.
//
// `mrtr::principal_fingerprint` (`src/protocol/mrtr.rs:357-365`) takes an
// `Option<&VerifiedIdentity>`, and the gateway reads that identity off the
// request extension (`src/gateway/router/handlers.rs:477`). So the negative is
// a handle minted while `CALLER_B` held the request and presented while
// `CALLER_A` does, and the positive is the same caller both times — neither
// side asserting a principal this file invented.
//
// What remains undecided is the principal of an API-key-only caller: the key
// is not retained past validation (`src/protocol/mrtr.rs:331-364`), so the
// verified-agent scheme is the only constructible one today. These cases do
// not depend on that answer.

/// GIVEN a handle minted for one principal, WHEN another presents it,
/// THEN the continuation guard refuses it.
#[tokio::test]
async fn ac_mrtr_4_a_handle_minted_for_one_principal_is_refused_for_another() {
    let (state, received, _store_dir) = state_with_fixture().await;
    let handle = mint_for(&state, &received, CALLER_B, TOOL_INTERIM, &arguments()).await;

    let (_status, response) =
        post(&state, &retry_body(1, TOOL_INTERIM, &arguments(), &handle)).await;

    assert_refused_by_the_continuation_guard(&response, "handle minted for a different principal");
}

/// GIVEN a handle minted against one tool, WHEN it is presented on another,
/// THEN the continuation guard refuses it.
#[tokio::test]
async fn ac_mrtr_4_a_handle_minted_for_one_tool_is_refused_for_another() {
    let (state, received, _store_dir) = state_with_fixture().await;
    let handle = mint_for(&state, &received, CALLER_A, TOOL_INTERIM, &arguments()).await;

    // A listed tool: R2 refuses an unlisted one first (F13), testing existence.
    let (_status, response) = post(&state, &retry_body(1, TOOL, &arguments(), &handle)).await;

    assert_refused_by_the_continuation_guard(&response, "handle minted against a different tool");
}

/// GIVEN a handle, WHEN presented on exactly what it was minted for,
/// THEN the continuation guard does not refuse it.
///
/// The load-bearing half: without it, an implementation that refuses every
/// retry passes both negatives above. See the STOP note for why this control
/// is provisional.
#[tokio::test]
async fn ac_mrtr_4_the_handle_it_was_minted_for_is_not_refused() {
    let (state, received, _store_dir) = state_with_fixture().await;
    let handle = mint_for(&state, &received, CALLER_A, TOOL_INTERIM, &arguments()).await;

    let (_status, response) =
        post(&state, &retry_body(1, TOOL_INTERIM, &arguments(), &handle)).await;

    assert_not_refused_by_the_continuation_guard(&response, "the handle's own request");
}

// ---------------------------------------------------------------------------
// MRTR.5a-c — single use, expiry, and atomicity on the minting process
// ---------------------------------------------------------------------------

/// GIVEN a handle already redeemed once, WHEN it is presented again,
/// THEN the second presentation is refused.
///
/// Both halves in one case on purpose: a ledger that refuses everything and a
/// ledger that refuses nothing are told apart only by asserting the first
/// redemption was *not* refused.
#[tokio::test]
async fn ac_mrtr_5a_a_handle_is_refused_on_its_second_redemption() {
    let (state, received, _store_dir) = state_with_fixture().await;
    let handle = mint_for(&state, &received, CALLER_A, TOOL_INTERIM, &arguments()).await;
    let body = retry_body(1, TOOL_INTERIM, &arguments(), &handle);

    let (_status, first) = post(&state, &body).await;
    let (_status, second) = post(&state, &body).await;

    assert_not_refused_by_the_continuation_guard(&first, "first redemption");
    assert_refused_by_the_continuation_guard(&second, "second redemption of the same handle");
}

/// GIVEN a handle whose deadline has passed, WHEN it is presented,
/// THEN it is refused.
///
/// The deadline is the only thing this case may stage. `Payload::mint` derives
/// `expires_at` from the clock and cannot be asked for a past one, so the
/// payload is re-minted with two timestamps moved — and every other field is
/// taken from a real production mint rather than rebuilt by hand.
///
/// Both timestamps sit inside `CONTINUATION_LIFETIME_SECS`: the window is 100s
/// wide so `mint` will still seal it, and the whole window is behind `now` so
/// the handle is late. Widening it past the ceiling would stage a second defect
/// and the refusal would name `LifetimeExceeded` instead — see
/// `ac_mrtr_8b_a_handle_outliving_the_ceiling_cannot_be_redeemed`, which is
/// where that belongs.
///
/// Hand-building all eight fields is what this avoids, and the avoidance is not
/// stylistic: a hand-written `original_request_digest` silently drifted from the
/// tool the retry posts, and a digest mismatch is refused by the *binding*
/// guard, which would leave this case green in a build with no deadline check at
/// all. Deriving the fields makes that drift unconstructible.
///
/// The `jti` is inherited with the rest. It is unconsumed and its exchange is
/// still open, which is what a legitimate retry carries — presenting it is a
/// first presentation, not a replay, so it stages no second defect for a guard
/// to refuse ahead of the deadline.
///
/// `assert_refused_by_the_continuation_guard` cannot name the reason: every
/// `ContinuationError` variant renders to one client sentence by design
/// (`src/protocol/continuation.rs:224-236`, deferred as DE-9a), so the route
/// assertion proves the refusal came from this guard and nothing finer. The
/// `keyring().open` assertion below is what names expiry, at the one place the
/// distinction survives.
#[tokio::test]
async fn ac_mrtr_5b_a_handle_past_its_deadline_is_refused() {
    let (state, received, _store_dir) = state_with_fixture().await;
    let args = arguments();
    let live = mint_for(&state, &received, CALLER_A, TOOL_INTERIM, &args).await;
    let now = now_secs();
    let minted = state
        .continuation
        .keyring()
        .open(&live, now)
        .expect("a handle the gateway just minted must open");

    let expired = Payload {
        issued_at: now - 200,
        expires_at: now - 100,
        ..minted
    };
    let handle = state
        .continuation
        .keyring()
        .mint(&expired)
        .expect("the production keyring must mint an expired payload too");
    assert!(
        matches!(
            state.continuation.keyring().open(&handle, now),
            Err(ContinuationError::Expired)
        ),
        "the deadline must be this handle's only defect, or the refusal below \
         proves whichever guard runs first"
    );

    let (_status, response) = post(&state, &retry_body(1, TOOL_INTERIM, &args, &handle)).await;

    assert_refused_by_the_continuation_guard(&response, "handle one hour past its deadline");
}

/// GIVEN a payload whose window is an hour wide, WHEN the gateway is asked to
/// seal it, THEN the handle is unredeemable — refused at the mint, and refused
/// at the open by any build that seals one anyway.
///
/// `CONTINUATION_LIFETIME_SECS` is the ceiling `expiry_for` mints at, and until
/// this case nothing enforced it: `open` compared `now` against whatever
/// `expires_at` the sealed payload carried, so a second mint site setting its
/// own deadline could issue a handle valid for a century and the keyring would
/// honour it. The AEAD seal means only this gateway can construct one — which
/// makes this a guard against our own future code, not against a client.
///
/// Asserted at both ends for the reason `MAX_ENVELOPE_LEN` already is: a bound
/// applied only when opening lets the gateway mint what it will later refuse.
/// Only the mint refusal fires. The open branch is unreachable for any payload
/// `mint` accepts — a legal window makes `now > expires_at` true first, so
/// `Expired` answers — and this case says so rather than pretending to
/// exercise it. The `Ok` arm below is what a build without the mint check
/// would take.
#[tokio::test]
async fn ac_mrtr_8b_a_handle_outliving_the_ceiling_cannot_be_redeemed() {
    let (state, received, _store_dir) = state_with_fixture().await;
    let args = arguments();
    let live = mint_for(&state, &received, CALLER_A, TOOL_INTERIM, &args).await;
    let now = now_secs();
    let minted = state
        .continuation
        .keyring()
        .open(&live, now)
        .expect("a handle the gateway just minted must open");

    let stretched = Payload {
        issued_at: now,
        expires_at: now + 3600,
        ..minted.clone()
    };
    match state.continuation.keyring().mint(&stretched) {
        Err(ContinuationError::LifetimeExceeded) => {}
        Err(other) => {
            panic!("an overlong window must be refused as LifetimeExceeded, got {other}")
        }
        Ok(handle) => assert!(
            matches!(
                state.continuation.keyring().open(&handle, now),
                Err(ContinuationError::LifetimeExceeded)
            ),
            "a build that seals an overlong window must still refuse to redeem it"
        ),
    }

    // The positive control the ceiling needs. Production mints land exactly on
    // it — `expiry_for` is `now + CONTINUATION_LIFETIME_SECS`, private to the
    // module, which is why 300 is spelled out here — so a `>=` comparison would
    // refuse every honest handle rather than only the overlong one.
    let at_the_ceiling = Payload {
        issued_at: now,
        expires_at: now + 300,
        ..minted
    };
    let handle = state
        .continuation
        .keyring()
        .mint(&at_the_ceiling)
        .expect("a window exactly the permitted width must still mint");
    assert!(
        state.continuation.keyring().open(&handle, now).is_ok(),
        "a window exactly the permitted width must still redeem"
    );
}

/// GIVEN one handle, WHEN two redemptions race on the minting process,
/// THEN exactly one of them is refused.
///
/// A non-atomic ledger — read, decide, then mark — lets both observe the
/// handle unspent and both succeed. Asserting on the *count* rather than on
/// which one won is what makes the case deterministic under a scheduler that
/// may order the two either way.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ac_mrtr_5c_two_racing_redemptions_yield_exactly_one_success() {
    let (state, received, _store_dir) = state_with_fixture().await;
    let handle = mint_for(&state, &received, CALLER_A, TOOL_INTERIM, &arguments()).await;
    let body = retry_body(1, TOOL_INTERIM, &arguments(), &handle);

    let (left, right) = {
        let (a, b) = (Arc::clone(&state), Arc::clone(&state));
        let (one, two) = (body.clone(), body);
        let first = tokio::spawn(async move { post(&a, &one).await.1 });
        let second = tokio::spawn(async move { post(&b, &two).await.1 });
        (
            first.await.expect("first redemption task"),
            second.await.expect("second redemption task"),
        )
    };

    let refused = [&left, &right]
        .iter()
        .filter(|response| {
            error_message(response).is_some_and(|message| {
                message.contains(ContinuationError::Malformed.client_message())
            })
        })
        .count();
    assert_eq!(
        refused, 1,
        "exactly one of two racing redemptions must be refused, {refused} were: {left:?} {right:?}"
    );
}

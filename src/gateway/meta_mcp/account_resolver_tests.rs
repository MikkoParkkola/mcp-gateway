// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The managed-account consumer on the path real traffic takes.
//!
//! THE ACTION IS ALWAYS A DISPATCH. Every case calls
//! `MetaMcp::code_mode_execute` (the existing Code Mode entry), which routes
//! through `invoke_tool` and the single identity gate — `gateway_invoke` calls
//! `resolve_caller_credential` DIRECTLY, so the public
//! `resolve_propagation_credential` wrapper is a second entry and not the
//! dispatch path. Nothing here is proved by resolving header vectors: the
//! oracles are the Authorization values and identity keys that reached the
//! transport, and — for refusals — the OBSERVED count of zero backend calls.
//!
//! WHAT IS REAL: the store, `AccountService`, `CustodyHandle`, the lease/release
//! recheck, `config::account_bindings::compile`, `BoundAccountBackend::effective`
//! and `install_account_strategies`. Only the `RefreshProvider` round trip is
//! scripted, and the `VerifiedIdentity` values are fixture principals handed to
//! the dispatch entry (this module does not exercise the OIDC wire or public
//! gateway startup).
//!
//! STATUS. Six cases exercise the current implementation. The seventh
//! (`registered_managed_backend_without_installed_strategy_refuses_with_zero_backend_calls`)
//! is an intended RED: the current
//! `.backend_identity_strategy(server).or_else(global)` fallback mints the
//! global signed assertion for a managed backend whose per-backend strategy was
//! never installed. The assertion is deliberately NOT weakened to accept that
//! wrongly minted credential.
//!
//! MULTI-THREAD RUNTIME: `CustodyHandle::refresh_if_expired` drives the refresh
//! future with `block_on` inside `spawn_blocking`, which needs a runtime with
//! more than the calling thread.
//!
//! NO SLEEPS: expiry is a seeded `expires_at`, and the revocation race uses the
//! explicit barrier in `account_resolver_gate.rs` with a bounded
//! `tokio::time::timeout`.

use std::sync::Arc;
use std::time::Duration;

use super::account_resolver_fixture::{
    ALICE_PERSONAL_TOKEN, ALICE_WORK_TOKEN, BOB_WORK_TOKEN, Bind, Descriptors, PERSONAL,
    REFRESHED_REVISION, ROTATED_TOKEN, SEEDED_REVISION, STATIC_FALLBACK, WORK, account_key,
    custody_with, custody_with_rotation, execute, expected_identity_key, external_cfg, gateway,
    grant, identity, slots,
};
use super::account_resolver_gate::gated;

/// Never-expiring, so no test takes the refresh path by accident.
const FRESH: u64 = u64::MAX;
/// Already expired at any wall clock, so the refresh path is entered by state
/// rather than by waiting.
const EXPIRED: u64 = 0;
/// Bounded wait for the release barrier. A stall is a failure, not a pass.
const BARRIER_TIMEOUT: Duration = Duration::from_secs(10);

/// ISOLATION (IDP.3) THROUGH THE REAL DISPATCH ENTRY. Two principals invoke the
/// SAME tool with the SAME arguments on ONE backend bound to ONE descriptor.
/// Each must reach the transport carrying only its own stored token, under its
/// own identity key. Their display `email`/`name` are identical, so the subject
/// is the only thing that can separate them; a cached first result served to the
/// second caller would show up as a missing second backend call.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn alice_and_bob_dispatch_only_their_own_token_on_one_descriptor() {
    let custody = custody_with(&[
        (account_key("alice", WORK), grant(ALICE_WORK_TOKEN, FRESH)),
        (account_key("bob", WORK), grant(BOB_WORK_TOKEN, FRESH)),
    ]);
    let installed = custody.installed();
    let (meta, dispatches) = gateway(
        &[("mail", Bind::Account(WORK))],
        &Descriptors::same(&[WORK]),
        &installed,
        &slots(&[("alice", WORK), ("bob", WORK)]),
    );

    execute(&meta, "mail", Some(&identity("alice")))
        .await
        .expect("alice's connected account must dispatch");
    execute(&meta, "mail", Some(&identity("bob")))
        .await
        .expect("bob's connected account must dispatch");

    let calls = dispatches.calls();
    assert_eq!(
        calls.len(),
        2,
        "both principals must reach the backend; a shared cache entry would \
         serve the second caller without a call: {calls:?}"
    );
    let alice_auth = calls[0]
        .authorization()
        .expect("alice's dispatch must carry a credential header");
    let bob_auth = calls[1]
        .authorization()
        .expect("bob's dispatch must carry a credential header");

    assert_eq!(
        alice_auth,
        format!("Bearer {ALICE_WORK_TOKEN}"),
        "alice must receive exactly her own stored token"
    );
    assert_eq!(
        bob_auth,
        format!("Bearer {BOB_WORK_TOKEN}"),
        "bob must receive exactly his own stored token"
    );
    // The identity/cache key is the account digest PLUS the grant authority the
    // credential was released under, which is what the production
    // `cache_binding` publishes. No seeded grant was refreshed here, so both are
    // at the seeded revision.
    assert_eq!(
        calls[0].identity_key.as_deref(),
        Some(expected_identity_key("alice", WORK, SEEDED_REVISION).as_str()),
        "the identity/cache key must be alice's authority-bearing account binding"
    );
    assert_eq!(
        calls[1].identity_key.as_deref(),
        Some(expected_identity_key("bob", WORK, SEEDED_REVISION).as_str()),
        "the identity/cache key must be bob's authority-bearing account binding"
    );
    assert_ne!(
        calls[0].identity_key, calls[1].identity_key,
        "identical requests from two principals must not share one cache/session key"
    );
    assert!(
        !format!("{calls:?}").contains(STATIC_FALLBACK),
        "no managed dispatch may carry the static credential"
    );
    assert_eq!(custody.releases(), 2, "each credential passes one recheck");
}

/// The descriptor KEY is the account identity. Two descriptors of the SAME
/// provider, the SAME resource and the SAME issuer — differing ONLY in their map
/// key — are two accounts for one principal, and neither may serve the other's
/// token. With the resource equal, a separation that merely reflected a
/// different audience cannot pass this.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn one_provider_two_descriptor_ids_stay_separate_accounts() {
    let custody = custody_with(&[
        (account_key("alice", WORK), grant(ALICE_WORK_TOKEN, FRESH)),
        (
            account_key("alice", PERSONAL),
            grant(ALICE_PERSONAL_TOKEN, FRESH),
        ),
    ]);
    let installed = custody.installed();
    let (meta, dispatches) = gateway(
        &[
            ("work-mail", Bind::Account(WORK)),
            ("personal-mail", Bind::Account(PERSONAL)),
        ],
        &Descriptors::same(&[WORK, PERSONAL]),
        &installed,
        &slots(&[("alice", WORK), ("alice", PERSONAL)]),
    );

    let caller = identity("alice");
    execute(&meta, "work-mail", Some(&caller))
        .await
        .expect("the work account must dispatch");
    execute(&meta, "personal-mail", Some(&caller))
        .await
        .expect("the personal account must dispatch");

    let calls = dispatches.calls();
    assert_eq!(calls.len(), 2, "both backends must be called: {calls:?}");
    assert_eq!(
        calls[0].authorization(),
        Some(format!("Bearer {ALICE_WORK_TOKEN}")),
        "the work backend must receive the work account's token"
    );
    assert_eq!(
        calls[1].authorization(),
        Some(format!("Bearer {ALICE_PERSONAL_TOKEN}")),
        "the personal backend must receive the personal account's token"
    );
    assert_ne!(
        calls[0].identity_key, calls[1].identity_key,
        "one provider's two descriptors must not collapse into one cache/session key"
    );
}

/// NO PRINCIPAL, NO ACCOUNT, NO FALLBACK — at the dispatch entry, not at a
/// resolver helper. A Code Mode call with no verified identity against a managed
/// backend is refused, and the proof that it did not degrade to a static
/// credential is that the backend was never called at all. (A managed backend
/// carries no static Authorization to fall back to: `compile` refuses that
/// configuration, so ZERO calls is the available proof.)
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn missing_verified_principal_refuses_with_zero_backend_calls() {
    let custody = custody_with(&[(account_key("alice", WORK), grant(ALICE_WORK_TOKEN, FRESH))]);
    let installed = custody.installed();
    let (meta, dispatches) = gateway(
        &[("mail", Bind::Account(WORK))],
        &Descriptors::same(&[WORK]),
        &installed,
        &slots(&[("alice", WORK)]),
    );

    let error = execute(&meta, "mail", None)
        .await
        .expect_err("a managed account without a verified principal must fail closed");

    assert_eq!(
        dispatches.count(),
        0,
        "the refusal must happen BEFORE dispatch: no backend call may be made"
    );
    let text = error.to_string();
    assert!(
        !text.contains(ALICE_WORK_TOKEN) && !text.contains(STATIC_FALLBACK),
        "the refusal must not carry credential material: {text}"
    );
    assert_eq!(
        custody.releases(),
        0,
        "no credential may be released without a principal"
    );
}

/// DEFENSIVE INCOMPLETE-INSTALL NEGATIVE, WITH ITS INJECTION LABELLED. This is
/// NOT a claim about config load or a valid startup: a valid configuration
/// installs a strategy for every bound backend or refuses to start. The managed
/// `mail` backend here is compiled and registered from the VALID descriptor
/// configuration, and is then omitted from the `Config` handed to the shared
/// installer — which models a backend dropped between compilation and
/// installation (a stale or partial reload). An unrelated, valid GLOBAL
/// signed-assertion strategy is installed beside it as a trap.
///
/// The consumer must fail closed: a managed backend with no installed account
/// strategy has no credential to present, and the global minting strategy is not
/// a substitute for the account holder's own token.
///
/// EXPECTED RED TODAY: the current
/// `.backend_identity_strategy(server).or_else(global)` fallback mints the
/// global assertion instead, so `mail` reaches the transport with a credential
/// nobody's account authorized. The assertion below is not relaxed to accept it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn registered_managed_backend_without_installed_strategy_refuses_with_zero_backend_calls() {
    let custody = custody_with(&[(account_key("alice", WORK), grant(ALICE_WORK_TOKEN, FRESH))]);
    let installed = custody.installed();
    let (meta, dispatches) = gateway(
        &[
            // The trap: a valid, unrelated external-control backend, whose
            // presence installs the process-wide signed-assertion strategy.
            ("partner", Bind::Propagation(external_cfg())),
            ("mail", Bind::Account(WORK)),
        ],
        &Descriptors {
            compiled: &[WORK],
            installed: &[],
        },
        &installed,
        &slots(&[("alice", WORK)]),
    );

    let error = execute(&meta, "mail", Some(&identity("alice")))
        .await
        .expect_err("a managed backend with no installed strategy must fail closed at dispatch");

    assert_eq!(
        dispatches.count(),
        0,
        "a managed backend whose account strategy was never installed must not reach the \
         backend at all — least of all with a globally minted assertion"
    );
    let text = error.to_string();
    assert!(
        !text.contains(ALICE_WORK_TOKEN) && !text.contains(STATIC_FALLBACK),
        "the refusal must carry no credential material: {text}"
    );
    assert_eq!(custody.releases(), 0, "nothing may be released");
}

/// THE RELEASE-TIME RECHECK, PROVED AT A BARRIER RATHER THAN ASSERTED.
///
/// The dispatch is paused at the entry to `release`, with the lease already
/// held, by the delegating wrapper in `account_resolver_gate.rs`. Only then is
/// the account really invalidated — through the real `CustodyHandle` the fixture
/// started, not through the wrapper — and only then is the release resumed.
/// Revoking before the lookup would prove nothing: the refresh/lookup would
/// refuse first and the recheck would never run.
///
/// Expected: the resumed release refuses, the dispatch errors, the backend is
/// never called, and the release observer records no successful release. The
/// wait is bounded and explicit — no sleep, and no auto-release on timeout or
/// drop.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn revocation_between_lease_and_release_refuses_at_the_recheck() {
    let alice = account_key("alice", WORK);
    let custody = custody_with(&[(alice.clone(), grant(ALICE_WORK_TOKEN, FRESH))]);
    let (gate, barrier) = gated(custody.installed());
    let installed = Arc::clone(&gate) as Arc<dyn crate::personal_accounts::AccountCustody>;
    let (meta, dispatches) = gateway(
        &[("mail", Bind::Account(WORK))],
        &Descriptors::same(&[WORK]),
        &installed,
        &slots(&[("alice", WORK)]),
    );
    let meta = Arc::new(meta);

    let dispatching = tokio::spawn({
        let meta = Arc::clone(&meta);
        async move {
            let caller = identity("alice");
            execute(&meta, "mail", Some(&caller)).await.map(|_| ())
        }
    });

    tokio::time::timeout(BARRIER_TIMEOUT, barrier.entered)
        .await
        .expect("the resolution must reach the release entry")
        .expect("the barrier must signal, not drop");

    // Real durable revocation through the real custody handle, while the lease
    // is held and before the release is allowed to proceed.
    custody
        .handle
        .invalidate(&alice)
        .await
        .expect("revocation must be applied");
    barrier
        .resume
        .send(())
        .expect("the release must be resumed explicitly");

    let outcome = tokio::time::timeout(BARRIER_TIMEOUT, dispatching)
        .await
        .expect("the dispatch must finish once the release is resumed")
        .expect("the dispatch task must not panic");
    let error = outcome.expect_err("a grant revoked before release must fail the recheck");

    assert_eq!(
        dispatches.count(),
        0,
        "a credential that failed the release recheck must never reach the backend"
    );
    assert_eq!(
        custody.releases(),
        0,
        "the release observer must record no successful release"
    );
    let text = error.to_string();
    assert!(
        !text.contains(ALICE_WORK_TOKEN) && !text.contains(STATIC_FALLBACK),
        "the refusal must carry neither the revoked token nor a static credential: {text}"
    );
}

/// EXPIRED GRANT GOES THROUGH THE REAL CUSTODY REFRESH. The seeded token is
/// already expired, so the dispatch must reach `refresh_if_expired` — the
/// production single-flight and version CAS — and put the ROTATED token on the
/// wire. Nothing re-implements a refresh here: the only scripted part is the
/// provider's answer, and its call count proves the production path ran once.
/// The refreshed token revision must also show up in the binding, because the
/// authority the credential was released under changed.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn expired_grant_is_refreshed_through_real_custody_before_dispatch() {
    let custody = custody_with_rotation(
        &[(account_key("alice", WORK), grant(ALICE_WORK_TOKEN, EXPIRED))],
        ROTATED_TOKEN,
    );
    let installed = custody.installed();
    let (meta, dispatches) = gateway(
        &[("mail", Bind::Account(WORK))],
        &Descriptors::same(&[WORK]),
        &installed,
        &slots(&[("alice", WORK)]),
    );

    execute(&meta, "mail", Some(&identity("alice")))
        .await
        .expect("an expired grant must be refreshed, not refused");

    let call = dispatches.only();
    assert_eq!(
        call.authorization(),
        Some(format!("Bearer {ROTATED_TOKEN}")),
        "the rotated token must be the one that reaches the backend"
    );
    assert_eq!(
        call.identity_key.as_deref(),
        Some(expected_identity_key("alice", WORK, REFRESHED_REVISION).as_str()),
        "a committed refresh must move the cache/session binding to the new token revision"
    );
    assert_eq!(
        custody.refreshes(),
        1,
        "exactly one provider round trip: the production single-flight owns this"
    );
}

/// ROUTE SELECTION IS PER BACKEND, NOT PROCESS-WIDE. One gateway carries a
/// `partner` backend served by the process-wide signed-assertion strategy and a
/// `mail` backend served by custody. Each must reach the wire with ITS OWN
/// credential shape; neither strategy may substitute for the other, which is
/// exactly what a single global strategy would do. Only the external backend
/// carries a static Authorization, and it must not degrade to it either.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn mixed_external_and_managed_backends_select_their_own_strategy() {
    let custody = custody_with(&[(account_key("alice", WORK), grant(ALICE_WORK_TOKEN, FRESH))]);
    let installed = custody.installed();
    let (meta, dispatches) = gateway(
        &[
            ("partner", Bind::Propagation(external_cfg())),
            ("mail", Bind::Account(WORK)),
        ],
        &Descriptors::same(&[WORK]),
        &installed,
        &slots(&[("alice", WORK)]),
    );

    let caller = identity("alice");
    execute(&meta, "partner", Some(&caller))
        .await
        .expect("the external backend must still mint its assertion");
    execute(&meta, "mail", Some(&caller))
        .await
        .expect("the managed backend must serve its custody credential");

    let calls = dispatches.calls();
    assert_eq!(calls.len(), 2, "both routes must dispatch: {calls:?}");
    let external_auth = calls[0]
        .authorization()
        .expect("minted assertion header expected");
    let managed_auth = calls[1]
        .authorization()
        .expect("custody credential header expected");

    assert!(
        !external_auth.contains(ALICE_WORK_TOKEN),
        "the vault credential must never be presented to the external backend"
    );
    assert_eq!(
        managed_auth,
        format!("Bearer {ALICE_WORK_TOKEN}"),
        "the managed backend must receive the stored account token, not a minted assertion"
    );
    assert!(
        !external_auth.contains(STATIC_FALLBACK) && !managed_auth.contains(STATIC_FALLBACK),
        "neither route may degrade to the static credential"
    );
    assert_ne!(
        external_auth, managed_auth,
        "two backends with different declared strategies must not share one credential"
    );
    assert_eq!(
        custody.releases(),
        1,
        "custody must be consulted for the managed backend only"
    );
}

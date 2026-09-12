// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! REST capabilities dispatching through the ONE account credential boundary.
//!
//! THE CLAIM UNDER TEST. A REST capability whose `auth.account` names an
//! `accounts.descriptors` map key executes as the VERIFIED caller, using the
//! same `IdentityPropagation` strategy instance the shared installer built for
//! that descriptor — the same custody, the same five-field account key, the same
//! mandatory release recheck an MCP backend gets. Not a second store, not a
//! second auth enum, not a managed-token branch beside the resolver.
//!
//! THE REFUSALS ARE PROVED BY ABSENCE. Every negative case asserts ZERO requests
//! at the real capture endpoint. That is what "before HTTP and before the legacy
//! operator OAuth lookup" means operationally: the endpoint would have recorded
//! a call, and the legacy path would have produced the gateway-held token, so a
//! recorded count of zero and an error that does not carry a token is the only
//! outcome that can pass.
//!
//! THE POSITIVE CONTROL IS FIRST. If the endpoint were unreachable every
//! refusal test would pass vacuously, so the Alice/Bob case establishes that the
//! very same capability, arguments and backend DO reach the wire.

use std::sync::Arc;

use serde_json::json;

use crate::capability::CapabilityExecutor;
use crate::identity_propagation::AccountStrategyRegistry;
use crate::personal_accounts::AccountCustody;

use super::account_resolver_fixture::{
    ALICE_PERSONAL_TOKEN, ALICE_WORK_TOKEN, BOB_WORK_TOKEN, PERSONAL, STATIC_FALLBACK, WORK,
    account_key, custody_with, grant, identity,
};
use super::account_rest_fixture::{
    Captured, EXPIRED_EXTERNAL_TOKEN, TOOL, backend_with, cacheable_base_url, cacheable_capability,
    caching_context, caching_executor, call, capability, capability_requiring_argument,
    capture_endpoint, context, declared_only, external, installed_expired_external,
    installed_gateway, managed, meta_execute, multi_user_caching_backend, prepared_caching_context,
    shared,
};

/// The gateway-held login a fallback would reach for. Seeded in the caching
/// cases as a TRAP: it is a perfectly valid legacy `oauth:google` token, so a
/// refusal that leaves it unused is a refusal that chose to fail closed with a
/// working alternative in hand.
const LEGACY_TRAP_TOKEN: &str = "synthetic-operator-legacy-trap-token-3d0a";

/// Never-expiring, so no case takes the refresh path by accident.
const FRESH: u64 = u64::MAX;

fn base_url(port: u16) -> String {
    format!("http://127.0.0.1:{port}")
}

/// A host that cannot resolve. Used where the assertion is that resolution
/// refused BEFORE the wire; if a refusal ever regressed into a dispatch, the
/// failure would be a transport error, not a silent pass.
const UNROUTABLE: &str = "https://rest-account-control.invalid";

fn assert_no_credential_leaked(error: &crate::Error, captured: &Captured) {
    let text = error.to_string();
    assert!(
        !text.contains(ALICE_WORK_TOKEN)
            && !text.contains(BOB_WORK_TOKEN)
            && !text.contains(STATIC_FALLBACK),
        "a refusal must carry neither an account token nor a static credential: {text}"
    );
    assert_eq!(
        captured.count(),
        0,
        "the refusal must happen before any HTTP request reaches the backend"
    );
}

/// THE POSITIVE CONTROL AND THE HEADLINE CASE.
///
/// One capability, one argument set, two principals. Alice must receive her own
/// account's token and Bob his own. The tokens are distinct per principal in the
/// seeded store, so a crossed credential is visible in the assertion rather than
/// inferred, and both descriptors share ONE resource so the descriptor id and
/// the verified subject are the only fields that differ.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn alice_and_bob_receive_their_own_account_credentials_from_one_rest_capability() {
    let (port, captured) = capture_endpoint().await;
    let custody = custody_with(&[
        (account_key("alice", WORK), grant(ALICE_WORK_TOKEN, FRESH)),
        (account_key("bob", WORK), grant(BOB_WORK_TOKEN, FRESH)),
    ]);
    let installed: Arc<dyn AccountCustody> = custody.installed();
    let (_meta, registry) = installed_gateway(&[(WORK, managed(WORK))], &installed);
    let backend = backend_with(
        &registry,
        capability(&base_url(port), "oauth:google", Some(WORK)),
    )
    .expect("a capability naming a declared descriptor with a matching provider must register");

    call(&backend, Some("alice"))
        .await
        .expect("Alice's dispatch must reach the endpoint");
    call(&backend, Some("bob"))
        .await
        .expect("Bob's dispatch must reach the endpoint");

    let seen = captured.authorizations();
    assert_eq!(seen.len(), 2, "both dispatches must reach the endpoint");
    assert_eq!(
        seen[0].as_deref(),
        Some(format!("Bearer {ALICE_WORK_TOKEN}").as_str()),
        "Alice must be served her own account's credential"
    );
    assert_eq!(
        seen[1].as_deref(),
        Some(format!("Bearer {BOB_WORK_TOKEN}").as_str()),
        "Bob must be served his own account's credential, not Alice's"
    );
    assert_eq!(
        custody.releases(),
        4,
        "each dispatch releases during preparation and rechecks before egress"
    );
}

/// NO VERIFIED IDENTITY, NO CREDENTIAL — AND NO FALLBACK.
///
/// The capability is the same one that just worked, so the only difference is
/// the missing identity. Falling through here would resolve the gateway-held
/// `oauth:google` token from the legacy `TokenStorage` and present one person's
/// login as another's, which is exactly what the account reference exists to
/// prevent.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_request_with_no_verified_identity_refuses_before_http() {
    let (port, captured) = capture_endpoint().await;
    let custody = custody_with(&[(account_key("alice", WORK), grant(ALICE_WORK_TOKEN, FRESH))]);
    let installed: Arc<dyn AccountCustody> = custody.installed();
    let (_meta, registry) = installed_gateway(&[(WORK, managed(WORK))], &installed);
    let backend = backend_with(
        &registry,
        capability(&base_url(port), "oauth:google", Some(WORK)),
    )
    .expect("registration is unaffected by the absence of a caller");

    let error = call(&backend, None)
        .await
        .expect_err("a managed account cannot be resolved without a verified caller");

    assert_no_credential_leaked(&error, &captured);
    assert_eq!(
        custody.releases(),
        0,
        "no credential may be released for a caller the gateway has not verified"
    );
}

/// A DECLARED DESCRIPTOR WITH NO INSTALLED STRATEGY REFUSES.
///
/// This is the state a reload leaves behind when a binding is dropped between
/// compilation and installation. The capability is admitted at registration —
/// the descriptor IS declared — and the dispatch is what must fail closed,
/// rather than borrowing an unrelated strategy or the legacy token.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_declared_account_with_no_installed_strategy_refuses_before_http() {
    let (port, captured) = capture_endpoint().await;
    let registry = declared_only(&[(WORK, managed(WORK))]);
    let backend = backend_with(
        &registry,
        capability(&base_url(port), "oauth:google", Some(WORK)),
    )
    .expect("a declared descriptor is a valid reference at registration time");

    let error = call(&backend, Some("alice"))
        .await
        .expect_err("no installed strategy means no credential, and no substitute");

    assert_no_credential_leaked(&error, &captured);
}

/// A REVOKED GRANT REFUSES AT THE RELEASE RECHECK, BEFORE THE WIRE.
///
/// The revocation is applied through the REAL `CustodyHandle` the fixture
/// started, so what refuses is the production recheck, not a fixture flag.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_revoked_grant_refuses_before_http() {
    let (port, captured) = capture_endpoint().await;
    let alice = account_key("alice", WORK);
    let custody = custody_with(&[(alice.clone(), grant(ALICE_WORK_TOKEN, FRESH))]);
    custody
        .handle
        .invalidate(&alice)
        .await
        .expect("revocation must be applied");
    let installed: Arc<dyn AccountCustody> = custody.installed();
    let (_meta, registry) = installed_gateway(&[(WORK, managed(WORK))], &installed);
    let backend = backend_with(
        &registry,
        capability(&base_url(port), "oauth:google", Some(WORK)),
    )
    .expect("registration does not consult grant state");

    let error = call(&backend, Some("alice"))
        .await
        .expect_err("a revoked account has no credential to serve");

    assert_no_credential_leaked(&error, &captured);
    assert_eq!(
        custody.releases(),
        0,
        "the release observer must record no successful release"
    );
}

/// AN UNKNOWN REFERENCE IS REFUSED AT REGISTRATION.
///
/// `auth.account` names a descriptor MAP KEY. A name that is not a key is an
/// operator error, and admitting the capability would leave a tool in the
/// surface that can only ever fail — or, worse, fall back.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_unknown_account_reference_is_refused_at_registration() {
    let custody = custody_with(&[(account_key("alice", WORK), grant(ALICE_WORK_TOKEN, FRESH))]);
    let installed: Arc<dyn AccountCustody> = custody.installed();
    let (_meta, registry) = installed_gateway(&[(WORK, managed(WORK))], &installed);

    // `.err().expect(..)` rather than `expect_err`: the Ok half is a production
    // backend that deliberately carries no `Debug`.
    let error = backend_with(
        &registry,
        capability(UNROUTABLE, "oauth:google", Some("no-such-account")),
    )
    .err()
    .expect("an unresolved account reference must not enter the tool surface");
    let text = error.to_string();
    assert!(
        text.contains("no-such-account"),
        "the refusal must name the unresolved reference: {text}"
    );
}

/// A PROVIDER MISMATCH IS REFUSED AT REGISTRATION AND, INDEPENDENTLY, AT
/// EXECUTION.
///
/// `auth.key` must be `oauth:<descriptor.provider>`. A capability keyed
/// `oauth:slack` pointing at a `google` descriptor is a refusal, never a
/// best-effort lookup and never a join by provider name. The execution half
/// covers a capability registered dynamically, past the registration boundary.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_provider_mismatch_is_refused_at_registration_and_at_execution() {
    let (port, captured) = capture_endpoint().await;
    let custody = custody_with(&[(account_key("alice", WORK), grant(ALICE_WORK_TOKEN, FRESH))]);
    let installed: Arc<dyn AccountCustody> = custody.installed();
    let (_meta, registry) = installed_gateway(&[(WORK, managed(WORK))], &installed);
    let mismatched = capability(&base_url(port), "oauth:slack", Some(WORK));

    let registration = backend_with(&registry, mismatched.clone())
        .err()
        .expect("a provider mismatch must not enter the tool surface");
    assert!(
        registration.to_string().contains("oauth:google"),
        "the refusal must state the key the descriptor's provider requires: {registration}"
    );

    // The execution guard, reached directly so the registration boundary is not
    // what refuses: this is the protection for a dynamically registered
    // capability.
    let executor = CapabilityExecutor::new().with_account_strategies(Arc::clone(&registry));
    let error = executor
        .execute_with_context(&mismatched, json!({}), context(Some("alice")))
        .await
        .expect_err("execution must refuse the mismatch independently of registration");

    assert_no_credential_leaked(&error, &captured);
    assert_eq!(
        custody.releases(),
        0,
        "a mismatched capability must never reach custody"
    );
}

/// SHARED AND DESCRIPTORLESS LEGACY BEHAVIOUR IS PRESERVED.
///
/// A `shared` descriptor names an account the deployment already serves
/// statically. Binding one must not tighten a configuration that never opted
/// into per-user credentials, so the gateway-held token is still what goes on
/// the wire — unchanged, and explicitly not routed through custody.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_shared_descriptor_keeps_the_legacy_gateway_held_token() {
    const LEGACY_TOKEN: &str = "synthetic-operator-shared-token-9f1c";
    let (port, captured) = capture_endpoint().await;
    let custody = custody_with(&[]);
    let installed: Arc<dyn AccountCustody> = custody.installed();
    let (_meta, registry) = installed_gateway(&[(PERSONAL, shared(PERSONAL))], &installed);

    let dir = tempfile::tempdir().expect("tempdir");
    let storage = Arc::new(
        crate::oauth::TokenStorage::new(dir.path().to_path_buf()).expect("token storage opens"),
    );
    let executor = CapabilityExecutor::with_token_storage(storage)
        .with_account_strategies(Arc::clone(&registry));
    executor.set_oauth_token(
        "google",
        crate::oauth::TokenInfo {
            expires_at: Some(u64::MAX),
            ..crate::oauth::TokenInfo::from_response(
                LEGACY_TOKEN.to_string(),
                None,
                None,
                None,
                None,
            )
        },
    );

    executor
        .execute_with_context(
            &capability(&base_url(port), "oauth:google", Some(PERSONAL)),
            json!({}),
            context(Some("alice")),
        )
        .await
        .expect("a shared descriptor keeps the existing static path");

    assert_eq!(
        captured.only(),
        format!("Bearer {LEGACY_TOKEN}"),
        "a shared descriptor must serve the existing gateway-held login unchanged"
    );
    assert_eq!(
        custody.releases(),
        0,
        "shared mode has no custody requirement and must not consult it"
    );
}

/// MIXED MODES COEXIST WITHOUT SUBSTITUTION.
///
/// One installer, one registry, two descriptors: an external one reusing the
/// configured `signed_assertion` strategy with `required: true`, and a managed
/// one under vault custody. Each capability must get the credential ITS
/// descriptor compiled to — the whole reason strategies are installed per
/// descriptor rather than once per process.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_external_descriptor_and_a_managed_one_coexist_without_substitution() {
    let (port, captured) = capture_endpoint().await;
    let custody = custody_with(&[(account_key("alice", WORK), grant(ALICE_WORK_TOKEN, FRESH))]);
    let installed: Arc<dyn AccountCustody> = custody.installed();
    let (_meta, registry) = installed_gateway(
        &[(WORK, managed(WORK)), (PERSONAL, external(PERSONAL))],
        &installed,
    );

    let vault_backend = backend_with(
        &registry,
        capability(&base_url(port), "oauth:google", Some(WORK)),
    )
    .expect("the managed capability must register");
    let external_backend = backend_with(
        &registry,
        capability(&base_url(port), "oauth:google", Some(PERSONAL)),
    )
    .expect("the external capability must register");

    call(&vault_backend, Some("alice"))
        .await
        .expect("the managed dispatch must reach the endpoint");
    call(&external_backend, Some("alice"))
        .await
        .expect("the external dispatch must reach the endpoint");

    let seen = captured.authorizations();
    assert_eq!(seen.len(), 2, "both dispatches must reach the endpoint");
    let vault = seen[0].clone().expect("managed call carries a credential");
    let minted = seen[1].clone().expect("external call carries a credential");
    assert_eq!(
        vault,
        format!("Bearer {ALICE_WORK_TOKEN}"),
        "the managed capability must be served its own account's token"
    );
    assert!(
        minted.starts_with("Bearer ") && minted != vault,
        "the external descriptor must mint its own assertion, never the vault token: {minted}"
    );
    assert_eq!(
        custody.releases(),
        2,
        "only the managed descriptor releases during preparation and rechecks before egress"
    );
}

/// THE ONE MetaMcp THREADING CONTROL.
///
/// Everything above hands the verified identity to the executor directly, which
/// proves the credential boundary but not that the GATEWAY fills it. This case
/// drives the real Code Mode dispatch entry twice against a capability whose
/// host cannot resolve, so the wire is irrelevant and the observable is custody:
///
/// - with no verified caller, the account boundary refuses and custody is never
///   consulted (`releases == 0`);
/// - with a verified caller, the SAME dispatch reaches custody and passes the
///   real release recheck (`releases == 1`) before failing at the unroutable
///   host.
///
/// The difference between the two runs is the `MetaMcpCallerContext`'s
/// `verified_identity` and nothing else, so a gateway that invented an issuer
/// from a `GrantSubject`, an API key name or a display name could not produce
/// it: both runs carry no grant subject and no API key name.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn meta_mcp_capability_dispatch_carries_the_verified_identity_to_the_account_boundary() {
    let custody = custody_with(&[(account_key("alice", WORK), grant(ALICE_WORK_TOKEN, FRESH))]);
    let installed: Arc<dyn AccountCustody> = custody.installed();
    let (meta, registry) = installed_gateway(&[(WORK, managed(WORK))], &installed);
    let backend = backend_with(
        &registry,
        capability(UNROUTABLE, "oauth:google", Some(WORK)),
    )
    .expect("the capability must register");
    meta.set_capabilities(Arc::clone(&backend));

    let anonymous = meta_execute(&meta, None)
        .await
        .expect_err("an unverified caller must not reach a managed account");
    assert!(
        !anonymous.to_string().contains(ALICE_WORK_TOKEN),
        "the refusal must not carry the account token"
    );
    assert_eq!(
        custody.releases(),
        0,
        "an unverified Code Mode dispatch must never reach custody"
    );

    let _ = meta_execute(&meta, Some("alice")).await;
    assert_eq!(
        custody.releases(),
        3,
        "Code Mode releases during preparation and rechecks before inner cache and egress"
    );
    assert_eq!(
        custody.refreshes(),
        0,
        "the seeded grant is fresh, so nothing may hit the refresh provider"
    );
}

// ── Warm cache ───────────────────────────────────────────────────────────────
//
// EVERYTHING ABOVE RUNS WITH THE CACHE OFF. `allow_loopback_egress` — the flag
// that lets an IP-literal endpoint be reached — also suppresses the response
// cache by design, so none of those cases can say anything about a cached
// entry. The cases below therefore run the OTHER way round: an explicit
// positive TTL, a `localhost` base URL that clears the SSRF guard on its own,
// no loopback relaxation, and a swapped (finite-timeout, unpinned) client. The
// endpoint's request COUNT is the oracle for a real cache hit, and its echoed
// body is the oracle for whose entry was served.

/// THE POSITIVE CACHE CONTROL: an identical second request is served WITHOUT a
/// second upstream call.
///
/// Without this, every "the revocation was refused" case below could pass
/// against a cache that never stores anything — two refusals prove nothing about
/// a cache that was never warm. Here the count stays at one and the second
/// response is byte-identical, including the per-request sequence number the
/// endpoint stamps, which a re-dispatch could not reproduce.
///
/// The account boundary still runs on the cached call: custody records TWO
/// releases for one HTTP request, because the credential is resolved and
/// rechecked BEFORE the cache is consulted, not skipped by a hit.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_identical_second_request_from_alice_is_served_from_the_warm_cache() {
    let (port, captured) = capture_endpoint().await;
    let custody = custody_with(&[(account_key("alice", WORK), grant(ALICE_WORK_TOKEN, FRESH))]);
    let installed: Arc<dyn AccountCustody> = custody.installed();
    let (_meta, registry) = installed_gateway(&[(WORK, managed(WORK))], &installed);
    let executor = caching_executor(&registry, None);
    let capability = cacheable_capability(&cacheable_base_url(port), "oauth:google", Some(WORK));

    let first = executor
        .execute_with_context(&capability, json!({}), caching_context("alice"))
        .await
        .expect("Alice's first dispatch must reach the endpoint");
    assert_eq!(
        captured.count(),
        1,
        "the first dispatch must actually go on the wire and prime the cache"
    );
    assert_eq!(
        first["authorization"],
        json!(format!("Bearer {ALICE_WORK_TOKEN}")),
        "Alice must be served her own account's credential"
    );

    let second = executor
        .execute_with_context(&capability, json!({}), caching_context("alice"))
        .await
        .expect("Alice's identical second dispatch must succeed");

    assert_eq!(
        captured.count(),
        1,
        "the identical second request must be served from cache: the endpoint's request count \
         must not move"
    );
    assert_eq!(
        first, second,
        "a warm cache hit must return the stored body verbatim, sequence number included"
    );
    assert_eq!(
        custody.releases(),
        3,
        "the cold dispatch releases twice; the warm hit rechecks custody once before cache"
    );
}

/// BOB IS NEVER SERVED ALICE'S CACHED RESPONSE.
///
/// Same capability, same arguments, same executor and a cache that is provably
/// warm (the case above shares this exact setup). The only thing that differs is
/// the verified caller — and therefore the account credential's opaque binding,
/// which the cache key is partitioned by. Bob must MISS, dispatch, and receive a
/// body carrying HIS credential; Alice's entry must survive his call intact.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn bob_is_never_served_alices_warm_cache_entry() {
    let (port, captured) = capture_endpoint().await;
    let custody = custody_with(&[
        (account_key("alice", WORK), grant(ALICE_WORK_TOKEN, FRESH)),
        (account_key("bob", WORK), grant(BOB_WORK_TOKEN, FRESH)),
    ]);
    let installed: Arc<dyn AccountCustody> = custody.installed();
    let (_meta, registry) = installed_gateway(&[(WORK, managed(WORK))], &installed);
    let executor = caching_executor(&registry, None);
    let capability = cacheable_capability(&cacheable_base_url(port), "oauth:google", Some(WORK));

    let alice_first = executor
        .execute_with_context(&capability, json!({}), caching_context("alice"))
        .await
        .expect("Alice primes the cache");
    assert_eq!(captured.count(), 1);

    let bob = executor
        .execute_with_context(&capability, json!({}), caching_context("bob"))
        .await
        .expect("Bob's dispatch must succeed on his own credential");

    assert_eq!(
        captured.count(),
        2,
        "Bob must miss Alice's entry and dispatch on his own"
    );
    assert_eq!(
        bob["authorization"],
        json!(format!("Bearer {BOB_WORK_TOKEN}")),
        "Bob must be served his own account's credential, never Alice's"
    );
    assert_ne!(
        bob, alice_first,
        "Bob must not receive Alice's cached response body"
    );

    let alice_again = executor
        .execute_with_context(&capability, json!({}), caching_context("alice"))
        .await
        .expect("Alice's entry must still be there");
    assert_eq!(
        captured.count(),
        2,
        "Alice's warm entry must survive Bob's miss — isolation, not a dead cache"
    );
    assert_eq!(
        alice_again, alice_first,
        "Alice must still be served her own stored body"
    );
}

/// A REVOCATION COMMITTED AFTER THE CREDENTIAL WAS PREPARED REFUSES THE WARM
/// ENTRY AND THE WIRE.
///
/// The credential is resolved FIRST, as the invoke path resolves it, and the
/// very same carried credential warms the cache. The revocation then lands
/// through the real `CustodyHandle`, strictly between that warm-up and the
/// second call. The second call is byte-identical to the first — the entry is
/// sitting there and would be returned by any check that ran after the lookup —
/// so it can only be refused by the recheck that runs BEFORE the lookup.
///
/// The trap: a valid gateway-held `oauth:google` token is loaded, so the legacy
/// fallback is available and working. It must stay unused, unrecorded and
/// unmentioned.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_revocation_after_prepare_refuses_the_warm_cache_entry_and_the_wire() {
    let (port, captured) = capture_endpoint().await;
    let alice = account_key("alice", WORK);
    let custody = custody_with(&[(alice.clone(), grant(ALICE_WORK_TOKEN, FRESH))]);
    let installed: Arc<dyn AccountCustody> = custody.installed();
    let (_meta, registry) = installed_gateway(&[(WORK, managed(WORK))], &installed);
    let dir = tempfile::tempdir().expect("tempdir");
    let executor = caching_executor(&registry, Some((LEGACY_TRAP_TOKEN, &dir)));
    let capability = cacheable_capability(&cacheable_base_url(port), "oauth:google", Some(WORK));

    // Resolved BEFORE the revocation and carried, exactly as the invoke path
    // carries it into the executor.
    let prepared = prepared_caching_context(&registry, "alice", WORK, "oauth:google").await;
    let warm = executor
        .execute_with_context(&capability, json!({}), prepared.clone())
        .await
        .expect("the prepared credential must dispatch while the grant is current");
    assert_eq!(captured.count(), 1, "the cache must actually be warm");
    assert_eq!(
        warm["authorization"],
        json!(format!("Bearer {ALICE_WORK_TOKEN}")),
        "the warm entry must be Alice's own account credential, not the legacy trap"
    );

    custody
        .handle
        .invalidate(&alice)
        .await
        .expect("revocation must be applied");

    let error = executor
        .execute_with_context(&capability, json!({}), prepared)
        .await
        .expect_err("a revoked grant must not be served its own warm cache entry");

    let text = error.to_string();
    assert!(
        !text.contains(ALICE_WORK_TOKEN) && !text.contains(LEGACY_TRAP_TOKEN),
        "the refusal must carry neither the account token nor the legacy trap: {text}"
    );
    assert_eq!(
        captured.count(),
        1,
        "the refusal must reach neither the cache nor the wire: no new request, and an error \
         instead of the stored body"
    );
}

/// AN ALREADY-EXPIRED EXTERNAL CREDENTIAL IS REFUSED AT THE INITIAL RESOLVE.
///
/// THE REGRESSION. `published_lifetime_open` used to read `expires_at <=
/// minted_at` as "this strategy published no lifetime" for EVERY strategy. That
/// reading is the vault's per-dispatch signal and is only safe because a managed
/// credential is separately re-released through durable custody. An external
/// descriptor has no lease, so the custody half is skipped entirely — and an
/// issuer that hands back a token whose expiry has already passed produces
/// exactly `expires_at <= minted_at`, which sailed through the check and went on
/// the wire.
///
/// The strategy here mints successfully with usable headers; the ONLY thing
/// wrong with the credential is that its published expiry is an hour in the
/// past. The refusal must therefore be attributable to the expiry alone, must
/// happen before the cache key is built and before egress, and must not fall
/// back to the seeded legacy token.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_already_expired_external_credential_refuses_before_cache_and_wire() {
    let (port, captured) = capture_endpoint().await;
    let registry = installed_expired_external(PERSONAL);
    let dir = tempfile::tempdir().expect("tempdir");
    let executor = caching_executor(&registry, Some((LEGACY_TRAP_TOKEN, &dir)));
    let capability =
        cacheable_capability(&cacheable_base_url(port), "oauth:google", Some(PERSONAL));

    let error = executor
        .execute_with_context(&capability, json!({}), caching_context("alice"))
        .await
        .expect_err("an external credential whose expiry has passed must never be used");

    let text = error.to_string();
    assert!(
        text.contains("expired"),
        "the refusal must be attributable to the published expiry: {text}"
    );
    assert!(
        !text.contains(EXPIRED_EXTERNAL_TOKEN) && !text.contains(LEGACY_TRAP_TOKEN),
        "the refusal must carry neither the expired credential nor the legacy trap: {text}"
    );
    assert_eq!(
        captured.count(),
        0,
        "an expired external credential must not reach the wire"
    );

    // And it is refused every time: nothing was stored under it, so a second
    // identical request cannot be answered from a cache entry either.
    let repeat = executor
        .execute_with_context(&capability, json!({}), caching_context("alice"))
        .await
        .expect_err("the refusal must be stable, not a one-off miss");
    assert!(
        !repeat.to_string().contains(EXPIRED_EXTERNAL_TOKEN),
        "the repeated refusal must not carry the expired credential"
    );
    assert_eq!(
        captured.count(),
        0,
        "no cached body and no egress on the repeat either"
    );
}

/// A registry that declares nothing still fails CLOSED at execution.
///
/// This is the standalone `CapabilityExecutor` a non-gateway embedder builds:
/// there is no account catalogue at all, so a capability naming one cannot be
/// resolved and must not reach the legacy `oauth:<provider>` storage.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_executor_with_no_account_catalogue_refuses_a_managed_capability() {
    let (port, captured) = capture_endpoint().await;
    let executor = CapabilityExecutor::new()
        .with_account_strategies(Arc::new(AccountStrategyRegistry::default()));

    let error = executor
        .execute_with_context(
            &capability(&base_url(port), "oauth:google", Some(WORK)),
            json!({}),
            context(Some("alice")),
        )
        .await
        .expect_err("an undeclared account reference has nothing to resolve against");

    assert_no_credential_leaked(&error, &captured);
}

// ── Multi-user gateways ──────────────────────────────────────────────────────
//
// EVERY CASE ABOVE RUNS ON A BACKEND THAT NEVER DECLARED ITSELF MULTI-USER.
// `CapabilityBackend::multi_user` defaults to false, so
// `call_tool_with_context` never reaches the per-user OAuth isolation guard
// (`capability::execution_context::validate_oauth_isolation`) in any of them —
// which means none of them says anything about the deployment this whole
// account boundary exists for: the one that serves Alice AND Bob.
//
// A real gateway sets that flag through `MetaMcp::set_multi_user` /
// `set_capabilities` as soon as `AuthConfig::implies_multi_user` is true (see
// `gateway::server`), and the guard then runs BEFORE the executor. It decides on
// `auth.key`, `auth.shared_account` and `metadata.exposure` alone — it never
// looks at `auth.account` — so a capability bound to a managed descriptor, whose
// credential IS minted per verified caller by the account registry, is refused
// with JSON-RPC -32001 before custody is ever consulted.
//
// The cases below declare the multi-user posture with the PRODUCTION setter and
// change nothing else. NOTHING here sets `auth.shared_account = true` and
// NOTHING marks a capability `exposure: personal`: either would silence the
// guard and hide the defect instead of stating it. The descriptorless control at
// the end pins the guard's genuine job so a fix cannot be a deletion.

/// THE HEADLINE MULTI-USER CASE.
///
/// Byte for byte the setup of
/// `alice_and_bob_receive_their_own_account_credentials_from_one_rest_capability`,
/// with ONE addition: `set_multi_user(true)`. The credential each principal gets
/// is minted from their own grant under real custody, so per-user isolation is
/// already structurally guaranteed here — this is precisely the deployment the
/// account binding was built for, and it is the one where the dispatch is
/// currently refused before the executor runs.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn alice_and_bob_receive_their_own_account_credentials_on_a_multi_user_gateway() {
    let (port, captured) = capture_endpoint().await;
    let custody = custody_with(&[
        (account_key("alice", WORK), grant(ALICE_WORK_TOKEN, FRESH)),
        (account_key("bob", WORK), grant(BOB_WORK_TOKEN, FRESH)),
    ]);
    let installed: Arc<dyn AccountCustody> = custody.installed();
    let (_meta, registry) = installed_gateway(&[(WORK, managed(WORK))], &installed);
    let backend = backend_with(
        &registry,
        capability(&base_url(port), "oauth:google", Some(WORK)),
    )
    .expect("a capability naming a declared descriptor with a matching provider must register");
    // The production setter, the same one gateway startup calls.
    backend.set_multi_user(true);

    call(&backend, Some("alice"))
        .await
        .expect("Alice's dispatch must reach the endpoint on a multi-user gateway");
    call(&backend, Some("bob"))
        .await
        .expect("Bob's dispatch must reach the endpoint on a multi-user gateway");

    let seen = captured.authorizations();
    assert_eq!(seen.len(), 2, "both dispatches must reach the endpoint");
    assert_eq!(
        seen[0].as_deref(),
        Some(format!("Bearer {ALICE_WORK_TOKEN}").as_str()),
        "Alice must be served her own account's credential"
    );
    assert_eq!(
        seen[1].as_deref(),
        Some(format!("Bearer {BOB_WORK_TOKEN}").as_str()),
        "Bob must be served his own account's credential, not Alice's"
    );
    assert_eq!(
        custody.releases(),
        6,
        "each dispatch releases once resolving the account for the isolation guard, then \
         rechecks in the executor's own preparation and again before egress — three per \
         dispatch, one more than the single-user sibling's two, and every one of them a real \
         custody recheck rather than a second mint"
    );
}

/// THE MetaMcp MULTI-USER THREADING CASE.
///
/// The sibling control
/// (`meta_mcp_capability_dispatch_carries_the_verified_identity_to_the_account_boundary`)
/// proves the gateway carries the verified identity to the account boundary on a
/// single-user gateway. This drives the SAME real Code Mode entry with
/// `MetaMcp::set_multi_user(true)` — which propagates the posture to the
/// registered capability backend — against the same unroutable host, so the wire
/// is irrelevant and custody is the observable.
///
/// The anonymous run must still refuse and never reach custody. The verified run
/// must reach custody and pass the real release recheck, with the SAME release
/// count the single-user control records: multi-user changes who may call, never
/// how a verified caller's own credential is released.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn meta_mcp_multi_user_dispatch_reaches_the_account_boundary_for_a_verified_caller() {
    let custody = custody_with(&[(account_key("alice", WORK), grant(ALICE_WORK_TOKEN, FRESH))]);
    let installed: Arc<dyn AccountCustody> = custody.installed();
    let (meta, registry) = installed_gateway(&[(WORK, managed(WORK))], &installed);
    let backend = backend_with(
        &registry,
        capability(UNROUTABLE, "oauth:google", Some(WORK)),
    )
    .expect("the capability must register");
    meta.set_capabilities(Arc::clone(&backend));
    // Set AFTER `set_capabilities`: one of the two startup orders the production
    // setters are documented to keep in sync.
    meta.set_multi_user(true);

    let anonymous = meta_execute(&meta, None)
        .await
        .expect_err("an unverified caller must not reach a managed account");
    assert!(
        !anonymous.to_string().contains(ALICE_WORK_TOKEN),
        "the refusal must not carry the account token"
    );
    assert_eq!(
        custody.releases(),
        0,
        "an unverified Code Mode dispatch must never reach custody"
    );

    let _ = meta_execute(&meta, Some("alice")).await;
    assert_eq!(
        custody.releases(),
        4,
        "the invoke path mints once; the multi-user isolation guard then RECHECKS that same \
         carried credential rather than minting a second one, and the executor's preparation \
         and pre-egress recheck follow — one more recheck than the single-user control's \
         three, and no additional mint"
    );
    assert_eq!(
        custody.refreshes(),
        0,
        "the seeded grant is fresh, so nothing may hit the refresh provider"
    );
}

/// ALICE'S IDENTICAL SECOND REQUEST IS SERVED FROM THE WARM CACHE ON A
/// MULTI-USER GATEWAY, AND THE LEGACY LOGIN IS NEVER TOUCHED.
///
/// Same shape as `an_identical_second_request_from_alice_is_served_from_the_warm_cache`
/// — explicit positive TTL, `localhost` base URL, no loopback relaxation so the
/// cache is live — but dispatched through the multi-user `CapabilityBackend`,
/// which is where the isolation guard sits. A valid gateway-held `oauth:google`
/// token is seeded as the TRAP: it is exactly the credential the guard exists to
/// keep out of a second caller's hands, and a descriptor-bound dispatch must
/// never present it, cached or not.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn alices_second_identical_request_hits_the_warm_cache_on_a_multi_user_gateway() {
    let (port, captured) = capture_endpoint().await;
    let custody = custody_with(&[(account_key("alice", WORK), grant(ALICE_WORK_TOKEN, FRESH))]);
    let installed: Arc<dyn AccountCustody> = custody.installed();
    let (_meta, registry) = installed_gateway(&[(WORK, managed(WORK))], &installed);
    let dir = tempfile::tempdir().expect("tempdir");
    let backend = multi_user_caching_backend(
        &registry,
        Some((LEGACY_TRAP_TOKEN, &dir)),
        cacheable_capability(&cacheable_base_url(port), "oauth:google", Some(WORK)),
    )
    .expect("a capability naming a declared descriptor must register");

    let first = backend
        .call_tool_with_context(TOOL, json!({}), caching_context("alice"))
        .await
        .expect("Alice's first dispatch must reach the endpoint on a multi-user gateway");
    assert!(!first.is_error, "the first dispatch must not be an error");
    assert_eq!(
        captured.count(),
        1,
        "the first dispatch must actually go on the wire and prime the cache"
    );
    assert_eq!(
        captured.authorizations()[0].as_deref(),
        Some(format!("Bearer {ALICE_WORK_TOKEN}").as_str()),
        "Alice must be served her own account's credential, never the seeded legacy trap"
    );

    let second = backend
        .call_tool_with_context(TOOL, json!({}), caching_context("alice"))
        .await
        .expect("Alice's identical second dispatch must succeed");

    assert_eq!(
        captured.count(),
        1,
        "the identical second request must be served from cache: the endpoint's request count \
         must not move"
    );
    // `ToolsCallResult` carries no `PartialEq`, so its serialized form is what is
    // compared. That form includes the per-request sequence number the endpoint
    // stamps, which a re-dispatch could not reproduce.
    let (first, second) = (
        serde_json::to_value(&first).expect("a tool result serializes"),
        serde_json::to_value(&second).expect("a tool result serializes"),
    );
    assert_eq!(
        first, second,
        "a warm cache hit must return the stored body verbatim, sequence number included"
    );
    assert!(
        !second.to_string().contains(LEGACY_TRAP_TOKEN),
        "no dispatch on this path may present the gateway-held legacy login"
    );
    assert_eq!(
        custody.releases(),
        5,
        "the cold dispatch releases three times (guard resolve, executor preparation recheck, \
         pre-egress recheck) and the warm hit twice (guard resolve, executor preparation \
         recheck) — the cache is consulted only AFTER custody has re-consented, so a \
         revocation can never be papered over by a warm entry"
    );
}

/// NO VERIFIED IDENTITY STILL REFUSES ON A MULTI-USER GATEWAY.
///
/// A change that admits descriptor-bound capabilities must not admit a caller
/// the gateway never verified. Refusal, zero requests at the endpoint, and no
/// credential released — stated without naming WHICH refusal, so the case holds
/// whether the isolation guard or the account boundary is what fails closed.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_multi_user_request_with_no_verified_identity_refuses_before_http() {
    let (port, captured) = capture_endpoint().await;
    let custody = custody_with(&[(account_key("alice", WORK), grant(ALICE_WORK_TOKEN, FRESH))]);
    let installed: Arc<dyn AccountCustody> = custody.installed();
    let (_meta, registry) = installed_gateway(&[(WORK, managed(WORK))], &installed);
    let backend = backend_with(
        &registry,
        capability(&base_url(port), "oauth:google", Some(WORK)),
    )
    .expect("registration is unaffected by the absence of a caller");
    backend.set_multi_user(true);

    let error = call(&backend, None)
        .await
        .expect_err("a managed account cannot be resolved without a verified caller");

    assert_no_credential_leaked(&error, &captured);
    assert_eq!(
        custody.releases(),
        0,
        "no credential may be released for a caller the gateway has not verified"
    );
}

/// A DECLARED DESCRIPTOR WITH NO INSTALLED STRATEGY STILL REFUSES ON A
/// MULTI-USER GATEWAY.
///
/// The reload gap, under the posture that matters most: with no strategy there
/// is no per-user credential to mint, so admitting the dispatch could only mean
/// falling through to the gateway-held login — the exact leak. Registration is
/// still admitted; DISPATCH must fail closed.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_multi_user_declared_account_with_no_installed_strategy_refuses_before_http() {
    let (port, captured) = capture_endpoint().await;
    let registry = declared_only(&[(WORK, managed(WORK))]);
    let backend = backend_with(
        &registry,
        capability(&base_url(port), "oauth:google", Some(WORK)),
    )
    .expect("a declared descriptor is a valid reference at registration time");
    backend.set_multi_user(true);

    let error = call(&backend, Some("alice"))
        .await
        .expect_err("no installed strategy means no credential, and no substitute");

    assert_no_credential_leaked(&error, &captured);
}

/// A REVOKED GRANT STILL REFUSES ON A MULTI-USER GATEWAY.
///
/// The revocation is applied through the REAL `CustodyHandle`, so what refuses
/// is the production recheck. Admitting descriptor-bound capabilities must not
/// weaken it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_multi_user_revoked_grant_refuses_before_http() {
    let (port, captured) = capture_endpoint().await;
    let alice = account_key("alice", WORK);
    let custody = custody_with(&[(alice.clone(), grant(ALICE_WORK_TOKEN, FRESH))]);
    custody
        .handle
        .invalidate(&alice)
        .await
        .expect("revocation must be applied");
    let installed: Arc<dyn AccountCustody> = custody.installed();
    let (_meta, registry) = installed_gateway(&[(WORK, managed(WORK))], &installed);
    let backend = backend_with(
        &registry,
        capability(&base_url(port), "oauth:google", Some(WORK)),
    )
    .expect("registration does not consult grant state");
    backend.set_multi_user(true);

    let error = call(&backend, Some("alice"))
        .await
        .expect_err("a revoked account has no credential to serve");

    assert_no_credential_leaked(&error, &captured);
    assert_eq!(
        custody.releases(),
        0,
        "the release observer must record no successful release"
    );
}

/// THE GUARD'S GENUINE JOB IS UNCHANGED.
///
/// A capability with NO `auth.account` on `oauth:google` has exactly one
/// credential available to it: the single gateway-held login, served to whoever
/// calls. That is the cross-user leak the isolation guard closes, and it must go
/// on refusing with JSON-RPC -32001 on a multi-user gateway — verified caller or
/// not. A change that admits descriptor-bound capabilities by relaxing or
/// deleting the guard fails HERE.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_multi_user_gateway_still_refuses_a_capability_with_no_account_reference() {
    let (port, captured) = capture_endpoint().await;
    let custody = custody_with(&[(account_key("alice", WORK), grant(ALICE_WORK_TOKEN, FRESH))]);
    let installed: Arc<dyn AccountCustody> = custody.installed();
    let (_meta, registry) = installed_gateway(&[(WORK, managed(WORK))], &installed);
    // No `account:` line at all — the legacy gateway-held OAuth shape.
    let backend = backend_with(&registry, capability(&base_url(port), "oauth:google", None))
        .expect("a capability with no account reference registers as it always has");
    backend.set_multi_user(true);

    let error = call(&backend, Some("alice"))
        .await
        .expect_err("a gateway-held OAuth login is not isolated per user");
    let text = error.to_string();
    assert!(
        text.contains("not isolated per user"),
        "the refusal must be the per-user OAuth isolation guard: {text}"
    );
    assert_no_credential_leaked(&error, &captured);
    assert_eq!(
        custody.releases(),
        0,
        "an unbound capability must never reach custody"
    );
}

/// A `shared` DESCRIPTOR STILL FACES THE UNCHANGED GUARD.
///
/// This is the case that separates "the account boundary minted a per-caller
/// credential" from "the capability merely NAMES an account". A `shared`
/// descriptor resolves to `AccountCredential::Legacy` — there is no per-caller
/// credential, only the gateway-held login again — so the dispatch must be
/// refused with the SAME -32001 an unbound capability gets. A fix that keyed the
/// exception on `auth.account` being present, rather than on a credential
/// actually having been prepared for this caller, fails HERE.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_multi_user_shared_descriptor_is_still_refused_by_the_isolation_guard() {
    let (port, captured) = capture_endpoint().await;
    let custody = custody_with(&[(
        account_key("alice", PERSONAL),
        grant(ALICE_PERSONAL_TOKEN, FRESH),
    )]);
    let installed: Arc<dyn AccountCustody> = custody.installed();
    let (_meta, registry) = installed_gateway(&[(PERSONAL, shared(PERSONAL))], &installed);
    let backend = backend_with(
        &registry,
        capability(&base_url(port), "oauth:google", Some(PERSONAL)),
    )
    .expect("a shared descriptor is a declared descriptor and registers normally");
    backend.set_multi_user(true);

    let error = call(&backend, Some("alice"))
        .await
        .expect_err("a shared descriptor serves the gateway-held login, which is not isolated");
    let text = error.to_string();
    assert!(
        text.contains("not isolated per user"),
        "the refusal must be the unchanged per-user OAuth isolation guard: {text}"
    );
    assert_no_credential_leaked(&error, &captured);
    assert_eq!(
        custody.releases(),
        0,
        "a shared descriptor has no custody requirement and must not consult it"
    );
}

/// A GRANT SUBJECT IS NOT AN ACCOUNT IDENTITY, ON A MULTI-USER GATEWAY EITHER.
///
/// `caller_identity` is a `GrantSubject`: an authorization handle whose
/// authority is not an OAuth issuer. The request below carries one and carries
/// NO `VerifiedIdentity`, so there is no issuer+subject pair from which a
/// managed account key could be built. Admitting it would mean minting — or
/// worse, falling back — for a principal the gateway never verified.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_multi_user_grant_subject_alone_does_not_authorize_a_managed_account() {
    let (port, captured) = capture_endpoint().await;
    let custody = custody_with(&[(account_key("alice", WORK), grant(ALICE_WORK_TOKEN, FRESH))]);
    let installed: Arc<dyn AccountCustody> = custody.installed();
    let (_meta, registry) = installed_gateway(&[(WORK, managed(WORK))], &installed);
    let backend = backend_with(
        &registry,
        capability(&base_url(port), "oauth:google", Some(WORK)),
    )
    .expect("the capability must register");
    backend.set_multi_user(true);

    let grant_subject_only = crate::capability::CapabilityExecutionContext::with_caller_identity(
        crate::identity_grants::GrantSubject::new("cloudflare_access", "alice", None),
    )
    .with_isolated_loopback_egress();

    let error = backend
        .call_tool_with_context(TOOL, json!({}), grant_subject_only)
        .await
        .expect_err("a grant subject cannot stand in for a verified end-user identity");

    assert_no_credential_leaked(&error, &captured);
    assert_eq!(
        custody.releases(),
        0,
        "no credential may be released for a principal the gateway has not verified"
    );
}

/// A CARRIED CREDENTIAL MINTED FOR ANOTHER DESCRIPTOR IS REFUSED BEFORE HTTP.
///
/// The credential is genuine, current, and belongs to this very caller — it is
/// simply the wrong ACCOUNT. Presenting it would serve Alice's personal mailbox
/// credential to a capability bound to her work account, so the exception must
/// turn on the descriptor the credential was minted for and not merely on the
/// presence of one.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_multi_user_carried_credential_for_another_descriptor_refuses_before_http() {
    let (port, captured) = capture_endpoint().await;
    let custody = custody_with(&[
        (account_key("alice", WORK), grant(ALICE_WORK_TOKEN, FRESH)),
        (
            account_key("alice", PERSONAL),
            grant(ALICE_PERSONAL_TOKEN, FRESH),
        ),
    ]);
    let installed: Arc<dyn AccountCustody> = custody.installed();
    let (_meta, registry) = installed_gateway(
        &[(WORK, managed(WORK)), (PERSONAL, managed(PERSONAL))],
        &installed,
    );
    let backend = multi_user_caching_backend(
        &registry,
        None,
        cacheable_capability(&cacheable_base_url(port), "oauth:google", Some(WORK)),
    )
    .expect("the work-bound capability must register");
    // Minted for PERSONAL, carried into a dispatch of the WORK-bound capability.
    let wrong_account =
        prepared_caching_context(&registry, "alice", PERSONAL, "oauth:google").await;

    let error = backend
        .call_tool_with_context(TOOL, json!({}), wrong_account)
        .await
        .expect_err("one capability's account credential must never excuse another's");

    assert_no_credential_leaked(&error, &captured);
    assert!(
        !error.to_string().contains(ALICE_PERSONAL_TOKEN),
        "the refusal must not carry the mismatched account's token"
    );
    assert_eq!(
        custody.releases(),
        1,
        "only the fixture's own mint for PERSONAL may appear; the dispatch must consume no \
         further custody"
    );
}

/// A CARRIED CREDENTIAL MINTED FOR ANOTHER CALLER IS REFUSED BEFORE HTTP.
///
/// The descriptor and the auth key both match; only the ACTOR differs. This is
/// the exact substitution the exception's `stable_actor_id` conjunct exists to
/// stop — Bob presenting a request that carries Alice's prepared credential —
/// and it must be refused by the live registry recheck, before any cache lookup
/// and before the wire.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_multi_user_carried_credential_for_another_caller_refuses_before_http() {
    let (port, captured) = capture_endpoint().await;
    let custody = custody_with(&[(account_key("alice", WORK), grant(ALICE_WORK_TOKEN, FRESH))]);
    let installed: Arc<dyn AccountCustody> = custody.installed();
    let (_meta, registry) = installed_gateway(&[(WORK, managed(WORK))], &installed);
    let backend = multi_user_caching_backend(
        &registry,
        None,
        cacheable_capability(&cacheable_base_url(port), "oauth:google", Some(WORK)),
    )
    .expect("the capability must register");
    // Alice's real credential, presented under Bob's verified identity.
    let alices_credential_bobs_request =
        prepared_caching_context(&registry, "alice", WORK, "oauth:google")
            .await
            .with_verified_identity(Arc::new(identity("bob")));

    let error = backend
        .call_tool_with_context(TOOL, json!({}), alices_credential_bobs_request)
        .await
        .expect_err("a credential minted for Alice must not be served for Bob");

    assert_no_credential_leaked(&error, &captured);
    assert_eq!(
        custody.releases(),
        1,
        "only the fixture's own mint for Alice may appear; the mismatched dispatch must consume \
         no further custody"
    );
}

/// AN INVALID CALL ACQUIRES NO CREDENTIAL AT ALL.
///
/// Resolving the account is not free: it takes a real custody lease and burns a
/// release against the account's audit record. A call that is about to be
/// rejected for a missing required argument never happens, so it must never
/// consume one. This pins the ORDER — path selector and schema validation
/// strictly before any custody work — which is otherwise invisible, because a
/// resolve-then-reject implementation returns the very same error to the caller.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_multi_user_dispatch_with_invalid_arguments_acquires_no_credential() {
    let (port, captured) = capture_endpoint().await;
    let custody = custody_with(&[(account_key("alice", WORK), grant(ALICE_WORK_TOKEN, FRESH))]);
    let installed: Arc<dyn AccountCustody> = custody.installed();
    let (_meta, registry) = installed_gateway(&[(WORK, managed(WORK))], &installed);
    let backend = backend_with(
        &registry,
        capability_requiring_argument(&base_url(port), "oauth:google", Some(WORK)),
    )
    .expect("the capability must register");
    backend.set_multi_user(true);

    // `folder` is required, and this verified caller COULD have resolved her
    // account — so a release here would be an acquisition made for nothing.
    let result = call(&backend, Some("alice"))
        .await
        .expect("a schema violation is reported as a tool error, not a transport failure");

    assert!(
        result.is_error,
        "a call missing a required argument must be rejected"
    );
    assert_eq!(
        captured.count(),
        0,
        "an invalid call must never reach the endpoint"
    );
    assert_eq!(
        custody.releases(),
        0,
        "an invalid call must never acquire, release or recheck an account credential"
    );
    assert!(
        !serde_json::to_string(&result)
            .expect("a tool result serializes")
            .contains(ALICE_WORK_TOKEN),
        "a validation error must not carry account credential material"
    );
}

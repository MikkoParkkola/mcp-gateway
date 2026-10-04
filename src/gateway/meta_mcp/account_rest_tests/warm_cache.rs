// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The response cache with account-bound credentials.

use super::*;

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

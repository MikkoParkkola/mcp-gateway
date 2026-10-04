// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Multi-user gateways and the per-user OAuth isolation guard.

use super::*;

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

/// THE `MetaMcp` MULTI-USER THREADING CASE.
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

    let anonymous = Box::pin(meta_execute(&meta, None))
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

    let _ = Box::pin(meta_execute(&meta, Some("alice"))).await;
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

/// STORE.2 C4: A CREDENTIAL PREPARED UNDER THE OLD GRANT IS NOT USABLE ONCE THE
/// ACCOUNT IS RECONNECTED.
///
/// The revocation sibling above stops at `invalidate`, which proves only that a
/// removed grant kills its warm entry. The criterion is stronger: after the user
/// reconnects and a NEW grant is published, the credential prepared under the
/// OLD one must still be refused — otherwise a cache entry outlives the
/// authority it was minted under, which is exactly the hole per-user isolation
/// is supposed to close.
///
/// The new grant is committed through the live `CustodyHandle` under a
/// compare-and-set expectation naming the grant it replaces, so this is the real
/// publication path and not a store the test reopened behind custody's back. The
/// second call is byte-identical to the first: the warm entry is sitting there,
/// and only a recheck that runs BEFORE the lookup can refuse it.
///
/// Three oracles, because two of them can pass for the wrong reason: the call is
/// refused, no new request reaches the wire, and the refusal carries NEITHER the
/// old token (served from cache) NOR the new one (silently re-resolved).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_reconnected_grant_refuses_the_credential_prepared_under_the_old_one() {
    let (port, captured) = capture_endpoint().await;
    let alice = account_key("alice", WORK);
    let seeded = grant(ALICE_WORK_TOKEN, FRESH);
    let custody = custody_with(&[(alice.clone(), seeded.clone())]);
    let installed: Arc<dyn AccountCustody> = custody.installed();
    let (_meta, registry) = installed_gateway(&[(WORK, managed(WORK))], &installed);
    let dir = tempfile::tempdir().expect("tempdir");
    let executor = caching_executor(&registry, Some((LEGACY_TRAP_TOKEN, &dir)));
    let capability = cacheable_capability(&cacheable_base_url(port), "oauth:google", Some(WORK));

    let prepared = prepared_caching_context(&registry, "alice", WORK, "oauth:google").await;
    let warm = executor
        .execute_with_context(&capability, json!({}), prepared.clone())
        .await
        .expect("the prepared credential must dispatch while its grant is current");
    assert_eq!(captured.count(), 1, "the cache must actually be warm");
    assert_eq!(
        warm["authorization"],
        json!(format!("Bearer {ALICE_WORK_TOKEN}")),
        "the warm entry must be Alice's own account credential, not the legacy trap"
    );

    let (expectation, reconnected) = reconnect_from(&seeded, ROTATED_TOKEN);
    custody
        .handle
        .commit_grant_if(&alice, &expectation, &reconnected)
        .await
        .expect("the reconnected grant must be published through live custody");

    let error = executor
        .execute_with_context(&capability, json!({}), prepared)
        .await
        .expect_err("a credential prepared under the superseded grant must be refused");

    let text = error.to_string();
    assert!(
        !text.contains(ALICE_WORK_TOKEN),
        "the refusal must not carry the superseded token: {text}"
    );
    assert!(
        !text.contains(ROTATED_TOKEN) && !text.contains(LEGACY_TRAP_TOKEN),
        "the refusal must not silently re-resolve to the new grant or fall back \
         to the legacy trap: {text}"
    );
    assert_eq!(
        captured.count(),
        1,
        "the refusal must reach neither the cache nor the wire: no new request, and an error \
         instead of the stored body"
    );
}

/// STORE.2 C5 (#556): AFTER A REAL REVOKE, THE FIRST CALL SERVES THE
/// SUCCESSOR'S CREDENTIAL UNDER A NEW GENERATION — NOT THE REVOKED ONE.
///
/// The sibling above proves a credential prepared under the OLD grant is
/// refused; it never proves a grant is actually SERVED after re-consent, and
/// its successor only bumps the token revision, never the generation. A
/// binding keyed on revision alone cannot tell "same consent, rotated token"
/// apart from "different consent entirely" — this is the axis #556 names as
/// untested. `revoke_and_reconnect` durably revokes the seeded grant through
/// real custody and commits a successor under `RECONNECT_GENERATION`'s
/// value, then a FRESH resolve (exactly what the next inbound request would
/// do) must dispatch the successor's token, reaching the real wire rather
/// than a cached reply, and the revoked token must never resurface.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_revoked_grant_is_replaced_by_its_successor_under_a_new_generation() {
    let (port, captured) = capture_endpoint().await;
    let alice = account_key("alice", WORK);
    let seeded = grant(ALICE_WORK_TOKEN, FRESH);
    let custody = custody_with(&[(alice.clone(), seeded.clone())]);
    let installed: Arc<dyn AccountCustody> = custody.installed();
    let (_meta, registry) = installed_gateway(&[(WORK, managed(WORK))], &installed);
    let dir = tempfile::tempdir().expect("tempdir");
    let executor = caching_executor(&registry, Some((LEGACY_TRAP_TOKEN, &dir)));
    let capability = cacheable_capability(&cacheable_base_url(port), "oauth:google", Some(WORK));

    let warm = prepared_caching_context(&registry, "alice", WORK, "oauth:google").await;
    executor
        .execute_with_context(&capability, json!({}), warm)
        .await
        .expect("the seeded grant must dispatch while it is current");
    assert_eq!(captured.count(), 1, "the first call must reach the wire");

    let successor = revoke_and_reconnect(&custody, &alice, &seeded, ROTATED_TOKEN).await;
    assert_ne!(
        successor.generation, seeded.generation,
        "the fixture must model a re-consent boundary, not a same-generation bump"
    );

    let fresh = prepared_caching_context(&registry, "alice", WORK, "oauth:google").await;
    let served = executor
        .execute_with_context(&capability, json!({}), fresh)
        .await
        .expect("the successor's grant must dispatch on the first call after re-consent");

    assert_eq!(
        served["authorization"],
        json!(format!("Bearer {ROTATED_TOKEN}")),
        "the first call after re-consent must carry the successor's token"
    );
    assert_eq!(
        captured.count(),
        2,
        "the successor's request must reach the real wire, not a cached reply"
    );
    let authorizations = captured.authorizations();
    assert!(
        authorizations
            .iter()
            .skip(1) // call 0 is the legitimate pre-revoke dispatch; only post-revoke calls matter here
            .flatten()
            .all(|value| !value.contains(ALICE_WORK_TOKEN)),
        "the revoked token must never reach the wire again after re-consent: {authorizations:?}"
    );
}

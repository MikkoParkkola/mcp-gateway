// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Per-caller dispatch, refusals before HTTP and descriptor coexistence.

use super::*;

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
        6,
        "A11: +1 per dispatch is the extra executor recheck, not a new mint (as multi-user)"
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
        3,
        "A11: the managed descriptor alone; +1 is the extra recheck, not a new mint"
    );
}

/// THE ONE `MetaMcp` THREADING CONTROL.
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
        "A11: Code Mode mints once; +1 is the extra backend recheck, not a new mint (as multi-user)"
    );
    assert_eq!(
        custody.refreshes(),
        0,
        "the seeded grant is fresh, so nothing may hit the refresh provider"
    );
}

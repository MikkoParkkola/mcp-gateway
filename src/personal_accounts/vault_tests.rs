// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The sole-operator principal, end to end through the REAL store.
//!
//! WHY A REAL STORE. The claim under test is that a solo deployment's stored
//! grant becomes reachable — not that a boolean flips. A scripted custody could
//! return a lease for any account key, including the wrong one, so it cannot
//! tell "the principal addresses the seeded grant" from "the principal
//! addresses nothing and the fake answered anyway". The store is seeded under
//! the key `account_key` builds, and a mismatch shows up as a refusal.
//!
//! The provider is scripted because a refresh is a network round trip, not
//! because custody is. Every grant seeded here is unexpired, so the provider is
//! never called on the positive path and says so by counting.

use std::collections::BTreeMap;
use std::future::Future;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use super::*;
use crate::identity_propagation::{CallerProof, CallerProvenance};
use crate::personal_accounts::service::{ProviderRefreshError, TokenRefresh};
use crate::personal_accounts::{GrantRecord, PersonalAccountStore, StoreConfig};

const KEY: [u8; 32] = [0x73; 32];
const DESCRIPTOR_ID: &str = "google-workspace-personal";
const RESOURCE: &str = "https://www.googleapis.com/drive/v3";
const SOLE_TOKEN: &str = "synthetic-sole-operator-access-private-material-4b71";
const ALICE_TOKEN: &str = "synthetic-alice-access-private-material-9f3a71";

/// RFC 6749's default scheme, as `vault::authorization_value` emits it.
const SCHEME: &str = "Bearer";

fn descriptor() -> AccountDescriptor {
    AccountDescriptor {
        descriptor_id: DESCRIPTOR_ID.into(),
        provider: "google".into(),
        resource: RESOURCE.into(),
        issuer: "https://accounts.google.com".into(),
    }
}

fn backend() -> BackendDescriptor {
    BackendDescriptor {
        id: DESCRIPTOR_ID.into(),
        audience: RESOURCE.into(),
        token_exchange_endpoint: None,
        token_exchange_scope: None,
    }
}

/// A verified caller, exactly as `key_server::oidc` produces one.
fn identity() -> VerifiedIdentity {
    VerifiedIdentity {
        subject: "alice-subject-8f21".into(),
        email: "alice@example.com".into(),
        name: Some("Alice Example".into()),
        groups: vec!["engineering".into()],
        issuer: "https://identity.example".into(),
    }
}

/// The account key a principal actually addresses. Built by the production
/// function, so a test cannot seed a key the gateway would never construct.
fn key_for(principal: Principal<'_>) -> AccountKey {
    account_key(Some(principal), &descriptor()).expect("principal and descriptor must bind")
}

fn unexpired_grant(access_token: &str) -> GrantRecord {
    GrantRecord {
        generation: "fedcba9876543210fedcba9876543210".into(),
        token_revision: 1,
        authorization_epoch: 1,
        descriptor_revision: "0".repeat(64),
        scopes: vec!["https://www.googleapis.com/auth/drive.readonly".into()],
        access_token: access_token.into(),
        refresh_token: Some("synthetic-refresh-private-material-8c9d21".into()),
        token_type: "Bearer".into(),
        expires_at: u64::MAX,
        provider_account_id: Some("synthetic-provider-account-private-1a92".into()),
        client_id: "synthetic-google-client".into(),
    }
}

fn store_config(root: &std::path::Path) -> StoreConfig {
    let root = root.canonicalize().expect("fixture root exists");
    StoreConfig {
        instance_id: "gateway-instance".into(),
        store_dir: root.join("records"),
        authority_dir: root.join("authority"),
        current_key_id: "current".into(),
        keys: BTreeMap::from([("current".into(), KEY.to_vec())]),
        max_entries: 10_000,
        max_authority_bytes: 16_777_216,
    }
}

fn seed(root: &std::path::Path, accounts: &[(AccountKey, GrantRecord)]) {
    let store = PersonalAccountStore::initialize(store_config(root)).expect("initialize");
    for (account, record) in accounts {
        store.commit_grant(account, record).expect("seed grant");
    }
    drop(store);
}

/// Counts calls and never rotates: every grant seeded here is unexpired, so a
/// non-zero count means custody refreshed something it should not have.
struct CountingProvider {
    calls: Arc<AtomicUsize>,
}

impl RefreshProvider for CountingProvider {
    fn refresh(
        &self,
        _account: &AccountKey,
        current: &GrantRecord,
    ) -> impl Future<Output = Result<TokenRefresh, ProviderRefreshError>> + Send {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let rotated = TokenRefresh {
            access_token: "synthetic-rotated-should-not-happen".into(),
            refresh_token: None,
            scopes: Some(current.scopes.clone()),
            token_type: "Bearer".into(),
            expires_at: u64::MAX,
        };
        async move { Ok(rotated) }
    }
}

struct SilentObserver;

impl CredentialReleaseObserver for SilentObserver {
    fn on_release(
        &self,
        _account: &AccountKey,
        _lease: &CredentialLease,
        _credentials: &ReleasedCredentials,
    ) {
    }
}

/// A strategy over the REAL store, with the deployment mode set as the install
/// site would set it.
fn strategy(root: &std::path::Path, sole_operator: bool) -> (VaultStrategy, Arc<AtomicUsize>) {
    let calls = Arc::new(AtomicUsize::new(0));
    let handle = CustodyHandle::start(
        store_config(root),
        CountingProvider {
            calls: Arc::clone(&calls),
        },
        SilentObserver,
        4,
    )
    .expect("custody starts against a seeded store");
    let custody: Arc<dyn AccountCustody> = Arc::new(handle);
    (
        VaultStrategy::new(custody, descriptor(), sole_operator),
        calls,
    )
}

fn block_on<F: Future>(fut: F) -> F::Output {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .expect("runtime")
        .block_on(fut)
}

/// The one seeded shape every test starts from: the solo deployment's grant,
/// stored under the key `account_key` builds for [`Principal::SoleOperator`].
fn seed_sole_operator(root: &std::path::Path) {
    seed(
        root,
        &[(
            key_for(Principal::SoleOperator),
            unexpired_grant(SOLE_TOKEN),
        )],
    );
}

/// TEST 1: the whole point. A grant stored under the sole-operator principal is
/// leasable end to end, on a deployment that asserted a single user and a
/// request that authenticated.
#[test]
fn a_sole_operator_grant_is_leasable_end_to_end() {
    let tmp = tempfile::TempDir::new().expect("root");
    seed_sole_operator(tmp.path());

    block_on(async {
        let (vault, refreshes) = strategy(tmp.path(), true);
        let principal = vault
            .principal(CallerProof::Operator(CallerProvenance::Credential))
            .expect("an asserted solo gateway mints for an authenticated caller");
        assert_eq!(principal, Principal::SoleOperator);

        let (credential, lease) = vault
            .prepare(principal, &backend())
            .await
            .expect("the seeded grant leases and releases");

        // The REAL durable answer: the token on the wire is the seeded one, so
        // the principal addressed the stored grant rather than nothing.
        assert_eq!(
            credential.headers,
            vec![(
                "Authorization".to_string(),
                format!("{SCHEME} {SOLE_TOKEN}")
            )],
        );
        assert_eq!(lease.account, key_for(Principal::SoleOperator));
        assert_eq!(
            refreshes.load(Ordering::SeqCst),
            0,
            "an unexpired grant needs no provider round trip"
        );
        // The lease is still the custody boundary: the REST registry calls this
        // before egress, and a feature that minted but could not recheck would
        // fail at the last step instead of the first.
        vault.recheck(&lease).await.expect("a live lease rechecks");
    });
}

/// TEST 2, THE SECURITY CASE, and the exact shape a default install ships.
///
/// `commands::generate_config` writes `auth.enabled: true`, `auth.single_user:
/// true` AND `public_paths: ["/health", "/mcp"]`. So the deployment predicate
/// is TRUE on a stock install while `/mcp` still serves callers that presented
/// nothing — `gateway/auth.rs` hands those an `AuthenticatedClient` with
/// `authenticated: false` and an empty `principal`, which classifies as
/// [`CallerProvenance::Anonymous`]. Authentication being CONFIGURED is not the
/// same as this request having been authenticated, and this is the test that
/// says so.
#[test]
fn an_anonymous_caller_gets_no_principal_on_an_asserted_solo_gateway() {
    let tmp = tempfile::TempDir::new().expect("root");
    seed_sole_operator(tmp.path());

    // `sole_operator: true` is the default install's own answer: enabled auth,
    // asserted single user, no second key, no IdP.
    let (vault, _) = strategy(tmp.path(), true);

    assert_eq!(
        CallerProvenance::classify(Some("")),
        CallerProvenance::Anonymous,
        "a public-path caller's empty credential principal is not authentication"
    );
    assert_eq!(
        CallerProvenance::classify(None),
        CallerProvenance::Anonymous
    );

    assert!(
        vault.principal(CallerProof::Anonymous).is_none(),
        "a caller the gateway never recognised gets no principal, so the stored grant it \
         would have addressed stays unreachable"
    );
    assert!(
        vault
            .principal(CallerProof::new(None, CallerProvenance::Anonymous))
            .is_none(),
        "and the same holds through the classifier the request path actually uses"
    );
}

/// The two-condition rule is enforced AT THE ENFORCEMENT POINT, not only in the
/// constructor.
///
/// `CallerProof`'s variants are `pub(crate)`, so any code in this crate can
/// build `Operator(CallerProvenance::Anonymous)` without going through
/// `CallerProof::new` — a state the classifier never produces and the
/// constructor would refuse. If `principal` matched `Operator(_)` and discarded
/// the provenance, that hand-built value would mint the deployment-wide
/// principal for a caller nothing established, and the second of the two
/// documented conditions would be convention rather than code.
///
/// Carrying the provenance in the type only helps if something reads it. This
/// test is what makes the reading load-bearing: delete the
/// `establishes_the_operator` call in `principal` and only this case goes red.
#[test]
fn a_hand_built_anonymous_operator_proof_mints_no_principal() {
    let tmp = tempfile::TempDir::new().expect("root");
    seed_sole_operator(tmp.path());
    let (vault, _) = strategy(tmp.path(), true);

    // Control, and it must come first: on this same vault the two established
    // provenances DO mint, so a `None` below is the provenance being refused
    // and not the vault refusing everyone.
    assert!(
        vault
            .principal(CallerProof::Operator(CallerProvenance::Credential))
            .is_some(),
        "control: a validated credential must still mint, or the assertion below \
         passes for a vault that mints for nobody"
    );
    assert!(
        vault
            .principal(CallerProof::Operator(CallerProvenance::LocalTransport))
            .is_some(),
        "control: stdio must still mint -- it is the shipped solo transport"
    );

    assert!(
        vault
            .principal(CallerProof::Operator(CallerProvenance::Anonymous))
            .is_none(),
        "an Operator proof carrying no established provenance must mint nothing, \
         however it was constructed: the enforcement point checks the request \
         fact rather than trusting that the constructor already did"
    );
}

/// stdio is admitted, and the type says WHY it is admitted.
///
/// A stdio gateway is spawned by the person using it and serves exactly that
/// one client, so the transport establishes the operator without any secret
/// being presented — `STDIO_CREDENTIAL_PRINCIPAL`'s own doc records that
/// reaching the gateway over stdio already grants full tool access. It is
/// admitted for minting because every current user is a solo user and stdio is
/// their transport; it is kept a DISTINCT variant so a later call site that
/// needs a validated secret can tell the two apart instead of reading one
/// boolean and assuming.
#[test]
fn stdio_is_admitted_but_stays_distinguishable_from_a_validated_secret() {
    let tmp = tempfile::TempDir::new().expect("root");
    seed_sole_operator(tmp.path());
    let (vault, _) = strategy(tmp.path(), true);

    assert_eq!(
        CallerProvenance::classify(Some("stdio")),
        CallerProvenance::LocalTransport,
        "the stdio constant is matched by name, not counted as a presented secret"
    );
    assert_eq!(
        CallerProvenance::classify(Some("a1b2c3-digest-of-a-validated-secret")),
        CallerProvenance::Credential
    );

    // Both mint today.
    for provenance in [
        CallerProvenance::LocalTransport,
        CallerProvenance::Credential,
    ] {
        assert_eq!(
            vault.principal(CallerProof::new(None, provenance)),
            Some(Principal::SoleOperator),
            "{provenance:?} establishes the operator on an asserted solo gateway"
        );
    }
    // And they remain distinguishable, which is the point of the variant.
    assert_ne!(
        CallerProvenance::LocalTransport,
        CallerProvenance::Credential
    );
}

/// TEST 3: the deployment half. No assertion, no principal — an authenticated
/// caller on a gateway that never claimed to serve one human is exactly the
/// multi-user shape `single_user` fails closed to.
#[test]
fn an_unasserted_gateway_gets_no_principal_without_an_identity() {
    let tmp = tempfile::TempDir::new().expect("root");
    seed_sole_operator(tmp.path());

    let (vault, _) = strategy(tmp.path(), false);
    assert!(
        vault
            .principal(CallerProof::Operator(CallerProvenance::Credential))
            .is_none(),
        "without the operator's assertion an authenticated caller is still nobody in particular"
    );
    assert!(vault.principal(CallerProof::Anonymous).is_none());
}

/// TEST 4: a verified caller is served THEIR account, never the shared one, and
/// the two address different grants. This is what stops the assertion from
/// widening into a proof: `sole_operator` is true here, and the verified arm
/// still wins.
#[test]
fn a_verified_caller_is_never_served_the_sole_operator_account() {
    let tmp = tempfile::TempDir::new().expect("root");
    let alice = identity();
    seed(
        tmp.path(),
        &[
            (
                key_for(Principal::SoleOperator),
                unexpired_grant(SOLE_TOKEN),
            ),
            (
                key_for(Principal::Verified(&alice)),
                unexpired_grant(ALICE_TOKEN),
            ),
        ],
    );

    block_on(async {
        let (vault, _) = strategy(tmp.path(), true);
        let principal = vault
            .principal(CallerProof::Verified(&alice))
            .expect("a verified caller always has a principal");
        assert_eq!(principal, Principal::Verified(&alice));

        let (credential, _lease) = vault
            .prepare(principal, &backend())
            .await
            .expect("alice's own grant leases");
        assert_eq!(
            credential.headers[0].1,
            format!("{SCHEME} {ALICE_TOKEN}"),
            "a verified caller gets their own token, not the deployment's"
        );
    });

    // Different accounts by digest, not by convention.
    assert_ne!(
        key_for(Principal::SoleOperator)
            .digest()
            .expect("well formed"),
        key_for(Principal::Verified(&alice))
            .digest()
            .expect("well formed"),
    );
}

/// The authority a sole-operator deployment records under is not an OIDC
/// issuer's shape, and the two never coexist anyway — the predicate behind
/// `sole_operator` is false whenever an issuer is configured
/// (`AuthConfig::grants_single_user_principal`, tested there).
///
/// Asserted as a property of the VALUE, not as an enforced boundary: nothing
/// validates `principal_authority` (design doc §3), and presenting a convention
/// as a boundary is the error review already caught once.
#[test]
fn the_sole_operator_authority_is_not_an_issuer_url() {
    let authority = key_for(Principal::SoleOperator).principal_authority;
    assert!(
        !authority.contains("://"),
        "an OIDC issuer is a URL; this is namespaced after \
         `openwebui_adapter::namespaced_issuer` and is not one: {authority}"
    );
    assert_ne!(
        Principal::SoleOperator.stable_actor_id(),
        Principal::Verified(&identity()).stable_actor_id(),
        "the audit trail tells the assertion apart from the proof"
    );
}

/// TEST: the absence discriminant survives the custody -> propagation boundary
/// and stays distinct from every other refusal (`MIK-6745.JOURNEY.1`, carrier).
///
/// WHAT WOULD BE WRONG WITHOUT IT. `VaultStrategy::prepare` maps every
/// `CustodyError` through one `PropagationError::Refuse(String)`. Absence,
/// revocation, reconnect-required, a busy custody and a store failure arrive as
/// the same variant differing only in interpolated prose, so no consumer can
/// branch on them without substring matching — including the `idp_refuse`
/// transparency-log record the direct backend route writes, which is the half
/// that matters for audit integrity.
///
/// THE PAIR IS THE POINT. Asserting only that an absent grant refuses would
/// pass for an implementation that refuses everyone identically — which is
/// precisely the pre-fix behaviour. So absence and revocation are asserted to
/// produce DIFFERENT discriminants, against the same fixture and backend.
///
/// ADMITTED-CASE CONTROL: `a_sole_operator_grant_is_leasable_end_to_end` above.
/// It proves this same store, descriptor, backend and principal DO lease and
/// release when a grant exists. Without that control green, every assertion
/// here would pass vacuously against a strategy that refused everything.
///
/// NOT AN OFFER. This asserts a discriminant, not a consent URL. The gateway
/// brokered consent journey is deferred (ADR-008 Slice C); nothing here
/// promises a flow the gateway cannot complete.
#[test]
fn absence_is_distinguishable_from_revocation_at_the_propagation_boundary() {
    // ABSENT: an initialized but empty store, so `lookup` ANSWERS "absent"
    // rather than failing. A store that failed to open would refuse for a
    // different reason and prove nothing about absence.
    let absent_root = tempfile::TempDir::new().expect("root");
    seed(absent_root.path(), &[]);
    let absent = block_on(async {
        let (vault, _) = strategy(absent_root.path(), true);
        let principal = vault
            .principal(CallerProof::Operator(CallerProvenance::Credential))
            .expect("an asserted solo gateway mints for an authenticated caller");
        vault
            .prepare(principal, &backend())
            .await
            .expect_err("no grant is stored, so nothing can be leased")
    });

    // REVOKED: the same seeded grant the control leases, then tombstoned
    // through the real store API. Not a fabricated error value.
    let revoked_root = tempfile::TempDir::new().expect("root");
    seed_sole_operator(revoked_root.path());
    {
        let store = PersonalAccountStore::open(store_config(revoked_root.path()))
            .expect("the seeded store reopens");
        store
            .revoke(&key_for(Principal::SoleOperator))
            .expect("the seeded grant revokes");
    }
    let revoked = block_on(async {
        let (vault, _) = strategy(revoked_root.path(), true);
        let principal = vault
            .principal(CallerProof::Operator(CallerProvenance::Credential))
            .expect("an asserted solo gateway mints for an authenticated caller");
        vault
            .prepare(principal, &backend())
            .await
            .expect_err("a revoked grant cannot be leased")
    });

    assert!(
        matches!(absent, PropagationError::AccountNotConnected(_)),
        "an absent grant must carry the absence discriminant across the custody \
         boundary, not be flattened into a generic refusal: {absent:?}"
    );
    assert!(
        !matches!(revoked, PropagationError::AccountNotConnected(_)),
        "a revoked grant is not an absent one; reporting revocation as absence \
         would invite a reconnect for a grant the user deliberately withdrew: \
         {revoked:?}"
    );
    assert_ne!(
        std::mem::discriminant(&absent),
        std::mem::discriminant(&revoked),
        "absence and revocation must differ by VARIANT, not only by the prose \
         inside one shared variant — a string difference is not something a \
         consumer or an audit record can branch on"
    );
}

// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Lease-lifetime rows for the account strategies, moved out of the module.
use super::*;

struct NeverMints;

#[async_trait::async_trait]
impl IdentityPropagation for NeverMints {
    async fn propagate(
        &self,
        _identity: &crate::key_server::oidc::VerifiedIdentity,
        _backend: &BackendDescriptor,
    ) -> std::result::Result<super::super::PropagatedCredential, super::super::PropagationError>
    {
        unreachable!("the lifetime predicate never mints")
    }
}

/// The positive control for a mint: a strategy that always hands back a credential.
struct Mints;

#[async_trait::async_trait]
impl IdentityPropagation for Mints {
    async fn propagate(
        &self,
        _identity: &crate::key_server::oidc::VerifiedIdentity,
        _backend: &BackendDescriptor,
    ) -> std::result::Result<super::super::PropagatedCredential, super::super::PropagationError>
    {
        Ok(minted(vec![("Authorization", "Bearer minted")]))
    }
}

/// `managed: None` is the EXTERNAL shape: no lease, so the durable custody
/// half of `revalidate` is skipped and this predicate is the only thing
/// standing between a stale published expiry and the wire.
fn external(expires_at: i64, minted_at: i64) -> PreparedAccountCredential {
    PreparedAccountCredential {
        descriptor_id: "acct".to_string(),
        auth_key: "oauth:google".to_string(),
        actor_id: "actor".to_string(),
        audience: "https://partner.invalid/".to_string(),
        cache_binding: "binding".to_string(),
        expires_at,
        minted_at,
        strategy: Arc::new(NeverMints),
        managed: None,
        headers: vec![("Authorization".to_string(), "Bearer x".to_string())],
    }
}

#[test]
fn execution_context_debug_redacts_prepared_credential_headers() {
    let secrets = [
        "Bearer fixture-token-never-log-1839",
        "fixture-api-key-never-log-2940",
    ];
    let mut credential = external(1_800_000_060, 1_800_000_000);
    credential.headers = vec![
        ("Authorization".to_string(), secrets[0].to_string()),
        ("X-Api-Key".to_string(), secrets[1].to_string()),
    ];
    let context = crate::capability::CapabilityExecutionContext::default()
        .with_account_credential(Arc::new(credential));
    let output = format!("{context:?}");
    assert!(output.contains("PreparedAccountCredential"));
    assert!(output.contains("Authorization"));
    assert!(output.contains("X-Api-Key"));
    assert!(output.contains("<redacted>"));
    for secret in secrets {
        assert!(
            !output.contains(secret),
            "execution context exposed credential material"
        );
    }
}

/// THE REGRESSION, at the predicate itself. An external credential whose
/// published expiry is in the past looks exactly like `expires_at <=
/// minted_at`, which the old universal reading treated as "no lifetime
/// published" and therefore as usable.
#[test]
fn an_external_credential_with_a_past_expiry_is_closed() {
    let now = 1_800_000_000;
    assert!(
        !external(now - 3600, now).published_lifetime_open(now),
        "an external credential whose expiry has already passed must never be open"
    );
    assert!(
        !external(now, now).published_lifetime_open(now),
        "expiry exactly at now is not a lifetime an external credential may use"
    );
    assert!(
        !external(0, now).published_lifetime_open(now),
        "an external strategy publishing no usable expiry publishes no usable credential"
    );
    assert!(
        external(now + 60, now).published_lifetime_open(now),
        "an external credential inside its own published lifetime stays usable; nothing \
         here shortens it"
    );
}

fn minted(headers: Vec<(&str, &str)>) -> super::super::PropagatedCredential {
    super::super::PropagatedCredential {
        headers: headers
            .into_iter()
            .map(|(name, value)| (name.to_owned(), value.to_owned()))
            .collect(),
        expires_at: i64::MAX,
        cache_binding: "binding".to_owned(),
        subject_key: "alice".to_owned(),
        audience: "https://partner.invalid/".to_owned(),
        scopes: Vec::new(),
    }
}

async fn audited(
    logger: Option<&Arc<TransparencyLogger>>,
    required: bool,
    credential: &super::super::PropagatedCredential,
) -> Result<()> {
    AccountStrategyRegistry::validate_and_audit_mint(
        logger,
        "alice",
        "acct",
        "https://partner.invalid/",
        required,
        credential,
    )
    .await
}

/// Mutant: an empty or unparseable minted header is let through to dispatch, or
/// a required account mints without a durable audit record.
#[tokio::test]
async fn a_minted_credential_is_validated_and_audited_before_it_is_used() {
    let good = minted(vec![("Authorization", "Bearer x")]);
    assert!(matches!(
        audited(None, false, &minted(Vec::new())).await,
        Err(Error::Config(_))
    ));
    for (name, value) in [("bad name", "x"), ("Authorization", "a\nb")] {
        let refused = audited(None, false, &minted(vec![(name, value)])).await;
        assert!(
            matches!(refused, Err(Error::Config(_))),
            "{name}: {refused:?}"
        );
    }
    assert!(matches!(
        audited(None, true, &good).await,
        Err(Error::Internal(_))
    ));
    // Positive control: not required, no log configured, is a no-op success.
    audited(None, false, &good)
        .await
        .expect("no log, not required");
}

/// Mutant: an audit write that fails still releases the credential, or leaks
/// the audit error text to the caller.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_failed_mint_audit_refuses_the_credential_without_the_error_text() {
    let file = tempfile::NamedTempFile::new().expect("tempfile");
    let config = Arc::new(crate::security::transparency_log::TransparencyLogConfig {
        enabled: true,
        path: file.path().to_string_lossy().to_string(),
        key_id: "test".to_string(),
        ..crate::security::transparency_log::TransparencyLogConfig::default()
    });
    let logger = Arc::new(TransparencyLogger::open(config).expect("logger opens"));
    let good = minted(vec![("Authorization", "Bearer x")]);
    audited(Some(&logger), true, &good)
        .await
        .expect("control: a healthy log audits");

    let release = logger.stall_next_write_for_test(std::time::Duration::from_millis(200));
    let Err(Error::Internal(message)) = audited(Some(&logger), true, &good).await else {
        panic!("a stalled audit must refuse the credential");
    };
    // The whole text, so appending any of the underlying audit error fails it.
    assert_eq!(
        message,
        "identity-propagation audit unavailable for account 'acct'"
    );
    release.release();
}

fn who(subject: &str) -> crate::key_server::oidc::VerifiedIdentity {
    crate::key_server::oidc::VerifiedIdentity {
        subject: subject.to_owned(),
        email: String::new(),
        name: None,
        groups: Vec::new(),
        issuer: "https://issuer.invalid".to_owned(),
    }
}

fn installed(
    strategy: Arc<dyn IdentityPropagation>,
    provider: &str,
    audience: &str,
) -> InstalledAccount {
    InstalledAccount {
        descriptor_id: "acct".to_owned(),
        provider: provider.to_owned(),
        audience: audience.to_owned(),
        required: true,
        token_exchange_endpoint: None,
        token_exchange_scope: None,
        strategy,
        managed: None,
    }
}

async fn check(
    registry: &AccountStrategyRegistry,
    prepared: &PreparedAccountCredential,
    caller: CallerProof<'_>,
) -> Option<String> {
    registry
        .revalidate(prepared, caller)
        .await
        .err()
        .map(|error| error.to_string())
}

/// Mutant: any one of the recheck refusals removed, so a credential minted
/// under an earlier configuration, caller or lifetime reaches the wire.
#[tokio::test]
async fn revalidate_refuses_each_way_the_world_moved_since_the_mint() {
    const AUDIENCE: &str = "https://partner.invalid/";
    let alice = who("alice");
    let strategy: Arc<dyn IdentityPropagation> = Arc::new(NeverMints);
    let mut prepared = external(i64::MAX, 0);
    prepared.strategy = Arc::clone(&strategy);
    prepared.actor_id = alice.stable_actor_id();
    let registry = AccountStrategyRegistry::default();
    // `why` names the refusal that must fire, so a removed guard cannot hide
    // behind a later one refusing for its own reason.
    let refused = |outcome: Option<String>, why: &str| {
        let text = outcome.unwrap_or_else(|| panic!("{why}: must refuse"));
        assert!(text.contains("no longer validates"), "{why}: {text}");
        assert!(text.contains(why), "{why}: {text}");
    };

    refused(
        check(&registry, &prepared, CallerProof::Verified(&alice)).await,
        "no longer declared",
    );
    registry.declare("acct", "google", DescriptorMode::External);
    refused(
        check(&registry, &prepared, CallerProof::Verified(&alice)).await,
        "no account strategy is installed",
    );
    // Now an otherwise-valid world, so only the shared declaration can refuse.
    registry.install(
        installed(Arc::clone(&strategy), "google", AUDIENCE),
        DescriptorMode::External,
    );
    assert_eq!(
        check(&registry, &prepared, CallerProof::Verified(&alice)).await,
        None,
        "control: the same world revalidates while declared external"
    );
    registry.declare("acct", "google", DescriptorMode::Shared);
    refused(
        check(&registry, &prepared, CallerProof::Verified(&alice)).await,
        "declared shared",
    );
    registry.install(
        installed(Arc::clone(&strategy), "github", AUDIENCE),
        DescriptorMode::External,
    );
    refused(
        check(&registry, &prepared, CallerProof::Verified(&alice)).await,
        "provider no longer matches",
    );
    registry.install(
        installed(Arc::clone(&strategy), "google", "https://other.invalid/"),
        DescriptorMode::External,
    );
    refused(
        check(&registry, &prepared, CallerProof::Verified(&alice)).await,
        "installed audience changed",
    );
    registry.install(
        installed(Arc::new(NeverMints), "google", AUDIENCE),
        DescriptorMode::External,
    );
    refused(
        check(&registry, &prepared, CallerProof::Verified(&alice)).await,
        "strategy was replaced",
    );

    registry.install(
        installed(Arc::clone(&strategy), "google", AUDIENCE),
        DescriptorMode::External,
    );
    refused(
        check(&registry, &prepared, CallerProof::Anonymous).await,
        "no verified end-user identity",
    );
    refused(
        check(&registry, &prepared, CallerProof::Verified(&who("mallory"))).await,
        "different caller",
    );
    let mut expired = external(1, 0);
    expired.strategy = Arc::clone(&strategy);
    expired.actor_id = alice.stable_actor_id();
    refused(
        check(&registry, &expired, CallerProof::Verified(&alice)).await,
        "published lifetime has run out",
    );

    // Positive control: the unmoved world revalidates.
    assert_eq!(
        check(&registry, &prepared, CallerProof::Verified(&alice)).await,
        None
    );
}

/// Mutant: an external descriptor mints for a caller with no verified identity.
#[tokio::test]
async fn an_external_mint_needs_a_verified_caller() {
    let installed = installed(Arc::new(Mints), "google", "https://partner.invalid/");
    let backend = BackendDescriptor {
        id: "partner".to_owned(),
        audience: "https://partner.invalid/".to_owned(),
        token_exchange_endpoint: None,
        token_exchange_scope: None,
    };
    let refused =
        AccountStrategyRegistry::mint(&installed, Principal::SoleOperator, &backend).await;
    assert!(matches!(refused, Err(PropagationError::Refuse(_))));

    // Positive control: a verified caller gets the strategy's credential and
    // no managed lease, so the refusal above is the identity rule, not a
    // mint path that refuses everyone.
    let alice = who("alice");
    let (credential, lease) =
        AccountStrategyRegistry::mint(&installed, Principal::Verified(&alice), &backend)
            .await
            .expect("a verified caller mints");
    assert_eq!(credential.headers[0].1, "Bearer minted");
    assert!(lease.is_none());
}

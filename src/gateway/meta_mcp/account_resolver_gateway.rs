// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Gateway assembly for the managed-account consumer tests.
//!
//! ONE COMPILATION, ONE INSTALL, BOTH PRODUCTION. The backend configuration is
//! a real [`Config`]; `config::account_bindings::compile` resolves every
//! `backends[*].account` reference and `BoundAccountBackend::effective` produces
//! the `BackendConfig` the backend is actually constructed with; the strategy is
//! installed by `gateway::server::account_bindings::install_account_strategies`.
//! Those are the same calls the real gateway makes, with the same custody
//! erasure (`Option<&Arc<dyn AccountCustody>>`). This module compiles no managed
//! propagation config of its own and constructs no `VaultStrategy`.

use super::*;

/// How one backend in the fixture is configured.
pub(in super::super) enum Bind<'a> {
    /// `account: <descriptor id>` — the managed consumer under test. Carries NO
    /// static Authorization (`compile` refuses that pair).
    Account(&'a str),
    /// The EXISTING backend-level `identity_propagation` block, untouched by
    /// this increment, served by the process-wide signed-assertion strategy.
    /// This one DOES carry the static header, so the mixed case can assert the
    /// external route did not degrade to it either.
    Propagation(IdentityPropagationConfig),
}

/// Which descriptor ids the configuration DECLARES, and which bound backends are
/// handed to the shared installer. They are the same set everywhere except the
/// one defensive case that deliberately drives a dispatch against a registered
/// managed backend whose install never happened.
pub(in super::super) struct Descriptors<'a> {
    pub(in super::super) compiled: &'a [&'a str],
    pub(in super::super) installed: &'a [&'a str],
}

impl<'a> Descriptors<'a> {
    pub(in super::super) fn same(ids: &'a [&'a str]) -> Self {
        Self {
            compiled: ids,
            installed: ids,
        }
    }
}

/// Subject-assertion lifetime, the same 5 minutes the production install sites
/// use.
const ASSERTION_TTL_SECS: i64 = 300;

/// The `accounts` block. The store settings are SYNTHETIC and nothing here opens
/// them: `compile` and `install_account_strategies` read the `descriptors` map,
/// and the custody they are given is the separately started real fixture
/// custody. No claim is made that a gateway opened this store.
fn accounts_config(ids: &[&str]) -> AccountsConfig {
    AccountsConfig {
        adapters: Vec::new(),
        schema_version: "accounts.v1".to_string(),
        enabled: true,
        deployment: "single_process".to_string(),
        instance_id: "gateway-consumer-tests".to_string(),
        store_dir: PathBuf::from("/synthetic/fixture/accounts/records"),
        authority_dir: PathBuf::from("/synthetic/fixture/accounts/authority"),
        current_key_id: "current".to_string(),
        // Left an unresolved reference on purpose: no environment is read here.
        keys: BTreeMap::from([(
            "current".to_string(),
            "env:FIXTURE_ACCOUNT_STORE_KEY".to_string(),
        )]),
        descriptors: Some(
            ids.iter()
                .map(|id| ((*id).to_string(), descriptor(id)))
                .collect(),
        ),
        limits: AccountsLimits::default(),
    }
}

/// The real `Config` the production compilation runs against.
fn fixture_config(binds: &[(&str, Bind<'_>)], declared: &[&str]) -> Config {
    let mut backends = HashMap::new();
    for (name, bind) in binds {
        let mut config = BackendConfig {
            enabled: true,
            transport: TransportConfig::Http {
                http_url: format!("https://{name}.invalid/mcp"),
                streamable_http: true,
                protocol_version: None,
            },
            ..BackendConfig::default()
        };
        match bind {
            Bind::Account(id) => config.account = Some((*id).to_string()),
            Bind::Propagation(idp) => {
                config.identity_propagation = Some(idp.clone());
                config
                    .headers
                    .insert("Authorization".to_string(), STATIC_FALLBACK.to_string());
            }
        }
        backends.insert((*name).to_string(), config);
    }
    Config {
        backends,
        accounts: Some(accounts_config(declared)),
        ..Config::default()
    }
}

/// The configuration the SHARED INSTALLER is given. Identical to the compiled
/// one except that a managed backend whose descriptor id is not in `installed`
/// is absent from `backends`, which is exactly what a reload that dropped a
/// backend between compilation and installation leaves behind.
fn installer_config(config: &Config, installed: &[&str]) -> Config {
    let mut config = config.clone();
    config.backends.retain(|_, backend| {
        backend
            .account
            .as_deref()
            .is_none_or(|id| installed.contains(&id))
    });
    config
}

/// A durable audit sink. A managed backend compiles to `required: true`, and the
/// MIK-6740 guard aborts a required mint with no transparency log, so every
/// managed fixture needs one. Leaked for the process, as the existing
/// propagation fixtures do.
fn leaked_transparency_logger() -> Arc<crate::security::TransparencyLogger> {
    use crate::security::TransparencyLogger;
    use crate::security::transparency_log::TransparencyLogConfig;

    let file = tempfile::NamedTempFile::new().expect("tempfile");
    let path = file.path().to_string_lossy().to_string();
    std::mem::forget(file);
    Arc::new(
        TransparencyLogger::open(Arc::new(TransparencyLogConfig {
            enabled: true,
            path,
            key_id: "test".to_string(),
            shared_secret: String::new(),
        }))
        .expect("logger opens"),
    )
}

/// Build the gateway under test: header/identity-capturing HTTP backends built
/// from the EFFECTIVE compiled configuration, and strategies installed through
/// the SAME production helper `Gateway::start` uses.
///
/// `identity_slots` pre-seeds the per-user transport slots a
/// `SessionMode::PerUser` backend selects (`Backend::pool_key_for`), so a
/// per-user dispatch reaches the capturing transport instead of opening a real
/// HTTP session. Both the seeded and the refreshed revision of each binding are
/// seeded, so a refresh happens inside `execute` rather than being pre-resolved
/// by setup. The shared slot is seeded too; the identity-key assertions in the
/// tests are what pin the binding.
pub(in super::super) fn gateway(
    binds: &[(&str, Bind<'_>)],
    descriptors: &Descriptors<'_>,
    custody: &Arc<dyn AccountCustody>,
    identity_slots: &[String],
) -> (MetaMcp, Arc<Dispatches>) {
    let config = fixture_config(binds, descriptors.compiled);
    // The production compilation, refusals included: an invalid fixture
    // configuration fails HERE rather than reaching a dispatch assertion.
    let bound = compile(&config).expect("fixture configuration must compile");

    let registry = Arc::new(BackendRegistry::new());
    let dispatches = Arc::new(Dispatches::default());
    let mut global_minting = false;

    for (name, bind) in binds {
        let declared = config
            .backends
            .get(*name)
            .expect("every bind is in the fixture configuration")
            .clone();
        // The effective configuration a bound consumer runs with — compiled
        // propagation applied and the backend's own OAuth block dropped — comes
        // from the production `BoundAccountBackend::effective`.
        let effective = bound
            .get(*name)
            .map_or_else(|| declared.clone(), |bound| bound.effective(&declared));
        global_minting |= matches!(bind, Bind::Propagation(_));

        let backend = Arc::new(Backend::new(
            name,
            effective,
            &crate::config::FailsafeConfig::default(),
            std::time::Duration::from_secs(60),
        ));
        let transport = Arc::new(CapturingTransport {
            dispatches: Arc::clone(&dispatches),
        });
        backend
            .set_transport_for_test(Arc::clone(&transport) as Arc<dyn crate::transport::Transport>);
        for binding in identity_slots {
            backend.set_pooled_transport_for_test(
                &PoolKey::PerUser {
                    binding: binding.clone(),
                },
                Arc::clone(&transport) as Arc<dyn crate::transport::Transport>,
            );
        }
        assert!(registry.register(backend), "fixture registry must accept");
    }

    let mut meta = MetaMcp::new(registry);
    meta.enable_transparency_log(leaked_transparency_logger());
    let gateway_key = Arc::new(GatewayKeyPair::generate().expect("keygen"));

    // The EXISTING process-wide install for legacy external control, unchanged:
    // the account installer handles the managed backends and adds no second
    // pipeline beside it.
    if global_minting {
        meta.set_identity_propagation(Arc::new(
            crate::identity_propagation::SignedAssertionStrategy::new(
                Arc::clone(&gateway_key),
                ASSERTION_TTL_SECS,
            ),
        ));
    }

    install_account_strategies(
        &installer_config(&config, descriptors.installed),
        Some(custody),
        &gateway_key,
        &meta,
    )
    .expect("the shared installer must accept the fixture configuration");
    (meta, dispatches)
}

/// The permissive authorizer the dispatch entry needs.
static ALLOW_ALL: crate::gateway::authz::AllowAll = crate::gateway::authz::AllowAll;

fn caller(verified_identity: Option<&VerifiedIdentity>) -> MetaMcpCallerContext<'_> {
    MetaMcpCallerContext {
        task: None,
        signing: None,
        execution: None,
        credential_principal: None,
        is_modern: false,
        protocol_revision: Some(crate::protocol::PROTOCOL_VERSION),
        authorizer: &ALLOW_ALL,
        verified_identity,
        api_key_name: None,
        agent_id: None,
        grant_subject: None,
        is_admin: false,
        input_capabilities: crate::protocol::meta::Declared::NONE,
        retry: &crate::protocol::mrtr::NO_RETRY,
        confirmation: crate::gateway::destructive_confirmation::ConfirmationChannel::Unavailable,
        era: crate::protocol::meta::Era::Legacy,
        channel: &crate::gateway::input_bridge::NoClientChannel,
    }
}

/// THE action under test: the real Code Mode dispatch entry, which routes
/// through `invoke_tool` and the single identity gate exactly as production
/// traffic does. Every case uses this one entry, refusals included.
pub(in super::super) async fn execute(
    meta: &MetaMcp,
    server: &str,
    caller_identity: Option<&VerifiedIdentity>,
) -> crate::Result<Value> {
    let context = caller(caller_identity);
    // ONE tool and ONE argument set for every principal: identical requests are
    // what make a crossed cache entry observable.
    let args = json!({ "tool": format!("{server}:read"), "arguments": { "folder": "inbox" } });
    meta.code_mode_execute(&args, Some("fixture-session"), &context)
        .await
}

/// Per-user pool slots for each `(subject, descriptor)` pair, at BOTH the seeded
/// and the refreshed token revision. The authority-bearing binding changes when
/// a refresh commits, so seeding only the seeded revision would make the refresh
/// case fail on a missing slot rather than on its credential.
pub(in super::super) fn slots(pairs: &[(&str, &str)]) -> Vec<String> {
    pairs
        .iter()
        .flat_map(|(subject, id)| {
            [
                expected_identity_key(subject, id, SEEDED_REVISION),
                expected_identity_key(subject, id, REFRESHED_REVISION),
            ]
        })
        .collect()
}

/// The legacy external-control propagation block a non-managed backend declares.
pub(in super::super) fn external_cfg() -> IdentityPropagationConfig {
    IdentityPropagationConfig {
        strategy: PropagationStrategyKind::SignedAssertion,
        audience: "https://partner.invalid/".to_string(),
        required: true,
        session_mode: crate::identity_propagation::SessionMode::Stateless,
        token_exchange_endpoint: None,
        token_exchange_scope: None,
    }
}

/// SHARED IS THE UNCHANGED PATH. An explicitly `shared` descriptor names an
/// account the deployment already serves statically: `compile` produces no
/// propagation, `install_account_strategies` installs nothing (custody `None`
/// is accepted, not refused), and the production `effective()` clears the
/// `account` reference so the backend runs the legacy static configuration.
/// The reference is retained in the raw `Config` — asserted positively below —
/// so a round trip still shows what the operator wrote.
///
/// FALSIFIER. A vendor `effective()` without the shared clear leaves
/// `account` set on the running backend; actual dispatch is then refused.
#[tokio::test]
async fn account_shared_descriptor_dispatches_legacy_without_identity_or_custody() {
    let name = "shared-backend";
    let mut config = fixture_config(&[(name, Bind::Account(WORK))], &[WORK]);
    {
        let accounts = config.accounts.as_mut().expect("fixture declares accounts");
        let descriptors = accounts
            .descriptors
            .as_mut()
            .expect("fixture declares descriptors");
        let descriptor = descriptors
            .get_mut(WORK)
            .expect("the fixture declared this descriptor id");
        // The ONLY edit: the declared mode. `compile` requires nothing further
        // of a shared descriptor (it matches on mode and returns `(None, None)`
        // before reading any managed field), and `external_strategy` is already
        // `None`, so no managed-only field is silently repurposed here.
        descriptor.mode = DescriptorMode::Shared;
    }

    // POSITIVE: the raw configuration keeps the reference the operator wrote.
    assert_eq!(
        config.backends[name].account.as_deref(),
        Some(WORK),
        "the declared account reference must survive in the raw Config"
    );

    let bound = compile(&config).expect("a shared binding must compile");
    let binding = bound.get(name).expect("the shared backend is bound");
    assert!(
        binding.propagation.is_none(),
        "shared compiles to no propagation: existing static behaviour, unchanged"
    );
    let declared = config.backends[name].clone();
    // NOT cleared by hand: this is the production supervisor correction.
    let effective = binding.effective(&declared);

    let registry = Arc::new(BackendRegistry::new());
    let dispatches = Arc::new(Dispatches::default());
    let backend = Arc::new(Backend::new(
        name,
        effective,
        &crate::config::FailsafeConfig::default(),
        std::time::Duration::from_secs(60),
    ));
    backend.set_transport_for_test(Arc::new(CapturingTransport {
        dispatches: Arc::clone(&dispatches),
    }) as Arc<dyn crate::transport::Transport>);
    assert!(registry.register(backend), "fixture registry must accept");

    let mut meta = MetaMcp::new(registry);
    meta.enable_transparency_log(leaked_transparency_logger());
    let gateway_key = Arc::new(GatewayKeyPair::generate().expect("keygen"));
    // THE SAME production installer, with NO custody: shared must not refuse.
    install_account_strategies(&config, None, &gateway_key, &meta)
        .expect("a shared binding must install with no custody");

    // THE SAME production dispatch entry, with NO verified identity.
    let result = execute(&meta, name, None)
        .await
        .expect("shared dispatch must succeed for an unidentified caller");
    assert!(
        result.to_string().contains("ok"),
        "the backend result must be returned to the caller: {result}"
    );

    assert_eq!(dispatches.count(), 1, "exactly one backend call");
    let call = dispatches.only();
    assert!(
        call.identity_key.is_none(),
        "shared must not bind a per-user pool slot: {:?}",
        call.identity_key
    );
    assert!(
        call.authorization().is_none(),
        "shared must mint no Authorization: {:?}",
        call.authorization()
    );
}

#[path = "account_raw_vault_tests.rs"]
mod raw_vault;

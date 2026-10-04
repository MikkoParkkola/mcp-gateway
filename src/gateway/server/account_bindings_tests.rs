// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Table tests on [`super::sole_operator_asserted`]: stdio always serves its
//! local operator; HTTP only when every single-user term holds, each HTTP
//! exclusion varied on its own from an otherwise eligible configuration.

use super::{ServeMode, sole_operator_asserted};
use crate::config::{ApiKeyConfig, AuthConfig, Config, KeyServerConfig, KeyServerProviderConfig};
use crate::personal_accounts::config::{AccountsConfig, AccountsLimits, AdapterConfig};

/// A named API key with every other field at its zero value.
fn api_key(name: &str) -> ApiKeyConfig {
    ApiKeyConfig {
        key: None,
        key_sha256: None,
        expires_at: None,
        name: name.to_string(),
        rate_limit: 0,
        backends: Vec::new(),
        allowed_tools: None,
        denied_tools: None,
        admin: false,
        kind: crate::config::ApiKeyKind::Shared,
    }
}

/// A minimal issuer entry; only its presence in `oidc` matters here.
fn oidc_issuer(issuer: &str) -> KeyServerProviderConfig {
    KeyServerProviderConfig {
        issuer: issuer.to_string(),
        jwks_uri: None,
        discovery_url: None,
        auto_discover: true,
        audiences: Vec::new(),
        allowed_domains: Vec::new(),
    }
}

/// The `accounts` block declaring exactly one adapter, otherwise the same
/// synthetic shape the `meta_mcp` fixtures use.
fn accounts_with_one_adapter() -> AccountsConfig {
    AccountsConfig {
        schema_version: "accounts.v1".to_string(),
        enabled: true,
        deployment: "single_process".to_string(),
        instance_id: "account-bindings-tests".to_string(),
        store_dir: "/synthetic/fixture/accounts/records".into(),
        authority_dir: "/synthetic/fixture/accounts/authority".into(),
        current_key_id: "current".to_string(),
        keys: std::collections::BTreeMap::from([(
            "current".to_string(),
            "env:FIXTURE_ACCOUNT_STORE_KEY".to_string(),
        )]),
        descriptors: None,
        limits: AccountsLimits::default(),
        adapters: vec![AdapterConfig::for_test("webui")],
        hosted: None,
    }
}

/// Auth enabled, declared single-user, one API key, no OIDC — the base
/// eligible-for-sole-operator shape every exclusion row starts from.
fn eligible_auth(api_keys: Vec<ApiKeyConfig>) -> AuthConfig {
    AuthConfig {
        enabled: true,
        bearer_token: None,
        api_keys,
        public_paths: vec!["/health".to_string()],
        client_circuit_breaker: None,
        single_user: true,
        dashboard_session: crate::config::DashboardSessionConfig::default(),
    }
}

/// One assertion per table row: `sole_operator_asserted(&config, mode)` must
/// equal `expected`, with the row's own name in the failure message.
fn assert_row(row: &str, config: &Config, mode: ServeMode, expected: bool) {
    assert_eq!(
        sole_operator_asserted(config, mode),
        expected,
        "row `{row}` ({mode:?}): expected sole_operator_asserted == {expected}"
    );
}

// ── Stdio: today's predicate must not carry over unconditionally ──────────

#[test]
fn stdio_auth_disabled_is_sole_operator() {
    let config = Config {
        auth: AuthConfig {
            enabled: false,
            ..eligible_auth(vec![api_key("only")])
        },
        ..Config::default()
    };
    assert_row("stdio: auth off", &config, ServeMode::Stdio, true);
}

#[test]
fn stdio_multiple_api_keys_is_sole_operator() {
    let config = Config {
        auth: eligible_auth(vec![api_key("a"), api_key("b")]),
        ..Config::default()
    };
    assert_row("stdio: multi-key", &config, ServeMode::Stdio, true);
}

#[test]
fn stdio_oidc_issuer_is_sole_operator() {
    let config = Config {
        auth: eligible_auth(vec![api_key("only")]),
        key_server: KeyServerConfig {
            oidc: vec![oidc_issuer("https://issuer.example.test")],
            ..Config::default().key_server
        },
        ..Config::default()
    };
    assert_row("stdio: OIDC issuer", &config, ServeMode::Stdio, true);
}

#[test]
fn stdio_identity_adapter_is_sole_operator() {
    let config = Config {
        auth: eligible_auth(vec![api_key("only")]),
        accounts: Some(accounts_with_one_adapter()),
        ..Config::default()
    };
    assert_row("stdio: identity adapter", &config, ServeMode::Stdio, true);
}

// ── HTTP: the eligible base and its zero-key variant ───────────────────────

#[test]
fn http_eligible_base_is_sole_operator() {
    let config = Config {
        auth: eligible_auth(vec![api_key("only")]),
        ..Config::default()
    };
    assert_row("http: eligible base", &config, ServeMode::Http, true);
}

#[test]
fn http_zero_api_keys_is_sole_operator() {
    let config = Config {
        auth: eligible_auth(Vec::new()),
        ..Config::default()
    };
    assert_row("http: zero keys", &config, ServeMode::Http, true);
}

// ── HTTP: the eligible base with exactly one exclusion ─────────────────────

#[test]
fn http_auth_disabled_is_not_sole_operator() {
    let config = Config {
        auth: AuthConfig {
            enabled: false,
            ..eligible_auth(vec![api_key("only")])
        },
        ..Config::default()
    };
    assert_row("http: auth disabled", &config, ServeMode::Http, false);
}

#[test]
fn http_single_user_false_is_not_sole_operator() {
    let config = Config {
        auth: AuthConfig {
            single_user: false,
            ..eligible_auth(vec![api_key("only")])
        },
        ..Config::default()
    };
    assert_row("http: single_user=false", &config, ServeMode::Http, false);
}

#[test]
fn http_bearer_only_is_sole_operator() {
    let config = Config {
        auth: AuthConfig {
            bearer_token: Some("operator-token".to_string()),
            ..eligible_auth(Vec::new())
        },
        ..Config::default()
    };
    assert_row("http: bearer only", &config, ServeMode::Http, true);
}

/// #2241: the bearer and one key are two credentials.
#[test]
fn http_bearer_plus_one_key_is_not_sole_operator() {
    let config = Config {
        auth: AuthConfig {
            bearer_token: Some("operator-token".to_string()),
            ..eligible_auth(vec![api_key("client")])
        },
        ..Config::default()
    };
    assert_row("http: bearer + one key", &config, ServeMode::Http, false);
}

#[test]
fn http_two_api_keys_is_not_sole_operator() {
    let config = Config {
        auth: eligible_auth(vec![api_key("a"), api_key("b")]),
        ..Config::default()
    };
    assert_row("http: two keys", &config, ServeMode::Http, false);
}

#[test]
fn http_oidc_issuer_is_not_sole_operator() {
    let config = Config {
        auth: eligible_auth(vec![api_key("only")]),
        key_server: KeyServerConfig {
            oidc: vec![oidc_issuer("https://issuer.example.test")],
            ..Config::default().key_server
        },
        ..Config::default()
    };
    assert_row("http: one OIDC issuer", &config, ServeMode::Http, false);
}

#[test]
fn http_identity_adapter_is_not_sole_operator() {
    let config = Config {
        auth: eligible_auth(vec![api_key("only")]),
        accounts: Some(accounts_with_one_adapter()),
        ..Config::default()
    };
    assert_row(
        "http: one identity adapter",
        &config,
        ServeMode::Http,
        false,
    );
}

fn bound_config(enabled: bool) -> Config {
    let yaml = format!(
        "backends:\n  mail:\n    http_url: https://backend.fixture.test/mcp\n    enabled: {enabled}\n    \
         account: work\n\
         accounts:\n  schema_version: accounts.v1\n  enabled: true\n  deployment: single_process\n  \
         instance_id: unit\n  store_dir: /unused/store\n  authority_dir: /unused/authority\n  \
         current_key_id: primary\n  keys:\n    primary: env:UNUSED\n  descriptors:\n    \
         work:\n      mode: personal_managed\n      provider: fixture\n      \
         resource: https://api.fixture.test/\n      issuer: https://issuer.fixture.test\n      \
         authorization_endpoint: https://issuer.fixture.test/authorize\n      \
         token_endpoint: https://issuer.fixture.test/token\n      client_id: fixture-client\n      \
         redirect_uri: https://gateway.fixture.test/callback\n      \
         scopes: [read]\n      send_resource_parameter: true\n"
    );
    serde_yaml::from_str(&yaml).expect("config parses")
}

fn install(config: &Config) -> crate::Result<()> {
    let registry = std::sync::Arc::new(crate::backend::BackendRegistry::new());
    let meta = crate::gateway::meta_mcp::MetaMcp::new(registry);
    let keys = std::sync::Arc::new(
        crate::gateway::oauth::jwks::GatewayKeyPair::generate().expect("a key pair"),
    );
    super::install_account_strategies(config, None, &keys, &meta, ServeMode::Http)
}

/// Mutant: an enabled managed binding with no custody installs nothing and
/// the backend is later served as though it were a shared one.
#[test]
fn a_managed_binding_with_no_custody_is_refused_not_installed_empty() {
    let error = install(&bound_config(true)).expect_err("no custody must refuse");
    let text = error.to_string();
    assert!(text.contains("no account custody was started"), "{text}");
    assert!(text.contains("'mail'") && text.contains("'work'"), "{text}");
}

/// Mutant: a disabled backend's binding is held to the custody check, or has a
/// strategy bound to something that cannot be dispatched to.
#[test]
fn a_disabled_backend_binding_is_skipped() {
    install(&bound_config(false)).expect("a disabled backend has nothing to install");
}

/// A binding to an external descriptor whose strategy mints nothing. Config
/// load refuses it (`external_strategy` admits only the two minting
/// strategies), so it is built here without load validation, as a reload
/// path that skipped it would. Mutant: the refusal dropped, so a `required`
/// binding installs nothing and is first discovered at dispatch.
#[test]
fn a_binding_to_a_strategy_that_mints_nothing_is_refused_at_install() {
    let config: Config = serde_yaml::from_str(
        r"
accounts:
  schema_version: accounts.v1
  deployment: single_process
  instance_id: unit
  store_dir: /unused/store
  authority_dir: /unused/authority
  current_key_id: primary
  keys:
    primary: env:UNUSED
  descriptors:
    partner-api:
      mode: external
      provider: partner
      resource: https://external.example.invalid/
      issuer: https://issuer.example.invalid
      external_strategy:
        strategy: passthrough
        audience: https://external.example.invalid/
        session_mode: stateless
        required: true
backends:
  partner:
    http_url: https://backend.example.invalid/mcp
    account: partner-api
",
    )
    .expect("the fixture parses without load validation");
    let meta = crate::gateway::meta_mcp::MetaMcp::new(std::sync::Arc::new(
        crate::backend::BackendRegistry::new(),
    ));
    let key =
        std::sync::Arc::new(crate::gateway::oauth::GatewayKeyPair::generate().expect("keygen"));

    let refused = super::install_account_strategies(&config, None, &key, &meta, ServeMode::Http)
        .expect_err("a binding that mints nothing must refuse");

    let text = refused.to_string();
    assert!(text.contains("mints no credential"), "{text}");
    assert!(text.contains("'partner'"), "{text}");
    assert!(meta.account_strategies().installed("partner-api").is_none());
}

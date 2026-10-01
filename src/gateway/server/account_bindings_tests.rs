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

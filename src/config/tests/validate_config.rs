// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! `Config::validate`, remote provenance and identity propagation.

use super::*;

// ── Config::validate — gateway.yaml validation (T5.10) ───────────────────────

#[test]
fn validate_default_config_passes() {
    // GIVEN: a default config (no backends, default port)
    // WHEN: validate is called
    // THEN: succeeds without error
    let config = Config::default();
    assert!(config.validate().is_ok());
}

#[test]
fn validate_rejects_missing_env_backed_auth_secret() {
    let config = Config {
        auth: AuthConfig {
            enabled: true,
            bearer_token: Some("env:MCP_GATEWAY_TEST_SECRET_SHOULD_NOT_EXIST".to_string()),
            ..AuthConfig::default()
        },
        ..Config::default()
    };

    let result = config.validate();

    assert!(matches!(result, Err(crate::Error::ConfigValidation(_))));
    assert!(
        result
            .unwrap_err()
            .to_string()
            .contains("MCP_GATEWAY_TEST_SECRET_SHOULD_NOT_EXIST")
    );
}

#[test]
fn validate_rejects_empty_backend_name() {
    // GIVEN: a config with an empty backend name
    let mut config = Config::default();
    config
        .backends
        .insert(String::new(), BackendConfig::default());
    // WHEN: validate is called
    let result = config.validate();
    // THEN: returns ConfigValidation error
    assert!(matches!(result, Err(crate::Error::ConfigValidation(_))));
    let msg = result.unwrap_err().to_string();
    assert!(msg.contains("empty"), "error should mention 'empty': {msg}");
}

#[test]
fn validate_rejects_backend_name_with_slash() {
    // GIVEN: a backend name containing a slash
    let mut config = Config::default();
    config
        .backends
        .insert("a/b".to_string(), BackendConfig::default());
    // WHEN: validate is called
    let result = config.validate();
    // THEN: returns ConfigValidation error mentioning the invalid char
    assert!(matches!(result, Err(crate::Error::ConfigValidation(_))));
    let msg = result.unwrap_err().to_string();
    assert!(msg.contains("a/b"), "error should include name: {msg}");
}

#[test]
fn validate_rejects_invalid_http_url() {
    // GIVEN: a backend with a malformed http_url
    let mut config = Config::default();
    config.backends.insert(
        "my_backend".to_string(),
        BackendConfig {
            transport: TransportConfig::Http {
                http_url: "not a url!@#".to_string(),
                streamable_http: false,
                protocol_version: None,
            },
            ..BackendConfig::default()
        },
    );
    // WHEN: validate is called
    let result = config.validate();
    // THEN: returns ConfigValidation error
    assert!(matches!(result, Err(crate::Error::ConfigValidation(_))));
}

#[test]
fn validate_rejects_empty_http_url() {
    // GIVEN: a backend with an empty http_url
    let mut config = Config::default();
    config.backends.insert(
        "my_backend".to_string(),
        BackendConfig {
            transport: TransportConfig::Http {
                http_url: String::new(),
                streamable_http: false,
                protocol_version: None,
            },
            ..BackendConfig::default()
        },
    );
    // WHEN: validate is called
    let result = config.validate();
    // THEN: returns ConfigValidation error
    assert!(matches!(result, Err(crate::Error::ConfigValidation(_))));
}

#[test]
fn validate_accepts_valid_http_backend() {
    // GIVEN: a backend with a valid http_url
    let mut config = Config::default();
    config.backends.insert(
        "my_backend".to_string(),
        BackendConfig {
            transport: TransportConfig::Http {
                http_url: "http://localhost:3000/mcp".to_string(),
                streamable_http: false,
                protocol_version: None,
            },
            ..BackendConfig::default()
        },
    );
    // WHEN: validate is called
    // THEN: succeeds
    assert!(config.validate().is_ok());
}

#[test]
fn validate_accepts_stdio_backend_without_url() {
    // GIVEN: a stdio backend (no http_url)
    let mut config = Config::default();
    config.backends.insert(
        "my_backend".to_string(),
        BackendConfig {
            transport: TransportConfig::Stdio {
                command: "my-server".to_string(),
                cwd: None,
                protocol_version: None,
            },
            ..BackendConfig::default()
        },
    );
    // WHEN: validate is called
    // THEN: succeeds (stdio has no URL to validate)
    assert!(config.validate().is_ok());
}

#[test]
fn config_load_rejects_invalid_http_url_from_yaml() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("gateway.yaml");
    write_owner_only(
        &path,
        r#"
backends:
  invalid_backend:
    http_url: "not a url"
"#,
    )
    .unwrap();

    let result = Config::load(Some(&path));

    assert!(matches!(result, Err(crate::Error::ConfigValidation(_))));
}

fn signed_remote_provenance_yaml() -> String {
    r#"
security:
  remote_server_signing:
    require_for_remote_backends: true
    trusted_keys:
      unit-test-key:
        algorithm: ed25519
        public_key: A6EHv/POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg=
    backends:
      signed_remote:
        subject: spiffe://example.test/mcp/signed
        issuer: unit-test
        issued_at: "2026-05-06T00:00:00Z"
        key_id: unit-test-key
        signature: st40TAeoj8K682cMoCIvE8Rr6C0HkvMVWJbZQvFWK2aNENh088ucj9smNr1WV0s7RgUuQFkePsiWKMjsYYhNCQ==
backends:
  signed_remote:
    http_url: https://signed.example.com/mcp
    streamable_http: true
"#
    .to_string()
}

#[test]
fn validate_accepts_signed_remote_backend_provenance() {
    let config: Config = serde_yaml::from_str(&signed_remote_provenance_yaml()).unwrap();

    assert!(config.validate().is_ok());
}

#[test]
fn config_parses_context_integrity_team_shared_preset() {
    let yaml = r"
security:
  context_integrity:
    preset: team_shared
";
    let config: Config = serde_yaml::from_str(yaml).unwrap();

    assert_eq!(
        config.security.context_integrity.preset,
        crate::config::ContextIntegrityPresetConfig::TeamShared
    );
    assert_eq!(
        config.security.context_integrity.license_tier(),
        "free_core"
    );
    assert_eq!(
        config.security.context_integrity.policy().mode,
        crate::context_integrity::ContextIntegrityPolicyMode::Enforce
    );
}

#[test]
fn validate_rejects_required_remote_backend_without_provenance() {
    let yaml = r"
security:
  remote_server_signing:
    require_for_remote_backends: true
    trusted_keys:
      unit-test-key:
        algorithm: ed25519
        public_key: A6EHv/POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg=
backends:
  unsigned_remote:
    http_url: https://unsigned.example.com/mcp
    streamable_http: true
";
    let config: Config = serde_yaml::from_str(yaml).unwrap();

    let result = config.validate();

    assert!(matches!(result, Err(crate::Error::ConfigValidation(_))));
    let msg = result.unwrap_err().to_string();
    assert!(
        msg.contains("unsigned_remote") && msg.contains("provenance"),
        "error should name the backend and provenance boundary: {msg}"
    );
}

#[test]
fn validate_rejects_tampered_remote_backend_provenance_signature() {
    let yaml = signed_remote_provenance_yaml().replace(
        "https://signed.example.com/mcp",
        "https://tampered.example.com/mcp",
    );
    let config: Config = serde_yaml::from_str(&yaml).unwrap();

    let result = config.validate();

    assert!(matches!(result, Err(crate::Error::ConfigValidation(_))));
    let msg = result.unwrap_err().to_string();
    assert!(
        msg.contains("signed_remote") && msg.contains("signature"),
        "error should name the backend and invalid signature: {msg}"
    );
}

// ── MIK-6728 slice 2a: identity_propagation config validation (fail-closed) ──

use crate::identity_propagation::{
    IdentityPropagationConfig, PropagationStrategyKind, SessionMode,
};

fn backend_with_idp(idp: IdentityPropagationConfig) -> BackendConfig {
    BackendConfig {
        transport: TransportConfig::Http {
            http_url: "https://backend.internal/mcp".to_string(),
            streamable_http: false,
            protocol_version: None,
        },
        identity_propagation: Some(idp),
        ..BackendConfig::default()
    }
}

fn oauth_cfg(enabled: bool) -> OAuthConfig {
    OAuthConfig {
        enabled,
        scopes: vec![],
        client_id: None,
        client_secret: None,
        callback_host: None,
        callback_port: None,
        callback_path: None,
        token_refresh_buffer_secs: 300,
        shared_account: false,
    }
}

#[test]
fn validate_accepts_stateless_signed_assertion_backend() {
    let mut config = Config::default();
    config.backends.insert(
        "memory".to_string(),
        backend_with_idp(IdentityPropagationConfig {
            strategy: PropagationStrategyKind::SignedAssertion,
            audience: "https://memory.internal".to_string(),
            required: true,
            session_mode: SessionMode::Stateless,
            token_exchange_endpoint: None,
            token_exchange_scope: None,
        }),
    );
    assert!(
        config.validate().is_ok(),
        "stateless signed-assertion must validate"
    );
}

#[test]
fn validate_accepts_per_user_session_mode_now_that_pool_ships() {
    // MIK-6735: the per-user transport pool gives each caller its own
    // transport/session, so per_user validates rather than being rejected.
    let mut config = Config::default();
    config.backends.insert(
        "mem".to_string(),
        backend_with_idp(IdentityPropagationConfig {
            strategy: PropagationStrategyKind::SignedAssertion,
            audience: "https://mem".to_string(),
            required: true,
            session_mode: SessionMode::PerUser,
            token_exchange_endpoint: None,
            token_exchange_scope: None,
        }),
    );
    assert!(
        config.validate().is_ok(),
        "per_user must validate now that the transport pool ships (MIK-6735)"
    );
}

#[test]
fn validate_rejects_identity_propagation_on_non_http_transport() {
    // IDP.2: stdio/websocket transports silently drop per-request headers, so a
    // propagation-configured non-HTTP backend must fail closed at load rather
    // than dispatch without the credential (MIK-6734 review finding).
    let mut config = Config::default();
    let mut backend = backend_with_idp(IdentityPropagationConfig {
        strategy: PropagationStrategyKind::SignedAssertion,
        audience: "https://mem".to_string(),
        required: true,
        session_mode: SessionMode::Stateless,
        token_exchange_endpoint: None,
        token_exchange_scope: None,
    });
    backend.transport = TransportConfig::Stdio {
        command: "echo".to_string(),
        cwd: None,
        protocol_version: None,
    };
    config.backends.insert("mem".to_string(), backend);
    let err = config.validate().unwrap_err().to_string();
    assert!(
        err.contains("http transport"),
        "error should require http transport: {err}"
    );
}

#[test]
fn validate_rejects_empty_audience_backend() {
    // IDP.3: empty audience defeats isolation; fail closed at load.
    let mut config = Config::default();
    config.backends.insert(
        "b".to_string(),
        backend_with_idp(IdentityPropagationConfig {
            strategy: PropagationStrategyKind::SignedAssertion,
            audience: String::new(),
            required: true,
            session_mode: SessionMode::Stateless,
            token_exchange_endpoint: None,
            token_exchange_scope: None,
        }),
    );
    assert!(matches!(
        config.validate(),
        Err(crate::Error::ConfigValidation(_))
    ));
}

#[test]
fn validate_rejects_required_unimplemented_strategy() {
    // IDP.2: a required backend on an unimplemented strategy (vault, MIK-6730
    // is not yet built) must not silently run without propagation.
    let mut config = Config::default();
    config.backends.insert(
        "b".to_string(),
        backend_with_idp(IdentityPropagationConfig {
            strategy: PropagationStrategyKind::Vault,
            audience: "https://mail".to_string(),
            required: true,
            session_mode: SessionMode::Stateless,
            token_exchange_endpoint: None,
            token_exchange_scope: None,
        }),
    );
    assert!(config.validate().is_err());
}

// MIK-6729 — token_exchange required with no endpoint is rejected at the full
// Config::validate() level (not just IdentityPropagationConfig::validate()
// in isolation), the same fail-closed path a real config-load would hit.
#[test]
fn validate_rejects_token_exchange_without_endpoint() {
    let mut config = Config::default();
    config.backends.insert(
        "mail".to_string(),
        backend_with_idp(IdentityPropagationConfig {
            strategy: PropagationStrategyKind::TokenExchange,
            audience: "https://mail".to_string(),
            required: true,
            session_mode: SessionMode::Stateless,
            token_exchange_endpoint: None,
            token_exchange_scope: None,
        }),
    );
    let err = config.validate().unwrap_err().to_string();
    assert!(
        err.contains("token_exchange_endpoint"),
        "error should name the missing field: {err}"
    );
}

// MIK-6729 — a properly-configured token_exchange backend validates cleanly
// end-to-end (audience, endpoint, http transport, stateless session).
#[test]
fn validate_accepts_properly_configured_token_exchange_backend() {
    let mut config = Config::default();
    config.backends.insert(
        "mail".to_string(),
        backend_with_idp(IdentityPropagationConfig {
            strategy: PropagationStrategyKind::TokenExchange,
            audience: "https://mail".to_string(),
            required: true,
            session_mode: SessionMode::Stateless,
            token_exchange_endpoint: Some("https://idp.internal/token".to_string()),
            token_exchange_scope: Some("mail.read".to_string()),
        }),
    );
    assert!(
        config.validate().is_ok(),
        "properly-configured token_exchange backend must validate"
    );
}

#[test]
fn validate_backend_without_idp_is_unchanged() {
    // IDP.5: absent config keeps today's behavior — default config validates.
    let config = Config::default();
    assert!(config.validate().is_ok());
}

#[test]
fn validate_rejects_identity_propagation_with_enabled_backend_oauth() {
    // F3: a backend running its own enabled oauth client persists a gateway-held
    // token during initialize(), authenticating the transport session as the
    // gateway before the per-request credential override — silently defeating
    // per-user propagation. The pairing must fail closed at load.
    let mut config = Config::default();
    let mut backend = backend_with_idp(IdentityPropagationConfig {
        strategy: PropagationStrategyKind::SignedAssertion,
        audience: "https://mem".to_string(),
        required: true,
        session_mode: SessionMode::Stateless,
        token_exchange_endpoint: None,
        token_exchange_scope: None,
    });
    backend.oauth = Some(oauth_cfg(true));
    config.backends.insert("mem".to_string(), backend);
    let err = config.validate().unwrap_err().to_string();
    assert!(
        err.contains("oauth"),
        "error should name the oauth co-config conflict: {err}"
    );
    assert!(err.contains("mem"), "error should name the backend: {err}");
}

#[test]
fn validate_accepts_identity_propagation_with_disabled_backend_oauth() {
    // A disabled backend oauth client never runs its authorize flow, so it
    // cannot persist a gateway-held token — the F3 conflict does not apply and
    // the propagation backend must still validate.
    let mut config = Config::default();
    let mut backend = backend_with_idp(IdentityPropagationConfig {
        strategy: PropagationStrategyKind::SignedAssertion,
        audience: "https://mem".to_string(),
        required: true,
        session_mode: SessionMode::Stateless,
        token_exchange_endpoint: None,
        token_exchange_scope: None,
    });
    backend.oauth = Some(oauth_cfg(false));
    config.backends.insert("mem".to_string(), backend);
    assert!(
        config.validate().is_ok(),
        "disabled backend oauth must not trip the F3 gate"
    );
}

// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Tests for the configuration module.

use std::env;
use std::io::Write;

use super::*;

#[test]
fn test_load_env_files_sets_env_vars() {
    let dir = tempfile::tempdir().unwrap();
    let env_path = dir.path().join("test.env");
    let mut f = std::fs::File::create(&env_path).unwrap();
    writeln!(f, "MCP_GW_TEST_KEY_A=hello_from_env_file").unwrap();
    writeln!(f, "MCP_GW_TEST_KEY_B=42").unwrap();
    drop(f);

    let config = Config {
        env_files: vec![env_path.to_string_lossy().to_string()],
        ..Default::default()
    };
    config.load_env_files();

    assert_eq!(
        env::var("MCP_GW_TEST_KEY_A").unwrap(),
        "hello_from_env_file"
    );
    assert_eq!(env::var("MCP_GW_TEST_KEY_B").unwrap(), "42");

    // Note: env::remove_var is unsafe in edition 2024 and lib forbids unsafe.
    // Test keys use unique MCP_GW_TEST_ prefix so won't conflict.
}

#[test]
fn test_load_env_files_skips_missing() {
    let config = Config {
        env_files: vec!["/nonexistent/path/.env".to_string()],
        ..Default::default()
    };
    // Should not panic
    config.load_env_files();
}

#[test]
fn test_load_env_files_later_file_overrides_earlier_file() {
    let dir = tempfile::tempdir().unwrap();
    let first_path = dir.path().join("first.env");
    let second_path = dir.path().join("second.env");
    let key = "MCP_GW_TEST_OVERRIDE_KEY";

    let mut first = std::fs::File::create(&first_path).unwrap();
    writeln!(first, "{key}=from_first").unwrap();
    drop(first);

    let mut second = std::fs::File::create(&second_path).unwrap();
    writeln!(second, "{key}=from_second").unwrap();
    drop(second);

    let config = Config {
        env_files: vec![
            first_path.to_string_lossy().to_string(),
            second_path.to_string_lossy().to_string(),
        ],
        ..Default::default()
    };

    config.load_env_files();

    assert_eq!(env::var(key).unwrap(), "from_second");
}

#[test]
fn test_load_env_files_empty() {
    let config = Config::default();
    assert!(config.env_files.is_empty());
    config.load_env_files(); // No-op, should not panic
}

#[test]
fn test_env_files_deserialized_from_yaml() {
    let yaml = r#"
env_files:
  - ~/.claude/secrets.env
  - /tmp/extra.env
server:
  host: "127.0.0.1"
  port: 39401
"#;
    let config: Config = serde_yaml::from_str(yaml).unwrap();
    assert_eq!(config.env_files.len(), 2);
    assert_eq!(config.env_files[0], "~/.claude/secrets.env");
}

#[test]
fn runtime_config_deserializes_profiles_and_plans_docker() {
    let yaml = r"
runtime:
  default_provider: local_process
  availability:
    docker: true
  profiles:
    gmail:
      provider: docker
      image: ghcr.io/example/gmail-mcp:1
      executable: mcp-gmail
      data_class: sensitive
      env_keys:
        - GMAIL_HANDLE
      guarded_env_keys:
        - GMAIL_HANDLE
      network_egress: none
      resources:
        cpu_cores: 2
        memory_mb: 768
        timeout_secs: 45
      restart:
        max_restarts: 3
        backoff_secs: 10
";
    let config: Config = serde_yaml::from_str(yaml).unwrap();

    let plan = config
        .runtime
        .plan_profile("gmail", "gmail")
        .expect("runtime profile plan");

    assert_eq!(plan.provider, crate::runtime::RuntimeProviderKind::Docker);
    assert_eq!(plan.policy.resources.memory_mb, 768);
    assert_eq!(plan.policy.restart.max_restarts, 3);
    assert!(plan.launch_command.is_some());
    assert!(!plan.is_denied());
}

#[test]
fn runtime_config_uses_defaults_for_partial_resource_and_restart_policy() {
    let yaml = r"
runtime:
  profiles:
    local_docs:
      provider: local_process
      executable: mcp-docs
      resources:
        memory_mb: 256
      restart:
        max_restarts: 4
";
    let config: Config = serde_yaml::from_str(yaml).unwrap();

    let plan = config
        .runtime
        .plan_profile("local_docs", "local-docs")
        .expect("runtime profile plan");

    assert_eq!(plan.policy.resources.cpu_cores, 1);
    assert_eq!(plan.policy.resources.memory_mb, 256);
    assert_eq!(plan.policy.resources.timeout_secs, 60);
    assert_eq!(plan.policy.restart.max_restarts, 4);
    assert_eq!(plan.policy.restart.backoff_secs, 5);
}

#[test]
fn backend_runtime_profile_deserializes_and_validates() {
    let yaml = r#"
runtime:
  profiles:
    local_safe:
      provider: local_process
      network_egress: none
backends:
  docs:
    command: "node server.js"
    runtime_profile: local_safe
"#;
    let config: Config = serde_yaml::from_str(yaml).expect("config");
    let backend = config.backends.get("docs").expect("backend");
    assert_eq!(backend.runtime_profile.as_deref(), Some("local_safe"));
    assert!(config.validate().is_ok());
}

#[test]
fn validate_rejects_unknown_backend_runtime_profile() {
    let yaml = r#"
backends:
  docs:
    command: "node server.js"
    runtime_profile: missing
"#;
    let config: Config = serde_yaml::from_str(yaml).expect("config");
    let result = config.validate();
    assert!(matches!(result, Err(crate::Error::ConfigValidation(_))));
    let msg = result.unwrap_err().to_string();
    assert!(
        msg.contains("backends.docs.runtime_profile"),
        "error should cite backend runtime profile: {msg}"
    );
}

#[test]
fn validate_rejects_container_runtime_profile_without_image() {
    let yaml = r"
runtime:
  profiles:
    missing_image:
      provider: docker
";
    let config: Config = serde_yaml::from_str(yaml).unwrap();

    let result = config.validate();

    assert!(matches!(result, Err(crate::Error::ConfigValidation(_))));
    let msg = result.unwrap_err().to_string();
    assert!(
        msg.contains("runtime.profiles.missing_image.image"),
        "error should name missing image field: {msg}"
    );
}

#[test]
fn validate_rejects_invalid_runtime_env_key() {
    let yaml = r"
runtime:
  profiles:
    unsafe_env:
      provider: local_process
      env_keys:
        - BAD-KEY
";
    let config: Config = serde_yaml::from_str(yaml).unwrap();

    let result = config.validate();

    assert!(matches!(result, Err(crate::Error::ConfigValidation(_))));
    let msg = result.unwrap_err().to_string();
    assert!(
        msg.contains("runtime.profiles.unsafe_env.env_keys"),
        "error should name invalid env key field: {msg}"
    );
}

// ── SurfacedToolConfig — config parsing (T2.2) ────────────────────────────────

#[test]
fn surfaced_tool_config_deserializes_from_yaml() {
    // GIVEN: a YAML snippet with surfaced_tools entries
    let yaml = r"
meta_mcp:
  surfaced_tools:
    - server: my_backend
      tool: my_tool
    - server: other_backend
      tool: another_tool
";
    // WHEN: parsing as Config
    let config: Config = serde_yaml::from_str(yaml).unwrap();
    // THEN: both entries are present with correct fields
    let tools = &config.meta_mcp.surfaced_tools;
    assert_eq!(tools.len(), 2);
    assert_eq!(tools[0].server, "my_backend");
    assert_eq!(tools[0].tool, "my_tool");
    assert_eq!(tools[1].server, "other_backend");
    assert_eq!(tools[1].tool, "another_tool");
}

#[test]
fn surfaced_tools_defaults_to_empty_vec() {
    // GIVEN: no surfaced_tools in config
    // WHEN: default config is created
    let config = Config::default();
    // THEN: surfaced_tools is empty
    assert!(config.meta_mcp.surfaced_tools.is_empty());
}

#[test]
fn surfaced_tools_omitted_in_yaml_parses_to_empty() {
    // GIVEN: a YAML with meta_mcp but no surfaced_tools key
    let yaml = r"
meta_mcp:
  warm_start:
    - my_backend
";
    // WHEN: parsing
    let config: Config = serde_yaml::from_str(yaml).unwrap();
    // THEN: surfaced_tools is empty (default applied)
    assert!(config.meta_mcp.surfaced_tools.is_empty());
}

#[test]
fn surfaced_tool_config_serializes_roundtrip() {
    // GIVEN: a SurfacedToolConfig
    let original = SurfacedToolConfig {
        server: "srv".to_string(),
        tool: "tl".to_string(),
    };
    // WHEN: round-tripping through JSON
    let json = serde_json::to_string(&original).unwrap();
    let deserialized: SurfacedToolConfig = serde_json::from_str(&json).unwrap();
    // THEN: fields are preserved
    assert_eq!(deserialized, original);
}

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
    std::fs::write(
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

// ── GW.IDLE.3 — ownership validation ────────────────────────────────────────
//
// `stop_when_idle_for` promises the gateway will stop a process. It can only
// honour that where it started the process. Accepting it elsewhere would repeat
// nowhere, trusted by operators.

#[test]
fn stop_when_idle_for_is_accepted_on_a_gateway_started_backend() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("gateway.yaml");
    std::fs::write(
        &path,
        "backends:\n  owned:\n    command: \"echo hi\"\n    stop_when_idle_for: 5m\n",
    )
    .expect("write");

    let cfg = Config::load(Some(&path)).expect("stdio backend may opt in");
    let backend = cfg
        .backends
        .get("owned")
        .expect("backend must survive parsing");
    assert_eq!(
        backend.stop_when_idle_for,
        Some(std::time::Duration::from_secs(300)),
        "the duration must round-trip, not silently default"
    );
}

#[test]
fn stop_when_idle_for_is_rejected_on_a_backend_the_gateway_does_not_start() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("gateway.yaml");
    // A LOCAL http backend: locality does not grant ownership. The gateway did
    // not start this server and cannot stop it.
    std::fs::write(
        &path,
        "backends:\n  external:\n    http_url: \"http://127.0.0.1:39400/mcp\"\n    stop_when_idle_for: 5m\n",
    )
    .expect("write");

    let err =
        Config::load(Some(&path)).expect_err("the gateway cannot stop a process it did not start");
    let msg = err.to_string();
    assert!(
        msg.contains("external"),
        "the error must name the offending backend, got: {msg}"
    );
    assert!(
        msg.contains("stop_when_idle_for"),
        "the error must name the setting, got: {msg}"
    );
}

#[test]
fn omitting_stop_when_idle_for_leaves_a_backend_running_indefinitely() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("gateway.yaml");
    std::fs::write(&path, "backends:\n  owned:\n    command: \"echo hi\"\n").expect("write");

    let cfg = Config::load(Some(&path)).expect("load");
    assert_eq!(
        cfg.backends
            .get("owned")
            .expect("backend")
            .stop_when_idle_for,
        None,
        "absent must mean never stop - no magic default that changes behaviour on upgrade"
    );
}

#[test]
fn an_http_backend_without_the_setting_still_loads() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("gateway.yaml");
    std::fs::write(
        &path,
        "backends:\n  external:\n    http_url: \"http://127.0.0.1:39400/mcp\"\n",
    )
    .expect("write");

    let cfg = Config::load(Some(&path)).expect("http backends are fine without the setting");
    assert!(
        cfg.backends.contains_key("external"),
        "control: the validation must reject only the setting, not the transport"
    );
}

#[test]
fn duration_parser_handles_milliseconds() {
    // Regression: the parser tested the "s" suffix BEFORE "ms", so "100ms" took
    // the seconds branch and failed to parse "100m" as an integer. Every ms value
    // in every duration field was rejected.
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("gateway.yaml");
    std::fs::write(
        &path,
        "backends:\n  owned:\n    command: \"echo hi\"\n    stop_when_idle_for: 1500ms\n",
    )
    .expect("write");

    let cfg = Config::load(Some(&path)).expect("ms suffix must parse");
    assert_eq!(
        cfg.backends
            .get("owned")
            .expect("backend")
            .stop_when_idle_for,
        Some(std::time::Duration::from_millis(1500))
    );
}

/// Flow style is valid YAML and loads identically to the block form. A
/// line-oriented detector saw nothing here, so an operator whose config used
/// flow mappings got the removal with no warning at all — the exact silence
/// this warning exists to break.
#[test]
fn retired_key_detector_sees_flow_style_mappings() {
    assert!(
        !Config::retired_keys_in_str("backends: {demo: {command: \"echo hi\", idle_timeout: 10m}}")
            .is_empty(),
        "flow-style mappings are valid YAML; the detector must see the key there too"
    );
}

/// The mirror failure: the key's NAME inside a value is not a use of the key.
/// A CHANGELOG excerpt or a description quoting `idle_timeout:` must not make
/// the gateway warn about a config that never set it.
#[test]
fn retired_key_detector_ignores_the_name_inside_values() {
    assert!(
        Config::retired_keys_in_str(
            "backends:\n  demo:\n    command: \"echo hi\"\n    description: |\n      idle_timeout: 10m is no longer supported\n"
        )
        .is_empty(),
        "the key name appearing inside a block scalar is text, not a set key"
    );
}

/// `Config::load` warns by reading the file from disk, a path the string-level
/// tests never touch. Without this, the detector could be perfect and still be
/// wired to nothing.
#[test]
fn retired_key_detector_reads_the_loaded_file() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("gateway.yaml");
    std::fs::write(
        &path,
        "backends:\n  demo:\n    command: \"echo hi\"\n    idle_timeout: 10m\n",
    )
    .expect("write config");

    assert_eq!(
        Config::retired_keys_in_file(&path)
            .iter()
            .map(|(k, _)| *k)
            .collect::<Vec<_>>(),
        vec!["idle_timeout"],
        "the file-reading path Config::load uses must find the retired key"
    );
}

// -------------------------------------------------------------------------
// Agent key material (MIK-7258)
//
// `DecodingKey::from_secret(b"")` is a valid key anyone can sign for, so an
// agent whose HS256 secret is empty verifies a token from any caller while the
// config reads as authenticated. Nothing rejected it, and the network-posture
// refusal then treated `agent_auth.enabled` as proof the tools demand a
// credential — an exemption meant to recognise security, recognising none.
//
// The check lives here rather than in that refusal because three attempts to
// judge key strength there each missed the next case.
// -------------------------------------------------------------------------

/// A config with agent auth on and one agent holding `secret`.
fn agent_config(secret: Option<&str>, rsa: Option<&str>) -> Config {
    let mut c = Config::default();
    c.agent_auth.enabled = true;
    c.agent_auth.agents = vec![crate::config::AgentDefinitionConfig {
        client_id: "svc".to_string(),
        name: "svc".to_string(),
        hs256_secret: secret.map(str::to_string),
        rs256_public_key: rsa.map(str::to_string),
        scopes: Vec::new(),
        issuer: None,
        audience: None,
    }];
    c
}

#[test]
fn an_agent_secret_that_could_not_reject_anybody_fails_validation() {
    for (label, secret) in [
        ("empty", ""),
        ("one character", "x"),
        (
            "thirty-one bytes, one short of the floor",
            &"k".repeat(31)[..],
        ),
    ] {
        let err = agent_config(Some(secret), None)
            .validate()
            .expect_err(&format!("an agent secret that is {label} was accepted"));
        let msg = err.to_string();
        assert!(
            msg.contains("svc") && msg.contains("hs256_secret"),
            "the message must name the agent and the field: {msg}"
        );
    }
}

#[test]
fn a_usable_agent_secret_validates() {
    agent_config(Some(&"k".repeat(32)), None)
        .validate()
        .expect("a 32-byte secret is the documented minimum and must be accepted");
    agent_config(
        None,
        Some("-----BEGIN PUBLIC KEY-----\nx\n-----END PUBLIC KEY-----"),
    )
    .validate()
    .expect("an RSA public key needs no shared secret");
}

#[test]
fn an_agent_with_no_key_material_at_all_fails_validation() {
    let err = agent_config(None, None)
        .validate()
        .expect_err("an agent that can verify nothing was accepted");
    assert!(
        err.to_string().contains("can verify nothing"),
        "the message must say what is wrong: {err}"
    );
}

#[test]
fn one_sound_agent_does_not_excuse_a_forgeable_sibling() {
    // A caller forges the WEAKEST agent's token and gets that agent's scopes,
    // so every enabled agent has to hold up. An earlier version of this check
    // asked whether ANY agent was sound, which is exactly backwards.
    let mut c = agent_config(Some(&"k".repeat(32)), None);
    c.agent_auth
        .agents
        .push(crate::config::AgentDefinitionConfig {
            client_id: "weak".to_string(),
            name: "weak".to_string(),
            hs256_secret: Some(String::new()),
            rs256_public_key: None,
            scopes: Vec::new(),
            issuer: None,
            audience: None,
        });
    let err = c
        .validate()
        .expect_err("a forgeable agent beside a sound one was accepted");
    assert!(
        err.to_string().contains("weak"),
        "the message must name the agent that is wrong, not the sound one: {err}"
    );
}

#[test]
fn agent_auth_disabled_ignores_key_material_entirely() {
    let mut c = agent_config(Some(""), None);
    c.agent_auth.enabled = false;
    c.validate()
        .expect("a disabled agent_auth block verifies nothing and gates nothing");
}

#[test]
fn an_agent_holding_both_key_types_fails_validation() {
    // The algorithm is read from the TOKEN HEADER (src/gateway/oauth/jwt.rs:120),
    // so a caller chooses which of the two keys verifies its token. An agent
    // configured with both is therefore only as strong as its WEAKER key, while
    // the operator who added an RSA key believes RSA is what is in force.
    // `AgentDefinition` already documents "exactly one"; nothing enforced it.
    let err = agent_config(
        Some("short"),
        Some("-----BEGIN PUBLIC KEY-----\nx\n-----END PUBLIC KEY-----"),
    )
    .validate()
    .expect_err("an agent holding both key types was accepted");
    let msg = err.to_string();
    assert!(
        msg.contains("svc") && msg.contains("both"),
        "the message must name the agent and the ambiguity: {msg}"
    );
}

// -------------------------------------------------------------------------
// MIK-7256 — env files on a failed load (§P2 failing tests)
//
// Written against `docs/design/mik-7256-env-files-on-a-failed-load.md` and the
// rows in `docs/design/mik-7256-test-plan.md`. The design's types do not exist
// yet, so these are expected to fail to COMPILE until implementation lands.
//
// The design states that expansion must reach its home "through an injected
// resolver rather than calling `dirs::home_dir()` inline" (design:314-315) but
// does not name the seam. These tests name it `config::HomeResolver`, with
// `fn home_dir(&self, so_far: &EnvOverlay) -> Option<PathBuf>`. The `so_far`
// parameter is not decoration: startup applies each file before expanding the
// next, so a resolver that cannot see the overlay under construction cannot
// reproduce production's sequential semantics, which is the property
// ENVFILE.19c exists to pin. Rename freely at implementation time.
// -------------------------------------------------------------------------

/// A [`HomeResolver`] that always answers with one directory, for the rows that
/// only need `HOME` pointed somewhere writable.
struct FixedHome(std::path::PathBuf);

impl HomeResolver for FixedHome {
    fn home_dir(&self, _so_far: &EnvOverlay) -> Option<std::path::PathBuf> {
        Some(self.0.clone())
    }
}

/// ENVFILE.19 — an `env_files` entry spelled `~/<file>` with `HOME` pointed at a
/// temp dir: the overlay OPENS the path startup recorded and reads the same
/// pairs.
///
/// Phrased as opening a recorded path rather than resolving one, because a row
/// that says "resolves" can go green on an overlay that re-expands and happens
/// to agree. Tilde expansion is a supported spelling today
/// (`src/config/mod.rs:290-298`); an overlay that skipped it would silently stop
/// rotating those files, and nothing else in the plan would go red.
#[test]
fn envfile_19_the_overlay_opens_the_tilde_path_startup_recorded() {
    // GIVEN: a home directory holding one env file, named by a `~/...` entry
    let home = tempfile::tempdir().unwrap();
    let env_path = home.path().join("rotating.env");
    let mut f = std::fs::File::create(&env_path).unwrap();
    writeln!(f, "MCP_GW_TEST_ENVFILE19_KEY=startup-value-19").unwrap();
    drop(f);

    let cfg_dir = tempfile::tempdir().unwrap();
    let cfg_path = cfg_dir.path().join("gateway.yaml");
    std::fs::write(&cfg_path, "env_files:\n  - \"~/rotating.env\"\n").unwrap();

    // WHEN: startup evaluates the config through an injected home
    let startup =
        Config::load_evaluated_with_home(Some(&cfg_path), &FixedHome(home.path().to_path_buf()))
            .unwrap();

    // THEN: the path startup RECORDED is the expanded one, not the `~` spelling
    assert_eq!(
        startup.env_paths.as_paths(),
        &[env_path.clone()],
        "startup must record the absolute path it opened"
    );

    // AND: the overlay carries the pairs read from that same file
    assert_eq!(
        startup
            .overlay
            .resolve("MCP_GW_TEST_ENVFILE19_KEY")
            .as_deref(),
        Some("startup-value-19"),
        "the overlay must carry the pairs of the file startup opened"
    );
}

/// ENVFILE.19d — `HOME` unset and `HOME` empty, each in its own CHILD PROCESS.
///
/// A child per variant because the case mutates a PROCESS-wide variable: an
/// in-process version races every other test the runner schedules beside it,
/// while the oracle it compares against is read in a different environment than
/// the one under test. Absent and empty are the same input to `dirs`, which
/// falls back rather than returning the empty value
/// (`dirs-sys-0.5.0/src/lib.rs:33-37`) — testing only the unset spelling lets an
/// implementation that special-cases one and not the other pass.
#[test]
fn envfile_19d_home_unset_and_home_empty_both_resolve_to_the_dirs_fallback() {
    for variant in ["unset", "empty"] {
        let mut cmd = std::process::Command::new(std::env::current_exe().unwrap());
        cmd.args([
            "--exact",
            "config::tests::envfile_19d_child_resolves_against_dirs_home_dir",
            "--ignored",
            "--nocapture",
        ]);
        cmd.env("MCP_GW_TEST_ENVFILE19D_VARIANT", variant);
        if variant == "unset" {
            cmd.env_remove("HOME");
        } else {
            cmd.env("HOME", "");
        }
        let out = cmd.output().unwrap();
        assert!(
            out.status.success(),
            "child for HOME={variant} failed:\n{}\n{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        // Printed only after both child assertions pass, so a child that
        // silently ran zero tests cannot be read as a pass.
        assert!(
            String::from_utf8_lossy(&out.stdout).contains("ENVFILE.19d child ok"),
            "child for HOME={variant} did not run the case"
        );
    }
}

/// The child half of ENVFILE.19d. Computes its OWN `dirs::home_dir()` as the
/// expected value rather than a passwd entry, which keeps the case honest on
/// Windows, where the function reads a known folder and does not consult `HOME`
/// at all.
#[test]
#[ignore = "driven by envfile_19d_home_unset_and_home_empty_both_resolve_to_the_dirs_fallback"]
fn envfile_19d_child_resolves_against_dirs_home_dir() {
    assert!(
        env::var_os("MCP_GW_TEST_ENVFILE19D_VARIANT").is_some(),
        "child must be launched by its parent, not run directly"
    );

    // GIVEN: a `~/...` entry, and this process's own idea of home
    let expected_home = dirs::home_dir().expect("dirs must fall back when HOME is unset or empty");
    let expected = expected_home.join("mcp-gw-test-envfile19d.env");

    let cfg_dir = tempfile::tempdir().unwrap();
    let cfg_path = cfg_dir.path().join("gateway.yaml");
    std::fs::write(
        &cfg_path,
        "env_files:\n  - \"~/mcp-gw-test-envfile19d.env\"\n",
    )
    .unwrap();

    // WHEN: startup evaluates it. The file is deliberately NOT created — a
    // missing path is skipped, and the RESOLUTION is what this row is about;
    // writing into the real home directory is not the test's business.
    let startup = Config::load_evaluated(Some(&cfg_path)).unwrap();

    // THEN: it resolved against this process's own `dirs::home_dir()`
    assert_eq!(
        startup.env_paths.as_paths(),
        &[expected.clone()],
        "startup must resolve `~` against dirs::home_dir()"
    );

    // AND: a reload opens the same path, taking it from what startup recorded
    let reloaded =
        Config::load_with_overlay(Some(&cfg_path), &startup.env_paths, &EnvOverlay::none())
            .unwrap();
    assert_eq!(
        reloaded.env_paths.as_paths(),
        &[expected],
        "a reload must open the path startup recorded, not resolve it again"
    );

    println!("ENVFILE.19d child ok");
}

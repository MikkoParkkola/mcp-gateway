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
        }),
    );
    assert!(
        config.validate().is_ok(),
        "stateless signed-assertion must validate"
    );
}

#[test]
fn validate_rejects_per_user_session_mode_until_pool_ships() {
    // IDP.7: per_user needs the transport pool (slice 2c); refuse rather than
    // reuse a shared session.
    let mut config = Config::default();
    config.backends.insert(
        "mem".to_string(),
        backend_with_idp(IdentityPropagationConfig {
            strategy: PropagationStrategyKind::SignedAssertion,
            audience: "https://mem".to_string(),
            required: true,
            session_mode: SessionMode::PerUser,
        }),
    );
    let err = config.validate().unwrap_err().to_string();
    assert!(
        err.contains("per_user"),
        "error should name per_user: {err}"
    );
    assert!(err.contains("mem"), "error should name the backend: {err}");
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
        }),
    );
    assert!(matches!(
        config.validate(),
        Err(crate::Error::ConfigValidation(_))
    ));
}

#[test]
fn validate_rejects_required_unimplemented_strategy() {
    // IDP.2: a required backend on an unimplemented strategy must not silently
    // run without propagation.
    let mut config = Config::default();
    config.backends.insert(
        "b".to_string(),
        backend_with_idp(IdentityPropagationConfig {
            strategy: PropagationStrategyKind::TokenExchange,
            audience: "https://mail".to_string(),
            required: true,
            session_mode: SessionMode::Stateless,
        }),
    );
    assert!(config.validate().is_err());
}

#[test]
fn validate_backend_without_idp_is_unchanged() {
    // IDP.5: absent config keeps today's behavior — default config validates.
    let config = Config::default();
    assert!(config.validate().is_ok());
}

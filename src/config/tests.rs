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

// ── Runtime policy config (MIK-6555 AC.3) ────────────────────────────────────

/// AC.3: Omitted runtime config defaults to local_compat.
/// AC.3: YAML without runtime becomes local_compat; YAML with docker policy
/// round-trips without losing fields.
#[test]
fn runtime_policy_config_defaults_and_roundtrip() {
    // GIVEN: a YAML backend without a `runtime` key
    let yaml_no_runtime = r#"
backends:
  my-backend:
    command: "./my-server"
"#;
    let config: Config = serde_yaml::from_str(yaml_no_runtime).unwrap();

    // THEN: runtime defaults to local_compat
    let backend = config.backends.get("my-backend").unwrap();
    assert_eq!(backend.runtime.provider, "local_compat");

    // GIVEN: a YAML backend with a docker runtime policy
    let yaml_docker = r#"
backends:
  my-backend:
    command: "./my-server"
    runtime:
      provider: docker
      resources:
        cpu: 1.0
        memory: "512MiB"
      mounts:
        allow_writable: true
        mounts:
          - host: /tmp/data
            container: /data
            writable: true
      egress:
        deny_default: true
        allowlist:
          - "10.0.0.0/8"
      env_policy:
        inherit_env: false
        allowlist:
          - PATH
      secrets:
        env_secrets:
          API_KEY: "env:MCP_SECRET"
      identity:
        user: "1000"
      timeouts:
        start_secs: 60
      log_policy:
        capture: true
        max_lines: 500
"#;
    let config: Config = serde_yaml::from_str(yaml_docker).unwrap();
    let backend = config.backends.get("my-backend").unwrap();

    // THEN: provider is docker
    assert_eq!(backend.runtime.provider, "docker");

    // AND: round-trip through YAML preserves all fields
    let roundtripped_yaml = serde_yaml::to_string(config).unwrap();
    let config2: Config = serde_yaml::from_str(&roundtripped_yaml).unwrap();
    let backend2 = config2.backends.get("my-backend").unwrap();
    assert_eq!(backend2.runtime.provider, "docker");
    assert!((backend2.runtime.resources.cpu - 1.0f64).abs() < f64::EPSILON);
    assert_eq!(backend2.runtime.resources.memory, "512MiB");
    assert!(backend2.runtime.mounts.allow_writable);
    assert_eq!(backend2.runtime.mounts.mounts.len(), 1);
    assert_eq!(backend2.runtime.mounts.mounts[0].host, "/tmp/data");
    assert_eq!(backend2.runtime.mounts.mounts[0].container, "/data");
    assert!(backend2.runtime.mounts.mounts[0].writable);
    assert!(backend2.runtime.egress.deny_default);
    assert_eq!(backend2.runtime.egress.allowlist.len(), 1);
    assert!(!backend2.runtime.env_policy.inherit_env);
    assert_eq!(backend2.runtime.env_policy.allowlist.len(), 1);
    assert_eq!(backend2.runtime.secrets.env_secrets.len(), 1);
    assert_eq!(
        backend2.runtime.identity.user.as_deref(),
        Some("1000")
    );
    assert_eq!(backend2.runtime.timeouts.start_secs, 60);
    assert!(backend2.runtime.log_policy.capture);
    assert_eq!(backend2.runtime.log_policy.max_lines, 500);
}

/// AC.3: BackendConfig default runtime is local_compat
#[test]
fn backend_config_default_runtime_is_local_compat() {
    let cfg = BackendConfig::default();
    assert_eq!(cfg.runtime.provider, "local_compat");
}

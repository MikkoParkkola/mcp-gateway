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
    let yaml = r#"
meta_mcp:
  surfaced_tools:
    - server: my_backend
      tool: my_tool
    - server: other_backend
      tool: another_tool
"#;
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
    let yaml = r#"
meta_mcp:
  warm_start:
    - my_backend
"#;
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
fn validate_rejects_empty_backend_name() {
    // GIVEN: a config with an empty backend name
    let mut config = Config::default();
    config.backends.insert(
        String::new(),
        BackendConfig::default(),
    );
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
    config.backends.insert(
        "a/b".to_string(),
        BackendConfig::default(),
    );
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

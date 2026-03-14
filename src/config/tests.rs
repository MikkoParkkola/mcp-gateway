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

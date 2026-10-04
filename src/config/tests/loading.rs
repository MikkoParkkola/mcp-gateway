// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Config loading, env files, runtime profiles and surfaced tools.

use super::*;

#[test]
fn unreadable_invalid_config_reports_secure_container_remediation_before_parsing() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("gateway.yaml");
    write_owner_only(&path, "this is: [invalid yaml").expect("write invalid config");
    // Unix: chmod 0000. Windows: a DACL entry denying the user read.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o000))
            .expect("remove config read permission");
    }
    #[cfg(windows)]
    crate::private_fs::test_support::deny_user("unreadable-config", &path, "RD");

    // Root and similarly privileged CI users can bypass mode 000. In that
    // environment this fixture cannot exercise PermissionDenied, so say why
    // the test is skipped instead of reporting a misleading pass or failure.
    if std::fs::File::open(&path).is_ok() {
        eprintln!("skipping unreadable-config regression: effective user can read mode 000");
        return;
    }

    let err = Config::load(Some(&path)).expect_err("an unreadable config must fail before parsing");
    let message = err.to_string();
    assert!(
        message.contains(&path.display().to_string()),
        "the diagnostic must name the selected config path: {message}"
    );
    // Unix names the container UID/GID to grant; Windows says to grant it through the ACL.
    let remediation = if cfg!(windows) { "ACL" } else { "1001" };
    assert!(
        message.contains(remediation),
        "the diagnostic must carry the platform's remediation ({remediation}): {message}"
    );
    assert!(
        !message.contains("invalid type") && !message.contains("invalid YAML"),
        "readability must be diagnosed before the deliberately invalid YAML is parsed: {message}"
    );
}

#[test]
fn missing_explicit_config_keeps_not_found_diagnostic() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("missing-gateway.yaml");

    let err = Config::load(Some(&path)).expect_err("a missing explicit config must fail");
    assert_eq!(
        err.to_string(),
        format!(
            "Configuration error: Config file not found: {}",
            path.display()
        )
    );
}

#[test]
fn readable_invalid_config_still_reports_parse_error() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("gateway.yaml");
    write_owner_only(&path, "this is: [invalid yaml").expect("write invalid config");

    let err = Config::load(Some(&path)).expect_err("invalid YAML must fail parsing");
    let message = err.to_string();
    // The path is matched by its last two components, not verbatim: the parser normalises a
    // leading `./`, which a relative TMPDIR produces and which cargo-mutants sets.
    let tail = format!(
        "{}{}gateway.yaml",
        dir.path()
            .file_name()
            .expect("tempdir has a final component")
            .to_string_lossy(),
        std::path::MAIN_SEPARATOR
    );
    assert!(
        message.contains(&tail) && !message.contains("Cannot read config file"),
        "a readable invalid file must retain the parser path: {message}"
    );
}

#[test]
fn test_load_env_files_sets_env_vars() {
    let dir = tempfile::tempdir().unwrap();
    let env_path = dir.path().join("test.env");
    write_owner_only(
        &env_path,
        "MCP_GW_TEST_KEY_A=hello_from_env_file\nMCP_GW_TEST_KEY_B=42\n",
    )
    .unwrap();

    let overlay = EnvOverlay::from_paths(&[env_path]);

    assert_eq!(
        overlay.resolve("MCP_GW_TEST_KEY_A").as_deref(),
        Some("hello_from_env_file")
    );
    assert_eq!(overlay.resolve("MCP_GW_TEST_KEY_B").as_deref(), Some("42"));
    assert!(
        env::var("MCP_GW_TEST_KEY_A").is_err(),
        "an env file must not reach the process environment"
    );
}

#[test]
fn test_load_env_files_skips_missing() {
    let overlay = EnvOverlay::from_paths(&[std::path::PathBuf::from("/nonexistent/path/.env")]);

    assert!(
        overlay.owned_keys().is_empty(),
        "a missing env file contributes nothing and must not panic"
    );
}

#[test]
fn test_load_env_files_later_file_overrides_earlier_file() {
    let dir = tempfile::tempdir().unwrap();
    let first_path = dir.path().join("first.env");
    let second_path = dir.path().join("second.env");
    let key = "MCP_GW_TEST_OVERRIDE_KEY";

    write_owner_only(&first_path, format!("{key}=from_first\n")).unwrap();
    write_owner_only(&second_path, format!("{key}=from_second\n")).unwrap();

    let overlay = EnvOverlay::from_paths(&[first_path, second_path]);

    assert_eq!(overlay.resolve(key).as_deref(), Some("from_second"));
}

#[test]
fn test_load_env_files_empty() {
    let config = Config::default();
    assert!(config.env_files.is_empty());

    let overlay = EnvOverlay::from_paths(&[]);
    assert!(overlay.owned_keys().is_empty());
}

#[test]
fn test_env_files_deserialized_from_yaml() {
    let yaml = r#"
env_files:
  - ~/.config/mcp-gateway/secrets.env
  - /tmp/extra.env
server:
  host: "127.0.0.1"
  port: 39401
"#;
    let config: Config = serde_yaml::from_str(yaml).unwrap();
    assert_eq!(config.env_files.len(), 2);
    assert_eq!(config.env_files[0], "~/.config/mcp-gateway/secrets.env");
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

// ── meta_mcp.prompts_resources_fetch_timeout (PR #465 aggregation bound) ─────

#[test]
fn meta_mcp_prompts_resources_fetch_timeout_deserializes_from_yaml() {
    // GIVEN: a YAML with an explicit aggregation timeout
    let yaml = r"
meta_mcp:
  prompts_resources_fetch_timeout: 5s
";
    // WHEN: parsing as Config
    let config: Config = serde_yaml::from_str(yaml).unwrap();
    // THEN: the timeout is read as a humantime Duration
    assert_eq!(
        config.meta_mcp.prompts_resources_fetch_timeout,
        Duration::from_secs(5)
    );
}

#[test]
fn meta_mcp_prompts_resources_fetch_timeout_defaults_to_ten_seconds() {
    // GIVEN: no prompts_resources_fetch_timeout in config
    // WHEN: a default config is created
    let config = Config::default();
    // THEN: the bound falls back to the documented 10s default
    assert_eq!(
        config.meta_mcp.prompts_resources_fetch_timeout,
        Duration::from_secs(10)
    );
}

#[test]
fn meta_mcp_prompts_resources_fetch_timeout_omitted_in_yaml_keeps_default() {
    // GIVEN: a YAML with meta_mcp but no aggregation timeout key
    let yaml = r"
meta_mcp:
  cache_ttl: 60s
";
    // WHEN: parsing
    let config: Config = serde_yaml::from_str(yaml).unwrap();
    // THEN: the default is applied
    assert_eq!(
        config.meta_mcp.prompts_resources_fetch_timeout,
        Duration::from_secs(10)
    );
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

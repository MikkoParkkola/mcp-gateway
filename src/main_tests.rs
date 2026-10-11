// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
use super::*;
use crate::commands::config_write::CommentLoss;
use mcp_gateway::cli::{Cli, InitProfile};
use mcp_gateway::config::{BackendConfig, Config, TransportConfig};
use mcp_gateway::discovery::{DiscoveredServer, DiscoverySource, ServerMetadata};
use mcp_gateway::gateway::test_helpers::write_config_fixture;
#[path = "main_cli_parse_tests.rs"]
mod cli_parse;
#[path = "main_dangling_tests.rs"]
mod dangling;
#[path = "main_stack_tests.rs"]
mod stack;

fn make_discovered_server(name: &str) -> DiscoveredServer {
    DiscoveredServer::new(
        name.to_string(),
        format!("{name} server"),
        DiscoverySource::ClaudeDesktop,
        TransportConfig::Stdio {
            command: format!("npx -y {name}"),
            cwd: None,
            protocol_version: None,
        },
        ServerMetadata::default(),
    )
}

fn make_cli(port: Option<u16>, host: Option<String>, no_meta_mcp: bool) -> Cli {
    Cli {
        config: None,
        port,
        host,
        log_level: "info".to_string(),
        log_format: None,
        no_meta_mcp,
        command: None,
    }
}

#[test]
fn apply_cli_overrides_no_overrides_preserves_defaults() {
    let mut config = Config::default();
    let cli = make_cli(None, None, false);

    let original_port = config.server.port;
    let original_host = config.server.host.clone();
    let original_meta = config.meta_mcp.enabled;

    apply_cli_overrides(&mut config, &cli);

    assert_eq!(config.server.port, original_port);
    assert_eq!(config.server.host, original_host);
    assert_eq!(config.meta_mcp.enabled, original_meta);
}

#[test]
fn apply_cli_overrides_port_override() {
    let mut config = Config::default();
    let cli = make_cli(Some(9999), None, false);
    apply_cli_overrides(&mut config, &cli);
    assert_eq!(config.server.port, 9999);
}

#[test]
fn apply_cli_overrides_host_override() {
    let mut config = Config::default();
    let cli = make_cli(None, Some("0.0.0.0".to_string()), false);
    apply_cli_overrides(&mut config, &cli);
    assert_eq!(config.server.host, "0.0.0.0");
}

#[test]
fn apply_cli_overrides_disable_meta_mcp() {
    let mut config = Config::default();
    assert!(config.meta_mcp.enabled);
    let cli = make_cli(None, None, true);
    apply_cli_overrides(&mut config, &cli);
    assert!(!config.meta_mcp.enabled);
}

#[test]
fn apply_cli_overrides_all_at_once() {
    let mut config = Config::default();
    let cli = make_cli(Some(8080), Some("192.168.1.1".to_string()), true);
    apply_cli_overrides(&mut config, &cli);
    assert_eq!(config.server.port, 8080);
    assert_eq!(config.server.host, "192.168.1.1");
    assert!(!config.meta_mcp.enabled);
}

#[test]
fn apply_cli_overrides_no_meta_mcp_false_keeps_enabled() {
    let mut config = Config::default();
    let cli = make_cli(None, None, false);
    apply_cli_overrides(&mut config, &cli);
    assert!(config.meta_mcp.enabled);
}

#[test]
fn apply_cli_overrides_port_zero_is_valid() {
    let mut config = Config::default();
    let cli = make_cli(Some(0), None, false);
    apply_cli_overrides(&mut config, &cli);
    assert_eq!(config.server.port, 0);
}

#[test]
fn apply_cli_overrides_host_empty_string() {
    let mut config = Config::default();
    let cli = make_cli(None, Some(String::new()), false);
    apply_cli_overrides(&mut config, &cli);
    assert_eq!(config.server.host, "");
}

#[test]
fn apply_cli_overrides_preserves_other_config_fields() {
    let mut config = Config::default();
    config
        .backends
        .insert("test".to_string(), BackendConfig::default());
    config.server.shutdown_timeout = std::time::Duration::from_secs(60);

    let cli = make_cli(Some(3000), None, false);
    apply_cli_overrides(&mut config, &cli);

    assert_eq!(config.server.port, 3000);
    assert!(config.backends.contains_key("test"));
    assert_eq!(
        config.server.shutdown_timeout,
        std::time::Duration::from_secs(60)
    );
}

#[test]
fn default_config_has_expected_defaults() {
    let config = Config::default();
    assert_eq!(config.server.port, 39400);
    assert_eq!(config.server.host, "127.0.0.1");
    assert!(config.meta_mcp.enabled);
    assert!(config.backends.is_empty());
}

#[test]
fn init_command_creates_config_file() {
    let dir = tempfile::tempdir().unwrap();
    let output = dir.path().join("gateway.yaml");
    let result = commands::run_init_command(&output, true, InitProfile::Local);
    assert_eq!(result, ExitCode::SUCCESS);
    assert!(output.exists());
    let content = std::fs::read_to_string(&output).unwrap();
    assert!(content.contains("server:"));
    assert!(content.contains("host: \"127.0.0.1\""));
    assert!(content.contains("port: 39400"));
    assert!(content.contains("meta_mcp:"));
    assert!(content.contains("enabled: true"));
}

#[test]
fn init_command_local_profile_writes_zero_key_sample_capabilities() {
    let dir = tempfile::tempdir().unwrap();
    let output = dir.path().join("gateway.yaml");

    let result = commands::run_init_command(&output, true, InitProfile::Local);

    assert_eq!(result, ExitCode::SUCCESS);
    let content = std::fs::read_to_string(&output).unwrap();
    assert!(content.contains("# Profile: local"));
    assert!(content.contains("directories:"));
    assert!(!content.contains("API_KEY"));
    assert!(!content.contains("docs/strategy"));
    assert!(!content.contains("docs/competitive"));

    let weather = dir
        .path()
        .join("capabilities/knowledge/weather_current.yaml");
    let holidays = dir
        .path()
        .join("capabilities/knowledge/public_holidays.yaml");
    assert!(weather.exists());
    assert!(holidays.exists());

    let weather_content = std::fs::read_to_string(weather).unwrap();
    let holidays_content = std::fs::read_to_string(holidays).unwrap();
    assert!(weather_content.contains("name: weather_current"));
    assert!(weather_content.contains("required: false"));
    assert!(holidays_content.contains("name: public_holidays"));
    assert!(holidays_content.contains("required: false"));
    assert!(!weather_content.contains("API_KEY"));
    assert!(!holidays_content.contains("API_KEY"));
}

#[test]
fn init_command_minimal_profile_skips_sample_capabilities() {
    let dir = tempfile::tempdir().unwrap();
    let output = dir.path().join("gateway.yaml");

    let result = commands::run_init_command(&output, true, InitProfile::Minimal);

    assert_eq!(result, ExitCode::SUCCESS);
    let content = std::fs::read_to_string(&output).unwrap();
    assert!(content.contains("# Profile: minimal"));
    assert!(!dir.path().join("capabilities").exists());
}

#[test]
fn write_discovered_to_config_creates_file_when_missing() {
    let dir = tempfile::tempdir().unwrap();
    let output = dir.path().join("discovered.yaml");
    let server = make_discovered_server("tavily");

    let written = write_discovered_to_config(&[server], Some(&output), CommentLoss::Refuse)
        .expect("write should succeed");

    assert_eq!(written, output);
    let loaded = Config::load(Some(&output)).expect("must reload");
    assert!(loaded.backends.contains_key("tavily"));
}

#[test]
fn write_discovered_to_config_preserves_existing_backends() {
    let dir = tempfile::tempdir().unwrap();
    let output = dir.path().join("discovered.yaml");
    let mut existing = Config::default();
    existing.backends.insert(
        "existing".to_string(),
        BackendConfig {
            transport: TransportConfig::Stdio {
                command: "echo existing".to_string(),
                cwd: None,
                protocol_version: None,
            },
            ..BackendConfig::default()
        },
    );
    write_config_fixture(&output, &existing).expect("initial write should succeed");

    let server = make_discovered_server("tavily");
    write_discovered_to_config(&[server], Some(&output), CommentLoss::Refuse)
        .expect("write should succeed");

    let loaded = Config::load(Some(&output)).expect("must reload");
    assert!(loaded.backends.contains_key("existing"));
    assert!(loaded.backends.contains_key("tavily"));
}

// GH462.CONFIG.1 / GH462.CONFIG.2: the shared loader's existing writer stays fail-closed.
#[test]
fn gh462_discovery_persistence_preserves_existing_invalid_files() {
    let dir = tempfile::tempdir().unwrap();
    let output = dir.path().join("discovered.yaml");
    let server = make_discovered_server("gh462-import");
    for original in [
        "backends:\n  original:\n    command: \"unterminated\n",
        "backends:\n  bad/name:\n    command: echo original\n",
    ] {
        mcp_gateway::gateway::test_helpers::write_owner_only(&output, original).unwrap();
        let error = Config::load_literal(Some(&output)).unwrap_err();
        if original.contains("bad/name") {
            assert!(matches!(error, mcp_gateway::Error::ConfigValidation(_)));
        }
        #[cfg(unix)] // Unix-only: (dev, ino) file identity via MetadataExt.
        let identity = {
            use std::os::unix::fs::MetadataExt;
            let metadata = std::fs::metadata(&output).unwrap();
            (metadata.dev(), metadata.ino())
        };
        assert!(
            write_discovered_to_config(
                std::slice::from_ref(&server),
                Some(&output),
                CommentLoss::Refuse
            )
            .is_err()
        );
        assert_eq!(std::fs::read(&output).unwrap(), original.as_bytes());
        #[cfg(unix)] // Unix-only: (dev, ino) file identity via MetadataExt.
        {
            use std::os::unix::fs::MetadataExt;
            let metadata = std::fs::metadata(&output).unwrap();
            assert_eq!((metadata.dev(), metadata.ino()), identity);
        }
    }
}

#[test]
fn init_command_with_examples_includes_capabilities() {
    let dir = tempfile::tempdir().unwrap();
    let output = dir.path().join("gateway.yaml");
    let result = commands::run_init_command(&output, true, InitProfile::Local);
    assert_eq!(result, ExitCode::SUCCESS);
    let content = std::fs::read_to_string(&output).unwrap();
    assert!(content.contains("capabilities:"));
    assert!(content.contains("directories:"));
}

#[test]
fn init_command_without_examples_omits_sample_backends() {
    let dir = tempfile::tempdir().unwrap();
    let output = dir.path().join("gateway.yaml");
    let result = commands::run_init_command(&output, false, InitProfile::Local);
    assert_eq!(result, ExitCode::SUCCESS);
    let content = std::fs::read_to_string(&output).unwrap();
    assert!(content.contains("capabilities:"));
    assert!(!content.contains("filesystem:"));
}

#[test]
fn init_command_refuses_to_overwrite_existing() {
    let dir = tempfile::tempdir().unwrap();
    let output = dir.path().join("gateway.yaml");
    std::fs::write(&output, "existing content").unwrap();
    let result = commands::run_init_command(&output, true, InitProfile::Local);
    assert_eq!(result, ExitCode::FAILURE);
    let content = std::fs::read_to_string(&output).unwrap();
    assert_eq!(content, "existing content");
}

#[test]
fn init_command_custom_output_path() {
    let dir = tempfile::tempdir().unwrap();
    let output = dir.path().join("custom-config.yaml");
    let result = commands::run_init_command(&output, true, InitProfile::Local);
    assert_eq!(result, ExitCode::SUCCESS);
    assert!(output.exists());
}

// MIK-6700 review #2: `audit verify` must FAIL CLOSED on a config load error,
// never silently downgrade to hash-only. An explicit --config path that does
// not exist is a load error, so resolve_audit_log_config returns Err (the
// Verify arm then exits non-zero rather than verifying hash-only).
#[test]
fn audit_config_load_failure_is_fail_closed() {
    let missing = std::path::Path::new("/nonexistent/mcp-gateway/does-not-exist.yaml");
    let result = resolve_audit_log_config(Some(missing));
    assert!(
        result.is_err(),
        "a missing explicit config path must be an Err (fail closed), not a default empty-secret config"
    );
}

// MIK-6742: `stats` used to default `--url` to a hardcoded
// `http://127.0.0.1:39400`, completely independent of `--config`. Running
// `mcp-gateway --config X stats` therefore silently talked to whatever else
// was listening on 39400 instead of the gateway `X` describes — returning
// that unrelated server's error (observed as a confusing 406 Not Acceptable
// against a real deployment where 39400 was already taken by a different
// process). These tests pin `resolve_stats_url`'s config-derived behavior so
// that regression can't come back unnoticed.

/// GIVEN an explicit `--url`
/// WHEN resolving the stats URL
/// THEN the explicit URL always wins, regardless of any config.
#[test]
fn resolve_stats_url_explicit_url_overrides_config() {
    let resolved = resolve_stats_url(Some("http://10.0.0.5:1234".to_string()), None, None, None);
    assert_eq!(resolved, "http://10.0.0.5:1234");
}

/// GIVEN no `--url` and no `--config` (and no config discoverable on disk)
/// WHEN resolving the stats URL
/// THEN it falls back to the same default gateway `serve` would use when
/// unconfigured (127.0.0.1:39400) — unchanged legacy behavior.
/// Serializes tests that mutate the process-global current directory.
/// `set_current_dir` is process-wide, so two such tests running in parallel
/// race: one captures `orig` while another has already chdir'd into a tempdir
/// that is then dropped/deleted, making the `orig` restore fail with `NotFound`.
/// Holding this lock for the whole chdir/restore window keeps `orig` valid.
static CWD_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[test]
fn resolve_stats_url_no_url_no_config_falls_back_to_default() {
    let _cwd = CWD_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let dir = tempfile::tempdir().unwrap();
    let orig = std::env::current_dir().unwrap();
    // Run from an empty directory so `Config::load(None)`'s well-known
    // fallback search does not pick up a stray gateway.yaml from the repo.
    std::env::set_current_dir(dir.path()).unwrap();
    let resolved = resolve_stats_url(None, None, None, None);
    std::env::set_current_dir(&orig).unwrap();
    assert_eq!(resolved, "http://127.0.0.1:39400");
}

/// GIVEN a `--config` file whose `server.port` is NOT the hardcoded default
/// (the exact MIK-6742 repro: `serve --config X` bound to a free, non-39400
/// port)
/// WHEN resolving the stats URL with no explicit `--url`
/// THEN the resolved URL carries the configured port — this is the
/// regression test that would have caught the original bug, where `stats`
/// ignored `--config` entirely.
#[test]
fn resolve_stats_url_no_url_derives_port_from_config_file() {
    let dir = tempfile::tempdir().unwrap();
    let config_path = dir.path().join("gateway.yaml");
    mcp_gateway::gateway::test_helpers::write_owner_only(
        &config_path,
        "server:\n  host: \"127.0.0.1\"\n  port: 39477\n",
    )
    .unwrap();

    let resolved = resolve_stats_url(None, Some(&config_path), None, None);

    assert_eq!(resolved, "http://127.0.0.1:39477");
}

/// GIVEN a `--config` file bound to a wildcard host (`0.0.0.0`)
/// WHEN resolving the stats URL
/// THEN the client-facing URL uses loopback, since a client cannot dial
/// `0.0.0.0` as a destination address.
#[test]
fn resolve_stats_url_no_url_translates_wildcard_bind_host() {
    let dir = tempfile::tempdir().unwrap();
    let config_path = dir.path().join("gateway.yaml");
    mcp_gateway::gateway::test_helpers::write_owner_only(
        &config_path,
        "server:\n  host: \"0.0.0.0\"\n  port: 39400\n",
    )
    .unwrap();

    let resolved = resolve_stats_url(None, Some(&config_path), None, None);

    assert_eq!(resolved, "http://127.0.0.1:39400");
}

/// GIVEN no `--url` and a `--port` CLI override (no `--config`)
/// WHEN resolving the stats URL
/// THEN the override port is reflected, mirroring the override `serve`
/// would apply via `apply_cli_overrides`.
#[test]
fn resolve_stats_url_no_url_applies_port_override() {
    let _cwd = CWD_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let dir = tempfile::tempdir().unwrap();
    let orig = std::env::current_dir().unwrap();
    std::env::set_current_dir(dir.path()).unwrap();
    let resolved = resolve_stats_url(None, None, Some(9999), None);
    std::env::set_current_dir(&orig).unwrap();
    assert_eq!(resolved, "http://127.0.0.1:9999");
}

fn make_cli_with_config(config: Option<std::path::PathBuf>) -> Cli {
    Cli {
        config,
        port: None,
        host: None,
        log_level: "info".to_string(),
        log_format: None,
        no_meta_mcp: false,
        command: None,
    }
}

#[test]
fn serve_config_path_none_stays_none() {
    let cli = make_cli_with_config(None);
    assert_eq!(serve_config_path(&cli), None);
}

#[test]
fn serve_config_path_missing_downgrades_to_none() {
    // Glama passes --config /config.yaml with no such file; serve must not
    // fail-loud on it (that reported a spurious "build failed").
    let cli = make_cli_with_config(Some(std::path::PathBuf::from(
        "/nonexistent/does-not-exist-config.yaml",
    )));
    assert_eq!(serve_config_path(&cli), None);
}

#[test]
fn serve_config_path_existing_is_preserved() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.yaml");
    mcp_gateway::gateway::test_helpers::write_owner_only(&path, "server:\n  port: 8080\n").unwrap();
    let cli = make_cli_with_config(Some(path.clone()));
    assert_eq!(serve_config_path(&cli), Some(path));
}

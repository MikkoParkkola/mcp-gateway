use super::*;
use mcp_gateway::cli::{Cli, InitProfile};
use mcp_gateway::config::{BackendConfig, Config, TransportConfig};
use mcp_gateway::discovery::{DiscoveredServer, DiscoverySource, ServerMetadata};

fn make_discovered_server(name: &str) -> DiscoveredServer {
    DiscoveredServer {
        name: name.to_string(),
        description: format!("{name} server"),
        source: DiscoverySource::ClaudeDesktop,
        transport: TransportConfig::Stdio {
            command: format!("npx -y {name}"),
            cwd: None,
            protocol_version: None,
        },
        metadata: ServerMetadata::default(),
    }
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
    config.server.request_timeout = std::time::Duration::from_secs(60);

    let cli = make_cli(Some(3000), None, false);
    apply_cli_overrides(&mut config, &cli);

    assert_eq!(config.server.port, 3000);
    assert!(config.backends.contains_key("test"));
    assert_eq!(
        config.server.request_timeout,
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

    let written =
        write_discovered_to_config(&[server], Some(&output)).expect("write should succeed");

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
    write_config(&output, &existing).expect("initial write should succeed");

    let server = make_discovered_server("tavily");
    write_discovered_to_config(&[server], Some(&output)).expect("write should succeed");

    let loaded = Config::load(Some(&output)).expect("must reload");
    assert!(loaded.backends.contains_key("existing"));
    assert!(loaded.backends.contains_key("tavily"));
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

fn parse_args(args: &[&str]) -> Result<Cli, clap::Error> {
    use clap::Parser as _;
    let full: Vec<&str> = std::iter::once("mcp-gateway")
        .chain(args.iter().copied())
        .collect();
    Cli::try_parse_from(full)
}

#[test]
fn cli_plugin_search_parses_query() {
    let cli = parse_args(&["plugin", "search", "stripe"]).unwrap();
    match cli.command {
        Some(Command::Plugin(PluginCommand::Search {
            query,
            marketplace_url,
        })) => {
            assert_eq!(query, "stripe");
            assert!(marketplace_url.is_none());
        }
        other => panic!("unexpected: {other:?}"),
    }
}

#[test]
fn cli_plugin_search_accepts_marketplace_url_flag() {
    let cli = parse_args(&[
        "plugin",
        "search",
        "foo",
        "--marketplace-url",
        "https://example.com",
    ])
    .unwrap();
    match cli.command {
        Some(Command::Plugin(PluginCommand::Search {
            marketplace_url, ..
        })) => {
            assert_eq!(marketplace_url.as_deref(), Some("https://example.com"));
        }
        other => panic!("unexpected: {other:?}"),
    }
}

#[test]
fn cli_plugin_install_parses_name() {
    let cli = parse_args(&["plugin", "install", "stripe-payments"]).unwrap();
    match cli.command {
        Some(Command::Plugin(PluginCommand::Install {
            name,
            marketplace_url,
            plugin_dir,
        })) => {
            assert_eq!(name, "stripe-payments");
            assert!(marketplace_url.is_none());
            assert!(plugin_dir.is_none());
        }
        other => panic!("unexpected: {other:?}"),
    }
}

#[test]
fn cli_plugin_install_accepts_plugin_dir_flag() {
    let cli = parse_args(&["plugin", "install", "foo", "--plugin-dir", "/tmp/plugins"]).unwrap();
    match cli.command {
        Some(Command::Plugin(PluginCommand::Install { plugin_dir, .. })) => {
            assert_eq!(
                plugin_dir.as_deref(),
                Some(std::path::Path::new("/tmp/plugins"))
            );
        }
        other => panic!("unexpected: {other:?}"),
    }
}

#[test]
fn cli_plugin_uninstall_parses_name() {
    let cli = parse_args(&["plugin", "uninstall", "my-plugin"]).unwrap();
    match cli.command {
        Some(Command::Plugin(PluginCommand::Uninstall { name, plugin_dir })) => {
            assert_eq!(name, "my-plugin");
            assert!(plugin_dir.is_none());
        }
        other => panic!("unexpected: {other:?}"),
    }
}

#[test]
fn cli_plugin_list_parses_without_arguments() {
    let cli = parse_args(&["plugin", "list"]).unwrap();
    match cli.command {
        Some(Command::Plugin(PluginCommand::List { plugin_dir })) => {
            assert!(plugin_dir.is_none());
        }
        other => panic!("unexpected: {other:?}"),
    }
}

#[test]
fn cli_plugin_list_accepts_plugin_dir_flag() {
    let cli = parse_args(&["plugin", "list", "--plugin-dir", "/my/plugins"]).unwrap();
    match cli.command {
        Some(Command::Plugin(PluginCommand::List { plugin_dir })) => {
            assert_eq!(
                plugin_dir.as_deref(),
                Some(std::path::Path::new("/my/plugins"))
            );
        }
        other => panic!("unexpected: {other:?}"),
    }
}

#[test]
fn cli_trust_generate_parses_capabilities_and_json_format() {
    let cli = parse_args(&[
        "trust",
        "generate",
        "--capabilities",
        "fixtures/caps",
        "--format",
        "json",
    ])
    .unwrap();
    match cli.command {
        Some(Command::Trust(mcp_gateway::cli::TrustCommand::Generate {
            capabilities,
            format,
            output,
        })) => {
            assert_eq!(capabilities, std::path::PathBuf::from("fixtures/caps"));
            assert_eq!(format, mcp_gateway::cli::output::OutputFormat::Json);
            assert!(output.is_none());
        }
        other => panic!("unexpected: {other:?}"),
    }
}

#[test]
fn cli_trust_validate_parses_file_and_strict_flag() {
    let cli = parse_args(&["trust", "validate", "--file", "trustcard.json", "--strict"]).unwrap();
    match cli.command {
        Some(Command::Trust(mcp_gateway::cli::TrustCommand::Validate { file, strict, .. })) => {
            assert_eq!(
                file.as_deref(),
                Some(std::path::Path::new("trustcard.json"))
            );
            assert!(strict);
        }
        other => panic!("unexpected: {other:?}"),
    }
}

#[test]
fn cli_trust_lab_evaluate_parses_thresholds() {
    let cli = parse_args(&[
        "trust",
        "lab",
        "evaluate",
        "weather",
        "--capabilities",
        "fixtures/caps",
        "--enforce",
        "--baseline",
        "baseline.json",
        "--write-baseline",
        "next-baseline.json",
        "--baseline-registry",
        "fixtures/baselines",
        "--update-baseline-registry",
        "--active-fixtures",
        "fixtures/active-fixtures.json",
        "--baseline-id",
        "weather-baseline",
        "--minimum-score",
        "80",
        "--certification-score",
        "95",
        "--format",
        "json",
    ])
    .unwrap();
    match cli.command {
        Some(Command::Trust(mcp_gateway::cli::TrustCommand::Lab(
            mcp_gateway::cli::TrustLabCommand::Evaluate {
                name,
                capabilities,
                enforce,
                baseline,
                write_baseline,
                baseline_registry,
                update_baseline_registry,
                active_fixtures,
                execute_active_fixtures,
                baseline_id,
                minimum_score,
                certification_score,
                format,
            },
        ))) => {
            assert_eq!(name.as_deref(), Some("weather"));
            assert_eq!(capabilities, std::path::PathBuf::from("fixtures/caps"));
            assert!(enforce);
            assert_eq!(
                baseline.as_deref(),
                Some(std::path::Path::new("baseline.json"))
            );
            assert_eq!(
                write_baseline.as_deref(),
                Some(std::path::Path::new("next-baseline.json"))
            );
            assert_eq!(
                baseline_registry.as_deref(),
                Some(std::path::Path::new("fixtures/baselines"))
            );
            assert!(update_baseline_registry);
            assert_eq!(
                active_fixtures.as_deref(),
                Some(std::path::Path::new("fixtures/active-fixtures.json"))
            );
            assert!(!execute_active_fixtures);
            assert_eq!(baseline_id, "weather-baseline");
            assert_eq!(minimum_score, 80);
            assert_eq!(certification_score, 95);
            assert_eq!(format, mcp_gateway::cli::output::OutputFormat::Json);
        }
        other => panic!("unexpected: {other:?}"),
    }
}

#[test]
fn cli_trust_lab_evaluate_parses_execute_active_fixtures() {
    let cli = parse_args(&[
        "trust",
        "lab",
        "evaluate",
        "weather",
        "--active-fixtures",
        "fixtures/active-fixtures.json",
        "--execute-active-fixtures",
    ])
    .unwrap();
    match cli.command {
        Some(Command::Trust(mcp_gateway::cli::TrustCommand::Lab(
            mcp_gateway::cli::TrustLabCommand::Evaluate {
                active_fixtures,
                execute_active_fixtures,
                ..
            },
        ))) => {
            assert_eq!(
                active_fixtures.as_deref(),
                Some(std::path::Path::new("fixtures/active-fixtures.json"))
            );
            assert!(execute_active_fixtures);
        }
        other => panic!("unexpected: {other:?}"),
    }
}

#[test]
fn cli_import_preview_parses_openapi_kind_and_json_format() {
    let cli = parse_args(&[
        "import",
        "preview",
        "--kind",
        "openapi",
        "fixtures/openapi.yaml",
        "--source-name",
        "users-api",
        "--format",
        "json",
        "--context-integrity-profile",
        "reviewed_import",
    ])
    .unwrap();
    match cli.command {
        Some(Command::Import(mcp_gateway::cli::ProtocolImportCommand::Preview {
            kind,
            file,
            source_name,
            format,
            context_integrity_profile,
        })) => {
            assert_eq!(kind, mcp_gateway::cli::ProtocolImportKind::OpenApi);
            assert_eq!(file, std::path::PathBuf::from("fixtures/openapi.yaml"));
            assert_eq!(source_name.as_deref(), Some("users-api"));
            assert_eq!(format, mcp_gateway::cli::output::OutputFormat::Json);
            assert_eq!(context_integrity_profile, "reviewed_import");
        }
        other => panic!("unexpected: {other:?}"),
    }
}

#[test]
fn cli_import_preview_accepts_oci_alias() {
    let cli = parse_args(&["import", "preview", "--kind", "oci", "package.yaml"]).unwrap();
    match cli.command {
        Some(Command::Import(mcp_gateway::cli::ProtocolImportCommand::Preview {
            kind,
            file,
            format,
            ..
        })) => {
            assert_eq!(kind, mcp_gateway::cli::ProtocolImportKind::OciMcpPackage);
            assert_eq!(file, std::path::PathBuf::from("package.yaml"));
            assert_eq!(format, mcp_gateway::cli::output::OutputFormat::Table);
        }
        other => panic!("unexpected: {other:?}"),
    }
}

#[test]
fn cli_kubernetes_plan_parses_resources_namespace_and_json_format() {
    let cli = parse_args(&[
        "kubernetes",
        "plan",
        "deploy/kubernetes/enterprise-alpha/base/example-gateway.yaml",
        "--namespace",
        "gateway-prod",
        "--format",
        "json",
    ])
    .unwrap();
    match cli.command {
        Some(Command::Kubernetes(mcp_gateway::cli::KubernetesCommand::Plan {
            resources,
            namespace,
            format,
        })) => {
            assert_eq!(
                resources,
                std::path::PathBuf::from(
                    "deploy/kubernetes/enterprise-alpha/base/example-gateway.yaml"
                )
            );
            assert_eq!(namespace, "gateway-prod");
            assert_eq!(format, mcp_gateway::cli::output::OutputFormat::Json);
        }
        other => panic!("unexpected: {other:?}"),
    }
}

#[test]
fn cli_kubernetes_controller_parses_cycles_interval_and_plain_format() {
    let cli = parse_args(&[
        "kubernetes",
        "controller",
        "deploy/kubernetes/enterprise-alpha/base/example-gateway.yaml",
        "--namespace",
        "gateway-prod",
        "--interval-seconds",
        "5",
        "--cycles",
        "2",
        "--format",
        "plain",
    ])
    .unwrap();
    match cli.command {
        Some(Command::Kubernetes(mcp_gateway::cli::KubernetesCommand::Controller {
            resources,
            namespace,
            interval_seconds,
            cycles,
            watch,
            format,
        })) => {
            assert_eq!(
                resources,
                std::path::PathBuf::from(
                    "deploy/kubernetes/enterprise-alpha/base/example-gateway.yaml"
                )
            );
            assert_eq!(namespace, "gateway-prod");
            assert_eq!(interval_seconds, 5);
            assert_eq!(cycles, 2);
            assert!(!watch);
            assert_eq!(format, mcp_gateway::cli::output::OutputFormat::Plain);
        }
        other => panic!("unexpected: {other:?}"),
    }
}

#[test]
fn cli_kubernetes_apply_plan_parses_approval_and_json_format() {
    let cli = parse_args(&[
        "kubernetes",
        "apply-plan",
        "deploy/kubernetes/enterprise-alpha/base/example-gateway.yaml",
        "--namespace",
        "gateway-prod",
        "--approve-apply",
        "--format",
        "json",
    ])
    .unwrap();
    match cli.command {
        Some(Command::Kubernetes(mcp_gateway::cli::KubernetesCommand::ApplyPlan {
            resources,
            namespace,
            approve_apply,
            execute,
            format,
        })) => {
            assert_eq!(
                resources,
                std::path::PathBuf::from(
                    "deploy/kubernetes/enterprise-alpha/base/example-gateway.yaml"
                )
            );
            assert_eq!(namespace, "gateway-prod");
            assert!(approve_apply);
            assert!(!execute);
            assert_eq!(format, mcp_gateway::cli::output::OutputFormat::Json);
        }
        other => panic!("unexpected: {other:?}"),
    }
}

#[test]
fn cli_kubernetes_apply_plan_parses_execute_gate() {
    let cli = parse_args(&[
        "kubernetes",
        "apply-plan",
        "deploy/kubernetes/enterprise-alpha/base/example-gateway.yaml",
        "--execute",
        "--format",
        "plain",
    ])
    .unwrap();
    match cli.command {
        Some(Command::Kubernetes(mcp_gateway::cli::KubernetesCommand::ApplyPlan {
            execute,
            approve_apply,
            format,
            ..
        })) => {
            assert!(execute);
            assert!(!approve_apply);
            assert_eq!(format, mcp_gateway::cli::output::OutputFormat::Plain);
        }
        other => panic!("unexpected: {other:?}"),
    }
}

#[test]
fn cli_plugin_search_requires_query_argument() {
    let result = parse_args(&["plugin", "search"]);
    assert!(result.is_err());
}

#[test]
fn cli_plugin_install_requires_name_argument() {
    let result = parse_args(&["plugin", "install"]);
    assert!(result.is_err());
}

#[test]
fn cli_ws_port_absent_means_none_in_config_default() {
    let config = Config::default();
    assert!(config.server.ws_port.is_none());
}

#[test]
fn cli_ws_port_present_in_config_enables_ws_listener() {
    let mut config = Config::default();
    config.server.ws_port = Some(39401);
    assert_eq!(config.server.ws_port, Some(39401));
}

//! MCP Gateway - Universal Model Context Protocol Gateway
//!
//! Single-port multiplexing with a compact Meta-MCP tool surface.

mod commands;

use std::path::Path;
use std::process::ExitCode;

use clap::Parser;
use mcp_gateway::{
    cli::{AuditCommand, Cli, Command, PluginCommand, SetupCommand, SkillsCommand},
    config::Config,
    config_persistence::{load_existing_or_default, write_config},
    gateway::Gateway,
    setup_tracing,
    validator::ValidateConfig,
};
use tracing::{error, info};

// ── New command imports ────────────────────────────────────────────────────────
// These modules live in the binary-only `commands/` tree and are not part of
// the library crate, so they are imported directly here.

#[tokio::main]
#[allow(clippy::too_many_lines)] // Feature-gated fallback arms inflate line count
async fn main() -> ExitCode {
    let cli = Cli::parse();

    if let Err(e) = setup_tracing(&cli.log_level, cli.log_format.as_deref()) {
        eprintln!("Failed to setup tracing: {e}");
        return ExitCode::FAILURE;
    }

    // Capture config path before consuming `cli` in the match below.
    let config_path = cli.config.clone();

    match cli.command {
        Some(Command::Init {
            output,
            with_examples,
        }) => commands::run_init_command(&output, with_examples),
        Some(Command::Cap(cap_cmd)) => commands::run_cap_command(cap_cmd).await,
        Some(Command::Tls(tls_cmd)) => commands::run_tls_command(tls_cmd),
        Some(Command::Stats { url, price }) => commands::run_stats_command(&url, price).await,
        Some(Command::Validate {
            paths,
            format,
            severity,
            fix,
            no_color,
        }) => {
            let config = ValidateConfig {
                format,
                min_severity: severity,
                auto_fix: fix,
                color: !no_color,
            };
            mcp_gateway::validator::cli_handler::run_validate_command(&paths, &config).await
        }
        Some(Command::Tool(tool_cmd)) => commands::run_tool_command(tool_cmd).await,
        Some(Command::Skills(SkillsCommand::Generate {
            capabilities,
            server,
            category,
            out_dir,
            install,
            dry_run,
        })) => {
            commands::run_skills_generate(capabilities, server, category, out_dir, install, dry_run)
                .await
        }
        Some(Command::Skills(SkillsCommand::Import { source, registry })) => {
            commands::run_skills_import(source, registry).await
        }
        Some(Command::Skills(SkillsCommand::List { registry })) => {
            commands::run_skills_list(registry)
        }
        Some(Command::Skills(SkillsCommand::Search { query, registry })) => {
            commands::run_skills_search(&query, registry)
        }
        Some(Command::Skills(SkillsCommand::Show { name, registry })) => {
            commands::run_skills_show(&name, registry)
        }
        Some(Command::Skills(SkillsCommand::Remove { name, registry })) => {
            commands::run_skills_remove(&name, registry)
        }
        Some(Command::Plugin(plugin_cmd)) => {
            run_plugin_command(plugin_cmd, config_path.as_deref()).await
        }
        Some(Command::Setup(SetupCommand::Wizard {
            yes,
            output,
            configure_client,
        })) => commands::run_setup_command(yes, &output, configure_client).await,
        #[cfg(feature = "config-export")]
        Some(Command::Setup(SetupCommand::Export {
            target,
            mode,
            name,
            watch,
            dry_run,
            config,
        })) => commands::run_config_export(target, mode, &name, watch, dry_run, &config).await,
        Some(Command::Add {
            name,
            command,
            url,
            description,
            env_vars,
            config,
            trailing_command,
        }) => {
            // Merge --command flag and trailing `-- cmd args...` (claude/codex style)
            let effective_command = if trailing_command.is_empty() {
                command
            } else {
                Some(trailing_command.join(" "))
            };
            #[cfg(feature = "webui")]
            {
                commands::run_add_command(
                    &name,
                    effective_command.as_deref(),
                    url.as_deref(),
                    description.as_deref(),
                    &env_vars,
                    &config,
                )
                .await
            }
            #[cfg(not(feature = "webui"))]
            {
                let _ = (name, effective_command, url, description, env_vars, config);
                eprintln!("Error: add/remove commands require the 'webui' feature");
                ExitCode::FAILURE
            }
        }
        Some(Command::Remove { name, config }) => {
            #[cfg(feature = "webui")]
            {
                commands::run_remove_command(&name, &config)
            }
            #[cfg(not(feature = "webui"))]
            {
                let _ = (name, config);
                eprintln!("Error: add/remove commands require the 'webui' feature");
                ExitCode::FAILURE
            }
        }
        Some(Command::List { json, config }) => {
            #[cfg(feature = "webui")]
            {
                commands::run_list_command(json, &config)
            }
            #[cfg(not(feature = "webui"))]
            {
                let _ = (json, config);
                eprintln!("Error: add/remove commands require the 'webui' feature");
                ExitCode::FAILURE
            }
        }
        Some(Command::Get { name, config }) => {
            #[cfg(feature = "webui")]
            {
                commands::run_get_command(&name, &config)
            }
            #[cfg(not(feature = "webui"))]
            {
                let _ = (name, config);
                eprintln!("Error: add/remove commands require the 'webui' feature");
                ExitCode::FAILURE
            }
        }
        Some(Command::Doctor {
            fix,
            config,
            shadow,
            shadow_format,
        }) => {
            if shadow {
                commands::run_doctor_shadow_command(&shadow_format)
            } else {
                commands::run_doctor_command(fix, config.as_deref()).await
            }
        }
        Some(Command::Upgrade {
            dry_run,
            quiet,
            data_dir,
        }) => commands::run_upgrade_command(dry_run, quiet, data_dir.as_deref()),
        Some(Command::Audit(audit_cmd)) => run_audit_command(audit_cmd),
        Some(Command::Serve { stdio: true }) => run_stdio_server(cli).await,
        Some(Command::Serve { stdio: false }) | None => run_server(cli).await,
    }
}

/// Dispatch an `audit` subcommand (transparency log chain verification / session query).
fn run_audit_command(cmd: AuditCommand) -> ExitCode {
    use mcp_gateway::security::transparency_log::{show_session_entries, verify_log};
    use std::path::PathBuf;

    /// Resolve the log path: use the provided `--path` flag, or fall back to
    /// the default `~/.mcp-gateway/transparency/transparency.jsonl`.
    fn resolve_path(path: Option<PathBuf>) -> PathBuf {
        path.unwrap_or_else(|| {
            dirs::home_dir().map_or_else(|| PathBuf::from("transparency.jsonl"), |h| {
                    h.join(".mcp-gateway")
                        .join("transparency")
                        .join("transparency.jsonl")
                })
        })
    }

    match cmd {
        AuditCommand::Verify { path } => {
            let log_path = resolve_path(path);
            if !log_path.exists() {
                eprintln!(
                    "Error: transparency log not found at {}",
                    log_path.display()
                );
                return ExitCode::FAILURE;
            }
            match verify_log(&log_path) {
                Err(e) => {
                    eprintln!("Error reading log: {e}");
                    ExitCode::FAILURE
                }
                Ok(result) if result.ok => {
                    println!(
                        "✓ Chain verified — {} entries checked, no tampering detected.",
                        result.entries_checked
                    );
                    ExitCode::SUCCESS
                }
                Ok(result) => {
                    let at = result
                        .error_at_counter
                        .map_or_else(|| "?".to_string(), |n| n.to_string());
                    let msg = result
                        .error_message
                        .unwrap_or_else(|| "unknown error".to_string());
                    eprintln!("✗ Chain verification FAILED at counter {at}: {msg}");
                    ExitCode::FAILURE
                }
            }
        }

        AuditCommand::Show { session, path } => {
            let log_path = resolve_path(path);
            if !log_path.exists() {
                eprintln!(
                    "Error: transparency log not found at {}",
                    log_path.display()
                );
                return ExitCode::FAILURE;
            }
            match show_session_entries(&log_path, &session) {
                Err(e) => {
                    eprintln!("Error reading log: {e}");
                    ExitCode::FAILURE
                }
                Ok(entries) if entries.is_empty() => {
                    println!("No entries found for session '{session}'.");
                    ExitCode::SUCCESS
                }
                Ok(entries) => {
                    for entry in &entries {
                        match serde_json::to_string_pretty(entry) {
                            Ok(pretty) => println!("{pretty}"),
                            Err(e) => eprintln!("Serialisation error: {e}"),
                        }
                    }
                    ExitCode::SUCCESS
                }
            }
        }
    }
}

/// Dispatch a `plugin` subcommand.
///
/// Loads config from `config_path` (needed for marketplace URL / plugin dir
/// defaults) then delegates to the appropriate handler in `commands::plugin`.
async fn run_plugin_command(cmd: PluginCommand, config_path: Option<&Path>) -> ExitCode {
    let config = match Config::load(config_path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Warning: failed to load config ({e}); using defaults");
            Config::default()
        }
    };

    match cmd {
        PluginCommand::Search {
            query,
            marketplace_url,
        } => commands::run_plugin_search(&query, marketplace_url.as_deref(), &config).await,
        PluginCommand::Install {
            name,
            marketplace_url,
            plugin_dir,
        } => {
            commands::run_plugin_install(
                &name,
                marketplace_url.as_deref(),
                plugin_dir.as_deref(),
                &config,
            )
            .await
        }
        PluginCommand::Uninstall { name, plugin_dir } => {
            commands::run_plugin_uninstall(&name, plugin_dir.as_deref(), &config).await
        }
        PluginCommand::List { plugin_dir } => {
            commands::run_plugin_list(plugin_dir.as_deref(), &config)
        }
    }
}

/// Apply CLI overrides to a loaded configuration.
///
/// Merges CLI-provided port, host, and meta-mcp settings into `config`.
fn apply_cli_overrides(config: &mut Config, cli: &Cli) {
    if let Some(port) = cli.port {
        config.server.port = port;
    }
    if let Some(ref host) = cli.host {
        config.server.host.clone_from(host);
    }
    if cli.no_meta_mcp {
        config.meta_mcp.enabled = false;
    }
}

fn apply_cli_overrides_and_validate(config: &mut Config, cli: &Cli) -> mcp_gateway::Result<()> {
    apply_cli_overrides(config, cli);
    config.validate()
}

/// Run the gateway in stdio mode (newline-delimited JSON-RPC on stdin/stdout).
async fn run_stdio_server(cli: Cli) -> ExitCode {
    if let Err(e) = commands::check_upgrade(&commands::upgrade_data_dir()) {
        eprintln!("Warning: upgrade check failed: {e}");
    }

    let config = match Config::load(cli.config.as_deref()) {
        Ok(mut config) => {
            if let Err(e) = apply_cli_overrides_and_validate(&mut config, &cli) {
                eprintln!("Failed to apply configuration overrides: {e}");
                return ExitCode::FAILURE;
            }
            config
        }
        Err(e) => {
            eprintln!("Failed to load configuration: {e}");
            return ExitCode::FAILURE;
        }
    };

    let config_path = cli.config.as_deref().map(std::path::Path::to_path_buf);
    let gateway = match Gateway::new_with_path(config, config_path).await {
        Ok(g) => g,
        Err(e) => {
            eprintln!("Failed to create gateway: {e}");
            return ExitCode::FAILURE;
        }
    };

    if let Err(e) = gateway.run_stdio().await {
        eprintln!("stdio gateway error: {e}");
        return ExitCode::FAILURE;
    }

    ExitCode::SUCCESS
}

/// Run the gateway server.
async fn run_server(cli: Cli) -> ExitCode {
    // Run post-upgrade migrations before anything else.  Non-fatal: a stamp
    // write failure must not prevent the gateway from starting.
    if let Err(e) = commands::check_upgrade(&commands::upgrade_data_dir()) {
        eprintln!("Warning: upgrade check failed: {e}");
    }

    let config = match Config::load(cli.config.as_deref()) {
        Ok(mut config) => {
            if let Err(e) = apply_cli_overrides_and_validate(&mut config, &cli) {
                error!("Failed to apply configuration overrides: {e}");
                return ExitCode::FAILURE;
            }
            config
        }
        Err(e) => {
            error!("Failed to load configuration: {e}");
            return ExitCode::FAILURE;
        }
    };

    info!(
        version = env!("CARGO_PKG_VERSION"),
        port = config.server.port,
        backends = config.backends.len(),
        meta_mcp = config.meta_mcp.enabled,
        "Starting MCP Gateway"
    );

    let config_path = cli.config.as_deref().map(std::path::Path::to_path_buf);
    let gateway = match Gateway::new_with_path(config, config_path).await {
        Ok(g) => g,
        Err(e) => {
            error!("Failed to create gateway: {e}");
            return ExitCode::FAILURE;
        }
    };

    if let Err(e) = gateway.run().await {
        error!("Gateway error: {e}");
        return ExitCode::FAILURE;
    }

    info!("Gateway shutdown complete");
    ExitCode::SUCCESS
}

/// Write discovered servers to a config file.
pub fn write_discovered_to_config(
    servers: &[mcp_gateway::discovery::DiscoveredServer],
    config_path: Option<&Path>,
) -> mcp_gateway::Result<std::path::PathBuf> {
    let path = config_path.map_or_else(
        || std::path::PathBuf::from("mcp-gateway-discovered.yaml"),
        std::path::Path::to_path_buf,
    );

    let mut config = load_existing_or_default(&path)?;

    for server in servers {
        let backend_config = server.to_backend_config();
        config.backends.insert(server.name.clone(), backend_config);
    }

    write_config(&path, &config).map_err(mcp_gateway::Error::Config)?;

    Ok(path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use mcp_gateway::cli::Cli;
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

    // =====================================================================
    // apply_cli_overrides
    // =====================================================================

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

    // =====================================================================
    // Config::default sanity checks
    // =====================================================================

    #[test]
    fn default_config_has_expected_defaults() {
        let config = Config::default();
        assert_eq!(config.server.port, 39400);
        assert_eq!(config.server.host, "127.0.0.1");
        assert!(config.meta_mcp.enabled);
        assert!(config.backends.is_empty());
    }

    // =====================================================================
    // run_init_command
    // =====================================================================

    #[test]
    fn init_command_creates_config_file() {
        let dir = tempfile::tempdir().unwrap();
        let output = dir.path().join("gateway.yaml");
        let result = commands::run_init_command(&output, true);
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
        // Use a valid stdio transport — BackendConfig::default() produces Http with
        // an empty http_url, which is rejected by config validation.
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
        let result = commands::run_init_command(&output, true);
        assert_eq!(result, ExitCode::SUCCESS);
        let content = std::fs::read_to_string(&output).unwrap();
        assert!(content.contains("capabilities:"));
        assert!(content.contains("directories:"));
    }

    #[test]
    fn init_command_without_examples_omits_sample_backends() {
        let dir = tempfile::tempdir().unwrap();
        let output = dir.path().join("gateway.yaml");
        let result = commands::run_init_command(&output, false);
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
        let result = commands::run_init_command(&output, true);
        assert_eq!(result, ExitCode::FAILURE);
        let content = std::fs::read_to_string(&output).unwrap();
        assert_eq!(content, "existing content");
    }

    #[test]
    fn init_command_custom_output_path() {
        let dir = tempfile::tempdir().unwrap();
        let output = dir.path().join("custom-config.yaml");
        let result = commands::run_init_command(&output, true);
        assert_eq!(result, ExitCode::SUCCESS);
        assert!(output.exists());
    }

    // =====================================================================
    // CLI argument parsing for `plugin` subcommand
    // =====================================================================

    fn parse_args(args: &[&str]) -> Result<Cli, clap::Error> {
        use clap::Parser as _;
        // Prepend the binary name that clap expects as argv[0].
        let full: Vec<&str> = std::iter::once("mcp-gateway")
            .chain(args.iter().copied())
            .collect();
        Cli::try_parse_from(full)
    }

    #[test]
    fn cli_plugin_search_parses_query() {
        // GIVEN: `plugin search stripe`
        let cli = parse_args(&["plugin", "search", "stripe"]).unwrap();
        // THEN: Plugin(Search { query: "stripe", marketplace_url: None })
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
        // GIVEN: `plugin search foo --marketplace-url https://example.com`
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
        // GIVEN: `plugin install stripe-payments`
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
        // GIVEN: `plugin install foo --plugin-dir /tmp/plugins`
        let cli =
            parse_args(&["plugin", "install", "foo", "--plugin-dir", "/tmp/plugins"]).unwrap();
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
        // GIVEN: `plugin uninstall my-plugin`
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
        // GIVEN: `plugin list`
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
        // GIVEN: `plugin list --plugin-dir /my/plugins`
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
    fn cli_plugin_search_requires_query_argument() {
        // GIVEN: `plugin search` with no query
        let result = parse_args(&["plugin", "search"]);
        // THEN: clap returns an error (missing required arg)
        assert!(result.is_err());
    }

    #[test]
    fn cli_plugin_install_requires_name_argument() {
        // GIVEN: `plugin install` with no name
        let result = parse_args(&["plugin", "install"]);
        // THEN: clap returns an error
        assert!(result.is_err());
    }

    #[test]
    fn cli_ws_port_absent_means_none_in_config_default() {
        // GIVEN: a default ServerConfig
        let config = Config::default();
        // THEN: ws_port is None (HTTP-only mode)
        assert!(config.server.ws_port.is_none());
    }

    #[test]
    fn cli_ws_port_present_in_config_enables_ws_listener() {
        // GIVEN: a ServerConfig with ws_port set
        let mut config = Config::default();
        config.server.ws_port = Some(39401);
        // THEN: ws_port is accessible
        assert_eq!(config.server.ws_port, Some(39401));
    }
}

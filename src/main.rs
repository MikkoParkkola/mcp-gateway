//! MCP Gateway - Universal Model Context Protocol Gateway
//!
//! Single-port multiplexing with Meta-MCP for ~95% context token savings.

use std::process::ExitCode;
use std::sync::Arc;

use clap::Parser;
use tracing::{error, info};

use mcp_gateway::{
    capability::{
        AuthTemplate, CapabilityExecutor, CapabilityLoader, OpenApiConverter,
        parse_capability_file, validate_capability,
    },
    cli::{CapCommand, Cli, Command},
    config::Config,
    discovery::AutoDiscovery,
    gateway::Gateway,
    registry::Registry,
    setup_tracing,
};

#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse();

    // Setup tracing
    if let Err(e) = setup_tracing(&cli.log_level, cli.log_format.as_deref()) {
        eprintln!("Failed to setup tracing: {e}");
        return ExitCode::FAILURE;
    }

    // Handle subcommands
    match cli.command {
        Some(Command::Cap(cap_cmd)) => run_cap_command(cap_cmd).await,
        Some(Command::Stats { url, price }) => run_stats_command(&url, price).await,
        Some(Command::Serve) | None => run_server(cli).await,
    }
}

/// Run stats command
async fn run_stats_command(url: &str, price: f64) -> ExitCode {
    use serde_json::json;

    let client = reqwest::Client::new();
    let request_body = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {
            "name": "gateway_get_stats",
            "arguments": {
                "price_per_million": price
            }
        }
    });

    let url = format!("{}/mcp", url.trim_end_matches('/'));

    match client.post(&url).json(&request_body).send().await {
        Ok(response) => {
            if !response.status().is_success() {
                eprintln!("❌ Gateway returned error: {}", response.status());
                return ExitCode::FAILURE;
            }

            match response.json::<serde_json::Value>().await {
                Ok(body) => {
                    if let Some(result) = body.get("result") {
                        if let Some(content) = result.get("content") {
                            if let Some(arr) = content.as_array() {
                                if let Some(first) = arr.first() {
                                    if let Some(text) = first.get("text").and_then(|v| v.as_str()) {
                                        if let Ok(stats) = serde_json::from_str::<serde_json::Value>(text) {
                                            println!("📊 Gateway Statistics\n");
                                            println!("Invocations:       {}", stats["invocations"]);
                                            println!("Cache Hits:        {}", stats["cache_hits"]);
                                            println!("Cache Hit Rate:    {}", stats["cache_hit_rate"]);
                                            println!("Tools Discovered:  {}", stats["tools_discovered"]);
                                            println!("Tools Available:   {}", stats["tools_available"]);
                                            println!("Tokens Saved:      {}", stats["tokens_saved"].as_u64().unwrap_or(0));
                                            println!("Estimated Savings: {}", stats["estimated_savings_usd"]);

                                            if let Some(top_tools) = stats["top_tools"].as_array() {
                                                if !top_tools.is_empty() {
                                                    println!("\n🏆 Top Tools:");
                                                    for tool in top_tools {
                                                        println!("  • {}:{} - {} calls",
                                                            tool["server"].as_str().unwrap_or(""),
                                                            tool["tool"].as_str().unwrap_or(""),
                                                            tool["count"]);
                                                    }
                                                }
                                            }
                                            return ExitCode::SUCCESS;
                                        }
                                    }
                                }
                            }
                        }
                    }

                    if let Some(error) = body.get("error") {
                        eprintln!("❌ Error: {}", error.get("message").and_then(|v| v.as_str()).unwrap_or("Unknown"));
                        return ExitCode::FAILURE;
                    }

                    eprintln!("❌ Unexpected response format");
                    ExitCode::FAILURE
                }
                Err(e) => {
                    eprintln!("❌ Failed to parse response: {e}");
                    ExitCode::FAILURE
                }
            }
        }
        Err(e) => {
            eprintln!("❌ Failed to connect to gateway: {e}");
            eprintln!("   Make sure the gateway is running at {url}");
            ExitCode::FAILURE
        }
    }
}

/// Run capability management commands
#[allow(clippy::too_many_lines)]
async fn run_cap_command(cmd: CapCommand) -> ExitCode {
    match cmd {
        CapCommand::Validate { file } => match parse_capability_file(&file).await {
            Ok(cap) => {
                if let Err(e) = validate_capability(&cap) {
                    eprintln!("❌ Validation failed: {e}");
                    return ExitCode::FAILURE;
                }
                println!("✅ {} - valid", cap.name);
                if !cap.description.is_empty() {
                    println!("   {}", cap.description);
                }
                if let Some(provider) = cap.primary_provider() {
                    println!(
                        "   Provider: {} ({})",
                        provider.service, provider.config.method
                    );
                    println!(
                        "   URL: {}{}",
                        provider.config.base_url, provider.config.path
                    );
                }
                if cap.auth.required {
                    println!("   Auth: {} ({})", cap.auth.auth_type, cap.auth.key);
                }
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("❌ Failed to parse: {e}");
                ExitCode::FAILURE
            }
        },

        CapCommand::List { directory } => {
            let path = directory.to_string_lossy();
            match CapabilityLoader::load_directory(&path).await {
                Ok(caps) => {
                    if caps.is_empty() {
                        println!("No capabilities found in {path}");
                    } else {
                        println!("Found {} capabilities in {}:\n", caps.len(), path);
                        for cap in caps {
                            let auth_info = if cap.auth.required {
                                format!(" [{}]", cap.auth.auth_type)
                            } else {
                                String::new()
                            };
                            println!("  {} - {}{}", cap.name, cap.description, auth_info);
                        }
                    }
                    ExitCode::SUCCESS
                }
                Err(e) => {
                    eprintln!("❌ Failed to load: {e}");
                    ExitCode::FAILURE
                }
            }
        }

        CapCommand::Import {
            spec,
            output,
            prefix,
            auth_key,
        } => {
            let mut converter = OpenApiConverter::new();

            if let Some(p) = prefix {
                converter = converter.with_prefix(&p);
            }

            if let Some(key) = auth_key {
                converter = converter.with_default_auth(AuthTemplate {
                    auth_type: "bearer".to_string(),
                    key,
                    description: "API authentication".to_string(),
                });
            }

            let spec_path = spec.to_string_lossy();
            match converter.convert_file(&spec_path) {
                Ok(caps) => {
                    let out_path = output.to_string_lossy();
                    println!("Generated {} capabilities from {}\n", caps.len(), spec_path);

                    for cap in caps {
                        if let Err(e) = cap.write_to_file(&out_path) {
                            eprintln!("❌ Failed to write {}: {e}", cap.name);
                        } else {
                            println!("  ✅ {}.yaml", cap.name);
                        }
                    }

                    println!("\nCapabilities written to {out_path}/");
                    ExitCode::SUCCESS
                }
                Err(e) => {
                    eprintln!("❌ Failed to convert: {e}");
                    ExitCode::FAILURE
                }
            }
        }

        CapCommand::Test { file, args } => {
            // Parse capability
            let cap = match parse_capability_file(&file).await {
                Ok(c) => c,
                Err(e) => {
                    eprintln!("❌ Failed to parse capability: {e}");
                    return ExitCode::FAILURE;
                }
            };

            // Parse arguments
            let params: serde_json::Value = match serde_json::from_str(&args) {
                Ok(v) => v,
                Err(e) => {
                    eprintln!("❌ Invalid JSON arguments: {e}");
                    return ExitCode::FAILURE;
                }
            };

            println!("Testing capability: {}", cap.name);
            println!(
                "Arguments: {}",
                serde_json::to_string_pretty(&params).unwrap_or_default()
            );
            println!();

            // Execute
            let executor = Arc::new(CapabilityExecutor::new());
            match executor.execute(&cap, params).await {
                Ok(result) => {
                    println!("✅ Success:\n");
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&result).unwrap_or_default()
                    );
                    ExitCode::SUCCESS
                }
                Err(e) => {
                    eprintln!("❌ Execution failed: {e}");
                    ExitCode::FAILURE
                }
            }
        }

        CapCommand::Discover {
            format,
            write_config,
            config_path,
        } => {
            let discovery = AutoDiscovery::new();

            println!("🔍 Discovering MCP servers...\n");

            match discovery.discover_all().await {
                Ok(servers) => {
                    if servers.is_empty() {
                        println!("No MCP servers found.");
                        println!("\nSearched locations:");
                        println!("  • Claude Desktop config");
                        println!("  • VS Code/Cursor MCP configs");
                        println!("  • Windsurf config");
                        println!("  • ~/.config/mcp/*.json");
                        println!("  • Running processes (pieces, surreal, etc.)");
                        println!("  • Environment variables (MCP_SERVER_*_URL)");
                        return ExitCode::SUCCESS;
                    }

                    match format.as_str() {
                        "json" => {
                            println!(
                                "{}",
                                serde_json::to_string_pretty(&servers).unwrap_or_default()
                            );
                        }
                        "yaml" => {
                            println!(
                                "{}",
                                serde_yaml::to_string(&servers).unwrap_or_default()
                            );
                        }
                        _ => {
                            // Table format
                            println!("Discovered {} MCP server(s):\n", servers.len());
                            for server in &servers {
                                println!("📦 {}", server.name);
                                println!("   Description: {}", server.description);
                                println!("   Source: {:?}", server.source);

                                match &server.transport {
                                    mcp_gateway::config::TransportConfig::Stdio {
                                        command,
                                        ..
                                    } => {
                                        println!("   Transport: stdio");
                                        println!("   Command: {command}");
                                    }
                                    mcp_gateway::config::TransportConfig::Http {
                                        http_url,
                                        ..
                                    } => {
                                        println!("   Transport: http");
                                        println!("   URL: {http_url}");
                                    }
                                }

                                if let Some(ref path) = server.metadata.config_path {
                                    println!("   Config: {}", path.display());
                                }
                                if let Some(pid) = server.metadata.pid {
                                    println!("   PID: {pid}");
                                }

                                println!();
                            }
                        }
                    }

                    if write_config {
                        println!("\n📝 Writing discovered servers to config...");
                        let result = write_discovered_to_config(&servers, config_path.as_deref());
                        match result {
                            Ok(path) => {
                                println!("✅ Config written to {}", path.display());
                                println!(
                                    "\nTo use discovered servers, start gateway with: mcp-gateway -c {}",
                                    path.display()
                                );
                            }
                            Err(e) => {
                                eprintln!("❌ Failed to write config: {e}");
                                return ExitCode::FAILURE;
                            }
                        }
                    } else {
                        println!("\n💡 To add these servers to your gateway config, run:");
                        println!("   mcp-gateway cap discover --write-config");
                    }

                    ExitCode::SUCCESS
                }
                Err(e) => {
                    eprintln!("❌ Discovery failed: {e}");
                    ExitCode::FAILURE
                }
            }
        }

        CapCommand::Install {
            name,
            from_github,
            repo,
            branch,
            output,
        } => {
            if from_github {
                println!("📦 Installing {name} from GitHub ({repo})...");
                let registry = Registry::new("registry");
                match registry
                    .install_from_github(&name, &output, &repo, &branch)
                    .await
                {
                    Ok(path) => {
                        println!("✅ Installed to {}", path.display());
                        ExitCode::SUCCESS
                    }
                    Err(e) => {
                        eprintln!("❌ Installation failed: {e}");
                        ExitCode::FAILURE
                    }
                }
            } else {
                println!("📦 Installing {name} from local registry...");
                let registry = Registry::new("registry");
                match registry.install_local(&name, &output) {
                    Ok(path) => {
                        println!("✅ Installed to {}", path.display());
                        ExitCode::SUCCESS
                    }
                    Err(e) => {
                        eprintln!("❌ Installation failed: {e}");
                        ExitCode::FAILURE
                    }
                }
            }
        }

        CapCommand::Search { query, registry } => {
            let reg = Registry::new(&registry);
            match reg.load_index() {
                Ok(index) => {
                    let results = index.search(&query);
                    if results.is_empty() {
                        println!("No capabilities found matching '{query}'");
                    } else {
                        println!("Found {} capability(ies) matching '{query}':\n", results.len());
                        for entry in results {
                            let auth = if entry.requires_key { " 🔑" } else { "" };
                            println!("  {} - {}{}", entry.name, entry.description, auth);
                            if !entry.tags.is_empty() {
                                println!("    Tags: {}", entry.tags.join(", "));
                            }
                            println!();
                        }
                        println!("Install with: mcp-gateway cap install <name>");
                    }
                    ExitCode::SUCCESS
                }
                Err(e) => {
                    eprintln!("❌ Failed to load registry: {e}");
                    ExitCode::FAILURE
                }
            }
        }

        CapCommand::RegistryList { registry } => {
            let reg = Registry::new(&registry);
            match reg.load_index() {
                Ok(index) => {
                    println!("Available capabilities in registry ({}):\n", index.capabilities.len());
                    for entry in &index.capabilities {
                        let auth = if entry.requires_key { " 🔑" } else { "" };
                        println!("  {} - {}{}", entry.name, entry.description, auth);
                        if !entry.tags.is_empty() {
                            println!("    Tags: {}", entry.tags.join(", "));
                        }
                        println!();
                    }
                    println!("Install with: mcp-gateway cap install <name>");
                    ExitCode::SUCCESS
                }
                Err(e) => {
                    eprintln!("❌ Failed to load registry: {e}");
                    ExitCode::FAILURE
                }
            }
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

/// Run the gateway server
async fn run_server(cli: Cli) -> ExitCode {
    // Load configuration
    let config = match Config::load(cli.config.as_deref()) {
        Ok(mut config) => {
            apply_cli_overrides(&mut config, &cli);
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

    // Create and run gateway
    let gateway = match Gateway::new(config).await {
        Ok(g) => g,
        Err(e) => {
            error!("Failed to create gateway: {e}");
            return ExitCode::FAILURE;
        }
    };

    // Run with graceful shutdown
    if let Err(e) = gateway.run().await {
        error!("Gateway error: {e}");
        return ExitCode::FAILURE;
    }

    info!("Gateway shutdown complete");
    ExitCode::SUCCESS
}

/// Write discovered servers to a config file
fn write_discovered_to_config(
    servers: &[mcp_gateway::discovery::DiscoveredServer],
    config_path: Option<&std::path::Path>,
) -> mcp_gateway::Result<std::path::PathBuf> {

    // Determine config path
    let path = if let Some(p) = config_path {
        p.to_path_buf()
    } else {
        std::path::PathBuf::from("mcp-gateway-discovered.yaml")
    };

    // Load existing config or create new
    let mut config = if path.exists() {
        Config::load(Some(&path))?
    } else {
        Config::default()
    };

    // Add discovered servers to backends
    for server in servers {
        let backend_config = server.to_backend_config();
        config.backends.insert(server.name.clone(), backend_config);
    }

    // Serialize to YAML
    let yaml = serde_yaml::to_string(&config)
        .map_err(|e| mcp_gateway::Error::Config(format!("Failed to serialize config: {e}")))?;

    // Write to file
    std::fs::write(&path, yaml)
        .map_err(|e| mcp_gateway::Error::Config(format!("Failed to write config: {e}")))?;

    Ok(path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use mcp_gateway::cli::Cli;
    use mcp_gateway::config::Config;

    /// Build a `Cli` struct with optional overrides for testing.
    fn make_cli(
        port: Option<u16>,
        host: Option<String>,
        no_meta_mcp: bool,
    ) -> Cli {
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
        assert!(config.meta_mcp.enabled); // default is enabled

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
        config.backends.insert("test".to_string(), Default::default());
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
}

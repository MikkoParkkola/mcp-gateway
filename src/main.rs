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
        Some(Command::Serve) | None => run_server(cli).await,
    }
}

/// Run capability management commands
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
    }
}

/// Run the gateway server
async fn run_server(cli: Cli) -> ExitCode {
    // Load configuration
    let config = match Config::load(cli.config.as_deref()) {
        Ok(mut config) => {
            // Apply CLI overrides
            if let Some(port) = cli.port {
                config.server.port = port;
            }
            if let Some(ref host) = cli.host {
                config.server.host = host.clone();
            }
            if cli.no_meta_mcp {
                config.meta_mcp.enabled = false;
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

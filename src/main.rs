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
    discovery,
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
        Some(Command::Discover { generate, format }) => run_discover(generate, &format).await,
        Some(Command::Serve) | None => run_server(cli).await,
    }
}

/// Run discovery command
async fn run_discover(generate: bool, format: &str) -> ExitCode {
    info!("Discovering MCP servers on this system...");

    match discovery::discover_servers().await {
        Ok(servers) => {
            if servers.is_empty() {
                println!("No MCP servers found on this system.");
                println!("\nSearched:");
                println!("  • Configuration files (Claude Desktop, VS Code)");
                println!("  • Running processes");
                println!("  • Package managers (npm, pip, cargo)");
                return ExitCode::SUCCESS;
            }

            if generate {
                // Generate gateway.yaml snippet
                println!("{}", discovery::generate_config(&servers));
            } else if format == "json" {
                // JSON output
                match serde_json::to_string_pretty(&servers) {
                    Ok(json) => println!("{}", json),
                    Err(e) => {
                        eprintln!("❌ Failed to serialize to JSON: {}", e);
                        return ExitCode::FAILURE;
                    }
                }
            } else {
                // Text output
                println!("Found {} MCP server(s):\n", servers.len());

                for server in &servers {
                    println!("📦 {}", server.name);
                    println!("   Transport: {}", server.transport);
                    println!("   Source: {}", server.source);

                    match server.transport {
                        discovery::TransportType::Stdio => {
                            if let Some(ref cmd) = server.command {
                                print!("   Command: {}", cmd);
                                if !server.args.is_empty() {
                                    print!(" {}", server.args.join(" "));
                                }
                                println!();
                            }
                        }
                        _ => {
                            if let Some(ref url) = server.url {
                                println!("   URL: {}", url);
                            }
                        }
                    }

                    if !server.env.is_empty() {
                        println!("   Environment: {} variable(s)", server.env.len());
                    }

                    println!();
                }

                println!("💡 Tip: Use --generate to output gateway.yaml configuration");
                println!("💡 Tip: Use --format json for JSON output");
            }

            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("❌ Discovery failed: {}", e);
            ExitCode::FAILURE
        }
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

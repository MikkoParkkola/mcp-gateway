//! MCP Gateway - Universal Model Context Protocol Gateway
//!
//! Single-port multiplexing with Meta-MCP for ~95% context token savings.

use std::process::ExitCode;

use clap::Parser;
use tracing::{error, info};

use mcp_gateway::{cli::Cli, config::Config, gateway::Gateway, setup_tracing};

#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse();

    // Setup tracing
    if let Err(e) = setup_tracing(&cli.log_level, cli.log_format.as_deref()) {
        eprintln!("Failed to setup tracing: {e}");
        return ExitCode::FAILURE;
    }

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

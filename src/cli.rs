//! Command-line interface

use std::path::PathBuf;

use clap::Parser;

/// Universal MCP Gateway - Single-port multiplexing with Meta-MCP
#[derive(Parser, Debug)]
#[command(name = "mcp-gateway")]
#[command(version, about, long_about = None)]
pub struct Cli {
    /// Path to configuration file (YAML)
    #[arg(short, long, env = "MCP_GATEWAY_CONFIG")]
    pub config: Option<PathBuf>,

    /// Port to listen on
    #[arg(short, long, env = "MCP_GATEWAY_PORT")]
    pub port: Option<u16>,

    /// Host to bind to
    #[arg(long, env = "MCP_GATEWAY_HOST")]
    pub host: Option<String>,

    /// Log level (trace, debug, info, warn, error)
    #[arg(long, default_value = "info", env = "MCP_GATEWAY_LOG_LEVEL")]
    pub log_level: String,

    /// Log format (text, json)
    #[arg(long, env = "MCP_GATEWAY_LOG_FORMAT")]
    pub log_format: Option<String>,

    /// Disable Meta-MCP mode
    #[arg(long)]
    pub no_meta_mcp: bool,
}

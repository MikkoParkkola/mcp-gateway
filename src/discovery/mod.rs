//! MCP Server Auto-Discovery
//!
//! Automatically discovers existing MCP servers on the system from:
//! - Configuration files (Claude Desktop, VS Code, custom MCP configs)
//! - Running processes
//! - Package managers (npm, pip, cargo)
//! - Docker containers

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

pub mod config_scanner;
pub mod package_scanner;
pub mod process_scanner;

use crate::Result;

/// A discovered MCP server
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveredServer {
    /// Server name/identifier
    pub name: String,
    /// Transport type (stdio, sse, streamable-http)
    pub transport: TransportType,
    /// Command to execute (for stdio)
    pub command: Option<String>,
    /// Command arguments
    pub args: Vec<String>,
    /// HTTP URL (for http/sse transports)
    pub url: Option<String>,
    /// Environment variables
    pub env: HashMap<String, String>,
    /// Discovery source
    pub source: DiscoverySource,
    /// Human-readable description
    pub description: String,
}

/// Transport type for discovered servers
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TransportType {
    /// Standard I/O transport
    Stdio,
    /// Server-Sent Events transport
    Sse,
    /// Streamable HTTP transport
    StreamableHttp,
}

impl std::fmt::Display for TransportType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Stdio => write!(f, "stdio"),
            Self::Sse => write!(f, "sse"),
            Self::StreamableHttp => write!(f, "streamable-http"),
        }
    }
}

/// Source of discovery
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DiscoverySource {
    /// Claude Desktop config
    ClaudeDesktop(String),
    /// VS Code settings
    VsCode(String),
    /// Custom MCP config
    McpConfig(String),
    /// Running process
    Process,
    /// NPM global package
    NpmGlobal,
    /// Pip package
    Pip,
    /// Cargo installed binary
    Cargo,
    /// Docker container
    Docker,
}

impl std::fmt::Display for DiscoverySource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ClaudeDesktop(path) => write!(f, "Claude Desktop ({})", path),
            Self::VsCode(path) => write!(f, "VS Code ({})", path),
            Self::McpConfig(path) => write!(f, "MCP Config ({})", path),
            Self::Process => write!(f, "Running Process"),
            Self::NpmGlobal => write!(f, "NPM Global"),
            Self::Pip => write!(f, "Pip"),
            Self::Cargo => write!(f, "Cargo"),
            Self::Docker => write!(f, "Docker"),
        }
    }
}

/// Main discovery function - aggregates all discovery sources
pub async fn discover_servers() -> Result<Vec<DiscoveredServer>> {
    let mut servers = Vec::new();

    // Scan configuration files
    if let Ok(config_servers) = config_scanner::scan_configs().await {
        servers.extend(config_servers);
    }

    // Scan running processes
    if let Ok(process_servers) = process_scanner::scan_processes().await {
        servers.extend(process_servers);
    }

    // Scan package managers
    if let Ok(package_servers) = package_scanner::scan_packages().await {
        servers.extend(package_servers);
    }

    // Deduplicate by name (prefer config sources over process/package)
    deduplicate_servers(&mut servers);

    Ok(servers)
}

/// Deduplicate servers by name, preferring earlier sources
fn deduplicate_servers(servers: &mut Vec<DiscoveredServer>) {
    let mut seen = HashMap::new();
    servers.retain(|server| {
        if seen.contains_key(&server.name) {
            false
        } else {
            seen.insert(server.name.clone(), true);
            true
        }
    });
}

/// Generate gateway.yaml configuration snippet
pub fn generate_config(servers: &[DiscoveredServer]) -> String {
    let mut output = String::from("# Auto-discovered MCP servers\n");
    output.push_str("# Add these to your gateway.yaml backends section\n\n");
    output.push_str("backends:\n");

    for server in servers {
        output.push_str(&format!("  {}:\n", server.name));
        output.push_str(&format!("    description: \"{}\"\n", server.description));
        output.push_str("    enabled: true\n");

        match server.transport {
            TransportType::Stdio => {
                if let Some(ref cmd) = server.command {
                    output.push_str(&format!("    command: \"{}\"\n", cmd));
                }
                if !server.args.is_empty() {
                    output.push_str("    args:\n");
                    for arg in &server.args {
                        output.push_str(&format!("      - \"{}\"\n", arg));
                    }
                }
            }
            TransportType::Sse => {
                if let Some(ref url) = server.url {
                    output.push_str(&format!("    http_url: \"{}\"\n", url));
                }
            }
            TransportType::StreamableHttp => {
                if let Some(ref url) = server.url {
                    output.push_str(&format!("    http_url: \"{}\"\n", url));
                    output.push_str("    streamable_http: true\n");
                }
            }
        }

        if !server.env.is_empty() {
            output.push_str("    env:\n");
            for (key, value) in &server.env {
                output.push_str(&format!("      {}: \"{}\"\n", key, value));
            }
        }

        output.push_str(&format!("    # Source: {}\n\n", server.source));
    }

    output
}

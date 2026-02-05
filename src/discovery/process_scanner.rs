//! Running process scanner for MCP servers

use std::collections::HashSet;

use tracing::{debug, warn};

use crate::config::TransportConfig;
use crate::{Error, Result};

use super::{DiscoveredServer, DiscoverySource, ServerMetadata};

/// Scans running processes for MCP servers
pub struct ProcessScanner {
    /// Known MCP server process patterns
    patterns: Vec<ProcessPattern>,
}

/// Process pattern to match MCP servers
struct ProcessPattern {
    /// Process name pattern
    name_pattern: String,
    /// Expected port (if HTTP)
    default_port: Option<u16>,
    /// Server name to use
    server_name: String,
    /// Description
    description: String,
}

impl ProcessScanner {
    /// Create new process scanner
    pub fn new() -> Self {
        Self {
            patterns: Self::default_patterns(),
        }
    }

    /// Default MCP server patterns to look for
    fn default_patterns() -> Vec<ProcessPattern> {
        vec![
            ProcessPattern {
                name_pattern: "pieces-os".to_string(),
                default_port: Some(39300),
                server_name: "pieces".to_string(),
                description: "Pieces OS MCP Server".to_string(),
            },
            ProcessPattern {
                name_pattern: "surreal".to_string(),
                default_port: Some(8000),
                server_name: "surrealdb".to_string(),
                description: "SurrealDB MCP Server".to_string(),
            },
            ProcessPattern {
                name_pattern: "mcp-server".to_string(),
                default_port: None,
                server_name: "generic-mcp".to_string(),
                description: "Generic MCP Server".to_string(),
            },
            ProcessPattern {
                name_pattern: "mcp".to_string(),
                default_port: None,
                server_name: "mcp".to_string(),
                description: "MCP Server Process".to_string(),
            },
        ]
    }

    /// Scan for running MCP server processes
    pub async fn scan(&self) -> Result<Vec<DiscoveredServer>> {
        let mut found_names = HashSet::new();

        // Try platform-specific process scanning
        #[cfg(target_os = "macos")]
        let mut servers = self.scan_macos().await?;

        #[cfg(target_os = "linux")]
        let mut servers = self.scan_linux().await?;

        #[cfg(target_os = "windows")]
        let mut servers = self.scan_windows().await?;

        #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
        let mut servers = Vec::new();

        // Deduplicate by name
        servers.retain(|s| found_names.insert(s.name.clone()));

        Ok(servers)
    }

    /// Scan processes on macOS using ps
    #[cfg(target_os = "macos")]
    async fn scan_macos(&self) -> Result<Vec<DiscoveredServer>> {
        use tokio::process::Command;

        let output = Command::new("ps")
            .args(["-ax", "-o", "pid,command"])
            .output()
            .await
            .map_err(|e| Error::Internal(format!("Failed to run ps: {e}")))?;

        let stdout = String::from_utf8_lossy(&output.stdout);
        self.parse_ps_output(&stdout)
    }

    /// Scan processes on Linux using ps
    #[cfg(target_os = "linux")]
    async fn scan_linux(&self) -> Result<Vec<DiscoveredServer>> {
        use tokio::process::Command;

        let output = Command::new("ps")
            .args(["-e", "-o", "pid,cmd", "--no-headers"])
            .output()
            .await
            .map_err(|e| Error::Internal(format!("Failed to run ps: {e}")))?;

        let stdout = String::from_utf8_lossy(&output.stdout);
        self.parse_ps_output(&stdout)
    }

    /// Scan processes on Windows
    #[cfg(target_os = "windows")]
    async fn scan_windows(&self) -> Result<Vec<DiscoveredServer>> {
        use tokio::process::Command;

        let output = Command::new("wmic")
            .args(["process", "get", "ProcessId,CommandLine", "/format:csv"])
            .output()
            .await
            .map_err(|e| Error::Internal(format!("Failed to run wmic: {e}")))?;

        let stdout = String::from_utf8_lossy(&output.stdout);
        self.parse_wmic_output(&stdout)
    }

    /// Parse ps output (macOS/Linux)
    fn parse_ps_output(&self, output: &str) -> Result<Vec<DiscoveredServer>> {
        let mut servers = Vec::new();

        for line in output.lines().skip(1) {
            // Skip header
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() < 2 {
                continue;
            }

            let pid_str = parts[0];
            let command = parts[1..].join(" ");

            // Try to parse PID
            let pid = pid_str.parse::<u32>().ok();

            // Check against patterns
            for pattern in &self.patterns {
                if command.to_lowercase().contains(&pattern.name_pattern.to_lowercase()) {
                    debug!(
                        "Found MCP server process: {} (PID: {:?})",
                        pattern.server_name, pid
                    );

                    // Try to extract port from command line
                    let port = Self::extract_port_from_command(&command)
                        .or(pattern.default_port);

                    let transport = if let Some(port) = port {
                        TransportConfig::Http {
                            http_url: format!("http://127.0.0.1:{port}"),
                            streamable_http: false,
                        }
                    } else {
                        // Can't determine transport, skip this one
                        warn!(
                            "Found {} process but could not determine port/transport",
                            pattern.server_name
                        );
                        continue;
                    };

                    servers.push(DiscoveredServer {
                        name: pattern.server_name.clone(),
                        description: format!("{} (running)", pattern.description),
                        source: DiscoverySource::RunningProcess,
                        transport,
                        metadata: ServerMetadata {
                            config_path: None,
                            pid,
                            port,
                            command: Some(command.clone()),
                            working_dir: None,
                        },
                    });

                    break; // Only match first pattern
                }
            }
        }

        Ok(servers)
    }

    /// Parse wmic output (Windows)
    #[cfg(target_os = "windows")]
    fn parse_wmic_output(&self, output: &str) -> Result<Vec<DiscoveredServer>> {
        let mut servers = Vec::new();

        for line in output.lines().skip(1) {
            // Skip header
            let parts: Vec<&str> = line.split(',').collect();
            if parts.len() < 3 {
                continue;
            }

            // WMIC CSV format: Node,CommandLine,ProcessId
            let command = parts[1];
            let pid_str = parts[2];

            let pid = pid_str.trim().parse::<u32>().ok();

            // Check against patterns
            for pattern in &self.patterns {
                if command.to_lowercase().contains(&pattern.name_pattern.to_lowercase()) {
                    debug!(
                        "Found MCP server process: {} (PID: {:?})",
                        pattern.server_name, pid
                    );

                    let port = Self::extract_port_from_command(command)
                        .or(pattern.default_port);

                    let transport = if let Some(port) = port {
                        TransportConfig::Http {
                            http_url: format!("http://127.0.0.1:{port}"),
                            streamable_http: false,
                        }
                    } else {
                        warn!(
                            "Found {} process but could not determine port/transport",
                            pattern.server_name
                        );
                        continue;
                    };

                    servers.push(DiscoveredServer {
                        name: pattern.server_name.clone(),
                        description: format!("{} (running)", pattern.description),
                        source: DiscoverySource::RunningProcess,
                        transport,
                        metadata: ServerMetadata {
                            config_path: None,
                            pid,
                            port,
                            command: Some(command.to_string()),
                            working_dir: None,
                        },
                    });

                    break;
                }
            }
        }

        Ok(servers)
    }

    /// Try to extract port from command line arguments
    fn extract_port_from_command(command: &str) -> Option<u16> {
        // Look for common port patterns:
        // --port 8000
        // -p 8000
        // :8000
        // port=8000

        let patterns = [
            r"--port\s+(\d+)",
            r"-p\s+(\d+)",
            r":(\d{4,5})\b",
            r"port=(\d+)",
        ];

        for pattern in &patterns {
            if let Ok(re) = regex::Regex::new(pattern) {
                if let Some(captures) = re.captures(command) {
                    if let Some(port_str) = captures.get(1) {
                        if let Ok(port) = port_str.as_str().parse::<u16>() {
                            return Some(port);
                        }
                    }
                }
            }
        }

        None
    }
}

impl Default for ProcessScanner {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_port_from_command() {
        assert_eq!(
            ProcessScanner::extract_port_from_command("surreal start --port 8000"),
            Some(8000)
        );

        assert_eq!(
            ProcessScanner::extract_port_from_command("mcp-server -p 3000"),
            Some(3000)
        );

        assert_eq!(
            ProcessScanner::extract_port_from_command("http://localhost:39300/mcp"),
            Some(39300)
        );

        assert_eq!(
            ProcessScanner::extract_port_from_command("node server.js port=5000"),
            Some(5000)
        );

        assert_eq!(
            ProcessScanner::extract_port_from_command("some-process --other-flag"),
            None
        );
    }
}

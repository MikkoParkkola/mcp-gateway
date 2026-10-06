// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Running process scanner for MCP servers

use std::collections::HashSet;

use tracing::debug;

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
    #[must_use]
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
    ///
    /// # Errors
    ///
    /// Returns an error if the platform process listing command fails.
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
        Ok(self.parse_ps_output(&stdout))
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
        Ok(self.parse_ps_output(&stdout))
    }

    /// Scan processes on Windows
    #[cfg(target_os = "windows")]
    async fn scan_windows(&self) -> Result<Vec<DiscoveredServer>> {
        let stdout = Self::powershell_listing("Win32_Process").await?;
        Ok(self.parse_ps_output(&stdout))
    }

    /// List `class` instances that carry a command line, one "pid command"
    /// line each behind a header line, the shape `parse_ps_output` reads.
    ///
    /// wmic is absent from current Windows images (removed from 11 24H2 and
    /// Server 2025), so this asks CIM. The class is a parameter so a test can
    /// run the production pipeline against a class that does not exist.
    #[cfg(target_os = "windows")]
    async fn powershell_listing(class: &str) -> Result<String> {
        use tokio::process::Command;

        let script = format!(
            "'PID COMMAND'; Get-CimInstance {class} | Where-Object {{ $_.CommandLine }} | ForEach-Object {{ '{{0}} {{1}}' -f $_.ProcessId, $_.CommandLine }}"
        );
        let output = Command::new("powershell")
            // A PowerShell 7 parent leaks a module path Windows PowerShell cannot load.
            .env_remove("PSModulePath")
            .args(["-NoProfile", "-NonInteractive", "-Command", &script])
            .output()
            .await
            .map_err(|e| Error::Internal(format!("Failed to run powershell: {e}")))?;
        // A failed query must not read as "no processes running".
        if !output.status.success() {
            return Err(Error::Internal(format!(
                "powershell process listing exited with {}",
                output.status
            )));
        }

        Ok(String::from_utf8_lossy(&output.stdout).into_owned())
    }

    /// Parse ps output (macOS/Linux) or the Windows equivalent
    #[cfg(any(target_os = "macos", target_os = "linux", target_os = "windows"))]
    fn parse_ps_output(&self, output: &str) -> Vec<DiscoveredServer> {
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
                if command
                    .to_lowercase()
                    .contains(&pattern.name_pattern.to_lowercase())
                {
                    debug!(
                        "Found MCP server process: {} (PID: {:?})",
                        pattern.server_name, pid
                    );

                    // Try to extract port from command line
                    let port = Self::extract_port_from_command(&command).or(pattern.default_port);

                    let transport = if let Some(port) = port {
                        TransportConfig::Http {
                            http_url: format!("http://127.0.0.1:{port}"),
                            streamable_http: None,
                            protocol_version: None,
                        }
                    } else {
                        // Can't determine transport, skip this one
                        debug!(
                            "Found {} process but could not determine port/transport",
                            pattern.server_name
                        );
                        continue;
                    };

                    servers.push(DiscoveredServer::new(
                        pattern.server_name.clone(),
                        format!("{} (running)", pattern.description),
                        DiscoverySource::RunningProcess,
                        transport,
                        ServerMetadata {
                            config_path: None,
                            pid,
                            port,
                            command: Some(command.clone()),
                            working_dir: None,
                        },
                    ));

                    break; // Only match first pattern
                }
            }
        }

        servers
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
            if let Ok(re) = regex::Regex::new(pattern)
                && let Some(captures) = re.captures(command)
                && let Some(port_str) = captures.get(1)
                && let Ok(port) = port_str.as_str().parse::<u16>()
            {
                return Some(port);
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

    /// MIK-7666.GH2367.1: a CIM query that fails without a terminating error
    /// is an error, not an empty process list.
    #[cfg(target_os = "windows")]
    #[tokio::test]
    async fn a_failing_cim_query_is_an_error_not_an_empty_list() {
        let listing = ProcessScanner::powershell_listing("Win32_NoSuchClassMik7666").await;
        assert!(listing.is_err(), "a failed query listed: {listing:?}");
    }

    /// Control: the production query still lists processes, this one included.
    #[cfg(target_os = "windows")]
    #[tokio::test]
    async fn the_process_query_lists_this_process() {
        let listing = ProcessScanner::powershell_listing("Win32_Process")
            .await
            .expect("the process query succeeds");
        let own = format!("{} ", std::process::id());
        assert!(
            listing.lines().any(|line| line.starts_with(&own)),
            "pid {own}missing from:\n{listing}"
        );
    }

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

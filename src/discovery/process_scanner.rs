//! Process scanner for running MCP servers

use std::collections::HashMap;

use tracing::{debug, warn};

use super::{DiscoveredServer, DiscoverySource, TransportType};
use crate::Result;

/// Scan for running MCP server processes
pub async fn scan_processes() -> Result<Vec<DiscoveredServer>> {
    let mut servers = Vec::new();

    // Use ps to find MCP-related processes
    match tokio::process::Command::new("ps")
        .args(["aux"])
        .output()
        .await
    {
        Ok(output) => {
            let stdout = String::from_utf8_lossy(&output.stdout);
            servers.extend(parse_ps_output(&stdout));
        }
        Err(e) => {
            warn!("Failed to execute ps command: {}", e);
        }
    }

    Ok(servers)
}

/// Parse ps output for MCP server processes
fn parse_ps_output(output: &str) -> Vec<DiscoveredServer> {
    let mut servers = Vec::new();

    // Look for common MCP server patterns
    let patterns = [
        ("@modelcontextprotocol/server-", "mcp-official"),
        ("mcp-server-", "mcp-server"),
        ("mcp_server", "mcp-server"),
        ("npx.*mcp", "mcp-npx"),
        ("uvx.*mcp", "mcp-uvx"),
    ];

    for line in output.lines() {
        for (pattern, prefix) in &patterns {
            if line.contains(pattern) {
                if let Some(server) = extract_server_from_process(line, prefix) {
                    debug!("Found running MCP server: {}", server.name);
                    servers.push(server);
                }
                break;
            }
        }
    }

    servers
}

/// Extract server information from a process line
fn extract_server_from_process(line: &str, prefix: &str) -> Option<DiscoveredServer> {
    // Extract command from ps output (usually after multiple spaces)
    let parts: Vec<&str> = line.split_whitespace().collect();

    // Find the actual command (skip PID, USER, etc.)
    let cmd_start = parts.iter().position(|&p| {
        p.contains("mcp")
            || p.contains("npx")
            || p.contains("uvx")
            || p.contains("node")
            || p.contains("python")
    })?;

    let cmd_parts = &parts[cmd_start..];
    if cmd_parts.is_empty() {
        return None;
    }

    let command = cmd_parts[0].to_string();
    let args: Vec<String> = cmd_parts[1..].iter().map(|s| s.to_string()).collect();

    // Try to extract a meaningful name
    let name = extract_server_name(cmd_parts, prefix);

    Some(DiscoveredServer {
        name,
        transport: TransportType::Stdio,
        command: Some(command),
        args,
        url: None,
        env: HashMap::new(),
        source: DiscoverySource::Process,
        description: "Running MCP server process".to_string(),
    })
}

/// Extract a meaningful server name from command parts
fn extract_server_name(cmd_parts: &[&str], prefix: &str) -> String {
    for part in cmd_parts {
        if let Some(name) = part.strip_prefix("@modelcontextprotocol/server-") {
            return format!("mcp-{}", name);
        }
        if let Some(name) = part.strip_prefix("mcp-server-") {
            return name.to_string();
        }
        if let Some(name) = part.strip_prefix("mcp_server_") {
            return name.to_string();
        }
    }

    // Fallback: use prefix + hash of command
    format!("{}-{}", prefix, simple_hash(cmd_parts.join(" ").as_bytes()))
}

/// Simple hash function for generating unique names
fn simple_hash(data: &[u8]) -> String {
    let sum: u32 = data.iter().map(|&b| u32::from(b)).sum();
    format!("{:08x}", sum)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_ps_output() {
        let ps_output = r#"
USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
user     12345  0.1  0.2 123456  7890 ?        Ss   10:00   0:01 npx -y @modelcontextprotocol/server-filesystem /tmp
user     12346  0.0  0.1 654321  4567 ?        S    10:01   0:00 python -m mcp_server_git
        "#;

        let servers = parse_ps_output(ps_output);
        assert!(!servers.is_empty());

        // Should find at least the filesystem server
        let filesystem = servers.iter().find(|s| s.name.contains("filesystem"));
        assert!(filesystem.is_some());
    }

    #[test]
    fn test_extract_server_name() {
        let parts = vec!["npx", "-y", "@modelcontextprotocol/server-filesystem", "/tmp"];
        let name = extract_server_name(&parts, "mcp");
        assert_eq!(name, "mcp-filesystem");
    }

    #[test]
    fn test_simple_hash() {
        let hash1 = simple_hash(b"test");
        let hash2 = simple_hash(b"test");
        let hash3 = simple_hash(b"different");

        assert_eq!(hash1, hash2);
        assert_ne!(hash1, hash3);
    }
}

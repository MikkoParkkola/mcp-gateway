//! Configuration file scanner for MCP servers

use std::{collections::HashMap, path::PathBuf};

use serde_json::Value;
use tracing::{debug, warn};

use super::{DiscoveredServer, DiscoverySource, TransportType};
use crate::Result;

/// Scan all configuration file sources
pub async fn scan_configs() -> Result<Vec<DiscoveredServer>> {
    let mut servers = Vec::new();

    // Claude Desktop configs
    servers.extend(scan_claude_desktop().await);

    // VS Code settings
    servers.extend(scan_vscode().await);

    // Custom MCP configs
    servers.extend(scan_mcp_configs().await);

    Ok(servers)
}

/// Scan Claude Desktop configuration files
async fn scan_claude_desktop() -> Vec<DiscoveredServer> {
    let mut servers = Vec::new();
    let config_paths = get_claude_config_paths();

    for path in config_paths {
        if !path.exists() {
            continue;
        }

        debug!("Scanning Claude Desktop config: {}", path.display());

        match tokio::fs::read_to_string(&path).await {
            Ok(content) => {
                if let Ok(parsed) = parse_claude_config(&content, &path) {
                    servers.extend(parsed);
                }
            }
            Err(e) => {
                warn!("Failed to read {}: {}", path.display(), e);
            }
        }
    }

    servers
}

/// Get possible Claude Desktop config paths
fn get_claude_config_paths() -> Vec<PathBuf> {
    let mut paths = Vec::new();

    if let Some(home) = dirs::home_dir() {
        // macOS
        paths.push(home.join("Library/Application Support/Claude/claude_desktop_config.json"));

        // Linux
        paths.push(home.join(".config/claude/claude_desktop_config.json"));

        // Alternative Claude Code location
        paths.push(home.join(".config/claude-code/claude_desktop_config.json"));
    }

    paths
}

/// Parse Claude Desktop config format
fn parse_claude_config(content: &str, path: &PathBuf) -> Result<Vec<DiscoveredServer>> {
    let mut servers = Vec::new();
    let json: Value = serde_json::from_str(content)?;

    // Claude Desktop format: { "mcpServers": { "name": { "command": "...", "args": [...], "env": {...} } } }
    if let Some(mcp_servers) = json.get("mcpServers").and_then(|v| v.as_object()) {
        for (name, config) in mcp_servers {
            if let Some(server) = parse_server_config(
                name,
                config,
                DiscoverySource::ClaudeDesktop(path.display().to_string()),
            ) {
                servers.push(server);
            }
        }
    }

    Ok(servers)
}

/// Parse a single server configuration from Claude/VS Code format
fn parse_server_config(
    name: &str,
    config: &Value,
    source: DiscoverySource,
) -> Option<DiscoveredServer> {
    let obj = config.as_object()?;

    // Check for command (stdio transport)
    if let Some(command) = obj.get("command").and_then(|v| v.as_str()) {
        let args = obj
            .get("args")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default();

        let env = obj
            .get("env")
            .and_then(|v| v.as_object())
            .map(|obj| {
                obj.iter()
                    .filter_map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_string())))
                    .collect()
            })
            .unwrap_or_default();

        return Some(DiscoveredServer {
            name: name.to_string(),
            transport: TransportType::Stdio,
            command: Some(command.to_string()),
            args,
            url: None,
            env,
            source,
            description: format!("MCP server: {}", name),
        });
    }

    // Check for URL (HTTP transport)
    if let Some(url) = obj.get("url").and_then(|v| v.as_str()) {
        let is_streamable = obj
            .get("streamable_http")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        let transport = if url.ends_with("/sse") {
            TransportType::Sse
        } else if is_streamable {
            TransportType::StreamableHttp
        } else {
            TransportType::Sse // Default to SSE for HTTP URLs
        };

        return Some(DiscoveredServer {
            name: name.to_string(),
            transport,
            command: None,
            args: Vec::new(),
            url: Some(url.to_string()),
            env: HashMap::new(),
            source,
            description: format!("MCP server: {}", name),
        });
    }

    None
}

/// Scan VS Code settings files
async fn scan_vscode() -> Vec<DiscoveredServer> {
    let mut servers = Vec::new();
    let config_paths = get_vscode_config_paths();

    for path in config_paths {
        if !path.exists() {
            continue;
        }

        debug!("Scanning VS Code settings: {}", path.display());

        match tokio::fs::read_to_string(&path).await {
            Ok(content) => {
                if let Ok(parsed) = parse_vscode_config(&content, &path) {
                    servers.extend(parsed);
                }
            }
            Err(e) => {
                warn!("Failed to read {}: {}", path.display(), e);
            }
        }
    }

    servers
}

/// Get possible VS Code config paths
fn get_vscode_config_paths() -> Vec<PathBuf> {
    let mut paths = Vec::new();

    if let Some(home) = dirs::home_dir() {
        // macOS
        paths.push(home.join("Library/Application Support/Code/User/settings.json"));

        // Linux
        paths.push(home.join(".config/Code/User/settings.json"));
    }

    paths
}

/// Parse VS Code settings for MCP servers
fn parse_vscode_config(content: &str, path: &PathBuf) -> Result<Vec<DiscoveredServer>> {
    let mut servers = Vec::new();

    // Remove comments (VS Code settings can have // comments)
    let cleaned = content
        .lines()
        .filter(|line| !line.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n");

    let json: Value = serde_json::from_str(&cleaned)?;

    // Look for mcp.servers or mcpServers in VS Code settings
    for key in ["mcp.servers", "mcpServers", "mcp"] {
        if let Some(mcp_servers) = json.get(key).and_then(|v| v.as_object()) {
            for (name, config) in mcp_servers {
                if let Some(server) = parse_server_config(
                    name,
                    config,
                    DiscoverySource::VsCode(path.display().to_string()),
                ) {
                    servers.push(server);
                }
            }
        }
    }

    Ok(servers)
}

/// Scan custom MCP configuration files
async fn scan_mcp_configs() -> Vec<DiscoveredServer> {
    let mut servers = Vec::new();
    let config_paths = get_mcp_config_paths();

    for path in config_paths {
        if !path.exists() {
            continue;
        }

        debug!("Scanning MCP config: {}", path.display());

        match tokio::fs::read_to_string(&path).await {
            Ok(content) => {
                if let Ok(parsed) = parse_mcp_config(&content, &path) {
                    servers.extend(parsed);
                }
            }
            Err(e) => {
                warn!("Failed to read {}: {}", path.display(), e);
            }
        }
    }

    servers
}

/// Get possible custom MCP config paths
fn get_mcp_config_paths() -> Vec<PathBuf> {
    let mut paths = Vec::new();

    if let Some(home) = dirs::home_dir() {
        // ~/.config/mcp/*.json
        if let Ok(entries) = std::fs::read_dir(home.join(".config/mcp")) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.extension().and_then(|s| s.to_str()) == Some("json") {
                    paths.push(path);
                }
            }
        }
    }

    paths
}

/// Parse custom MCP config format
fn parse_mcp_config(content: &str, path: &PathBuf) -> Result<Vec<DiscoveredServer>> {
    let mut servers = Vec::new();
    let json: Value = serde_json::from_str(content)?;

    // Try mcpServers format (same as Claude Desktop)
    if let Some(mcp_servers) = json.get("mcpServers").and_then(|v| v.as_object()) {
        for (name, config) in mcp_servers {
            if let Some(server) = parse_server_config(
                name,
                config,
                DiscoverySource::McpConfig(path.display().to_string()),
            ) {
                servers.push(server);
            }
        }
    }

    // Try servers array format
    if let Some(server_array) = json.get("servers").and_then(|v| v.as_array()) {
        for (idx, config) in server_array.iter().enumerate() {
            let default_name = format!("server-{}", idx);
            let name = config
                .get("name")
                .and_then(|v| v.as_str())
                .unwrap_or(&default_name);

            if let Some(server) = parse_server_config(
                name,
                config,
                DiscoverySource::McpConfig(path.display().to_string()),
            ) {
                servers.push(server);
            }
        }
    }

    Ok(servers)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_claude_config_stdio() {
        let config = r#"{
            "mcpServers": {
                "filesystem": {
                    "command": "npx",
                    "args": ["-y", "@modelcontextprotocol/server-filesystem", "/tmp"],
                    "env": {
                        "DEBUG": "true"
                    }
                }
            }
        }"#;

        let path = PathBuf::from("/test/config.json");
        let servers = parse_claude_config(config, &path).unwrap();

        assert_eq!(servers.len(), 1);
        assert_eq!(servers[0].name, "filesystem");
        assert_eq!(servers[0].transport, TransportType::Stdio);
        assert_eq!(servers[0].command, Some("npx".to_string()));
        assert_eq!(servers[0].args.len(), 3);
        assert_eq!(servers[0].env.get("DEBUG"), Some(&"true".to_string()));
    }

    #[test]
    fn test_parse_claude_config_http() {
        let config = r#"{
            "mcpServers": {
                "remote": {
                    "url": "https://example.com/mcp/sse"
                }
            }
        }"#;

        let path = PathBuf::from("/test/config.json");
        let servers = parse_claude_config(config, &path).unwrap();

        assert_eq!(servers.len(), 1);
        assert_eq!(servers[0].name, "remote");
        assert_eq!(servers[0].transport, TransportType::Sse);
        assert_eq!(
            servers[0].url,
            Some("https://example.com/mcp/sse".to_string())
        );
    }

    #[test]
    fn test_parse_empty_config() {
        let config = r#"{}"#;
        let path = PathBuf::from("/test/config.json");
        let servers = parse_claude_config(config, &path).unwrap();
        assert_eq!(servers.len(), 0);
    }
}

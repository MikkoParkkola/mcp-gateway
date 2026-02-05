//! Package manager scanner for MCP servers

use std::collections::HashMap;

use serde_json::Value;
use tracing::debug;

use super::{DiscoveredServer, DiscoverySource, TransportType};
use crate::Result;

/// Scan all package managers for MCP servers
pub async fn scan_packages() -> Result<Vec<DiscoveredServer>> {
    let mut servers = Vec::new();

    // Scan npm global packages
    servers.extend(scan_npm_global().await);

    // Scan pip packages
    servers.extend(scan_pip().await);

    // Scan cargo binaries
    servers.extend(scan_cargo().await);

    Ok(servers)
}

/// Scan npm global packages for MCP servers
async fn scan_npm_global() -> Vec<DiscoveredServer> {
    let mut servers = Vec::new();

    debug!("Scanning npm global packages");

    match tokio::process::Command::new("npm")
        .args(["list", "-g", "--json", "--depth=0"])
        .output()
        .await
    {
        Ok(output) => {
            if output.status.success() {
                let stdout = String::from_utf8_lossy(&output.stdout);
                if let Ok(parsed) = parse_npm_output(&stdout) {
                    servers.extend(parsed);
                }
            }
        }
        Err(e) => {
            debug!("npm not available or failed: {}", e);
        }
    }

    servers
}

/// Parse npm list output for MCP servers
fn parse_npm_output(output: &str) -> Result<Vec<DiscoveredServer>> {
    let mut servers = Vec::new();
    let json: Value = serde_json::from_str(output)?;

    if let Some(dependencies) = json.get("dependencies").and_then(|v| v.as_object()) {
        for (name, _info) in dependencies {
            // Look for MCP server packages
            if name.contains("mcp-server")
                || name.contains("@modelcontextprotocol/server")
                || name.starts_with("mcp_")
            {
                if let Some(server) = create_npm_server(name) {
                    servers.push(server);
                }
            }
        }
    }

    Ok(servers)
}

/// Create a server entry for an npm package
fn create_npm_server(package_name: &str) -> Option<DiscoveredServer> {
    // Extract server name from package
    let name = if let Some(stripped) = package_name.strip_prefix("@modelcontextprotocol/server-") {
        format!("mcp-{}", stripped)
    } else if let Some(stripped) = package_name.strip_prefix("mcp-server-") {
        stripped.to_string()
    } else {
        package_name.to_string()
    };

    Some(DiscoveredServer {
        name: name.clone(),
        transport: TransportType::Stdio,
        command: Some("npx".to_string()),
        args: vec!["-y".to_string(), package_name.to_string()],
        url: None,
        env: HashMap::new(),
        source: DiscoverySource::NpmGlobal,
        description: format!("NPM MCP server: {}", name),
    })
}

/// Scan pip packages for MCP servers
async fn scan_pip() -> Vec<DiscoveredServer> {
    let mut servers = Vec::new();

    debug!("Scanning pip packages");

    match tokio::process::Command::new("pip")
        .args(["list", "--format=json"])
        .output()
        .await
    {
        Ok(output) => {
            if output.status.success() {
                let stdout = String::from_utf8_lossy(&output.stdout);
                if let Ok(parsed) = parse_pip_output(&stdout) {
                    servers.extend(parsed);
                }
            }
        }
        Err(e) => {
            debug!("pip not available or failed: {}", e);
        }
    }

    servers
}

/// Parse pip list output for MCP servers
fn parse_pip_output(output: &str) -> Result<Vec<DiscoveredServer>> {
    let mut servers = Vec::new();
    let json: Value = serde_json::from_str(output)?;

    if let Some(packages) = json.as_array() {
        for package in packages {
            if let Some(name) = package.get("name").and_then(|v| v.as_str()) {
                if name.contains("mcp-server") || name.contains("mcp_server") {
                    if let Some(server) = create_pip_server(name) {
                        servers.push(server);
                    }
                }
            }
        }
    }

    Ok(servers)
}

/// Create a server entry for a pip package
fn create_pip_server(package_name: &str) -> Option<DiscoveredServer> {
    let name = package_name.replace('_', "-");

    // Most Python MCP servers expose a module that can be run
    let module_name = package_name.replace('-', "_");

    Some(DiscoveredServer {
        name: name.clone(),
        transport: TransportType::Stdio,
        command: Some("python".to_string()),
        args: vec!["-m".to_string(), module_name],
        url: None,
        env: HashMap::new(),
        source: DiscoverySource::Pip,
        description: format!("Python MCP server: {}", name),
    })
}

/// Scan cargo installed binaries for MCP servers
async fn scan_cargo() -> Vec<DiscoveredServer> {
    let mut servers = Vec::new();

    debug!("Scanning cargo binaries");

    // Check cargo install --list
    match tokio::process::Command::new("cargo")
        .args(["install", "--list"])
        .output()
        .await
    {
        Ok(output) => {
            if output.status.success() {
                let stdout = String::from_utf8_lossy(&output.stdout);
                servers.extend(parse_cargo_output(&stdout));
            }
        }
        Err(e) => {
            debug!("cargo not available or failed: {}", e);
        }
    }

    servers
}

/// Parse cargo install --list output for MCP servers
fn parse_cargo_output(output: &str) -> Vec<DiscoveredServer> {
    let mut servers = Vec::new();

    for line in output.lines() {
        // Skip indented lines (binaries), we only want package names
        if line.starts_with(char::is_whitespace) {
            continue;
        }

        // Lines starting with package name (no leading whitespace)
        if let Some(package_name) = line.split_whitespace().next() {
            if package_name.contains("mcp-server") || package_name.contains("mcp_server") {
                if let Some(server) = create_cargo_server(package_name) {
                    servers.push(server);
                }
            }
        }
    }

    servers
}

/// Create a server entry for a cargo package
fn create_cargo_server(package_name: &str) -> Option<DiscoveredServer> {
    let name = package_name.to_string();

    Some(DiscoveredServer {
        name: name.clone(),
        transport: TransportType::Stdio,
        command: Some(package_name.to_string()),
        args: Vec::new(),
        url: None,
        env: HashMap::new(),
        source: DiscoverySource::Cargo,
        description: format!("Rust MCP server: {}", name),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_npm_output() {
        let npm_json = r#"{
            "dependencies": {
                "@modelcontextprotocol/server-filesystem": {
                    "version": "1.0.0"
                },
                "some-other-package": {
                    "version": "2.0.0"
                }
            }
        }"#;

        let servers = parse_npm_output(npm_json).unwrap();
        assert_eq!(servers.len(), 1);
        assert_eq!(servers[0].name, "mcp-filesystem");
        assert_eq!(servers[0].command, Some("npx".to_string()));
    }

    #[test]
    fn test_parse_pip_output() {
        let pip_json = r#"[
            {"name": "mcp-server-git", "version": "1.0.0"},
            {"name": "requests", "version": "2.28.0"}
        ]"#;

        let servers = parse_pip_output(pip_json).unwrap();
        assert_eq!(servers.len(), 1);
        assert_eq!(servers[0].name, "mcp-server-git");
        assert_eq!(servers[0].command, Some("python".to_string()));
        assert!(servers[0].args.contains(&"mcp_server_git".to_string()));
    }

    #[test]
    fn test_parse_cargo_output() {
        let cargo_output = r#"
mcp-server-example v1.0.0:
    mcp-server-example
some-other-tool v2.0.0:
    some-other-tool
        "#;

        let servers = parse_cargo_output(cargo_output);
        assert_eq!(servers.len(), 1);
        assert_eq!(servers[0].name, "mcp-server-example");
    }

    #[test]
    fn test_create_npm_server() {
        let server = create_npm_server("@modelcontextprotocol/server-filesystem").unwrap();
        assert_eq!(server.name, "mcp-filesystem");
        assert_eq!(
            server.args,
            vec![
                "-y".to_string(),
                "@modelcontextprotocol/server-filesystem".to_string()
            ]
        );
    }
}

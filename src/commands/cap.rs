//! Capability (`cap`) subcommand handlers for `mcp-gateway`.

use std::process::ExitCode;
use std::sync::Arc;

use mcp_gateway::{
    capability::{
        AuthTemplate, CapabilityExecutor, CapabilityLoader, OpenApiConverter,
        parse_capability_file, validate_capability,
    },
    cli::CapCommand,
    discovery::AutoDiscovery,
    registry::Registry,
};

/// Run a `cap` subcommand (validate, list, import, test, discover, install, search, ...).
#[allow(clippy::too_many_lines)]
pub async fn run_cap_command(cmd: CapCommand) -> ExitCode {
    match cmd {
        CapCommand::Validate { file } => cap_validate(file).await,
        CapCommand::List { directory } => cap_list(directory).await,
        CapCommand::Import {
            spec,
            output,
            prefix,
            auth_key,
        } => cap_import(spec, output, prefix, auth_key).await,
        CapCommand::Test { file, args } => cap_test(file, args).await,
        CapCommand::Discover {
            format,
            write_config,
            config_path,
        } => cap_discover(format, write_config, config_path).await,
        CapCommand::Install {
            name,
            from_github,
            repo,
            branch,
            output,
        } => cap_install(name, from_github, repo, branch, output).await,
        CapCommand::Search {
            query,
            capabilities,
        } => cap_search(query, capabilities).await,
        CapCommand::RegistryList { capabilities } => cap_registry_list(capabilities).await,
    }
}

async fn cap_validate(file: std::path::PathBuf) -> ExitCode {
    match parse_capability_file(&file).await {
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
    }
}

async fn cap_list(directory: std::path::PathBuf) -> ExitCode {
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

#[allow(clippy::unused_async)]
async fn cap_import(
    spec: std::path::PathBuf,
    output: std::path::PathBuf,
    prefix: Option<String>,
    auth_key: Option<String>,
) -> ExitCode {
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

async fn cap_test(file: std::path::PathBuf, args: String) -> ExitCode {
    let cap = match parse_capability_file(&file).await {
        Ok(c) => c,
        Err(e) => {
            eprintln!("❌ Failed to parse capability: {e}");
            return ExitCode::FAILURE;
        }
    };
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

async fn cap_discover(
    format: String,
    write_config: bool,
    config_path: Option<std::path::PathBuf>,
) -> ExitCode {
    let discovery = AutoDiscovery::new();
    println!("🔍 Discovering MCP servers...\n");
    match discovery.discover_all().await {
        Ok(servers) => {
            if servers.is_empty() {
                print_discover_empty();
                return ExitCode::SUCCESS;
            }
            print_discovered_servers(&servers, &format);
            if write_config {
                println!("\n📝 Writing discovered servers to config...");
                match crate::write_discovered_to_config(&servers, config_path.as_deref()) {
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

fn print_discover_empty() {
    println!("No MCP servers found.");
    println!("\nSearched locations:");
    println!("  • Claude Desktop config");
    println!("  • VS Code/Cursor MCP configs");
    println!("  • Windsurf config");
    println!("  • ~/.config/mcp/*.json");
    println!("  • Running processes (pieces, surreal, etc.)");
    println!("  • Environment variables (MCP_SERVER_*_URL)");
}

fn print_discovered_servers(servers: &[mcp_gateway::discovery::DiscoveredServer], format: &str) {
    match format {
        "json" => println!(
            "{}",
            serde_json::to_string_pretty(servers).unwrap_or_default()
        ),
        "yaml" => println!("{}", serde_yaml::to_string(servers).unwrap_or_default()),
        _ => {
            println!("Discovered {} MCP server(s):\n", servers.len());
            for server in servers {
                print_server_entry(server);
            }
        }
    }
}

fn print_server_entry(server: &mcp_gateway::discovery::DiscoveredServer) {
    println!("📦 {}", server.name);
    println!("   Description: {}", server.description);
    println!("   Source: {:?}", server.source);
    match &server.transport {
        mcp_gateway::config::TransportConfig::Stdio { command, .. } => {
            println!("   Transport: stdio");
            println!("   Command: {command}");
        }
        mcp_gateway::config::TransportConfig::Http { http_url, .. } => {
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

async fn cap_install(
    name: String,
    from_github: bool,
    repo: String,
    branch: String,
    output: std::path::PathBuf,
) -> ExitCode {
    if from_github {
        println!("📦 Installing {name} from GitHub ({repo})...");
        let registry = Registry::new(&output);
        match registry.install_from_github(&name, &repo, &branch).await {
            Ok(path) => {
                println!("✅ Installed to {}", path.display());
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("❌ Installation failed: {e}");
                ExitCode::FAILURE
            }
        }
    } else {
        println!("ℹ️  All capabilities are already available in the capabilities directory.");
        println!("   Use 'cap list' to see available capabilities.");
        ExitCode::SUCCESS
    }
}

async fn cap_search(query: String, capabilities: std::path::PathBuf) -> ExitCode {
    let reg = Registry::new(&capabilities);
    match reg.build_index().await {
        Ok(index) => {
            let results = index.search(&query);
            if results.is_empty() {
                println!("No capabilities found matching '{query}'");
            } else {
                println!(
                    "Found {} capability(ies) matching '{query}':\n",
                    results.len()
                );
                for entry in results {
                    let auth = if entry.requires_key { " 🔑" } else { "" };
                    println!("  {} - {}{}", entry.name, entry.description, auth);
                    if !entry.tags.is_empty() {
                        println!("    Tags: {}", entry.tags.join(", "));
                    }
                    println!();
                }
                println!("All capabilities are already available in the capabilities directory.");
            }
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("❌ Failed to build registry index: {e}");
            ExitCode::FAILURE
        }
    }
}

async fn cap_registry_list(capabilities: std::path::PathBuf) -> ExitCode {
    let reg = Registry::new(&capabilities);
    match reg.build_index().await {
        Ok(index) => {
            println!("Available capabilities ({}):\n", index.capabilities.len());
            for entry in &index.capabilities {
                let auth = if entry.requires_key { " 🔑" } else { "" };
                println!("  {} - {}{}", entry.name, entry.description, auth);
                if !entry.tags.is_empty() {
                    println!("    Tags: {}", entry.tags.join(", "));
                }
                println!();
            }
            println!("All capabilities are available in the capabilities directory.");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("❌ Failed to build registry index: {e}");
            ExitCode::FAILURE
        }
    }
}

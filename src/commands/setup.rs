//! Implementation of `mcp-gateway setup`.
//!
//! Scans all known AI-client configs for MCP servers, lets the user
//! pick which ones to import (unless `--yes` skips interactivity), merges
//! the selection into the gateway config, and optionally writes the gateway
//! URL back into each client config.

use std::collections::HashMap;
use std::io::{self, IsTerminal};
use std::path::Path;
use std::process::ExitCode;

#[cfg(feature = "config-export")]
use mcp_gateway::cli::{ConnectionMode, ExportTarget};
use mcp_gateway::{
    cli::InitProfile,
    config::{Config, TransportConfig},
    config_persistence::{load_config_or_default, write_config},
    discovery::{AutoDiscovery, DiscoveredServer, DiscoverySource},
};

// ── Public entry point ────────────────────────────────────────────────────────

/// Run `mcp-gateway setup`.
///
/// # Arguments
///
/// * `yes` – skip all prompts and import every discovered server
/// * `output` – gateway config file to create or extend
/// * `configure_client` – write gateway entry into each detected AI client
pub async fn run_setup_command(yes: bool, output: &Path, configure_client: bool) -> ExitCode {
    println!("MCP Gateway Setup");
    println!("=================");
    println!();

    // ── 1. Discover ────────────────────────────────────────────────────────
    let servers = discover_all_servers().await;
    if servers.is_empty() {
        return handle_empty_discovery(output, configure_client).await;
    }

    print_discovery_summary(&servers);

    // ── 2. Selection ───────────────────────────────────────────────────────
    let selected = if yes || !io::stdin().is_terminal() {
        println!(
            "Importing all {} discovered servers (--yes).",
            servers.len()
        );
        servers.iter().collect::<Vec<_>>()
    } else {
        match interactive_select(&servers) {
            Ok(sel) => sel,
            Err(e) => {
                eprintln!("Error: Selection failed: {e}");
                return ExitCode::FAILURE;
            }
        }
    };

    if selected.is_empty() {
        println!("No servers selected. Nothing to import.");
        return ExitCode::SUCCESS;
    }

    // ── 3. Ensure first-run config ─────────────────────────────────────────
    if !output.exists() {
        let code = bootstrap_local_profile(output);
        if code != ExitCode::SUCCESS {
            return code;
        }
    }

    // ── 4. Merge into config ───────────────────────────────────────────────
    let mut config = load_config_or_default(output);
    let added = merge_servers_into_config(&mut config, &selected);

    if let Err(e) = write_config(output, &config) {
        eprintln!("Error: Failed to write {}: {e}", output.display());
        return ExitCode::FAILURE;
    }

    println!();
    println!("Imported {added} server(s) into {}", output.display());

    // ── 5. Client config ───────────────────────────────────────────────────
    if configure_client {
        let code = configure_ai_clients(output).await;
        if code != ExitCode::SUCCESS {
            return code;
        }
    }

    // ── 6. Next steps ──────────────────────────────────────────────────────
    print_next_steps(output);
    ExitCode::SUCCESS
}

// ── Discovery helpers ──────────────────────────────────────────────────────────

async fn discover_all_servers() -> Vec<DiscoveredServer> {
    println!("Scanning AI client configurations...");
    let discovery = AutoDiscovery::new();
    match discovery.discover_all().await {
        Ok(servers) => servers,
        Err(e) => {
            eprintln!("Warning: Discovery partially failed: {e}");
            Vec::new()
        }
    }
}

async fn handle_empty_discovery(output: &Path, configure_client: bool) -> ExitCode {
    println!("No MCP servers found in any AI client config.");

    let bootstrapped = if output.exists() {
        println!("Using existing gateway config at {}.", output.display());
        false
    } else {
        let code = bootstrap_local_profile(output);
        if code != ExitCode::SUCCESS {
            return code;
        }
        true
    };

    if configure_client {
        return configure_ai_clients(output).await;
    }

    if !bootstrapped {
        print_next_steps(output);
    }
    ExitCode::SUCCESS
}

fn bootstrap_local_profile(output: &Path) -> ExitCode {
    println!(
        "Bootstrapping a local zero-key starter config at {}.",
        output.display()
    );
    super::run_init_command(output, true, InitProfile::Local)
}

async fn configure_ai_clients(output: &Path) -> ExitCode {
    #[cfg(feature = "config-export")]
    {
        super::config_export::run_config_export(
            ExportTarget::All,
            ConnectionMode::Proxy,
            "gateway",
            false,
            false,
            None,
            output,
        )
        .await
    }

    #[cfg(not(feature = "config-export"))]
    {
        let _ = output;
        eprintln!("Error: setup --configure-client requires the config-export feature");
        ExitCode::FAILURE
    }
}

fn print_discovery_summary(servers: &[DiscoveredServer]) {
    // Group by source and print counts.
    let mut by_source: HashMap<String, usize> = HashMap::new();
    for s in servers {
        let label = source_label(&s.source);
        *by_source.entry(label).or_insert(0) += 1;
    }

    let mut entries: Vec<_> = by_source.into_iter().collect();
    entries.sort_by_key(|(k, _)| k.clone());

    for (source, count) in &entries {
        let noun = if *count == 1 { "server" } else { "servers" };
        println!("  Found {count} {noun} in {source}");
    }
    println!();
}

fn source_label(source: &DiscoverySource) -> String {
    match source {
        DiscoverySource::ClaudeDesktop => "Claude Desktop".to_string(),
        DiscoverySource::ClaudeCode => "Claude Code".to_string(),
        DiscoverySource::VsCode => "VS Code".to_string(),
        DiscoverySource::Cursor => "Cursor".to_string(),
        DiscoverySource::Windsurf => "Windsurf".to_string(),
        DiscoverySource::Zed => "Zed".to_string(),
        DiscoverySource::Continue => "Continue.dev".to_string(),
        DiscoverySource::Codex => "OpenAI Codex CLI".to_string(),
        DiscoverySource::McpConfig => "~/.config/mcp".to_string(),
        DiscoverySource::RunningProcess => "running process".to_string(),
        DiscoverySource::Environment => "environment".to_string(),
    }
}

// ── Interactive selection ──────────────────────────────────────────────────────

/// Prompt the user to select which servers to import via a numbered list.
///
/// Prints each server with its index, then reads a comma-separated list of
/// numbers (or "all" / blank for everything).  Returns only the selected
/// entries.  This replaces the `dialoguer::MultiSelect` dependency with a
/// simple stdin-based prompt that works in any terminal.
fn interactive_select(servers: &[DiscoveredServer]) -> Result<Vec<&DiscoveredServer>, io::Error> {
    let labels: Vec<String> = servers
        .iter()
        .map(|s| {
            let transport = match &s.transport {
                TransportConfig::Stdio { command, .. } => {
                    let short = command
                        .split_whitespace()
                        .next()
                        .unwrap_or(command.as_str());
                    format!("stdio: {short}")
                }
                TransportConfig::Http { http_url, .. } => format!("http: {http_url}"),
                #[cfg(feature = "a2a")]
                TransportConfig::A2a { a2a_url, .. } => format!("a2a: {a2a_url}"),
            };
            format!("{} [{}] ({})", s.name, source_label(&s.source), transport)
        })
        .collect();

    println!("Select servers to import (default: all):");
    for (i, label) in labels.iter().enumerate() {
        println!("  [{i}] {label}");
    }
    println!();
    print!("Enter numbers separated by commas, or press Enter to import all: ");
    io::Write::flush(&mut io::stdout())?;

    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    let trimmed = input.trim();

    if trimmed.is_empty() || trimmed.eq_ignore_ascii_case("all") {
        return Ok(servers.iter().collect());
    }

    let mut selected = Vec::new();
    for part in trimmed.split(',') {
        let part = part.trim();
        match part.parse::<usize>() {
            Ok(i) if i < servers.len() => selected.push(&servers[i]),
            Ok(i) => eprintln!(
                "  Warning: index {i} out of range (max {}), skipped",
                servers.len() - 1
            ),
            Err(_) => eprintln!("  Warning: '{part}' is not a valid number, skipped"),
        }
    }

    Ok(selected)
}

// ── Config mutation ────────────────────────────────────────────────────────────

/// Merge selected servers into `config.backends`, skipping duplicates.
///
/// Returns the number of newly-added backends.
fn merge_servers_into_config(config: &mut Config, selected: &[&DiscoveredServer]) -> usize {
    let mut added = 0usize;
    for server in selected {
        if config.backends.contains_key(&server.name) {
            println!("  Skipping '{}' (already in config)", server.name);
            continue;
        }
        config
            .backends
            .insert(server.name.clone(), server.to_backend_config());
        println!("  Added '{}'", server.name);
        added += 1;
    }
    added
}

// ── Output helpers ─────────────────────────────────────────────────────────────

fn print_next_steps(config_path: &Path) {
    println!();
    println!("Next steps:");
    println!("  1. Start the gateway:");
    println!("     mcp-gateway -c {}", config_path.display());
    println!("  2. Check everything is working:");
    println!("     mcp-gateway doctor -c {}", config_path.display());
}

// ── Tests ──────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use mcp_gateway::config::{BackendConfig, Config, TransportConfig};
    use mcp_gateway::discovery::{DiscoveredServer, DiscoverySource, ServerMetadata};

    fn make_stdio_server(name: &str, source: DiscoverySource) -> DiscoveredServer {
        DiscoveredServer {
            name: name.to_string(),
            description: format!("{name} description"),
            source,
            transport: TransportConfig::Stdio {
                command: format!("npx -y @test/{name}"),
                cwd: None,
                protocol_version: None,
            },
            metadata: ServerMetadata::default(),
        }
    }

    #[test]
    fn merge_servers_adds_new_backends() {
        // GIVEN: an empty config and two discovered servers
        let mut config = Config::default();
        let s1 = make_stdio_server("tavily", DiscoverySource::ClaudeDesktop);
        let s2 = make_stdio_server("github", DiscoverySource::ClaudeCode);
        let selected: Vec<&DiscoveredServer> = vec![&s1, &s2];

        // WHEN: merging
        let added = merge_servers_into_config(&mut config, &selected);

        // THEN: two backends are created
        assert_eq!(added, 2);
        assert!(config.backends.contains_key("tavily"));
        assert!(config.backends.contains_key("github"));
    }

    #[test]
    fn merge_servers_skips_duplicates() {
        // GIVEN: a config that already has "tavily"
        let mut config = Config::default();
        config
            .backends
            .insert("tavily".to_string(), BackendConfig::default());

        let s = make_stdio_server("tavily", DiscoverySource::ClaudeDesktop);
        let selected: Vec<&DiscoveredServer> = vec![&s];

        // WHEN: merging
        let added = merge_servers_into_config(&mut config, &selected);

        // THEN: nothing new is added
        assert_eq!(added, 0);
        assert_eq!(config.backends.len(), 1);
    }

    #[test]
    fn merge_servers_empty_selection_adds_nothing() {
        // GIVEN: a config with one backend
        let mut config = Config::default();
        config
            .backends
            .insert("existing".to_string(), BackendConfig::default());

        // WHEN: merging an empty selection
        let added = merge_servers_into_config(&mut config, &[]);

        // THEN: nothing changes
        assert_eq!(added, 0);
        assert_eq!(config.backends.len(), 1);
    }

    #[tokio::test]
    async fn empty_discovery_bootstraps_local_profile_when_config_missing() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("gateway.yaml");

        let code = handle_empty_discovery(&path, false).await;

        assert_eq!(code, ExitCode::SUCCESS);
        assert!(path.exists());
        assert!(
            dir.path()
                .join("capabilities/knowledge/weather_current.yaml")
                .exists()
        );
        assert!(
            dir.path()
                .join("capabilities/knowledge/public_holidays.yaml")
                .exists()
        );
    }

    #[tokio::test]
    async fn empty_discovery_preserves_existing_config() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("gateway.yaml");
        let existing = "server:\n  host: 127.0.0.1\n  port: 39400\n";
        std::fs::write(&path, existing).unwrap();

        let code = handle_empty_discovery(&path, false).await;

        assert_eq!(code, ExitCode::SUCCESS);
        assert_eq!(std::fs::read_to_string(&path).unwrap(), existing);
        assert!(
            !dir.path()
                .join("capabilities/knowledge/weather_current.yaml")
                .exists()
        );
    }

    #[test]
    fn first_run_import_path_preserves_local_sample_capabilities() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("gateway.yaml");
        let server = make_stdio_server("surrealdb", DiscoverySource::RunningProcess);

        let code = bootstrap_local_profile(&path);
        assert_eq!(code, ExitCode::SUCCESS);

        let mut config = load_config_or_default(&path);
        let selected = vec![&server];
        let added = merge_servers_into_config(&mut config, &selected);
        write_config(&path, &config).unwrap();

        let reloaded = Config::load(Some(&path)).unwrap();
        assert_eq!(added, 1);
        assert!(reloaded.backends.contains_key("surrealdb"));
        assert!(
            dir.path()
                .join("capabilities/knowledge/weather_current.yaml")
                .exists()
        );
    }

    #[test]
    fn source_label_covers_all_variants() {
        // GIVEN: all known DiscoverySource variants
        let sources = [
            DiscoverySource::ClaudeDesktop,
            DiscoverySource::ClaudeCode,
            DiscoverySource::VsCode,
            DiscoverySource::Cursor,
            DiscoverySource::Windsurf,
            DiscoverySource::Zed,
            DiscoverySource::Continue,
            DiscoverySource::Codex,
            DiscoverySource::McpConfig,
            DiscoverySource::RunningProcess,
            DiscoverySource::Environment,
        ];
        // WHEN / THEN: none produce an empty label
        for source in &sources {
            assert!(
                !source_label(source).is_empty(),
                "Empty label for {source:?}"
            );
        }
    }

    #[test]
    fn write_config_round_trips_through_yaml() {
        // GIVEN: a config with one backend
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.yaml");
        let mut config = Config::default();
        config.backends.insert(
            "test".to_string(),
            DiscoveredServer {
                name: "test".to_string(),
                description: "a test server".to_string(),
                source: DiscoverySource::ClaudeDesktop,
                transport: TransportConfig::Stdio {
                    command: "npx -y test".to_string(),
                    cwd: None,
                    protocol_version: None,
                },
                metadata: ServerMetadata::default(),
            }
            .to_backend_config(),
        );

        // WHEN: writing to disk
        write_config(&path, &config).expect("write must succeed");

        // THEN: the file can be re-loaded and contains the backend
        let loaded = Config::load(Some(&path)).expect("must reload");
        assert!(loaded.backends.contains_key("test"));
    }
}

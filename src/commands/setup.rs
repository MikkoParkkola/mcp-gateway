// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
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

use super::config_write::CommentLoss;
#[cfg(feature = "config-export")]
use mcp_gateway::cli::{ConnectionMode, ExportTarget};
use mcp_gateway::cli_support::shown;
#[cfg(test)]
use mcp_gateway::gateway::test_helpers::write_config_fixture;
use mcp_gateway::security::sanitize::redact_url_for_diagnostics;
use mcp_gateway::{
    cli::InitProfile,
    config::{Config, TransportConfig},
    config_persistence::load_existing_or_default,
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
pub async fn run_setup_command(
    yes: bool,
    output: &Path,
    configure_client: bool,
    mode: CommentLoss,
) -> ExitCode {
    println!("MCP Gateway Setup");
    println!("=================");
    println!();

    // Refuse an unloadable destination before discovery can lead to bootstrap
    // or client configuration, including the empty-discovery path.
    if let Err(e) = load_existing_or_default(output) {
        eprintln!("Error: Failed to load {}: {e}", output.display());
        return ExitCode::FAILURE;
    }

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

    // ── 3–4. Ensure first-run config, merge into it ────────────────────────
    let added = match import_servers(output, mode, &selected) {
        Ok(added) => added,
        Err(code) => return code,
    };

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

/// One-line transport description for the import list.
fn transport_label(transport: &TransportConfig) -> String {
    match transport {
        TransportConfig::Stdio { command, .. } => {
            let short = command
                .split_whitespace()
                .next()
                .unwrap_or(command.as_str());
            format!("stdio: {short}")
        }
        TransportConfig::Http { http_url, .. } => {
            format!("http: {}", redact_url_for_diagnostics(http_url))
        }
        TransportConfig::WebSocket { ws_url, .. } => {
            format!("websocket: {}", redact_url_for_diagnostics(ws_url))
        }
        #[cfg(feature = "a2a")]
        TransportConfig::A2a { a2a_url, .. } => {
            format!("a2a: {}", redact_url_for_diagnostics(a2a_url))
        }
    }
}

/// One server of the selection prompt: name, client and transport, the
/// client's text escaped for the terminal.
fn select_label(server: &DiscoveredServer) -> String {
    format!(
        "{} [{}] ({})",
        shown(&server.name),
        source_label(&server.source),
        shown(&transport_label(&server.transport))
    )
}

/// A server's name in single quotes, escaped for the terminal.
fn quoted_name(name: &str) -> String {
    format!("'{}'", shown(name))
}

/// Prompt the user to select which servers to import via a numbered list.
///
/// Prints each server with its index, then reads a comma-separated list of
/// numbers (or "all" / blank for everything).  Returns only the selected
/// entries.  This replaces the `dialoguer::MultiSelect` dependency with a
/// simple stdin-based prompt that works in any terminal.
fn interactive_select(servers: &[DiscoveredServer]) -> Result<Vec<&DiscoveredServer>, io::Error> {
    let labels: Vec<String> = servers.iter().map(select_label).collect();

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

/// Steps 3 and 4 of `setup`, the import of the selected servers: create the
/// first-run config when there is none, then merge `selected` into it under
/// one hold of the config lock (`config_write::write` loads the file under
/// that hold). It is the only write `run_setup_command` makes for a
/// selection, so the overlap row (MIK-8241) that drives it covers the import
/// path. The empty-discovery path (`handle_empty_discovery`) writes on its
/// own and is not covered by that row.
fn import_servers(
    output: &Path,
    mode: CommentLoss,
    selected: &[&DiscoveredServer],
) -> Result<usize, ExitCode> {
    if !output.exists() {
        let code = bootstrap_local_profile(output);
        if code != ExitCode::SUCCESS {
            return Err(code);
        }
    }
    let mut added = 0;
    super::config_write::write(output, mode, |config| {
        added = merge_servers_into_config(config, selected)?;
        Ok(())
    })
    .map_err(|e| {
        // The message can name a client's server and keys: escaped once,
        // here, where it is printed.
        eprintln!("Error: {}", shown(&e));
        ExitCode::FAILURE
    })?;
    Ok(added)
}

/// Merge selected servers into `config.backends`, skipping duplicates.
///
/// Returns the number of newly-added backends.
///
/// # Errors
///
/// A server holding a secret reference that does not resolve, naming the
/// field and entry (ADR-028): nothing is written, since the closure fails.
fn merge_servers_into_config(
    config: &mut Config,
    selected: &[&DiscoveredServer],
) -> Result<usize, String> {
    // Every server the loop below will add is checked before anything is
    // added or printed, so a refusal leaves no half-reported import. Skipped
    // ones (already configured, or a repeat name) are never checked.
    let overlay = config.env_overlay();
    let mut seen = std::collections::HashSet::new();
    for server in selected {
        if config.backends.contains_key(&server.name) || !seen.insert(&server.name) {
            continue;
        }
        server
            .to_backend_config()
            .check_secret_references(&server.name, &overlay)
            .map_err(|refused| {
                format!(
                    "'{}' has secret references that do not resolve: {}",
                    server.name,
                    refused.join("; ")
                )
            })?;
    }
    let mut added = 0usize;
    for server in selected {
        if config.backends.contains_key(&server.name) {
            println!(
                "  Skipping {} (already in config)",
                quoted_name(&server.name)
            );
            continue;
        }
        let backend = server.to_backend_config();
        config.backends.insert(server.name.clone(), backend);
        println!("  Added {}", quoted_name(&server.name));
        added += 1;
    }
    Ok(added)
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

    /// The selection prompt and the import lines show a client's server
    /// name, and a stdio command's first word, escaped.
    #[test]
    fn setup_shows_a_client_name_escaped() {
        let server = DiscoveredServer::new(
            "srv\u{1b}[31m\u{202e}x".to_string(),
            String::new(),
            DiscoverySource::ClaudeDesktop,
            TransportConfig::Stdio {
                command: "np\u{1b}\u{202e}x tool".to_string(),
                cwd: None,
                protocol_version: None,
            },
            mcp_gateway::discovery::ServerMetadata::default(),
        );
        let mut plain_name = server.clone();
        plain_name.name = "srv".to_string();
        for text in [
            select_label(&server),
            quoted_name(&server.name),
            // The transport alone: the name is plain, so only the command's
            // first word can carry the escape.
            select_label(&plain_name),
        ] {
            for raw in ['\u{1b}', '\u{202e}', '\u{2028}'] {
                assert!(!text.contains(raw), "{raw:?} in {text:?}");
            }
            assert!(text.contains("\\u{1b}"), "{text}");
        }
    }

    #[test]
    fn transport_label_hides_url_credentials() {
        let ws: TransportConfig = serde_json::from_value(serde_json::json!({
            "ws_url": "ws://user:pass@host/mcp?token=x"
        }))
        .unwrap();
        let http: TransportConfig = serde_json::from_value(serde_json::json!({
            "http_url": "http://user:pass@host/mcp?token=x"
        }))
        .unwrap();
        for label in [transport_label(&ws), transport_label(&http)] {
            assert!(label.contains("host"), "{label}");
            assert!(
                !label.contains("pass") && !label.contains("token=x"),
                "{label}"
            );
        }
    }
    use mcp_gateway::config::{BackendConfig, Config, TransportConfig};
    use mcp_gateway::discovery::{DiscoveredServer, DiscoverySource, ServerMetadata};

    fn make_stdio_server(name: &str, source: DiscoverySource) -> DiscoveredServer {
        DiscoveredServer::new(
            name.to_string(),
            format!("{name} description"),
            source,
            TransportConfig::Stdio {
                command: format!("npx -y @test/{name}"),
                cwd: None,
                protocol_version: None,
            },
            ServerMetadata::default(),
        )
    }

    /// MIK-8241 MIK-CLI-OVERLAP.2: the setup import overlapping a gateway's
    /// locked mutation loads the file under the lock it writes with, so the
    /// mutation's backend and the imported server both survive. The row
    /// drives `import_servers`, the only write `run_setup_command` makes.
    #[tokio::test]
    async fn setup_import_racing_a_gateway_mutation_keeps_both() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("gateway.yaml");
        mcp_gateway::gateway::test_helpers::write_owner_only(
            &path,
            "backends:\n  a:\n    command: a\n",
        )
        .expect("write");
        let at = path.clone();
        let mutated = mcp_gateway::config_reload::mutate_config_and_reload(&path, None, |config| {
            let queued = mcp_gateway::gateway::test_helpers::when_waiting_for_config_lock(&at);
            let import = at.clone();
            let cli = std::thread::spawn(move || {
                let server = make_stdio_server("tavily", DiscoverySource::ClaudeDesktop);
                import_servers(&import, CommentLoss::Refuse, &[&server])
                    .map_err(|_| "import failed")
            });
            assert!(
                queued
                    .recv_timeout(std::time::Duration::from_secs(10))
                    .is_ok(),
                "the setup import never waited for the config lock"
            );
            let x = crate::yaml::from_str("command: x\n").expect("backend");
            config.backends.insert("x".into(), x);
            Ok::<_, String>(cli)
        })
        .await;
        let Ok(mcp_gateway::config_reload::ConfigMutation::Applied(cli, _)) = mutated else {
            panic!("mutation not applied");
        };
        assert_eq!(cli.join().expect("cli thread"), Ok(1));
        let config = Config::load_literal(Some(&path)).expect("loads");
        let mut names: Vec<_> = config.backends.keys().map(String::as_str).collect();
        names.sort_unstable();
        assert_eq!(names, ["a", "tavily", "x"]);
    }

    #[test]
    fn b3j_merge_refuses_a_server_whose_secret_reference_does_not_resolve() {
        let mut config = Config::default();
        let server = unresolved_server("tool");
        let refused =
            merge_servers_into_config(&mut config, &[&server]).expect_err("refused before writing");
        assert!(refused.contains("backends.tool.env.API_KEY"), "{refused}");
        assert!(config.backends.is_empty());
    }

    fn unresolved_server(name: &str) -> DiscoveredServer {
        let mut server = make_stdio_server(name, DiscoverySource::ClaudeDesktop);
        server.env = [(
            "API_KEY".to_string(),
            "file:/nonexistent/mcp-gateway-b3/token".to_string(),
        )]
        .into_iter()
        .collect();
        server
    }

    #[test]
    fn b3j_merge_skips_an_existing_server_without_checking_its_references() {
        let mut config = Config::default();
        config
            .backends
            .insert("x".to_string(), BackendConfig::default());
        let x = unresolved_server("x");
        let y = make_stdio_server("y", DiscoverySource::ClaudeCode);
        let added = merge_servers_into_config(&mut config, &[&x, &y]).expect("merged");
        assert_eq!(added, 1);
        assert!(config.backends.contains_key("y"));
    }

    #[test]
    fn b3j_merge_checks_only_the_first_of_a_repeated_name() {
        let mut config = Config::default();
        let first = make_stdio_server("x", DiscoverySource::ClaudeCode);
        let repeat = unresolved_server("x");
        let added = merge_servers_into_config(&mut config, &[&first, &repeat]).expect("merged");
        assert_eq!(added, 1);
        assert!(config.backends.contains_key("x"));
    }

    #[test]
    fn merge_servers_adds_new_backends() {
        // GIVEN: an empty config and two discovered servers
        let mut config = Config::default();
        let s1 = make_stdio_server("tavily", DiscoverySource::ClaudeDesktop);
        let s2 = make_stdio_server("github", DiscoverySource::ClaudeCode);
        let selected: Vec<&DiscoveredServer> = vec![&s1, &s2];

        // WHEN: merging
        let added = merge_servers_into_config(&mut config, &selected).expect("merged");

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
        let added = merge_servers_into_config(&mut config, &selected).expect("merged");

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
        let added = merge_servers_into_config(&mut config, &[]).expect("merged");

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
        mcp_gateway::gateway::test_helpers::write_owner_only(&path, existing).unwrap();

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

        // The import step itself: bootstrap the missing file, then the locked
        // merge write, in that order.
        let added = import_servers(&path, CommentLoss::Refuse, &[&server]).expect("imports");

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
            DiscoveredServer::new(
                "test".to_string(),
                "a test server".to_string(),
                DiscoverySource::ClaudeDesktop,
                TransportConfig::Stdio {
                    command: "npx -y test".to_string(),
                    cwd: None,
                    protocol_version: None,
                },
                ServerMetadata::default(),
            )
            .to_backend_config(),
        );

        // WHEN: writing to disk
        write_config_fixture(&path, &config).expect("write must succeed");

        // THEN: the file can be re-loaded and contains the backend
        let loaded = Config::load(Some(&path)).expect("must reload");
        assert!(loaded.backends.contains_key("test"));
    }
}

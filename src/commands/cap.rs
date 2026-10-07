// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Capability (`cap`) subcommand handlers for `mcp-gateway`.

use std::process::ExitCode;
use std::sync::Arc;

use mcp_gateway::{
    capability::{
        AuthTemplate, CapabilityExecutor, CapabilityLoader, IssueSeverity, OpenApiConverter,
        compute_capability_hash, parse_capability_file, rewrite_with_pin, validate_capability,
        validate_capability_definition,
    },
    cli::CapCommand,
    config_persistence::CommentLoss,
    discovery::{
        AutoDiscovery,
        shadow::{ShadowRemediationAction, ShadowScanReport, ShadowTrustStatus},
    },
    registry::Registry,
};

/// Run a `cap` subcommand (validate, list, import, test, discover, install, search, ...).
#[allow(clippy::too_many_lines)]
pub async fn run_cap_command(cmd: CapCommand, config: Option<&std::path::Path>) -> ExitCode {
    match cmd {
        CapCommand::Validate { file } => cap_validate(file).await,
        CapCommand::Pin { file } => cap_pin(file).await,
        CapCommand::List { directory } => cap_list(directory, config).await,
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
            shadow,
            gateway_config,
            force,
        } => {
            let mode = super::config_write::comment_loss(force);
            cap_discover(
                format,
                write_config,
                config_path,
                shadow,
                gateway_config,
                mode,
            )
            .await
        }
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
        #[cfg(feature = "discovery")]
        CapCommand::ImportUrl {
            url,
            prefix,
            output,
            auth,
            max_endpoints,
            dry_run,
            cost_per_call,
        } => {
            super::discover::cap_import_url(
                url,
                prefix,
                output,
                auth,
                max_endpoints,
                dry_run,
                cost_per_call,
            )
            .await
        }
    }
}

async fn cap_validate(file: std::path::PathBuf) -> ExitCode {
    match parse_capability_file(&file).await {
        Ok(cap) => {
            if let Err(e) = validate_capability(&cap) {
                eprintln!("❌ Validation failed: {e}");
                return ExitCode::FAILURE;
            }
            // The structural checks the loader runs: an error here means the
            // gateway would skip the file, a warning that it loads with a smell.
            let issues = validate_capability_definition(&cap, Some(&file.to_string_lossy()));
            for issue in &issues {
                eprintln!("{issue}");
            }
            if issues.iter().any(|i| i.severity == IssueSeverity::Error) {
                eprintln!("❌ Validation failed: structural errors above");
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

/// Compute the SHA-256 of a capability YAML (excluding its own `sha256:`
/// line) and rewrite the file in place with the pin prepended.
///
/// This is the operator-facing half of the rug-pull guard: once a
/// capability is pinned, the loader refuses to *load* it if the file
/// changes without the pin being re-issued. The gateway still starts and
/// hot-reload still proceeds — the tampered capability is dropped with a
/// warning (`src/capability/loader.rs`, `src/capability/watcher.rs`), so a
/// poisoned file reads as a missing tool rather than a startup failure.
async fn cap_pin(file: std::path::PathBuf) -> ExitCode {
    let content = match tokio::fs::read_to_string(&file).await {
        Ok(c) => c,
        Err(e) => {
            eprintln!("❌ Failed to read {}: {e}", file.display());
            return ExitCode::FAILURE;
        }
    };

    // Sanity-check: the file must parse as a capability before we pin it.
    if let Err(e) = serde_yaml::from_str::<serde_yaml::Value>(&content) {
        eprintln!("❌ Not a valid YAML file ({}): {e}", file.display());
        return ExitCode::FAILURE;
    }

    let hash = compute_capability_hash(&content);
    let pinned = rewrite_with_pin(&content, &hash);

    if let Err(e) = tokio::fs::write(&file, &pinned).await {
        eprintln!("❌ Failed to write pinned file {}: {e}", file.display());
        return ExitCode::FAILURE;
    }

    println!("✅ Pinned {}", file.display());
    println!("   sha256: {hash}");
    ExitCode::SUCCESS
}

/// The executor `cap list` asks "is this one served?" with: the environment
/// the gateway would start with (its config's `env_files` over the process
/// environment), so the answer is the one `tools/list` gives.
///
/// A config that cannot be loaded is an error, not a reason to answer from the
/// process environment: the gateway would refuse to start on it, so a listing
/// computed without it would show readiness the gateway never has.
fn list_executor(
    config: Option<&std::path::Path>,
) -> Result<CapabilityExecutor, (std::path::PathBuf, mcp_gateway::Error)> {
    let (_, load_path) = crate::discovered_config::resolve(config);
    match mcp_gateway::config::Config::load_evaluated(load_path.as_deref()) {
        Ok(evaluated) => {
            let env = Arc::new(mcp_gateway::config::LiveEnv::new(
                evaluated.overlay,
                evaluated.env_paths,
            ));
            Ok(CapabilityExecutor::for_listing(&evaluated.config, env))
        }
        Err(e) => Err((load_path.unwrap_or_default(), e)),
    }
}

async fn cap_list(directory: std::path::PathBuf, config: Option<&std::path::Path>) -> ExitCode {
    let executor = match list_executor(config) {
        Ok(executor) => executor,
        Err((path, e)) => {
            eprintln!("❌ Failed to load config {}: {e}", path.display());
            return ExitCode::FAILURE;
        }
    };
    let path = directory.to_string_lossy();
    match CapabilityLoader::load_directory(&path).await {
        Ok(caps) => {
            if caps.is_empty() {
                println!("No capabilities found in {path}");
            } else {
                println!("Found {} capabilities in {}:\n", caps.len(), path);
                for cap in caps {
                    println!("{}", executor.list_line(&cap));
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
    let spec_ref = spec.to_string_lossy().to_string();
    let is_url = spec_ref.starts_with("http://") || spec_ref.starts_with("https://");
    let result = if is_url {
        converter.convert_url(&spec_ref).await
    } else {
        converter.convert_file(&spec_ref)
    };

    match result {
        Ok(caps) => {
            let out_path = output.to_string_lossy();
            let count = caps.len();
            println!(
                "Imported {count} tools from {spec_ref}. Review {out_path}/ before loading.\n"
            );
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
    // The schema check a gateway call gets (MIK-7943); the arguments go on as
    // given, as in `invoke`.
    let verdict = mcp_gateway::capability::validate_arguments(&params, &cap.schema.input);
    if !verdict.is_valid() {
        eprintln!("❌ {}", verdict.format_error(&cap.schema.input));
        return ExitCode::FAILURE;
    }
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
    shadow: bool,
    gateway_config: Option<std::path::PathBuf>,
    mode: CommentLoss,
) -> ExitCode {
    let discovery = AutoDiscovery::new();
    let structured_output = matches!(format.as_str(), "json" | "yaml");
    if !structured_output {
        println!("🔍 Discovering MCP servers...\n");
    }
    match discovery.discover_all().await {
        Ok(servers) => {
            if shadow {
                return cap_discover_shadow(
                    servers,
                    &format,
                    gateway_config,
                    write_config,
                    config_path,
                    mode,
                )
                .await;
            }

            // In json/yaml mode stdout carries only the document; every other
            // line goes to stderr so the output parses as one value (#1909).
            let say = |text: &str| {
                if structured_output {
                    eprintln!("{text}");
                } else {
                    println!("{text}");
                }
            };
            if servers.is_empty() {
                if structured_output {
                    print_discovered_servers(&servers, &format);
                }
                say(DISCOVER_EMPTY);
                return ExitCode::SUCCESS;
            }
            print_discovered_servers(&servers, &format);
            if write_config {
                say("\n📝 Writing discovered servers to config...");
                match crate::write_discovered_to_config(&servers, config_path.as_deref(), mode) {
                    Ok(path) => {
                        say(&format!("✅ Config written to {}", path.display()));
                        say(&format!(
                            "\nTo use discovered servers, start gateway with: mcp-gateway -c {}",
                            path.display()
                        ));
                    }
                    Err(e) => {
                        eprintln!("❌ Failed to write config: {e}");
                        return ExitCode::FAILURE;
                    }
                }
            } else {
                say("\n💡 To add these servers to your gateway config, run:");
                say("   mcp-gateway cap discover --write-config");
            }
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("❌ Discovery failed: {e}");
            ExitCode::FAILURE
        }
    }
}

/// Handle `cap discover --shadow`: show only servers that are not registered
/// as backends in the gateway configuration.
async fn cap_discover_shadow(
    discovered: Vec<mcp_gateway::discovery::DiscoveredServer>,
    format: &str,
    gateway_config: Option<std::path::PathBuf>,
    write_config: bool,
    output_config_path: Option<std::path::PathBuf>,
    mode: CommentLoss,
) -> ExitCode {
    // Resolve which gateway config to load. Try the provided path first, then
    // fall back to `gateway.yaml` in the current directory.
    let compare_config_path =
        gateway_config.unwrap_or_else(|| std::path::PathBuf::from("gateway.yaml"));

    let registered_names: std::collections::HashSet<String> =
        if let Ok(config) = mcp_gateway::config::Config::load(Some(&compare_config_path)) {
            config.backends.into_keys().collect()
        } else {
            // Config not found or unreadable — all discovered servers are unregistered.
            eprintln!(
                "⚠️  Could not load gateway config from '{}'; \
                 treating all discovered servers as unregistered.",
                compare_config_path.display()
            );
            std::collections::HashSet::new()
        };

    let shadow_servers: Vec<_> = discovered
        .iter()
        .filter(|s| !registered_names.contains(&s.name))
        .cloned()
        .collect();
    let report = ShadowScanReport::from_discovered(
        &discovered,
        &registered_names,
        Some(&compare_config_path),
    );
    let adoptable_names: std::collections::HashSet<&str> = report
        .assets
        .iter()
        .filter(|asset| asset.remediation.action == ShadowRemediationAction::AdoptIntoGateway)
        .map(|asset| asset.name.as_str())
        .collect();

    match format {
        "json" => println!(
            "{}",
            serde_json::to_string_pretty(&report).unwrap_or_default()
        ),
        "yaml" => println!("{}", serde_yaml::to_string(&report).unwrap_or_default()),
        _ => print_shadow_report(&report),
    }

    if write_config && !shadow_servers.is_empty() {
        let adoptable_servers: Vec<_> = shadow_servers
            .iter()
            .filter(|server| adoptable_names.contains(server.name.as_str()))
            .cloned()
            .collect();
        if adoptable_servers.is_empty() {
            eprintln!("No adoptable local shadow servers found; leaving gateway config unchanged.");
            eprintln!("Review the report actions before changing network or sensitive findings.");
            return ExitCode::SUCCESS;
        }

        let apply_path = output_config_path.unwrap_or_else(|| compare_config_path.clone());
        match crate::write_discovered_to_config(&adoptable_servers, Some(&apply_path), mode) {
            Ok(path) => {
                eprintln!(
                    "Adopted {} local shadow server(s) into {}",
                    adoptable_servers.len(),
                    path.display()
                );
                let skipped = shadow_servers.len().saturating_sub(adoptable_servers.len());
                if skipped > 0 {
                    eprintln!(
                        "Skipped {skipped} shadow finding(s) that require owner review or quarantine."
                    );
                }
                eprintln!(
                    "Verify with: mcp-gateway cap discover --shadow --gateway-config {}",
                    path.display()
                );
            }
            Err(e) => {
                eprintln!("❌ Failed to adopt shadow servers: {e}");
                return ExitCode::FAILURE;
            }
        }
    }

    ExitCode::SUCCESS
}

fn print_shadow_report(report: &ShadowScanReport) {
    if report.assets.is_empty() {
        println!("✅ No shadow servers found — all discovered MCP servers are registered.");
        println!("Passive scan only; no discovered tools were invoked.");
        return;
    }

    println!(
        "⚠️  Found {} shadow (unregistered) MCP server(s). Passive scan only; no discovered tools were invoked.\n",
        report.summary.unmanaged_total
    );
    println!("Action groups:");
    for group in &report.action_groups {
        println!("  {:?}: {} asset(s)", group.action, group.count);
    }
    println!();

    for asset in &report.assets {
        println!("📦 {}", asset.name);
        println!("   ID: {}", asset.id);
        println!("   Severity: {:?}", asset.severity);
        println!("   Source: {:?}", asset.source);
        println!("   Trust: {:?}", asset.trust_status);
        println!("   Transport: {}", asset.transport.kind);
        if let Some(endpoint) = &asset.transport.endpoint {
            println!("   Endpoint: {endpoint}");
        }
        if let Some(path) = &asset.evidence.config_path {
            println!("   Config: {path}");
        }
        if let Some(pid) = asset.evidence.pid {
            println!("   PID: {pid}");
        }
        if let Some(executable) = &asset.evidence.executable {
            println!("   Executable: {executable} (arguments redacted)");
        }
        println!("   Auth exposure: {:?}", asset.auth_exposure);
        println!("   Data risk: {:?}", asset.data_risk);
        println!("   Recommended action: {:?}", asset.remediation.action);
        println!("   Confidence: {:?}", asset.remediation.confidence);
        println!(
            "   Confirmation required: {}",
            asset.remediation.confirmation_required
        );
        println!("   Verify: {}", asset.remediation.verification_step);
        if asset.remediation.action == ShadowRemediationAction::AdoptIntoGateway
            && let Some(command) = &asset.remediation.apply_command
        {
            println!("   Apply after review: {command}");
        }
        if asset.trust_status == ShadowTrustStatus::Unmanaged {
            println!("   Reason: {}", asset.risk_reasons.join(", "));
        }
        println!();
    }

    println!("Default mode is dry-run. To adopt reviewed local unmanaged servers, rerun with:");
    println!("   mcp-gateway cap discover --shadow --write-config");
}

const DISCOVER_EMPTY: &str = "No MCP servers found.

Searched locations:
  • Claude Desktop config
  • VS Code/Cursor MCP configs
  • Windsurf config
  • ~/.config/mcp/*.json
  • Running processes (pieces, surreal, etc.)
  • Environment variables (MCP_SERVER_*_URL)";

fn print_discovered_servers(servers: &[mcp_gateway::discovery::DiscoveredServer], format: &str) {
    match format {
        "json" | "yaml" => {
            let redacted: Vec<_> = servers
                .iter()
                .map(mcp_gateway::discovery::DiscoveredServer::redacted_for_diagnostics)
                .collect();
            if format == "json" {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&redacted).unwrap_or_default()
                );
            } else {
                println!("{}", serde_yaml::to_string(&redacted).unwrap_or_default());
            }
        }
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
            println!(
                "   Command: {}",
                mcp_gateway::security::summarize_stdio_command(command)
            );
        }
        mcp_gateway::config::TransportConfig::Http { http_url, .. } => {
            println!("   Transport: http");
            println!(
                "   URL: {}",
                mcp_gateway::security::diagnostic_url(http_url)
            );
        }
        mcp_gateway::config::TransportConfig::WebSocket { ws_url, .. } => {
            println!("   Transport: websocket");
            println!("   URL: {}", mcp_gateway::security::diagnostic_url(ws_url));
        }
        #[cfg(feature = "a2a")]
        mcp_gateway::config::TransportConfig::A2a { a2a_url, .. } => {
            println!("   Transport: a2a");
            println!("   URL: {}", mcp_gateway::security::diagnostic_url(a2a_url));
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

#[cfg(test)]
mod tests {
    use super::cap_pin;
    use mcp_gateway::capability::{compute_capability_hash, parse_capability_file};
    use std::io::Write;
    use std::process::ExitCode;
    use tempfile::TempDir;

    const PINNABLE_YAML: &str = "\
name: pin_cli_cap
description: CLI pin test
providers:
  primary:
    service: rest
    config:
      base_url: https://example.com
      path: /cli
";

    /// Extract the exit-code discriminant for comparison in tests.
    fn is_success(code: ExitCode) -> bool {
        // ExitCode doesn't expose its raw value publicly; compare via Debug.
        format!("{code:?}") == format!("{:?}", ExitCode::SUCCESS)
    }

    #[tokio::test]
    async fn cap_pin_writes_valid_hash_and_roundtrips_through_loader() {
        // GIVEN: a fresh, unpinned capability YAML on disk
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("pin_me.yaml");
        {
            let mut f = std::fs::File::create(&path).unwrap();
            f.write_all(PINNABLE_YAML.as_bytes()).unwrap();
        }
        let expected_hash = compute_capability_hash(PINNABLE_YAML);

        // WHEN: running `mcp-gateway cap pin <file>`
        let code = cap_pin(path.clone()).await;

        // THEN: command succeeds
        assert!(is_success(code), "cap_pin should exit successfully");

        // AND: the file now begins with a sha256 line carrying the right hash
        let written = std::fs::read_to_string(&path).unwrap();
        assert!(written.starts_with(&format!("sha256: {expected_hash}\n")));

        // AND: the loader accepts the rewritten file (pin verification passes)
        let cap = parse_capability_file(&path).await.unwrap();
        assert_eq!(cap.name, "pin_cli_cap");
        assert_eq!(cap.sha256.as_deref(), Some(expected_hash.as_str()));
    }

    /// `cap pin` never writes a file the loader then refuses. A pin line that
    /// already hides a second `sha256:` after a YAML line break would
    /// otherwise be rewritten into a file with two pins (#1212).
    #[tokio::test]
    async fn cap_pin_never_writes_a_file_the_loader_refuses() {
        for brk in ['\r', '\u{85}', '\u{2028}', '\u{2029}'] {
            let dir = TempDir::new().unwrap();
            let path = dir.path().join("malformed.yaml");
            let original = format!("sha256: old{brk}sha256: older\n{PINNABLE_YAML}");
            std::fs::write(&path, &original).unwrap();

            let code = cap_pin(path.clone()).await;

            if is_success(code) {
                parse_capability_file(&path)
                    .await
                    .unwrap_or_else(|e| panic!("break {brk:?}: cap pin wrote a refused file: {e}"));
            } else {
                assert_eq!(
                    std::fs::read_to_string(&path).unwrap(),
                    original,
                    "break {brk:?}: a refused pin changed the file"
                );
            }
        }
    }
}

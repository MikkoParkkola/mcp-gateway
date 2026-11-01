// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! `cap discover`: finding MCP servers on this machine, the shadow scan, and
//! printing what either found. Moved from `cap.rs` for the file-size ceiling.

use std::process::ExitCode;

use mcp_gateway::discovery::{
    AutoDiscovery,
    shadow::{ShadowRemediationAction, ShadowScanReport, ShadowTrustStatus},
};

use super::super::config_write::CommentLoss;

pub(super) async fn cap_discover(
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
                    Ok((path, written, skipped)) => {
                        say(&format!(
                            "✅ Wrote {written} server(s) to {}; skipped {skipped}",
                            path.display()
                        ));
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

    let loaded = mcp_gateway::config::Config::load(Some(&compare_config_path)).ok();
    let registered_names: std::collections::HashSet<String> = if let Some(config) = &loaded {
        config.backends.keys().cloned().collect()
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
    // The record key is only read here, never created: a report keys its
    // URL asset ids with the gateway's key, or says they are for this run.
    let report = ShadowScanReport::from_discovered(
        &discovered,
        &registered_names,
        Some(&compare_config_path),
        loaded.as_ref(),
        &mcp_gateway::config_persistence::gateway_data_dir(),
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
        "yaml" => println!("{}", crate::yaml::to_string(&report).unwrap_or_default()),
        _ => print_shadow_report(&report),
    }

    if write_config && !shadow_servers.is_empty() {
        let adoptable_servers: Vec<_> = shadow_servers
            .iter()
            .filter(|server| adoptable_names.contains(server.name.as_str()))
            .cloned()
            .collect();
        if adoptable_servers.is_empty() {
            // Nothing written is a failure a script can see.
            eprintln!("No adoptable local shadow servers found; leaving gateway config unchanged.");
            eprintln!("Review the report actions before changing network or sensitive findings.");
            return ExitCode::FAILURE;
        }

        let apply_path = output_config_path.unwrap_or_else(|| compare_config_path.clone());
        match crate::write_discovered_to_config(&adoptable_servers, Some(&apply_path), mode) {
            // The counts are what the writer wrote and skipped: it applies
            // the shared adopt rule and skips `capabilities.name`.
            Ok((path, adopted, refused)) => {
                eprintln!(
                    "Adopted {adopted} local shadow server(s) into {}; skipped {refused}",
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
    if let Some(note) = &report.ids_note {
        println!("Note: {note}.");
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
                println!("{}", crate::yaml::to_string(&redacted).unwrap_or_default());
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

// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! CLI command handlers for `mcp-gateway`.
//!
//! Each public function corresponds to a top-level `Command` variant and
//! returns an `ExitCode` so `main` can remain a thin dispatcher.

#[cfg(feature = "webui")]
mod add_remove;
mod cap;
#[cfg(feature = "config-export")]
mod config_export;
#[cfg(feature = "discovery")]
pub(crate) mod discover;
mod doctor;
mod identity;
mod kubernetes;
pub mod paths;
mod plugin;
mod protocol_import;
mod ranking;
mod setup;
mod skills;
mod stats;
mod trust;
mod upgrade;

#[cfg(feature = "webui")]
pub use add_remove::{run_add_command, run_get_command, run_list_command, run_remove_command};
pub use cap::run_cap_command;
#[cfg(feature = "config-export")]
pub use config_export::run_config_export;
pub use doctor::{run_doctor_command, run_doctor_shadow_command};
pub use identity::run_identity_command;
pub use kubernetes::run_kubernetes_command;
pub use plugin::{run_plugin_install, run_plugin_list, run_plugin_search, run_plugin_uninstall};
pub use protocol_import::run_protocol_import_command;
pub use ranking::run_ranking_command;
pub use setup::run_setup_command;
pub use skills::{
    run_skills_generate, run_skills_import, run_skills_list, run_skills_remove, run_skills_search,
    run_skills_show,
};
pub use stats::{default_stats_url, run_stats_command};
pub use trust::run_trust_command;
pub use upgrade::{check_upgrade, data_dir as upgrade_data_dir, run_upgrade_command};

use std::process::ExitCode;

use mcp_gateway::{
    cli::{
        InitProfile, TlsCommand, ToolCommand,
        completion::{ShellTarget, generate_completion},
        invoke::{ToolCatalogue, build_completion_tool_names, execute_tool, resolve_args},
        output::{OutputFormat, print_tool_inspect, print_tool_list, print_tool_result},
    },
    mtls::{CaParams, CertGenerator, LeafCertParams},
};

// ── init ─────────────────────────────────────────────────────────────────────

/// Generate a starter gateway configuration file.
///
const LOCAL_SAMPLE_CAPABILITIES: &[(&str, &str)] = &[
    (
        "capabilities/knowledge/weather_current.yaml",
        include_str!("../../capabilities/knowledge/weather_current.yaml"),
    ),
    (
        "capabilities/knowledge/public_holidays.yaml",
        include_str!("../../capabilities/knowledge/public_holidays.yaml"),
    ),
];

/// Generate a starter gateway configuration file.
///
/// Writes a commented YAML configuration to `output`. The local profile also
/// writes zero-key sample capability files next to the config so a clean install
/// can route a tool call without manual YAML authoring.
pub fn run_init_command(
    output: &std::path::Path,
    with_examples: bool,
    profile: InitProfile,
) -> ExitCode {
    if output.exists() {
        eprintln!(
            "Error: {} already exists. Remove it first or choose a different path with --output.",
            output.display()
        );
        return ExitCode::FAILURE;
    }

    let sample_files = init_sample_capability_files(output, with_examples, profile);
    if let Err(e) = preflight_init_targets(output, &sample_files) {
        eprintln!("Error: {e}");
        return ExitCode::FAILURE;
    }

    let config_content = build_init_config(with_examples, profile);

    match write_init_files(output, &config_content, &sample_files) {
        Ok(()) => {
            print_init_success(output, profile, !sample_files.is_empty());
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("Error: Failed to write {}: {e}", output.display());
            ExitCode::FAILURE
        }
    }
}

fn build_init_config(with_examples: bool, profile: InitProfile) -> String {
    let write_local_samples = with_examples && profile == InitProfile::Local;
    let examples_section = if write_local_samples {
        concat!(
            "\n",
            "# Capabilities - direct REST API integration (no MCP server needed)\n",
            "# The local profile writes zero-key sample tools into ./capabilities/.\n",
            "capabilities:\n",
            "  enabled: true\n",
            "  directories:\n",
            "    - capabilities\n",
            "\n",
            "# Add MCP backends with `mcp-gateway add <name> -- <command>` or run:\n",
            "#   mcp-gateway setup wizard --configure-client\n",
            "# backends:\n",
            "#   filesystem:\n",
            "#     command: \"npx -y @anthropic/mcp-server-filesystem /path/to/dir\"\n",
            "#     description: \"File system access\"\n",
        )
    } else {
        concat!(
            "\n",
            "# Capabilities - direct REST API integration\n",
            "capabilities:\n",
            "  enabled: true\n",
            "  directories:\n",
            "    - capabilities\n",
            "\n",
            "# Add your MCP backends here:\n",
            "# backends:\n",
            "#   my-server:\n",
            "#     command: \"npx -y @my/mcp-server\"\n",
            "#     description: \"My MCP server\"\n",
        )
    };

    format!(
        concat!(
            "# MCP Gateway Configuration\n",
            "# ========================\n",
            "# Generated by: mcp-gateway init\n",
            "# Profile: {profile}\n",
            "#\n",
            "# Documentation: https://github.com/MikkoParkkola/mcp-gateway#readme\n",
            "\n",
            "# Server settings\n",
            "server:\n",
            "  host: \"127.0.0.1\"\n",
            "  port: 39400\n",
            "\n",
            "# Meta-MCP mode - exposes a compact gateway tool surface\n",
            "# Common deployment: 14 tools (12 minimum, 15 with webhooks)\n",
            "# Keeps prompt overhead low by discovering backend tools on demand\n",
            "meta_mcp:\n",
            "  enabled: true\n",
            "  cache_tools: true\n",
            "  cache_ttl: 300s\n",
            "{examples_section}",
        ),
        profile = profile,
        examples_section = examples_section,
    )
}

fn init_sample_capability_files(
    output: &std::path::Path,
    with_examples: bool,
    profile: InitProfile,
) -> Vec<(std::path::PathBuf, &'static str)> {
    if !with_examples || profile != InitProfile::Local {
        return Vec::new();
    }

    let base = output
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| std::path::Path::new("."));

    LOCAL_SAMPLE_CAPABILITIES
        .iter()
        .map(|(relative, content)| (base.join(relative), *content))
        .collect()
}

fn preflight_init_targets(
    output: &std::path::Path,
    sample_files: &[(std::path::PathBuf, &'static str)],
) -> std::io::Result<()> {
    if let Some(parent) = output.parent().filter(|p| !p.as_os_str().is_empty())
        && parent.exists()
        && !parent.is_dir()
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            format!("{} exists and is not a directory", parent.display()),
        ));
    }

    for (path, _) in sample_files {
        if path.exists() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::AlreadyExists,
                format!(
                    "{} already exists; remove it or rerun with --with-examples=false",
                    path.display()
                ),
            ));
        }
    }

    Ok(())
}

fn write_init_files(
    output: &std::path::Path,
    config_content: &str,
    sample_files: &[(std::path::PathBuf, &'static str)],
) -> std::io::Result<()> {
    if let Some(parent) = output.parent().filter(|p| !p.as_os_str().is_empty()) {
        std::fs::create_dir_all(parent)?;
    }

    for (path, _) in sample_files {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
    }

    std::fs::write(output, config_content)?;

    for (path, content) in sample_files {
        std::fs::write(path, content)?;
    }

    Ok(())
}

fn print_init_success(output: &std::path::Path, profile: InitProfile, wrote_samples: bool) {
    println!("Created {}", output.display());
    println!("Profile: {profile}");
    if wrote_samples {
        println!("Created zero-key sample capabilities under ./capabilities/");
    }
    println!();
    println!("Next steps:");
    println!("  1. Run diagnostics:");
    println!("     mcp-gateway doctor -c {}", output.display());
    println!("  2. Start the gateway:");
    println!("     mcp-gateway -c {}", output.display());
    println!("  3. Add to your MCP client:");
    println!("     mcp-gateway setup wizard --configure-client");
    println!("  4. Or add manually:");
    println!("     {{");
    println!("       \"mcpServers\": {{");
    println!("         \"gateway\": {{");
    println!("           \"url\": \"http://127.0.0.1:39400/mcp\"");
    println!("         }}");
    println!("       }}");
    println!("     }}");
}

// ── tls ──────────────────────────────────────────────────────────────────────

/// Run `mcp-gateway tls` subcommands.
#[allow(clippy::too_many_lines)]
pub fn run_tls_command(cmd: TlsCommand) -> ExitCode {
    match cmd {
        TlsCommand::InitCa {
            cn,
            validity_days,
            out,
        } => tls_init_ca(&cn, validity_days, &out),
        TlsCommand::IssueServer {
            ca_cert,
            ca_key,
            cn,
            san_dns,
            validity_days,
            out,
        } => tls_issue_server(&ca_cert, &ca_key, &cn, &san_dns, validity_days, &out),
        TlsCommand::IssueClient {
            ca_cert,
            ca_key,
            cn,
            ou,
            spiffe_uri,
            validity_days,
            out,
        } => tls_issue_client(
            &ca_cert,
            &ca_key,
            &cn,
            ou.as_deref(),
            spiffe_uri,
            validity_days,
            &out,
        ),
    }
}

fn tls_init_ca(cn: &str, validity_days: u32, out: &std::path::Path) -> ExitCode {
    println!("Generating Root CA: {cn}");
    let params = CaParams { cn, validity_days };
    match CertGenerator::init_ca(&params) {
        Ok(cert) => {
            if let Err(e) = CertGenerator::write_to_dir(&cert, out, "ca") {
                eprintln!("Error: Failed to write CA files: {e}");
                return ExitCode::FAILURE;
            }
            println!("  CA cert: {}", out.join("ca.crt").display());
            println!("  CA key:  {}", out.join("ca.key").display());
            println!();
            println!("Keep the CA key offline or in a vault.");
            println!("Add to gateway.yaml:");
            println!("  mtls:");
            println!("    ca_cert: \"{}\"", out.join("ca.crt").display());
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("Error: CA generation failed: {e}");
            ExitCode::FAILURE
        }
    }
}

fn tls_issue_server(
    ca_cert: &std::path::Path,
    ca_key: &std::path::Path,
    cn: &str,
    san_dns: &str,
    validity_days: u32,
    out: &std::path::Path,
) -> ExitCode {
    println!("Issuing server certificate for: {cn}");
    let (ca_cert_pem, ca_key_pem) = match read_ca_files(ca_cert, ca_key) {
        Ok(pair) => pair,
        Err(code) => return code,
    };
    let sans: Vec<String> = san_dns
        .split(',')
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
        .collect();
    let params = LeafCertParams {
        cn,
        ou: None,
        san_dns: sans,
        san_uris: vec![],
        validity_days,
    };
    match CertGenerator::issue_leaf(&params, &ca_cert_pem, &ca_key_pem) {
        Ok(cert) => {
            if let Err(e) = CertGenerator::write_to_dir(&cert, out, "server") {
                eprintln!("Error: Failed to write server cert files: {e}");
                return ExitCode::FAILURE;
            }
            println!("  Cert: {}", out.join("server.crt").display());
            println!("  Key:  {}", out.join("server.key").display());
            println!();
            println!("Add to gateway.yaml:");
            println!("  mtls:");
            println!("    enabled: true");
            println!("    server_cert: \"{}\"", out.join("server.crt").display());
            println!("    server_key:  \"{}\"", out.join("server.key").display());
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("Error: Server cert generation failed: {e}");
            ExitCode::FAILURE
        }
    }
}

fn tls_issue_client(
    ca_cert: &std::path::Path,
    ca_key: &std::path::Path,
    cn: &str,
    ou: Option<&str>,
    spiffe_uri: Option<String>,
    validity_days: u32,
    out: &std::path::Path,
) -> ExitCode {
    println!("Issuing client certificate for: {cn}");
    let (ca_cert_pem, ca_key_pem) = match read_ca_files(ca_cert, ca_key) {
        Ok(pair) => pair,
        Err(code) => return code,
    };
    let san_uris = spiffe_uri.map(|u| vec![u]).unwrap_or_default();
    let params = LeafCertParams {
        cn,
        ou,
        san_dns: vec![],
        san_uris,
        validity_days,
    };
    let stem = cn.replace(['/', ' '], "-");
    match CertGenerator::issue_leaf(&params, &ca_cert_pem, &ca_key_pem) {
        Ok(cert) => {
            if let Err(e) = CertGenerator::write_to_dir(&cert, out, &stem) {
                eprintln!("Error: Failed to write client cert files: {e}");
                return ExitCode::FAILURE;
            }
            println!("  Cert: {}", out.join(format!("{stem}.crt")).display());
            println!("  Key:  {}", out.join(format!("{stem}.key")).display());
            println!();
            println!("Configure the agent:");
            println!(
                "  export MCP_GATEWAY_CLIENT_CERT={}",
                out.join(format!("{stem}.crt")).display()
            );
            println!(
                "  export MCP_GATEWAY_CLIENT_KEY={}",
                out.join(format!("{stem}.key")).display()
            );
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("Error: Client cert generation failed: {e}");
            ExitCode::FAILURE
        }
    }
}

/// Read CA cert and key PEM files, returning early with `FAILURE` on I/O errors.
fn read_ca_files(
    ca_cert: &std::path::Path,
    ca_key: &std::path::Path,
) -> Result<(String, String), ExitCode> {
    let cert = std::fs::read_to_string(ca_cert).map_err(|e| {
        eprintln!("Error: Cannot read CA cert '{}': {e}", ca_cert.display());
        ExitCode::FAILURE
    })?;
    let key = std::fs::read_to_string(ca_key).map_err(|e| {
        eprintln!("Error: Cannot read CA key '{}': {e}", ca_key.display());
        ExitCode::FAILURE
    })?;
    Ok((cert, key))
}

// ── tool ─────────────────────────────────────────────────────────────────────

/// Run `mcp-gateway tool` subcommands (CLI bridge for direct tool invocation).
pub async fn run_tool_command(cmd: ToolCommand) -> ExitCode {
    match cmd {
        ToolCommand::List {
            capabilities,
            format,
        } => tool_list(capabilities, format).await,
        ToolCommand::Inspect {
            tool,
            capabilities,
            format,
        } => tool_inspect(tool, capabilities, format).await,
        ToolCommand::Invoke {
            tool,
            capabilities,
            args,
            kv_args,
            format,
        } => tool_invoke(tool, capabilities, args, kv_args, format).await,
        ToolCommand::Completions {
            shell,
            capabilities,
        } => tool_completions(shell, capabilities).await,
    }
}

async fn tool_list(capabilities: std::path::PathBuf, format: OutputFormat) -> ExitCode {
    let dir = capabilities.to_string_lossy();
    // `tool list` scans a *local* capability-YAML directory. It is independent
    // of the running gateway's `-c gateway.yaml` config (including
    // `capabilities.enabled`), which controls the server, not this CLI scan.
    // When the directory is absent, report an empty catalogue with a one-line
    // explanation rather than hard-failing (see issue #225); the `discover`
    // path already degrades this way for the same condition.
    if !capabilities.exists() {
        eprintln!(
            "No capability catalogue at '{dir}'. `tool list` scans a local directory of \
             capability YAML files (set -C/--capabilities or MCP_GATEWAY_CAPABILITIES) and is \
             independent of your server config. A configured gateway exposes its tools over MCP \
             at runtime, not via this command."
        );
        print_tool_list(&[], format);
        return ExitCode::SUCCESS;
    }
    match ToolCatalogue::load(&dir).await {
        Ok(cat) => {
            print_tool_list(&cat.list_entries(), format);
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("Error: Failed to load capabilities from '{dir}': {e}");
            ExitCode::FAILURE
        }
    }
}

async fn tool_inspect(
    tool: String,
    capabilities: std::path::PathBuf,
    format: OutputFormat,
) -> ExitCode {
    let dir = capabilities.to_string_lossy();
    match ToolCatalogue::load(&dir).await {
        Ok(cat) => {
            if let Some(cap) = cat.find(&tool) {
                print_tool_inspect(&cap.name, &cap.description, &cap.schema.input, format);
                ExitCode::SUCCESS
            } else {
                eprintln!(
                    "Error: Tool '{tool}' not found. Run 'tool list' to see available tools."
                );
                ExitCode::FAILURE
            }
        }
        Err(e) => {
            eprintln!("Error: Failed to load capabilities from '{dir}': {e}");
            ExitCode::FAILURE
        }
    }
}

async fn tool_invoke(
    tool: String,
    capabilities: std::path::PathBuf,
    args: Option<String>,
    kv_args: Vec<String>,
    format: OutputFormat,
) -> ExitCode {
    let dir = capabilities.to_string_lossy();
    let catalogue = match ToolCatalogue::load(&dir).await {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Error: Failed to load capabilities from '{dir}': {e}");
            return ExitCode::FAILURE;
        }
    };
    let resolved = match resolve_args(args.as_deref(), &kv_args, true) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("Error: {e}");
            return ExitCode::FAILURE;
        }
    };
    match execute_tool(&catalogue, &tool, resolved).await {
        Ok(result) => {
            print_tool_result(&result, format);
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("Error: {e}");
            ExitCode::FAILURE
        }
    }
}

async fn tool_completions(
    shell: clap_complete::Shell,
    capabilities: std::path::PathBuf,
) -> ExitCode {
    let dir = capabilities.to_string_lossy();
    let tool_names = build_completion_tool_names(&dir).await;
    let target = ShellTarget::from_shell(shell).unwrap_or(ShellTarget::Bash);
    let script = generate_completion(target, &tool_names);
    print!("{script}");
    ExitCode::SUCCESS
}

//! MCP Gateway - Universal Model Context Protocol Gateway
//!
//! Single-port multiplexing with a compact Meta-MCP tool surface.

mod commands;

use std::path::Path;
use std::process::ExitCode;

use clap::Parser;
use mcp_gateway::{
    cli::{AuditCommand, Cli, Command, PluginCommand, SetupCommand, SkillsCommand},
    config::Config,
    config_persistence::{load_existing_or_default, write_config},
    gateway::Gateway,
    setup_tracing,
    validator::ValidateConfig,
};
use tracing::{error, info};

// ── New command imports ────────────────────────────────────────────────────────
// These modules live in the binary-only `commands/` tree and are not part of
// the library crate, so they are imported directly here.

#[tokio::main]
#[allow(clippy::too_many_lines)] // Feature-gated fallback arms inflate line count
async fn main() -> ExitCode {
    let cli = Cli::parse();

    if let Err(e) = setup_tracing(&cli.log_level, cli.log_format.as_deref()) {
        eprintln!("Failed to setup tracing: {e}");
        return ExitCode::FAILURE;
    }

    // Capture config path before consuming `cli` in the match below.
    let config_path = cli.config.clone();

    match cli.command {
        Some(Command::Init {
            output,
            profile,
            with_examples,
        }) => commands::run_init_command(&output, with_examples, profile),
        Some(Command::Cap(cap_cmd)) => commands::run_cap_command(cap_cmd).await,
        Some(Command::Import(import_cmd)) => {
            commands::run_protocol_import_command(import_cmd).await
        }
        Some(Command::Kubernetes(kubernetes_cmd)) => {
            commands::run_kubernetes_command(kubernetes_cmd)
        }
        Some(Command::Ranking(ranking_cmd)) => commands::run_ranking_command(ranking_cmd),
        Some(Command::Tls(tls_cmd)) => commands::run_tls_command(tls_cmd),
        Some(Command::Trust(trust_cmd)) => commands::run_trust_command(trust_cmd).await,
        Some(Command::Identity(identity_cmd)) => commands::run_identity_command(identity_cmd).await,
        Some(Command::Stats { url, price }) => commands::run_stats_command(&url, price).await,
        Some(Command::Validate {
            paths,
            format,
            severity,
            fix,
            no_color,
        }) => {
            let config = ValidateConfig {
                format,
                min_severity: severity,
                auto_fix: fix,
                color: !no_color,
            };
            mcp_gateway::validator::cli_handler::run_validate_command(&paths, &config).await
        }
        Some(Command::Tool(tool_cmd)) => commands::run_tool_command(tool_cmd).await,
        Some(Command::Skills(SkillsCommand::Generate {
            capabilities,
            server,
            category,
            out_dir,
            install,
            dry_run,
        })) => {
            commands::run_skills_generate(capabilities, server, category, out_dir, install, dry_run)
                .await
        }
        Some(Command::Skills(SkillsCommand::Import { source, registry })) => {
            commands::run_skills_import(source, registry).await
        }
        Some(Command::Skills(SkillsCommand::List { registry })) => {
            commands::run_skills_list(registry)
        }
        Some(Command::Skills(SkillsCommand::Search { query, registry })) => {
            commands::run_skills_search(&query, registry)
        }
        Some(Command::Skills(SkillsCommand::Show { name, registry })) => {
            commands::run_skills_show(&name, registry)
        }
        Some(Command::Skills(SkillsCommand::Remove { name, registry })) => {
            commands::run_skills_remove(&name, registry)
        }
        Some(Command::Plugin(plugin_cmd)) => {
            run_plugin_command(plugin_cmd, config_path.as_deref()).await
        }
        Some(Command::Setup(SetupCommand::Wizard {
            yes,
            output,
            configure_client,
        })) => commands::run_setup_command(yes, &output, configure_client).await,
        #[cfg(feature = "config-export")]
        Some(Command::Setup(SetupCommand::Export {
            target,
            mode,
            name,
            watch,
            dry_run,
            rollback,
            config,
        })) => {
            commands::run_config_export(target, mode, &name, watch, dry_run, rollback, &config)
                .await
        }
        Some(Command::Add {
            name,
            command,
            url,
            description,
            env_vars,
            config,
            trailing_command,
        }) => {
            // Merge --command flag and trailing `-- cmd args...` (claude/codex style)
            let effective_command = if trailing_command.is_empty() {
                command
            } else {
                Some(trailing_command.join(" "))
            };
            #[cfg(feature = "webui")]
            {
                commands::run_add_command(
                    &name,
                    effective_command.as_deref(),
                    url.as_deref(),
                    description.as_deref(),
                    &env_vars,
                    &config,
                )
                .await
            }
            #[cfg(not(feature = "webui"))]
            {
                let _ = (name, effective_command, url, description, env_vars, config);
                eprintln!("Error: add/remove commands require the 'webui' feature");
                ExitCode::FAILURE
            }
        }
        Some(Command::Remove { name, config }) => {
            #[cfg(feature = "webui")]
            {
                commands::run_remove_command(&name, &config)
            }
            #[cfg(not(feature = "webui"))]
            {
                let _ = (name, config);
                eprintln!("Error: add/remove commands require the 'webui' feature");
                ExitCode::FAILURE
            }
        }
        Some(Command::List { json, config }) => {
            #[cfg(feature = "webui")]
            {
                commands::run_list_command(json, &config)
            }
            #[cfg(not(feature = "webui"))]
            {
                let _ = (json, config);
                eprintln!("Error: add/remove commands require the 'webui' feature");
                ExitCode::FAILURE
            }
        }
        Some(Command::Get { name, config }) => {
            #[cfg(feature = "webui")]
            {
                commands::run_get_command(&name, &config)
            }
            #[cfg(not(feature = "webui"))]
            {
                let _ = (name, config);
                eprintln!("Error: add/remove commands require the 'webui' feature");
                ExitCode::FAILURE
            }
        }
        Some(Command::Doctor {
            fix,
            config,
            format,
            shadow,
            shadow_format,
        }) => {
            if shadow {
                commands::run_doctor_shadow_command(&shadow_format)
            } else {
                commands::run_doctor_command(fix, config.as_deref(), format).await
            }
        }
        Some(Command::Upgrade {
            dry_run,
            quiet,
            data_dir,
        }) => commands::run_upgrade_command(dry_run, quiet, data_dir.as_deref()),
        Some(Command::Audit(audit_cmd)) => run_audit_command(audit_cmd, cli.config.as_deref()),
        #[cfg(feature = "runtime-substrate")]
        Some(Command::Runtime(rt_cmd)) => run_runtime_command(rt_cmd),
        Some(Command::Serve { stdio: true }) => Box::pin(run_stdio_server(cli)).await,
        Some(Command::Serve { stdio: false }) | None => run_server(cli).await,
    }
}

/// Handle `mcp-gateway runtime …` (feature `runtime-substrate`).
///
/// This is the wired call path that exercises the otherwise-dormant
/// descriptor-to-substrate compiler (MIK-5226). It runs schema + security
/// preflight, compiles, and prints the bundle as JSON. It does NOT launch a
/// sandbox — provisioning a live runtime is deliberately out of scope until a
/// launcher exists.
#[cfg(feature = "runtime-substrate")]
fn run_runtime_command(cmd: mcp_gateway::cli::RuntimeCommand) -> ExitCode {
    use mcp_gateway::cli::RuntimeCommand;
    use mcp_gateway::runtime::provision;

    match cmd {
        RuntimeCommand::Compile { descriptor, both } => {
            match provision::compile_descriptor_file(&descriptor, both) {
                Ok(report) => {
                    for w in &report.warnings {
                        eprintln!("warning: {w}");
                    }
                    if both && !report.divergences.is_empty() {
                        eprintln!("cross-substrate divergences:");
                        for d in &report.divergences {
                            eprintln!("  - {d}");
                        }
                    }
                    eprintln!("substrate: {}", report.substrate.name());
                    match serde_json::to_string_pretty(&report.bundle) {
                        Ok(json) => {
                            println!("{json}");
                            ExitCode::SUCCESS
                        }
                        Err(e) => {
                            eprintln!("error: failed to serialize bundle: {e}");
                            ExitCode::FAILURE
                        }
                    }
                }
                Err(e) => {
                    eprintln!("error: {e}");
                    ExitCode::FAILURE
                }
            }
        }
    }
}

/// Resolve the transparency-log signing config from the gateway config, so
/// `audit verify` authenticates the per-entry HMAC when a secret is set
/// (MIK-6700 HMAC.3). A config LOAD FAILURE is propagated as `Err` (fail
/// closed) — never silently downgraded to an empty secret, which would let
/// a stale-sig forgery pass with exit 0 when the config is missing or
/// malformed. A successfully-loaded config with no secret legitimately
/// verifies hash-only.
fn resolve_audit_log_config(
    config_path: Option<&std::path::Path>,
) -> mcp_gateway::Result<mcp_gateway::security::transparency_log::TransparencyLogConfig> {
    use mcp_gateway::security::transparency_log::TransparencyLogConfig;
    let c = Config::load(config_path)?;
    Ok(TransparencyLogConfig {
        key_id: c.security.transparency_log.key_id.clone(),
        shared_secret: c.security.transparency_log.shared_secret.clone(),
        ..TransparencyLogConfig::default()
    })
}

/// Resolve the audit log path: use the provided `--path` flag, or fall back to
/// the default `~/.mcp-gateway/transparency/transparency.jsonl`.
fn resolve_audit_log_path(path: Option<std::path::PathBuf>) -> std::path::PathBuf {
    use std::path::PathBuf;
    path.unwrap_or_else(|| {
        dirs::home_dir().map_or_else(
            || PathBuf::from("transparency.jsonl"),
            |h| {
                h.join(".mcp-gateway")
                    .join("transparency")
                    .join("transparency.jsonl")
            },
        )
    })
}

/// Dispatch an `audit` subcommand (transparency log chain verification / session query).
fn run_audit_command(cmd: AuditCommand, config_path: Option<&std::path::Path>) -> ExitCode {
    use mcp_gateway::security::transparency_log::{show_session_entries, verify_log_signed};

    let resolve_log_config = resolve_audit_log_config;
    let resolve_path = resolve_audit_log_path;

    match cmd {
        AuditCommand::Verify { path } => {
            let log_path = resolve_path(path);
            if !log_path.exists() {
                eprintln!(
                    "Error: transparency log not found at {}",
                    log_path.display()
                );
                return ExitCode::FAILURE;
            }
            let log_config = match resolve_log_config(config_path) {
                Ok(c) => c,
                Err(e) => {
                    // Fail closed: a config we cannot load must NOT downgrade to
                    // hash-only and report success (MIK-6700 review finding #2).
                    eprintln!(
                        "Error: could not load gateway config for signed verification: {e}. Refusing to verify (a load failure must not silently downgrade to hash-only)."
                    );
                    return ExitCode::FAILURE;
                }
            };
            let signed = !log_config.shared_secret.is_empty();
            // Fail closed on the root danger: a log that WAS signed, verified
            // without a secret, would silently degrade to hash-only and pass a
            // stale-sig forgery with exit 0 — regardless of why the secret is
            // absent (no config discovered, wrong config, unset env).
            // (MIK-6700 review finding #2, residual no-config path.)
            if !signed {
                match mcp_gateway::security::transparency_log::log_contains_signed_entry(&log_path)
                {
                    Ok(true) => {
                        eprintln!(
                            "Error: log at {} has signed entries but no shared secret is configured — refusing hash-only verify (HMAC unauthenticated). Set security.transparency_log.shared_secret.",
                            log_path.display()
                        );
                        return ExitCode::FAILURE;
                    }
                    Ok(false) => {}
                    Err(e) => {
                        eprintln!("Error reading log: {e}");
                        return ExitCode::FAILURE;
                    }
                }
            }
            match verify_log_signed(&log_path, &log_config) {
                Err(e) => {
                    eprintln!("Error reading log: {e}");
                    ExitCode::FAILURE
                }
                Ok(result) if result.ok => {
                    let mode = if signed {
                        "hash chain + per-entry HMAC"
                    } else {
                        "hash chain (no secret configured; HMAC not checked)"
                    };
                    println!(
                        "✓ Chain verified ({mode}) — {} entries checked, no tampering detected.",
                        result.entries_checked
                    );
                    ExitCode::SUCCESS
                }
                Ok(result) => {
                    let at = result
                        .error_at_counter
                        .map_or_else(|| "?".to_string(), |n| n.to_string());
                    let msg = result
                        .error_message
                        .unwrap_or_else(|| "unknown error".to_string());
                    eprintln!("✗ Chain verification FAILED at counter {at}: {msg}");
                    ExitCode::FAILURE
                }
            }
        }

        AuditCommand::Show { session, path } => {
            let log_path = resolve_path(path);
            if !log_path.exists() {
                eprintln!(
                    "Error: transparency log not found at {}",
                    log_path.display()
                );
                return ExitCode::FAILURE;
            }
            match show_session_entries(&log_path, &session) {
                Err(e) => {
                    eprintln!("Error reading log: {e}");
                    ExitCode::FAILURE
                }
                Ok(entries) if entries.is_empty() => {
                    println!("No entries found for session '{session}'.");
                    ExitCode::SUCCESS
                }
                Ok(entries) => {
                    for entry in &entries {
                        match serde_json::to_string_pretty(entry) {
                            Ok(pretty) => println!("{pretty}"),
                            Err(e) => eprintln!("Serialisation error: {e}"),
                        }
                    }
                    ExitCode::SUCCESS
                }
            }
        }
    }
}

/// Dispatch a `plugin` subcommand.
///
/// Loads config from `config_path` (needed for marketplace URL / plugin dir
/// defaults) then delegates to the appropriate handler in `commands::plugin`.
async fn run_plugin_command(cmd: PluginCommand, config_path: Option<&Path>) -> ExitCode {
    let config = match Config::load(config_path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Warning: failed to load config ({e}); using defaults");
            Config::default()
        }
    };

    match cmd {
        PluginCommand::Search {
            query,
            marketplace_url,
        } => commands::run_plugin_search(&query, marketplace_url.as_deref(), &config).await,
        PluginCommand::Install {
            name,
            marketplace_url,
            plugin_dir,
        } => {
            commands::run_plugin_install(
                &name,
                marketplace_url.as_deref(),
                plugin_dir.as_deref(),
                &config,
            )
            .await
        }
        PluginCommand::Uninstall { name, plugin_dir } => {
            commands::run_plugin_uninstall(&name, plugin_dir.as_deref(), &config).await
        }
        PluginCommand::List { plugin_dir } => {
            commands::run_plugin_list(plugin_dir.as_deref(), &config)
        }
    }
}

/// Apply CLI overrides to a loaded configuration.
///
/// Merges CLI-provided port, host, and meta-mcp settings into `config`.
fn apply_cli_overrides(config: &mut Config, cli: &Cli) {
    if let Some(port) = cli.port {
        config.server.port = port;
    }
    if let Some(ref host) = cli.host {
        config.server.host.clone_from(host);
    }
    if cli.no_meta_mcp {
        config.meta_mcp.enabled = false;
    }
}

fn apply_cli_overrides_and_validate(config: &mut Config, cli: &Cli) -> mcp_gateway::Result<()> {
    apply_cli_overrides(config, cli);
    config.validate()
}

/// Run the gateway in stdio mode (newline-delimited JSON-RPC on stdin/stdout).
async fn run_stdio_server(cli: Cli) -> ExitCode {
    if let Err(e) = commands::check_upgrade(&commands::upgrade_data_dir()) {
        eprintln!("Warning: upgrade check failed: {e}");
    }

    let config = match Config::load(cli.config.as_deref()) {
        Ok(mut config) => {
            if let Err(e) = apply_cli_overrides_and_validate(&mut config, &cli) {
                eprintln!("Failed to apply configuration overrides: {e}");
                return ExitCode::FAILURE;
            }
            config
        }
        Err(e) => {
            eprintln!("Failed to load configuration: {e}");
            return ExitCode::FAILURE;
        }
    };

    let config_path = cli.config.as_deref().map(std::path::Path::to_path_buf);
    let gateway = match Gateway::new_with_path(config, config_path).await {
        Ok(g) => g,
        Err(e) => {
            eprintln!("Failed to create gateway: {e}");
            return ExitCode::FAILURE;
        }
    };

    if let Err(e) = gateway.run_stdio().await {
        eprintln!("stdio gateway error: {e}");
        return ExitCode::FAILURE;
    }

    ExitCode::SUCCESS
}

/// Run the gateway server.
async fn run_server(cli: Cli) -> ExitCode {
    // Run post-upgrade migrations before anything else.  Non-fatal: a stamp
    // write failure must not prevent the gateway from starting.
    if let Err(e) = commands::check_upgrade(&commands::upgrade_data_dir()) {
        eprintln!("Warning: upgrade check failed: {e}");
    }

    let config = match Config::load(cli.config.as_deref()) {
        Ok(mut config) => {
            if let Err(e) = apply_cli_overrides_and_validate(&mut config, &cli) {
                error!("Failed to apply configuration overrides: {e}");
                return ExitCode::FAILURE;
            }
            config
        }
        Err(e) => {
            error!("Failed to load configuration: {e}");
            return ExitCode::FAILURE;
        }
    };

    info!(
        version = env!("CARGO_PKG_VERSION"),
        port = config.server.port,
        backends = config.backends.len(),
        meta_mcp = config.meta_mcp.enabled,
        "Starting MCP Gateway"
    );

    let config_path = cli.config.as_deref().map(std::path::Path::to_path_buf);
    let gateway = match Gateway::new_with_path(config, config_path).await {
        Ok(g) => g,
        Err(e) => {
            error!("Failed to create gateway: {e}");
            return ExitCode::FAILURE;
        }
    };

    if let Err(e) = gateway.run().await {
        error!("Gateway error: {e}");
        return ExitCode::FAILURE;
    }

    info!("Gateway shutdown complete");
    ExitCode::SUCCESS
}

/// Write discovered servers to a config file.
pub fn write_discovered_to_config(
    servers: &[mcp_gateway::discovery::DiscoveredServer],
    config_path: Option<&Path>,
) -> mcp_gateway::Result<std::path::PathBuf> {
    let path = config_path.map_or_else(
        || std::path::PathBuf::from("mcp-gateway-discovered.yaml"),
        std::path::Path::to_path_buf,
    );

    let mut config = load_existing_or_default(&path)?;

    for server in servers {
        let backend_config = server.to_backend_config();
        config.backends.insert(server.name.clone(), backend_config);
    }

    write_config(&path, &config).map_err(mcp_gateway::Error::Config)?;

    Ok(path)
}

#[cfg(test)]
#[path = "main_tests.rs"]
mod tests;

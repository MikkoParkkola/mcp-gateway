// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Synchronous CLI entry point and command dispatch.

use std::{path::Path, process::ExitCode};

use crate::{
    cli::{Cli, Command, SetupCommand, SkillsCommand},
    commands::{self, CliExit, fail},
    config::{Config, EnvOverlay},
    gateway::Gateway,
    setup_tracing_flush,
    trust::run_provenance_command,
    validator::ValidateConfig,
};
use tracing::{error, info, warn};

#[path = "main_runtime.rs"]
mod runtime;
use runtime::RuntimeShutdown;

/// Run the CLI synchronously, owning tracing, runtime shutdown and log flushing.
///
/// Call this entry point only once per process, after parsing arguments. It
/// installs tracing globally and creates its own Tokio runtime; never call it
/// twice or from inside a Tokio runtime.
pub fn run(args: Cli) -> ExitCode {
    // First, before tracing or any runtime: the invocation a restart would
    // re-exec. It never stops startup.
    crate::restart::invocation::capture_and_install(
        crate::restart::invocation::CaptureInputs {
            args: std::env::args_os().collect(),
            cwd: std::env::current_dir(),
            path_env: std::env::var_os("PATH"),
            #[cfg(unix)]
            mask: crate::restart::invocation::current_thread_mask(),
        },
        &args,
    );
    // Bound outside the runtime, so the log flush runs after the runtime's
    // own shutdown and keeps what that shutdown logs.
    let flush_logs = match setup_tracing_flush(&args.log_level, args.log_format.as_deref()) {
        Ok(flush) => flush,
        Err(e) => {
            return fail(
                CliExit::LocalFailure,
                &format!("logging could not start: {e}"),
                "Check the --log-level and --log-format values.",
            );
        }
    };
    // The boot's retirement plan cell: an HTTP stop stores its plan here, and
    // the runtime wait, the log writer's stop and the exit then end inside
    // that stop's total. Empty for every other command and for stdio.
    let plan = crate::retire::RetireCell::default();
    let mode = RuntimeShutdown::of(args.command.as_ref());
    let (code, left_running) =
        runtime::block_on(mode, &plan, dispatch(args, std::sync::Arc::clone(&plan)));
    crate::retire::tail(code, left_running, plan.get().copied(), flush_logs)
}

#[allow(clippy::too_many_lines)] // Feature-gated fallback arms inflate line count
async fn dispatch(cli: Cli, plan: crate::retire::RetireCell) -> ExitCode {
    // Capture config path (and the port/host overrides `stats` also needs)
    // before consuming `cli` in the match below.
    let config_path = cli.config.clone();
    let port_override = cli.port;
    let host_override = cli.host.clone();

    match cli.command {
        Some(Command::Init {
            output,
            profile,
            with_examples,
        }) => commands::run_init_command(&output, with_examples, profile),
        Some(Command::Cap(cap_cmd)) => {
            commands::run_cap_command(cap_cmd, cli.config.as_deref()).await
        }
        Some(Command::Import(import_cmd)) => {
            commands::run_protocol_import_command(import_cmd).await
        }
        Some(Command::Kubernetes(kubernetes_cmd)) => {
            commands::run_kubernetes_command(kubernetes_cmd)
        }
        Some(Command::Ranking(ranking_cmd)) => commands::run_ranking_command(ranking_cmd),
        Some(Command::Tls(tls_cmd)) => commands::run_tls_command(tls_cmd),
        Some(Command::Trust(trust_cmd)) => commands::run_trust_command(trust_cmd).await,
        Some(Command::Provenance(cmd)) => run_provenance_command(&cmd, config_path.as_deref()),
        Some(Command::Identity(identity_cmd)) => commands::run_identity_command(identity_cmd).await,
        // Offline and synchronous on purpose: initializing custody state must
        // not share a dispatch path with anything that starts the gateway.
        Some(Command::Accounts(accounts_cmd)) => {
            commands::run_accounts_command(&accounts_cmd, config_path.as_deref())
        }
        Some(Command::HashKey { verify, json }) => commands::run_hash_key_command(
            verify.as_deref(),
            crate::cli::output::Render::from_json_flag(json),
        ),
        Some(Command::Stats { gateway, json }) => {
            let effective_url = resolve_stats_url(
                gateway.url,
                config_path.as_deref(),
                port_override,
                host_override.as_deref(),
            );
            commands::run_stats_command(
                &effective_url,
                crate::cli::output::Render::from_json_flag(json),
            )
            .await
        }
        #[cfg(feature = "webui")]
        Some(Command::DashboardLink(args)) => {
            let load = || Config::load(config_path.as_deref()).map_err(|e| e.to_string());
            commands::run_dashboard_link_args(args, load, port_override, host_override.as_deref())
                .await
        }
        // The endpoint it calls exists only with the web UI; say so rather
        // than let the command fail with a bare 404.
        #[cfg(not(feature = "webui"))]
        Some(Command::DashboardLink(_)) => without_webui("dashboard-link"),
        #[cfg(feature = "webui")]
        Some(Command::Events(args)) => {
            let load = || Config::load(config_path.as_deref()).map_err(|e| e.to_string());
            commands::run_events_command(args, load, port_override, host_override.as_deref()).await
        }
        #[cfg(not(feature = "webui"))]
        Some(Command::Events(_)) => without_webui("events"),
        #[cfg(feature = "webui")]
        Some(Command::Api(args)) => {
            let load = || Config::load(config_path.as_deref()).map_err(|e| e.to_string());
            commands::run_api_command(args, load, port_override, host_override.as_deref()).await
        }
        #[cfg(not(feature = "webui"))]
        Some(Command::Api(_)) => without_webui("api"),
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
                color: commands::color::for_stdout(no_color),
            };
            crate::validator::cli_handler::run_validate_command(&paths, &config).await
        }
        Some(Command::Tool(tool_cmd)) => {
            commands::run_tool_command(tool_cmd, config_path.as_deref()).await
        }
        Some(Command::Skills(SkillsCommand::Generate {
            capabilities,
            server,
            category,
            out_dir,
            install,
            dry_run,
        })) => {
            commands::run_skills_generate(
                capabilities,
                config_path.as_deref(),
                server,
                category,
                out_dir,
                install,
                dry_run,
            )
            .await
        }
        Some(Command::Skills(SkillsCommand::Import { source, registry })) => {
            commands::run_skills_import(source, registry).await
        }
        Some(Command::Skills(SkillsCommand::List { registry, json })) => {
            commands::run_skills_list(registry, crate::cli::output::Render::from_json_flag(json))
        }
        Some(Command::Skills(SkillsCommand::Search {
            query,
            registry,
            json,
        })) => commands::run_skills_search(
            &query,
            registry,
            crate::cli::output::Render::from_json_flag(json),
        ),
        Some(Command::Skills(SkillsCommand::Show {
            name,
            registry,
            json,
        })) => commands::run_skills_show(
            &name,
            registry,
            crate::cli::output::Render::from_json_flag(json),
        ),
        Some(Command::Skills(SkillsCommand::Remove { name, registry })) => {
            commands::run_skills_remove(&name, registry)
        }
        Some(Command::Setup(SetupCommand::Wizard {
            yes,
            output,
            configure_client,
            force,
        })) => {
            let mode = commands::config_write::comment_loss(force);
            commands::run_setup_command(yes, &output, configure_client, mode).await
        }
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
            env_file,
            keep_as_text,
            force,
            trailing_command,
        }) => {
            let config = cli_config_or_default(config_path.as_deref());
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
                    commands::AddValues {
                        env_vars: &env_vars,
                        env_file: env_file.as_deref(),
                        keep_as_text: &keep_as_text,
                    },
                    &config,
                    commands::config_write::comment_loss(force),
                )
                .await
            }
            #[cfg(not(feature = "webui"))]
            {
                let _ = (
                    name,
                    effective_command,
                    url,
                    description,
                    env_vars,
                    env_file,
                    keep_as_text,
                    config,
                    force,
                );
                without_webui("add")
            }
        }
        Some(Command::Remove { name, force }) => {
            let config = cli_config_or_default(config_path.as_deref());
            #[cfg(feature = "webui")]
            {
                commands::run_remove_command(
                    &name,
                    &config,
                    commands::config_write::comment_loss(force),
                )
            }
            #[cfg(not(feature = "webui"))]
            {
                let _ = (name, config, force);
                without_webui("remove")
            }
        }
        Some(Command::List { json, available }) => {
            let config = cli_config_or_default(config_path.as_deref());
            #[cfg(feature = "webui")]
            {
                if available {
                    commands::run_list_available_command(json)
                } else {
                    commands::run_list_command(json, &config)
                }
            }
            #[cfg(not(feature = "webui"))]
            {
                let _ = (json, available, config);
                without_webui("list")
            }
        }
        Some(Command::Get { name, json }) => {
            let config = cli_config_or_default(config_path.as_deref());
            #[cfg(feature = "webui")]
            {
                commands::run_get_command(
                    &name,
                    &config,
                    crate::cli::output::Render::from_json_flag(json),
                )
            }
            #[cfg(not(feature = "webui"))]
            {
                let _ = (name, config, json);
                without_webui("get")
            }
        }
        Some(Command::Doctor {
            fix,
            config,
            format,
            shadow,
            shadow_format,
            start_stdio,
            show_stderr,
            no_registry_check,
        }) => {
            if shadow {
                commands::run_doctor_shadow_command(&shadow_format)
            } else {
                let probe = commands::StdioProbe::from_flags(start_stdio, show_stderr);
                commands::run_doctor_command(
                    fix,
                    config.as_deref(),
                    format,
                    probe,
                    no_registry_check,
                )
                .await
            }
        }
        Some(Command::Upgrade {
            dry_run,
            quiet,
            data_dir,
        }) => commands::run_upgrade_with_config(
            dry_run,
            quiet,
            data_dir.as_deref(),
            cli.config.as_deref(),
        ),
        #[cfg(feature = "webui")]
        Some(Command::Audit(mcp_gateway::cli::AuditCommand::LookupEmail(args))) => {
            let load = || Config::load(config_path.as_deref()).map_err(|e| e.to_string());
            commands::run_audit_lookup_command(args, load, port_override, host_override.as_deref())
                .await
        }
        // The route it calls exists only with the web UI.
        #[cfg(not(feature = "webui"))]
        Some(Command::Audit(mcp_gateway::cli::AuditCommand::LookupEmail(_))) => {
            without_webui("audit lookup-email")
        }
        Some(Command::Audit(audit_cmd)) => {
            commands::run_audit_command(audit_cmd, cli.config.as_deref())
        }
        #[cfg(feature = "runtime-substrate")]
        Some(Command::Runtime(rt_cmd)) => run_runtime_command(rt_cmd),
        Some(Command::Serve { stdio: true }) => Box::pin(run_stdio_server(cli)).await,
        Some(Command::Serve { stdio: false }) | None => Box::pin(run_server(cli, plan)).await,
    }
}

/// Handle `mcp-gateway runtime …` (feature `runtime-substrate`).
///
/// This is the wired call path that exercises the otherwise-dormant
/// descriptor-to-substrate compiler. It runs schema + security
/// preflight, compiles, and prints the bundle as JSON. It does NOT launch a
/// sandbox — provisioning a live runtime is deliberately out of scope until a
/// launcher exists.
#[cfg(feature = "runtime-substrate")]
fn run_runtime_command(cmd: crate::cli::RuntimeCommand) -> ExitCode {
    use crate::cli::RuntimeCommand;
    use crate::cli::stdout::println;
    use crate::runtime::provision;

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
                        Err(e) => fail(
                            CliExit::LocalFailure,
                            &format!("the compiled bundle could not be written as JSON: {e}"),
                            "Report this as a bug, with the descriptor that produced it.",
                        ),
                    }
                }
                Err(e) => fail(
                    CliExit::LocalFailure,
                    &e.to_string(),
                    &format!(
                        "Check that {} exists, that you can read it, and that it is a valid descriptor.",
                        descriptor.display()
                    ),
                ),
            }
        }
    }
}

/// Resolve the base URL the `stats` command should query when `--gateway` was
/// not given explicitly.
///
/// `stats` used to hardcode `http://127.0.0.1:39400` as its `--url` default,
/// completely independent of `--config`. That meant `mcp-gateway --config X
/// stats` silently ignored `X` and talked to whatever else happened to be
/// listening on port 39400 the moment `serve --config X` used a different
/// port — returning that unrelated service's error and misattributing it to
/// the gateway. This derives the default from the same
/// `server.host`/`server.port` (plus `--port`/`--host` overrides) that
/// `serve` binds to, so `stats` targets the gateway `--config` describes.
///
/// An explicit `url` (`--gateway`, or `MCP_GATEWAY_URL`) always wins and is returned as-is.
fn resolve_stats_url(
    url: Option<String>,
    config_path: Option<&Path>,
    port_override: Option<u16>,
    host_override: Option<&str>,
) -> String {
    url.unwrap_or_else(|| {
        let mut config = Config::load(config_path).unwrap_or_else(|e| {
            eprintln!("Warning: failed to load config ({e}); using defaults for stats URL");
            Config::default()
        });
        if let Some(port) = port_override {
            config.server.port = port;
        }
        if let Some(host) = host_override {
            config.server.host = host.to_string();
        }
        commands::default_stats_url(&config.server.host, config.server.port)
    })
}

/// A command this build leaves out because it was compiled without the web UI: `command` is its path as typed.
#[cfg(not(feature = "webui"))]
fn without_webui(command: &str) -> ExitCode {
    fail(
        CliExit::LocalFailure,
        &format!("'mcp-gateway {command}' is not in this build (cargo feature `webui` is off)."),
        "Install a build with the webui feature to use it.",
    )
}

/// Apply CLI overrides (port, host, measurement window, meta-mcp) to `config`.
fn apply_cli_overrides(config: &mut Config, cli: &Cli) {
    if let Some(port) = cli.port {
        config.server.port = port;
    }
    if let Some(ref host) = cli.host {
        config.server.host.clone_from(host);
    }
    config.server.protocol_revision_window = cli.protocol_revision_window.unwrap_or_default();
    if cli.no_meta_mcp {
        config.meta_mcp.enabled = false;
    }
}

/// Apply the CLI overrides, then validate against the environment the config
/// was actually evaluated against.
///
/// `overlay`, not the process environment. An env file loads into an overlay and
/// is never exported, so `Config::validate` — which validates against an empty
/// overlay — refuses every `env:` reference an env file supplies, including the
/// account store key. Validating here and resolving there is not a difference of
/// strictness; it is validating a different configuration.
fn apply_cli_overrides_and_validate(
    config: &mut Config,
    cli: &Cli,
    overlay: &EnvOverlay,
) -> crate::Result<()> {
    apply_cli_overrides(config, cli);
    config.validate_with_env(overlay)
}

/// The file `add`, `remove`, `list` and `get` use: the global `--config` /
/// `MCP_GATEWAY_CONFIG`, else `./gateway.yaml`. Unlike the stdio path below, a
/// named file is used as given, never swapped for a fallback.
fn cli_config_or_default(global: Option<&Path>) -> std::path::PathBuf {
    global.map_or_else(|| "gateway.yaml".into(), Path::to_path_buf)
}

/// Run the gateway in stdio mode (newline-delimited JSON-RPC on stdin/stdout).
/// Resolve the effective `--config` path for the **stdio** serve command only.
///
/// An explicitly-supplied path that does not exist is downgraded to `None`
/// (fall through to `Config::load`'s fallback-location search, then env vars,
/// then built-in defaults) instead of a hard failure, so the published
/// container image boots over stdio when no config has been mounted yet. Glama's
/// build smoke-test starts the container with `serve --stdio --config
/// /config.yaml` even though the generated Dockerfile never writes that file;
/// fail-loud there reports a spurious "build failed".
///
/// Scoped to stdio deliberately: stdio is a local pipe with no network listener,
/// so starting on defaults cannot expose an unauthenticated network surface. The
/// HTTP `run_server` path stays fail-loud (`Config::load(cli.config)` directly)
/// because its defaults (`auth.enabled=false`, `meta_mcp.enabled=true`) would be
/// a fail-open regression if an intended `--config` went missing. `audit`/
/// `validate`/`doctor` likewise keep `Config::load`'s fail-loud behavior.
fn serve_config_path(cli: &Cli) -> Option<std::path::PathBuf> {
    match cli.config.as_deref() {
        Some(p) if !p.exists() => {
            warn!(
                target: "mcp_gateway",
                "config file {} not found; continuing over stdio without it \
                 (fallback locations, env vars, then defaults)",
                p.display()
            );
            None
        }
        other => other.map(std::path::Path::to_path_buf),
    }
}

/// A fatal start or run error of `serve`. It is logged like every gateway error; when the log's filter drops that
/// event (`--log-level off`, `RUST_LOG=off`, or a directive that leaves the gateway's errors out) it is also printed
/// straight to stderr, escaped by the log's own rule, so a failed start is never silent and text quoted from
/// gateway.yaml never starts a line of its own. The probe names the same target, level and field as the event, so a
/// field-keyed directive answers it exactly as it answers the event.
fn fatal(message: &str) {
    error!(target: "mcp_gateway", "{message}");
    if !tracing::event_enabled!(target: "mcp_gateway", tracing::Level::ERROR, message) {
        eprintln!("{}", crate::log_escape::escaped(message));
    }
}

async fn run_stdio_server(cli: Cli) -> ExitCode {
    if let Err(e) = commands::check_upgrade(&commands::upgrade_data_dir()) {
        warn!(target: "mcp_gateway", "upgrade check failed: {e}");
    }

    let config_path = serve_config_path(&cli);
    let (discovered, load_path) = discovered_config::resolve(config_path.as_deref());
    // `load_evaluated`, not `load`: an env file is read into an overlay the
    // gateway carries, never into the process environment, so the environment
    // has to travel with the config it was evaluated against.
    let (config, env) = match commands::load_for_serve(load_path.as_deref()).await {
        Ok(mut evaluated) => {
            let env = std::sync::Arc::new(evaluated.live_env());
            let mut config = evaluated.config;
            if let Err(e) = apply_cli_overrides_and_validate(&mut config, &cli, &evaluated.overlay)
            {
                fatal(&format!("Failed to apply configuration overrides: {e}"));
                return ExitCode::FAILURE;
            }
            (config, env)
        }
        Err(e) => {
            fatal(&format!("Failed to load configuration: {e}"));
            return ExitCode::FAILURE;
        }
    };

    // `new_evaluated`, not `new_with_path().with_env()`: the constructor must
    // hold the overlay while it validates and while it brings account custody
    // up, and the await below must not begin until custody is READY. Attaching
    // the environment afterwards would validate against an empty one and would
    // reach serving with no custody at all.
    let gateway = match Gateway::new_evaluated(config, env, config_path).await {
        Ok(g) => discovered_config::watch(g, discovered),
        Err(e) => {
            fatal(&format!("Failed to create gateway: {e}"));
            return ExitCode::FAILURE;
        }
    };

    // Box::pin: the run_stdio future is large (>16KB) since MetaMcpCallerContext
    // gained the identity-propagation field; boxing keeps it off the
    // stack and satisfies clippy::large_futures.
    if let Err(e) = Box::pin(gateway.run_stdio()).await {
        fatal(&format!("stdio gateway error: {e}"));
        return ExitCode::FAILURE;
    }

    // The stdio path's last line, as the HTTP path's "Gateway shutdown
    // complete": written just before exit, so it is the line the exit flush
    // must not lose.
    info!(target: "mcp_gateway", "stdio: shutdown complete");
    ExitCode::SUCCESS
}

/// Run the gateway server.
async fn run_server(cli: Cli, plan: crate::retire::RetireCell) -> ExitCode {
    // Run post-upgrade migrations before anything else.  Non-fatal: a stamp
    // write failure must not prevent the gateway from starting.
    if let Err(e) = commands::check_upgrade(&commands::upgrade_data_dir()) {
        warn!(target: "mcp_gateway", "upgrade check failed: {e}");
    }

    // HTTP serve stays fail-loud: an explicit --config that cannot be loaded
    // must NOT silently start on defaults (auth.enabled=false,
    // meta_mcp.enabled=true would be a network-facing fail-open). Only the
    // stdio path (a local pipe, no network auth surface) degrades — see
    // serve_config_path / run_stdio_server.
    let (discovered, load_path) = discovered_config::resolve(cli.config.as_deref());
    let (config, env) = match commands::load_for_serve(load_path.as_deref()).await {
        Ok(mut evaluated) => {
            let env = std::sync::Arc::new(evaluated.live_env());
            let mut config = evaluated.config;
            if let Err(e) = apply_cli_overrides_and_validate(&mut config, &cli, &evaluated.overlay)
            {
                fatal(&format!("Failed to apply configuration overrides: {e}"));
                return ExitCode::FAILURE;
            }
            (config, env)
        }
        Err(e) => {
            fatal(&format!("Failed to load configuration: {e}"));
            return ExitCode::FAILURE;
        }
    };

    info!(
        target: "mcp_gateway",
        version = env!("CARGO_PKG_VERSION"),
        port = config.server.port,
        backends = config.backends.len(),
        meta_mcp = config.meta_mcp.enabled,
        "Starting MCP Gateway"
    );

    let config_path = cli.config.as_deref().map(std::path::Path::to_path_buf);
    // See `run_stdio_server`: the constructor owns validation-against-overlay
    // and the custody bring-up, and both must complete before `run` serves.
    let mut gateway = match Gateway::new_evaluated(config, env, config_path).await {
        Ok(g) => discovered_config::watch(g, discovered),
        Err(e) => {
            fatal(&format!("Failed to create gateway: {e}"));
            return ExitCode::FAILURE;
        }
    };
    gateway.set_retire_cell(plan);

    if let Err(e) = gateway.run().await {
        fatal(&format!("Gateway error: {e}"));
        return ExitCode::FAILURE;
    }

    info!(target: "mcp_gateway", "Gateway shutdown complete");
    ExitCode::SUCCESS
}

/// Write discovered servers to a config file, literal env and header values
/// through the secret store. Returns the file, how many servers were written
/// and how many were skipped; each skipped one is named on stderr with its
/// reasons, never a value.
///
/// # Errors
///
/// Nothing was written: every server was skipped, the secret store refused,
/// or the file could not be loaded or saved.
pub(crate) fn write_discovered_to_config(
    servers: &[crate::discovery::DiscoveredServer],
    config_path: Option<&Path>,
    mode: crate::commands::config_write::CommentLoss,
) -> crate::Result<(std::path::PathBuf, usize, usize)> {
    use crate::cli_support::{Outcome, adopt_literals, describe_skipped};

    let path = config_path.map_or_else(
        || std::path::PathBuf::from("mcp-gateway-discovered.yaml"),
        std::path::Path::to_path_buf,
    );

    let mut adoption = None;
    let saved = commands::config_write::write(&path, mode, |config| {
        adoption = Some(adopt_literals(&path, config, servers)?);
        Ok(())
    });
    let Some(mut adoption) = adoption else {
        return Err(crate::Error::Config(saved.err().unwrap_or_default()));
    };
    let outcomes = std::mem::take(&mut adoption.outcomes);
    adoption.settle(&saved);
    saved.map_err(crate::Error::Config)?;
    for skipped in outcomes
        .iter()
        .filter(|o| matches!(o, Outcome::Skipped { .. }))
    {
        eprintln!(
            "⚠️  Skipped discovered server {}",
            describe_skipped(std::slice::from_ref(skipped))
        );
    }
    let written = outcomes
        .iter()
        .filter(|o| matches!(o, Outcome::Adopted { .. }))
        .count();
    Ok((path, written, outcomes.len() - written))
}

#[path = "main_discovered_config.rs"]
pub(crate) mod discovered_config;
#[cfg(tp1)]
#[cfg(test)]
#[path = "main_tests.rs"]
mod tests;

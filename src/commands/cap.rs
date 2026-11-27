// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Capability (`cap`) subcommand handlers for `mcp-gateway`.

use crate::cli::stdout::{print, println};

use std::process::ExitCode;
use std::sync::Arc;

use super::{CliExit, check_config_command, fail, usage};

use mcp_gateway::{
    capability::{
        AuthTemplate, CapabilityExecutor, CapabilityLoader, IssueSeverity, OpenApiConverter,
        parse_capability_file, validate_capability, validate_capability_definition,
    },
    cli::CapCommand,
    registry::Registry,
};

use crate::cli::output::Render;

#[path = "cap_json.rs"]
mod json;
#[path = "cap_render.rs"]
mod render;
mod server_scan;
use server_scan::cap_discover;

/// Run a `cap` subcommand (validate, list, import, test, discover, install, search, ...).
#[allow(clippy::too_many_lines)]
pub async fn run_cap_command(cmd: CapCommand, config: Option<&std::path::Path>) -> ExitCode {
    match cmd {
        CapCommand::Validate { file, json } => {
            cap_validate(file, Render::from_json_flag(json)).await
        }
        CapCommand::Pin { file } => cap_pin(file).await,
        CapCommand::List { directory, json } => {
            cap_list(directory, config, Render::from_json_flag(json)).await
        }
        CapCommand::Import {
            spec,
            output,
            prefix,
            auth_key,
        } => cap_import(spec, output, prefix, auth_key).await,
        CapCommand::Test { file, args, json } => {
            cap_test(file, args, Render::from_json_flag(json)).await
        }
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
            json,
        } => cap_search(query, capabilities, Render::from_json_flag(json)).await,
        CapCommand::RegistryList { capabilities, json } => {
            cap_registry_list(capabilities, Render::from_json_flag(json)).await
        }
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

async fn cap_validate(file: std::path::PathBuf, render: Render) -> ExitCode {
    match parse_capability_file(&file).await {
        Ok(cap) => {
            if let Err(e) = validate_capability(&cap) {
                return fail(
                    CliExit::LocalFailure,
                    &format!("Validation failed: {e}"),
                    &fix_and_rerun(&file),
                );
            }
            // The structural checks the loader runs: an error here means the
            // gateway would skip the file, a warning that it loads with a smell.
            let issues = validate_capability_definition(&cap, Some(&file.to_string_lossy()));
            for issue in &issues {
                eprintln!("{issue}");
            }
            if issues.iter().any(|i| i.severity == IssueSeverity::Error) {
                return fail(
                    CliExit::LocalFailure,
                    "Validation failed: structural errors above",
                    &fix_and_rerun(&file),
                );
            }
            if render == Render::Json {
                let warnings = issues
                    .iter()
                    .filter(|i| i.severity == IssueSeverity::Warning)
                    .map(ToString::to_string)
                    .collect();
                return crate::cli::output::print_document(json::validate(&cap, warnings));
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
        Err(e) => fail(
            CliExit::LocalFailure,
            &format!("Failed to parse: {e}"),
            &check_capability_file(&file),
        ),
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
    // Under the capability directory's lock, written atomically: the same
    // lock the web editor takes, so a pin never lands between its checks.
    let pinned = {
        let file = file.clone();
        tokio::task::spawn_blocking(move || mcp_gateway::capability::pin_file(&file)).await
    };
    match pinned {
        Ok(Ok(hash)) => {
            println!("✅ Pinned {}", file.display());
            println!("   sha256: {hash}");
            ExitCode::SUCCESS
        }
        Ok(Err(error)) => fail(CliExit::LocalFailure, &error, &check_capability_file(&file)),
        Err(join) => fail(
            CliExit::LocalFailure,
            &format!("Pinning {} stopped: {join}", file.display()),
            "Rerun 'mcp-gateway cap pin', and report this as a bug if it stops again.",
        ),
    }
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
    let (_, load_path) = crate::cli::entry::discovered_config::resolve(config);
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

async fn cap_list(
    directory: std::path::PathBuf,
    config: Option<&std::path::Path>,
    render: Render,
) -> ExitCode {
    let executor = match list_executor(config) {
        Ok(executor) => executor,
        Err((path, e)) => {
            return fail(
                CliExit::LocalFailure,
                &format!("Failed to load config {}: {e}", path.display()),
                &format!("Run '{}' to see why.", check_config_command(&path)),
            );
        }
    };
    let path = directory.to_string_lossy();
    match CapabilityLoader::load_directory(&path).await {
        Ok(caps) if render == Render::Json => {
            let items = caps
                .iter()
                .map(|cap| json::ListItem {
                    name: &cap.name,
                    description: &cap.description,
                    auth_type: cap.auth.required.then_some(cap.auth.auth_type.as_str()),
                    missing_credential: executor
                        .missing_credential(&cap.auth, &mut std::collections::HashMap::new()),
                })
                .collect();
            crate::cli::output::print_document(json::list(&path, items))
        }
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
        Err(e) => fail(
            CliExit::LocalFailure,
            &format!("Failed to load: {e}"),
            &format!("Check that {path} exists and holds capability files."),
        ),
    }
}

/// What `cap import --auth-key` says for a value that is not a credential
/// reference: every form the resolver reads, and never the value.
const AUTH_KEY_REFUSAL: &str = "--auth-key takes a credential reference: env:NAME, keychain:NAME, \
oauth:PROVIDER, file:PATH, {env.NAME} or a variable NAME";

async fn cap_import(
    spec: std::path::PathBuf,
    output: std::path::PathBuf,
    prefix: Option<String>,
    auth_key: Option<String>,
) -> ExitCode {
    // Read through the resolver's own parser, so this accepts exactly the
    // forms a capability's auth key can use, and never echoes a value.
    if auth_key
        .as_deref()
        .is_some_and(|key| crate::capability::credential_form(key).is_err())
    {
        return mutant!("N15", crate::commands::fail(crate::commands::CliExit::LocalFailure, "cap import", AUTH_KEY_REFUSAL), usage("cap import", AUTH_KEY_REFUSAL));
    }
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
            let mut failed = 0_usize;
            for cap in &caps {
                if let Err(e) = cap.write_to_file(&out_path) {
                    failed += 1;
                    eprintln!("❌ Failed to write {}: {e}", cap.name);
                } else {
                    println!("  ✅ {}.yaml", cap.name);
                }
            }
            // Counted after the writes, so the summary says what happened.
            let written = caps.len() - failed;
            println!(
                "\nImported {written} tools from {spec_ref} into {out_path}/. Review them before loading."
            );
            if failed > 0 {
                // A tool not written, an existing name included, is a failed
                // import: a script must not read it as done.
                return fail(
                    CliExit::LocalFailure,
                    &format!("{failed} tools could not be written"),
                    "Each failed tool is named above: move or rename the files in the way, or pick another --output.",
                );
            }
            ExitCode::SUCCESS
        }
        Err(e) => fail(
            CliExit::LocalFailure,
            &format!("Failed to convert: {e}"),
            &format!("Check that {spec_ref} exists and is an OpenAPI document."),
        ),
    }
}

async fn cap_test(file: std::path::PathBuf, args: String, render: Render) -> ExitCode {
    let executor = CapabilityExecutor::new();
    let mut print_banner = |banner: &str| print!("{banner}");
    cap_test_with(&executor, &file, &args, render, &mut print_banner)
        .await
        .emit(crate::cli::output::OnWriteFailure::ExitOnBrokenPipe)
}

/// What `cap test` prints and exits with, the call made through `executor`. In text the banner goes to `banner_out`
/// before the call, as it always has, so a slow call shows what it runs and an interrupt keeps the banner; the rest
/// is returned. Under `--json` nothing goes out before the call, and only a successful call prints a document
/// (MIK-9764.JSONF.1, design D2, D5).
async fn cap_test_with(
    executor: &CapabilityExecutor,
    file: &std::path::Path,
    args: &str,
    render: Render,
    banner_out: &mut dyn FnMut(&str),
) -> crate::cli::output::Printed {
    use crate::cli::output::Printed;
    let cap = match parse_capability_file(file).await {
        Ok(c) => c,
        Err(e) => {
            return Printed::error(
                CliExit::LocalFailure,
                &format!("Failed to parse capability: {e}"),
                &check_capability_file(file),
            );
        }
    };
    let params: serde_json::Value = match serde_json::from_str(args) {
        Ok(v) => v,
        Err(e) => {
            return Printed::error(
                mutant!("N9", CliExit::LocalFailure, CliExit::Usage),
                &format!("Invalid JSON arguments: {e}"),
                "Run 'mcp-gateway cap test --help' for usage.",
            );
        }
    };
    // The schema check a gateway call gets (MIK-7943); the arguments go on as
    // given, as in `invoke`.
    let verdict = mcp_gateway::capability::validate_arguments(&params, &cap.schema.input);
    if !verdict.is_valid() {
        return Printed::error(
            CliExit::LocalFailure,
            &verdict.format_error(&cap.schema.input),
            "Pass --args matching the capability's input schema.",
        );
    }
    if render == Render::Text {
        banner_out(&format!(
            "Testing capability: {}\nArguments: {}\n\n",
            cap.name,
            serde_json::to_string_pretty(&params).unwrap_or_default()
        ));
    }
    match executor.execute(&cap, params.clone()).await {
        Ok(result) => {
            let stdout = match render {
                Render::Text => format!(
                    "✅ Success:\n\n{}\n",
                    serde_json::to_string_pretty(&result).unwrap_or_default()
                ),
                Render::Json => match json::test(&cap.name, &params, &result) {
                    Ok(doc) => doc,
                    Err(why) => {
                        return Printed::error(
                            CliExit::LocalFailure,
                            &format!("Could not print the capability document: {why}"),
                            "Rerun without --json for the text form, and report this as a bug.",
                        );
                    }
                },
            };
            Printed {
                stdout,
                stderr: String::new(),
                exit: 0,
            }
        }
        Err(e) => Printed::error(
            CliExit::LocalFailure,
            &format!("Execution failed: {e}"),
            "Check the capability's provider, its URL and any credential it names, then rerun.",
        ),
    }
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
            Err(e) => fail(
                CliExit::LocalFailure,
                &format!("Installation failed: {e}"),
                "Check the capability name, --repo and --branch, then rerun.",
            ),
        }
    } else {
        println!("ℹ️  All capabilities are already available in the capabilities directory.");
        println!("   Use 'cap list' to see available capabilities.");
        ExitCode::SUCCESS
    }
}

async fn cap_search(query: String, capabilities: std::path::PathBuf, render: Render) -> ExitCode {
    let reg = Registry::new(&capabilities);
    match reg.build_index().await {
        Ok(index) => {
            let results = index.search(&query);
            if render == Render::Json {
                return crate::cli::output::print_document(json::search(&query, &results));
            }
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
        Err(e) => fail(
            CliExit::LocalFailure,
            &format!("Failed to build registry index: {e}"),
            &format!(
                "Check that {} exists and holds capability files.",
                capabilities.display()
            ),
        ),
    }
}

async fn cap_registry_list(capabilities: std::path::PathBuf, render: Render) -> ExitCode {
    let reg = Registry::new(&capabilities);
    match reg.build_index().await {
        Ok(index) if render == Render::Json => {
            crate::cli::output::print_document(json::registry_list(&index.capabilities))
        }
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
        Err(e) => fail(
            CliExit::LocalFailure,
            &format!("Failed to build registry index: {e}"),
            &format!(
                "Check that {} exists and holds capability files.",
                capabilities.display()
            ),
        ),
    }
}

/// The remedy for a capability file that could not be read or parsed: it names the file.
fn check_capability_file(file: &std::path::Path) -> String {
    format!(
        "Check that {} exists and is a capability YAML file.",
        file.display()
    )
}

/// The remedy for a capability file that parsed but failed validation.
fn fix_and_rerun(file: &std::path::Path) -> String {
    format!(
        "Fix {} as the message says, then rerun 'mcp-gateway cap validate'.",
        file.display()
    )
}

#[cfg(tp2)]
#[cfg(test)]
#[path = "cap_tests.rs"]
mod tests;

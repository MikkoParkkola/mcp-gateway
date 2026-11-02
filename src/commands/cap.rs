// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Capability (`cap`) subcommand handlers for `mcp-gateway`.

use std::process::ExitCode;
use std::sync::Arc;

use mcp_gateway::{
    capability::{
        AuthTemplate, CapabilityExecutor, CapabilityLoader, IssueSeverity, OpenApiConverter,
        parse_capability_file, validate_capability, validate_capability_definition,
    },
    cli::CapCommand,
    registry::Registry,
};

#[path = "cap_render.rs"]
mod render;
mod server_scan;
use server_scan::cap_discover;

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
        Ok(Err(error)) => {
            eprintln!("❌ {error}");
            ExitCode::FAILURE
        }
        Err(join) => {
            eprintln!("❌ Pinning {} stopped: {join}", file.display());
            ExitCode::FAILURE
        }
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

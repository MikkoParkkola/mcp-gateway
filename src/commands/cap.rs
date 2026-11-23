// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Capability (`cap`) subcommand handlers for `mcp-gateway`.

use crate::cli::stdout::{print, println};

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
            eprintln!("❌ Failed to load config {}: {e}", path.display());
            return ExitCode::FAILURE;
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
        Err(e) => {
            eprintln!("❌ Failed to load: {e}");
            ExitCode::FAILURE
        }
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
        eprintln!("Error: {AUTH_KEY_REFUSAL}");
        return ExitCode::from(2);
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
                eprintln!("{failed} tools could not be written.");
                return ExitCode::FAILURE;
            }
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("❌ Failed to convert: {e}");
            ExitCode::FAILURE
        }
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
    let failed = |stdout: String, stderr: String| Printed {
        stdout,
        stderr,
        exit: 1,
    };
    let cap = match parse_capability_file(file).await {
        Ok(c) => c,
        Err(e) => {
            return failed(
                String::new(),
                format!("❌ Failed to parse capability: {e}\n"),
            );
        }
    };
    let params: serde_json::Value = match serde_json::from_str(args) {
        Ok(v) => v,
        Err(e) => return failed(String::new(), format!("❌ Invalid JSON arguments: {e}\n")),
    };
    // The schema check a gateway call gets (MIK-7943); the arguments go on as
    // given, as in `invoke`.
    let verdict = mcp_gateway::capability::validate_arguments(&params, &cap.schema.input);
    if !verdict.is_valid() {
        return failed(
            String::new(),
            format!("❌ {}\n", verdict.format_error(&cap.schema.input)),
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
                        return failed(
                            String::new(),
                            format!("❌ Could not print the capability document: {why}\n"),
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
        Err(e) => failed(String::new(), format!("❌ Execution failed: {e}\n")),
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
        Err(e) => {
            eprintln!("❌ Failed to build registry index: {e}");
            ExitCode::FAILURE
        }
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
        Err(e) => {
            eprintln!("❌ Failed to build registry index: {e}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(tp2)]
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

    /// LD6: `cap validate` refuses a misspelt key with the loader's message
    /// (the same `parse_capability_file` error `validate` prints) and fails.
    #[tokio::test]
    async fn ld6_cap_validate_refuses_a_misspelt_key() {
        let dir = TempDir::new().expect("dir");
        let path = dir.path().join("typo.yaml");
        std::fs::write(
            &path,
            "name: typo\ndescription: d\nproviders:\n  primary:\n    service: rest\n    rate_lmit:\n      interval_ms: 1000\n    config:\n      base_url: https://typo.test\n      path: /x\n",
        )
        .expect("write");
        let message = parse_capability_file(&path)
            .await
            .expect_err("refused")
            .to_string();
        assert_eq!(
            message,
            format!(
                "Configuration error: {}: key `rate_lmit` is not a capability provider field. Did you mean: rate_limit?",
                path.display()
            )
        );
        assert!(
            !is_success(super::cap_validate(path, super::Render::Text).await),
            "cap validate fails"
        );
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

    /// J11, the failures before the call (MIK-9764.JSONF.1): an unreadable capability file, arguments that are not
    /// JSON and arguments the input schema refuses each leave stdout empty in both forms, exit 1, and name the
    /// failure on stderr, the same in both forms.
    #[tokio::test]
    async fn cap_test_failures_before_the_call_print_nothing_on_stdout() {
        use crate::cli::output::Render;
        let dir = TempDir::new().unwrap();
        let file = dir.path().join("city_cap.yaml");
        std::fs::write(
            &file,
            "name: city_cap\ndescription: City\nschema:\n  input:\n    type: object\n    properties:\n      \
             city:\n        type: string\n    required: [city]\nproviders:\n  primary:\n    service: rest\n    \
             config:\n      base_url: https://city.test\n      path: /now\n      method: GET\n",
        )
        .unwrap();
        let missing = dir.path().join("missing.yaml");
        let executor = mcp_gateway::capability::CapabilityExecutor::new();
        // (file, arguments, the start of the stderr line, a word it must name)
        let cases = [
            (
                &missing,
                r#"{"city": "Oulu"}"#,
                "❌ Failed to parse capability: ",
                "missing.yaml",
            ),
            (&file, "{", "❌ Invalid JSON arguments: ", "EOF"),
            // The schema refusal: `city` is required and missing.
            (&file, "{}", "❌ ", "city"),
        ];
        for (path, args, start, names) in cases {
            for render in [Render::Text, Render::Json] {
                let mut banner = String::new();
                let printed = super::cap_test_with(&executor, path, args, render, &mut |b| {
                    banner.push_str(b);
                })
                .await;
                assert_eq!(
                    banner, "",
                    "no banner before a refused call: {args} {render:?}"
                );
                assert_eq!(
                    (printed.stdout.as_str(), printed.exit),
                    ("", 1),
                    "{args} {render:?}"
                );
                assert!(
                    printed.stderr.starts_with(start) && printed.stderr.contains(names),
                    "{args} {render:?}: {}",
                    printed.stderr
                );
            }
        }
    }

    /// J11, order: in text the banner goes out before the call. The backend answers 200 only once the banner has
    /// reached the test (it waits up to 10 s, then answers 500), so a banner held back until the call returns gets
    /// the 500 and this row fails.
    #[tokio::test]
    async fn cap_test_text_banner_goes_out_before_the_call() {
        use crate::cli::output::Render;
        use std::io::Read as _;
        let (seen_tx, seen_rx) = std::sync::mpsc::channel::<()>();
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        std::thread::spawn(move || {
            let Ok((mut stream, _)) = listener.accept() else {
                return;
            };
            let mut request = vec![0_u8; 65536];
            let _ = stream.read(&mut request);
            let (status, body) = match seen_rx.recv_timeout(std::time::Duration::from_secs(10)) {
                Ok(()) => ("200 OK", r#"{"ok":true}"#),
                Err(_) => ("500 Banner Late", r#"{"ok":false}"#),
            };
            let head = format!(
                "HTTP/1.1 {status}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
                body.len()
            );
            let _ = stream.write_all(head.as_bytes());
            let _ = stream.write_all(body.as_bytes());
        });
        let dir = TempDir::new().unwrap();
        let file = dir.path().join("order_cap.yaml");
        std::fs::write(
            &file,
            format!(
                "name: order_cap\ndescription: Order\nschema:\n  input:\n    type: object\nproviders:\n  primary:\n    \
                 service: rest\n    config:\n      base_url: http://127.0.0.1:{port}\n      path: /now\n      \
                 method: GET\n"
            ),
        )
        .unwrap();
        let executor =
            mcp_gateway::capability::CapabilityExecutor::new().with_test_loopback_egress();
        let mut banner = String::new();
        let printed = super::cap_test_with(&executor, &file, "{}", Render::Text, &mut |b| {
            banner.push_str(b);
            let _ = seen_tx.send(());
        })
        .await;
        assert_eq!(banner, "Testing capability: order_cap\nArguments: {}\n\n");
        assert_eq!(
            (printed.exit, printed.stdout.as_str()),
            (0, "✅ Success:\n\n{\n  \"ok\": true\n}\n"),
            "{}",
            printed.stderr
        );
    }

    /// J11 (MIK-9764.JSONF.1): a successful `cap test` through an executor that may reach loopback (the `cfg(test)`
    /// seam): under `--json` one document with the capability, the arguments and the result (with no response
    /// transform the result is the body); in text the banner, the arguments and the pretty result, as today.
    #[tokio::test]
    async fn cap_test_prints_one_document_on_success() {
        use crate::cli::output::{Printed, Render};
        use std::io::Read as _;
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        std::thread::spawn(move || {
            let body = br#"{"temp":21,"unit":"C"}"#;
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { return };
                let mut request = vec![0_u8; 65536];
                let _ = stream.read(&mut request);
                let head = format!(
                    "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
                    body.len()
                );
                let _ = stream.write_all(head.as_bytes());
                let _ = stream.write_all(body);
            }
        });
        let dir = TempDir::new().unwrap();
        let file = dir.path().join("now_cap.yaml");
        std::fs::write(
            &file,
            format!(
                "name: now_cap\ndescription: Now\nschema:\n  input:\n    type: object\n    properties:\n      \
                 city:\n        type: string\nproviders:\n  primary:\n    service: rest\n    config:\n      \
                 base_url: http://127.0.0.1:{port}\n      path: /now\n      method: GET\n"
            ),
        )
        .unwrap();
        let executor =
            mcp_gateway::capability::CapabilityExecutor::new().with_test_loopback_egress();
        let args = r#"{"city": "Oulu"}"#;

        let mut banner = String::new();
        let json = super::cap_test_with(&executor, &file, args, Render::Json, &mut |b| {
            banner.push_str(b);
        })
        .await;
        assert_eq!(banner, "", "--json sends nothing out before the call");
        assert_eq!(
            json,
            Printed {
                stdout: "{\"schema_version\":1,\"capability\":\"now_cap\",\"arguments\":{\"city\":\"Oulu\"},\
                         \"result\":{\"temp\":21,\"unit\":\"C\"}}\n"
                    .to_owned(),
                stderr: String::new(),
                exit: 0,
            }
        );
        let text = super::cap_test_with(&executor, &file, args, Render::Text, &mut |b| {
            banner.push_str(b);
        })
        .await;
        assert_eq!(
            banner, "Testing capability: now_cap\nArguments: {\n  \"city\": \"Oulu\"\n}\n\n",
            "text sends the banner out before the call"
        );
        assert_eq!(
            text,
            Printed {
                stdout: "✅ Success:\n\n{\n  \"temp\": 21,\n  \"unit\": \"C\"\n}\n".to_owned(),
                stderr: String::new(),
                exit: 0,
            }
        );
    }
}

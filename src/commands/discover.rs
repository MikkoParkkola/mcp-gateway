//! CLI handler for `cap import-url` (RFC-0074).
//!
//! Runs the full discovery pipeline:
//! SSRF check -> parallel probe -> format detection -> `OpenAPI` conversion ->
//! quality scoring -> dedup -> write YAML files (or dry-run report).

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use tracing::info;

use mcp_gateway::capability::CapabilityLoader;
use mcp_gateway::capability::discovery::{DiscoveryEngine, DiscoveryOptions};

/// Run `cap import-url`.
///
/// Probes `url` for an API specification, converts it to capability YAML
/// files, and writes them to `output`.  With `--dry-run` it prints what
/// would be generated without writing.
#[allow(clippy::too_many_arguments)]
pub async fn cap_import_url(
    url: String,
    prefix: Option<String>,
    output: PathBuf,
    auth: Option<String>,
    max_endpoints: usize,
    dry_run: bool,
    cost_per_call: Option<f64>,
) -> ExitCode {
    // Collect existing capability names for dedup
    let existing_names = collect_existing_names(&output).await;

    let options = DiscoveryOptions {
        prefix,
        output_dir: output.clone(),
        auth,
        max_endpoints,
        dry_run,
        existing_names,
        cost_per_call,
        ..DiscoveryOptions::default()
    };

    let engine = DiscoveryEngine::new(options);

    println!("Discovering API spec from {url} ...");

    match engine.discover(&url).await {
        Ok(caps) => {
            if caps.is_empty() {
                println!(
                    "No capabilities generated (all endpoints were deduplicated or filtered)."
                );
                return ExitCode::SUCCESS;
            }

            if dry_run {
                println!(
                    "\nDry run: would generate {} capability(ies):\n",
                    caps.len()
                );
                for cap in &caps {
                    println!("  {}.yaml", cap.name);
                }
                println!("\nRerun without --dry-run to write files.");
                return ExitCode::SUCCESS;
            }

            let out_path = output.to_string_lossy();
            println!("\nGenerated {} capability(ies):\n", caps.len());

            let mut success_count = 0usize;
            let mut fail_count = 0usize;

            for cap in &caps {
                match cap.write_to_file(&out_path) {
                    Ok(()) => {
                        println!("  OK  {}/{}.yaml", out_path, cap.name);
                        info!(name = %cap.name, "Wrote capability");
                        success_count += 1;
                    }
                    Err(e) => {
                        eprintln!("  FAIL  {}: {e}", cap.name);
                        fail_count += 1;
                    }
                }
            }

            println!();
            println!("Wrote {success_count} capability file(s) to {out_path}/");
            if fail_count > 0 {
                eprintln!("{fail_count} file(s) failed to write.");
                return ExitCode::FAILURE;
            }

            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("Discovery failed: {e}");
            eprintln!();
            eprintln!("Tips:");
            eprintln!("  - Ensure the URL is publicly accessible");
            eprintln!("  - Try --auth if the API requires authentication");
            eprintln!("  - Use 'cap import <file>' for local spec files");
            ExitCode::FAILURE
        }
    }
}

/// Collect names of capabilities already present in `output_dir`.
///
/// Returns an empty list if the directory does not exist or cannot be read.
async fn collect_existing_names(output_dir: &Path) -> Vec<String> {
    let path = output_dir.to_string_lossy();
    CapabilityLoader::load_directory(&path)
        .await
        .unwrap_or_default()
        .into_iter()
        .map(|cap| cap.name)
        .collect()
}

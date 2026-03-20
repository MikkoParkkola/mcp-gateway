//! Command handler for `mcp-gateway skills generate`.

use std::path::PathBuf;
use std::process::ExitCode;

use mcp_gateway::{
    capability::CapabilityLoader,
    skills::{default_agent_paths, install_bundles, renderer::render_bundles},
};

/// Run `mcp-gateway skills generate`.
pub async fn run_skills_generate(
    capabilities: PathBuf,
    server: Option<String>,
    category: Option<String>,
    out_dir: PathBuf,
    install: bool,
    dry_run: bool,
) -> ExitCode {
    let dir = capabilities.to_string_lossy();
    let mut caps = match CapabilityLoader::load_directory(&dir).await {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Error: Failed to load capabilities from '{dir}': {e}");
            return ExitCode::FAILURE;
        }
    };

    // Apply optional filters
    if let Some(ref prefix) = server {
        caps.retain(|c| c.name.starts_with(prefix.as_str()));
    }
    if let Some(ref cat) = category {
        let cat_lower = cat.to_lowercase();
        caps.retain(|c| c.metadata.category.to_lowercase() == cat_lower);
    }

    if caps.is_empty() {
        eprintln!("No capabilities matched the given filters.");
        return ExitCode::FAILURE;
    }

    let bundles = render_bundles(&caps);
    let total_commands: usize = bundles.iter().map(|b| b.command_docs.len()).sum();

    println!(
        "Generating {} skill bundle(s) ({} commands) into {}",
        bundles.len(),
        total_commands,
        out_dir.display()
    );

    if dry_run {
        print_dry_run_summary(&bundles);
        return ExitCode::SUCCESS;
    }

    let agent_paths = if install {
        let cwd = std::env::current_dir().unwrap_or_default();
        default_agent_paths(&cwd)
    } else {
        vec![]
    };

    match install_bundles(&bundles, &out_dir, &agent_paths).await {
        Ok(results) => {
            for r in &results {
                println!("  mcp-gateway-{} -> {}", r.category, r.paths[0].display());
                if r.paths.len() > 1 {
                    for link in r.paths.iter().skip(1) {
                        println!("    linked: {}", link.display());
                    }
                }
            }
            println!("\nDone. {} bundle(s) generated.", results.len());
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("Error: Failed to install skill bundles: {e}");
            ExitCode::FAILURE
        }
    }
}

fn print_dry_run_summary(bundles: &[mcp_gateway::skills::SkillBundle]) {
    println!("\n[dry-run] Would generate:");
    for bundle in bundles {
        println!("  mcp-gateway-{}/", bundle.category);
        println!("    SKILL.md");
        println!("    crust.json");
        for (name, _) in &bundle.command_docs {
            println!("    commands/{name}.md");
        }
    }
}

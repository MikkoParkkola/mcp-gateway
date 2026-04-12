//! Command handlers for `mcp-gateway skills *` subcommands.
//!
//! - `generate` — render capability YAML files as SKILL.md bundles (existing).
//! - `import`   — parse a SKILL.md file/dir/URL into the local skill registry.
//! - `list`     — list all imported skills.
//! - `search`   — fulltext search the imported skill registry.
//! - `show`     — dump the full content of an imported skill.
//! - `remove`   — delete a skill from the registry.
//!
//! **Security**: the import path is **read-only**.  Parsed SKILL.md files
//! are stored as structured records only; no code blocks from the body are
//! executed.  The CLI surfaces the content so humans/agents can decide what
//! to do with it.

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use mcp_gateway::{
    capability::CapabilityLoader,
    skills::{
        ImportedSkill, SkillRegistry, default_agent_paths, install_bundles, parse_skill_dir,
        parse_skill_file, renderer::render_bundles,
    },
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

/// Run `mcp-gateway skills import <source>`.
///
/// Resolves `source` as a local path (file or directory) or an `http(s)://`
/// URL, parses the SKILL.md, and persists it to the registry.
pub async fn run_skills_import(source: String, registry_path: Option<PathBuf>) -> ExitCode {
    let path = resolve_registry_path(registry_path);

    let skill = match load_skill_from_source(&source).await {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Error: {e}");
            return ExitCode::FAILURE;
        }
    };

    let mut registry = match SkillRegistry::load(&path) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("Error: Failed to load registry '{}': {e}", path.display());
            return ExitCode::FAILURE;
        }
    };

    let replaced = registry.insert(skill.clone());
    if let Err(e) = registry.save(&path) {
        eprintln!("Error: Failed to save registry '{}': {e}", path.display());
        return ExitCode::FAILURE;
    }

    if replaced {
        println!("Updated skill '{}' in {}", skill.name, path.display());
    } else {
        println!("Imported skill '{}' into {}", skill.name, path.display());
    }
    print_skill_summary(&skill);

    // Note: SKILL.md bodies may contain bash/python code blocks. We DO NOT
    // execute them here. The user can inspect them via `skills show <name>`.
    if !skill.code_blocks.is_empty() {
        println!(
            "\nNote: this skill contains {} code block(s). They are stored \
             read-only and will NOT be executed automatically. Use \
             `mcp-gateway skills show {}` to inspect them.",
            skill.code_blocks.len(),
            skill.name
        );
    }

    ExitCode::SUCCESS
}

/// Run `mcp-gateway skills list`.
pub fn run_skills_list(registry_path: Option<PathBuf>) -> ExitCode {
    let path = resolve_registry_path(registry_path);
    let registry = match SkillRegistry::load(&path) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("Error: Failed to load registry '{}': {e}", path.display());
            return ExitCode::FAILURE;
        }
    };

    if registry.is_empty() {
        println!("No skills imported. Use `mcp-gateway skills import <path>` to add one.");
        return ExitCode::SUCCESS;
    }

    println!("{} skill(s) in {}:\n", registry.len(), path.display());
    for skill in registry.iter() {
        let version = skill.version.as_deref().unwrap_or("-");
        let desc = truncate(&skill.description, 70);
        println!("  {:<32} {:<10} {desc}", skill.name, version);
    }
    ExitCode::SUCCESS
}

/// Run `mcp-gateway skills search <query>`.
pub fn run_skills_search(query: &str, registry_path: Option<PathBuf>) -> ExitCode {
    let path = resolve_registry_path(registry_path);
    let registry = match SkillRegistry::load(&path) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("Error: Failed to load registry '{}': {e}", path.display());
            return ExitCode::FAILURE;
        }
    };

    let hits = registry.search(query);
    if hits.is_empty() {
        println!("No skills matched '{query}'.");
        return ExitCode::SUCCESS;
    }

    println!("{} match(es) for '{query}':\n", hits.len());
    for skill in hits {
        let desc = truncate(&skill.description, 70);
        println!("  {:<32} {desc}", skill.name);
    }
    ExitCode::SUCCESS
}

/// Run `mcp-gateway skills show <name>`.
pub fn run_skills_show(name: &str, registry_path: Option<PathBuf>) -> ExitCode {
    let path = resolve_registry_path(registry_path);
    let registry = match SkillRegistry::load(&path) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("Error: Failed to load registry '{}': {e}", path.display());
            return ExitCode::FAILURE;
        }
    };

    let Some(skill) = registry.get(name) else {
        eprintln!(
            "Error: skill '{name}' not found. Run `mcp-gateway skills list` to see all skills."
        );
        return ExitCode::FAILURE;
    };

    println!("Name:        {}", skill.name);
    println!("Description: {}", skill.description);
    if let Some(v) = &skill.version {
        println!("Version:     {v}");
    }
    if let Some(e) = &skill.effort {
        println!("Effort:      {e}");
    }
    if !skill.allowed_tools.is_empty() {
        println!("Tools:       {}", skill.allowed_tools.join(", "));
    }
    if !skill.triggers.is_empty() {
        println!("Triggers:    {}", skill.triggers.join(", "));
    }
    if !skill.keywords.is_empty() {
        println!("Keywords:    {}", skill.keywords.join(", "));
    }
    if let Some(src) = &skill.source_path {
        println!("Source:      {}", src.display());
    }
    if !skill.auxiliary_files.is_empty() {
        println!("Auxiliary files:");
        for p in &skill.auxiliary_files {
            println!("  - {}", p.display());
        }
    }
    if !skill.code_blocks.is_empty() {
        println!(
            "\nEmbedded code blocks ({}): read-only, not executed.",
            skill.code_blocks.len()
        );
        for (i, block) in skill.code_blocks.iter().enumerate() {
            println!(
                "  [{i}] lang={} ({} bytes)",
                block.lang,
                block.content.len()
            );
        }
    }
    println!("\n--- Body ---\n{}", skill.body);
    ExitCode::SUCCESS
}

/// Run `mcp-gateway skills remove <name>`.
pub fn run_skills_remove(name: &str, registry_path: Option<PathBuf>) -> ExitCode {
    let path = resolve_registry_path(registry_path);
    let mut registry = match SkillRegistry::load(&path) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("Error: Failed to load registry '{}': {e}", path.display());
            return ExitCode::FAILURE;
        }
    };

    if registry.remove(name).is_none() {
        eprintln!("Error: skill '{name}' not found.");
        return ExitCode::FAILURE;
    }

    if let Err(e) = registry.save(&path) {
        eprintln!("Error: Failed to save registry '{}': {e}", path.display());
        return ExitCode::FAILURE;
    }
    println!("Removed '{name}' from {}", path.display());
    ExitCode::SUCCESS
}

// ── helpers ──────────────────────────────────────────────────────────────────

fn resolve_registry_path(path: Option<PathBuf>) -> PathBuf {
    path.unwrap_or_else(SkillRegistry::default_path)
}

fn print_skill_summary(skill: &ImportedSkill) {
    println!("  description: {}", skill.description);
    if let Some(v) = &skill.version {
        println!("  version:     {v}");
    }
    if !skill.allowed_tools.is_empty() {
        println!("  tools:       {}", skill.allowed_tools.join(", "));
    }
    if !skill.triggers.is_empty() {
        println!("  triggers:    {}", skill.triggers.join(", "));
    }
}

/// Load a skill from a local path or an http(s) URL.
async fn load_skill_from_source(source: &str) -> Result<ImportedSkill, String> {
    if source.starts_with("http://") || source.starts_with("https://") {
        return fetch_skill_from_url(source).await;
    }

    let path = Path::new(source);
    if !path.exists() {
        return Err(format!("Source not found: '{}'", path.display()));
    }
    if path.is_dir() {
        parse_skill_dir(path).map_err(|e| e.to_string())
    } else {
        parse_skill_file(path).map_err(|e| e.to_string())
    }
}

async fn fetch_skill_from_url(url: &str) -> Result<ImportedSkill, String> {
    let response = reqwest::get(url)
        .await
        .map_err(|e| format!("Failed to fetch '{url}': {e}"))?;
    if !response.status().is_success() {
        return Err(format!("GET '{url}' returned HTTP {}", response.status()));
    }
    let content = response
        .text()
        .await
        .map_err(|e| format!("Failed to read body from '{url}': {e}"))?;
    mcp_gateway::skills::parse_skill_md(&content).map_err(|e| e.to_string())
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        return s.to_owned();
    }
    let mut end = max;
    while !s.is_char_boundary(end) && end > 0 {
        end -= 1;
    }
    format!("{}…", &s[..end])
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

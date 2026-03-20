//! Skill bundle installer.
//!
//! Writes rendered [`SkillBundle`]s to the filesystem and optionally links
//! them into the standard agent discovery paths:
//!
//! - `.agents/skills/<name>/`   — universal agent convention
//! - `.claude/skills/<name>/`   — Claude Code convention
//!
//! Each bundle directory contains:
//! - `SKILL.md`
//! - `commands/<capability_name>.md`
//! - `crust.json` — ownership marker (compatible with the `crust` registry)

use std::path::{Path, PathBuf};

use tokio::fs;
use tracing::{debug, info, warn};

use crate::Result;
use super::renderer::SkillBundle;

/// Static content for the `crust.json` ownership marker.
const CRUST_JSON: &str = concat!(
    r#"{"generator":"mcp-gateway","version":""#,
    env!("CARGO_PKG_VERSION"),
    r#"","managed":true}"#,
);

/// Outcome of a single bundle install.
#[derive(Debug, Clone)]
pub struct InstallResult {
    /// Category of the bundle
    pub category: String,
    /// Directories written to
    pub paths: Vec<PathBuf>,
}

/// Install a set of bundles to an output directory and optional agent paths.
///
/// For each bundle:
/// 1. Writes `<out_dir>/mcp-gateway-<category>/SKILL.md`
/// 2. Writes `<out_dir>/mcp-gateway-<category>/commands/<name>.md`
/// 3. Writes `<out_dir>/mcp-gateway-<category>/crust.json`
/// 4. If `agent_paths` is non-empty, symlinks (or copies as fallback) the
///    bundle directory into each path.
///
/// # Errors
///
/// Returns an error if any bundle directory or file cannot be written.
pub async fn install_bundles(
    bundles: &[SkillBundle],
    out_dir: &Path,
    agent_paths: &[PathBuf],
) -> Result<Vec<InstallResult>> {
    let mut results = Vec::with_capacity(bundles.len());
    for bundle in bundles {
        let result = install_bundle(bundle, out_dir, agent_paths).await?;
        results.push(result);
    }
    Ok(results)
}

/// Install a single bundle. Returns the list of paths written.
///
/// # Errors
///
/// Returns an error if the bundle directory or any file within it cannot be
/// created or written.
pub async fn install_bundle(
    bundle: &SkillBundle,
    out_dir: &Path,
    agent_paths: &[PathBuf],
) -> Result<InstallResult> {
    let bundle_dir = out_dir.join(format!("mcp-gateway-{}", bundle.category));
    let commands_dir = bundle_dir.join("commands");

    fs::create_dir_all(&commands_dir).await.map_err(|e| {
        crate::Error::Io(e)
    })?;

    // Write SKILL.md
    fs::write(bundle_dir.join("SKILL.md"), &bundle.skill_index)
        .await
        .map_err(crate::Error::Io)?;

    // Write per-command docs
    for (name, content) in &bundle.command_docs {
        let cmd_path = commands_dir.join(format!("{name}.md"));
        fs::write(&cmd_path, content)
            .await
            .map_err(crate::Error::Io)?;
        debug!(path = %cmd_path.display(), "Wrote command doc");
    }

    // Write ownership marker
    fs::write(bundle_dir.join("crust.json"), CRUST_JSON)
        .await
        .map_err(crate::Error::Io)?;

    info!(
        category = %bundle.category,
        commands = bundle.command_docs.len(),
        path = %bundle_dir.display(),
        "Installed skill bundle"
    );

    let mut paths = vec![bundle_dir.clone()];

    // Link into agent discovery paths
    for agent_root in agent_paths {
        let link_path = agent_root.join(format!("mcp-gateway-{}", bundle.category));
        match link_or_copy(&bundle_dir, &link_path).await {
            Ok(()) => {
                info!(
                    category = %bundle.category,
                    target = %link_path.display(),
                    "Linked skill bundle"
                );
                paths.push(link_path);
            }
            Err(e) => {
                warn!(
                    category = %bundle.category,
                    target = %link_path.display(),
                    error = %e,
                    "Failed to link skill bundle"
                );
            }
        }
    }

    Ok(InstallResult {
        category: bundle.category.clone(),
        paths,
    })
}

/// Standard agent discovery paths relative to `base_dir`.
#[must_use]
pub fn default_agent_paths(base_dir: &Path) -> Vec<PathBuf> {
    vec![
        base_dir.join(".agents").join("skills"),
        base_dir.join(".claude").join("skills"),
    ]
}

/// Attempt a symlink; fall back to recursive copy on platforms that reject it.
async fn link_or_copy(src: &Path, dst: &Path) -> Result<()> {
    // Remove stale target if present
    if dst.exists() || dst.is_symlink() {
        if dst.is_dir() && !dst.is_symlink() {
            fs::remove_dir_all(dst).await.map_err(crate::Error::Io)?;
        } else {
            fs::remove_file(dst).await.map_err(crate::Error::Io)?;
        }
    }

    // Ensure parent exists
    if let Some(parent) = dst.parent() {
        fs::create_dir_all(parent).await.map_err(crate::Error::Io)?;
    }

    // Try symlink first (Unix), fall back to copy
    #[cfg(unix)]
    {
        tokio::fs::symlink(src, dst)
            .await
            .map_err(crate::Error::Io)
    }
    #[cfg(not(unix))]
    {
        copy_dir_recursive(src, dst).await
    }
}

/// Recursively copy a directory tree (Windows fallback).
#[cfg(not(unix))]
async fn copy_dir_recursive(src: &Path, dst: &Path) -> Result<()> {
    fs::create_dir_all(dst).await.map_err(crate::Error::Io)?;
    let mut entries = fs::read_dir(src)
        .await
        .map_err(crate::Error::Io)?;
    while let Some(entry) = entries
        .next_entry()
        .await
        .map_err(crate::Error::Io)?
    {
        let dst_entry = dst.join(entry.file_name());
        if entry.path().is_dir() {
            Box::pin(copy_dir_recursive(&entry.path(), &dst_entry)).await?;
        } else {
            fs::copy(entry.path(), &dst_entry)
                .await
                .map_err(crate::Error::Io)?;
        }
    }
    Ok(())
}

// ── tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn make_bundle(category: &str, commands: &[&str]) -> SkillBundle {
        SkillBundle {
            category: category.to_owned(),
            skill_index: format!("---\nname: mcp-gateway-{category}\n---\n# {category}\n"),
            command_docs: commands
                .iter()
                .map(|n| ((*n).to_owned(), format!("# {n}\ndescription\n")))
                .collect(),
        }
    }

    // ── install paths ─────────────────────────────────────────────────────────

    #[tokio::test]
    async fn install_bundle_creates_skill_md_and_commands() {
        // GIVEN: a simple bundle
        let tmp = TempDir::new().unwrap();
        let bundle = make_bundle("search", &["search_web", "search_news"]);
        // WHEN: installed
        let result = install_bundle(&bundle, tmp.path(), &[]).await.unwrap();
        // THEN: SKILL.md and command docs exist
        let bundle_dir = tmp.path().join("mcp-gateway-search");
        assert!(bundle_dir.join("SKILL.md").exists());
        assert!(bundle_dir.join("commands/search_web.md").exists());
        assert!(bundle_dir.join("commands/search_news.md").exists());
        assert_eq!(result.category, "search");
        assert_eq!(result.paths.len(), 1);
    }

    #[tokio::test]
    async fn install_bundle_writes_crust_json() {
        // GIVEN: a bundle
        let tmp = TempDir::new().unwrap();
        let bundle = make_bundle("utility", &["ping"]);
        // WHEN
        install_bundle(&bundle, tmp.path(), &[]).await.unwrap();
        // THEN: crust.json contains generator marker
        let crust = std::fs::read_to_string(
            tmp.path().join("mcp-gateway-utility").join("crust.json"),
        )
        .unwrap();
        assert!(crust.contains("mcp-gateway"));
    }

    #[tokio::test]
    async fn install_bundle_links_into_agent_paths() {
        // GIVEN: an agent path target
        let tmp = TempDir::new().unwrap();
        let agent_root = tmp.path().join(".claude").join("skills");
        let bundle = make_bundle("finance", &["get_quote"]);
        // WHEN
        let result = install_bundle(&bundle, tmp.path(), &[agent_root.clone()])
            .await
            .unwrap();
        // THEN: link exists at agent path
        let link = agent_root.join("mcp-gateway-finance");
        assert!(link.exists(), "agent path link should exist");
        assert_eq!(result.paths.len(), 2);
    }

    #[tokio::test]
    async fn install_bundles_installs_all_bundles() {
        // GIVEN: two bundles
        let tmp = TempDir::new().unwrap();
        let bundles = vec![
            make_bundle("search", &["search_web"]),
            make_bundle("finance", &["stock_quote"]),
        ];
        // WHEN
        let results = install_bundles(&bundles, tmp.path(), &[]).await.unwrap();
        // THEN: both installed
        assert_eq!(results.len(), 2);
        assert!(tmp.path().join("mcp-gateway-search").exists());
        assert!(tmp.path().join("mcp-gateway-finance").exists());
    }

    #[tokio::test]
    async fn install_bundle_overwrites_existing_bundle() {
        // GIVEN: an already-installed bundle
        let tmp = TempDir::new().unwrap();
        let bundle1 = make_bundle("search", &["old_tool"]);
        install_bundle(&bundle1, tmp.path(), &[]).await.unwrap();
        // WHEN: reinstalled with different commands
        let bundle2 = make_bundle("search", &["new_tool"]);
        install_bundle(&bundle2, tmp.path(), &[]).await.unwrap();
        // THEN: new file exists
        assert!(tmp.path().join("mcp-gateway-search/commands/new_tool.md").exists());
    }

    // ── default_agent_paths ───────────────────────────────────────────────────

    #[test]
    fn default_agent_paths_returns_two_standard_locations() {
        // GIVEN: a project root
        let base = Path::new("/project");
        // WHEN
        let paths = default_agent_paths(base);
        // THEN: both discovery paths present
        assert!(paths.iter().any(|p| p.ends_with(".agents/skills")));
        assert!(paths.iter().any(|p| p.ends_with(".claude/skills")));
    }
}

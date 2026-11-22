// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

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

use tracing::{debug, info, warn};

use super::renderer::SkillBundle;
use crate::Result;

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
    install_bundle_kept(
        bundle,
        out_dir,
        agent_paths,
        &InstallKeep::silent(out_dir, agent_paths),
    )
    .await
}

/// What every write on the install path holds while it runs: the temp dirs a
/// test kept (`crate::spawn_keep`), and a row's seams.
#[derive(Clone, Default)]
pub(crate) struct InstallKeep {
    kept: crate::spawn_keep::Kept,
    #[cfg(test)]
    pub(crate) seams: Option<std::sync::Arc<Seams>>,
}

impl InstallKeep {
    /// The keep a detached regen loop takes when it spawns: its output dir
    /// and every agent root, each reported when no test kept it.
    pub(crate) fn at_spawn(out_dir: &Path, agent_paths: &[PathBuf]) -> Self {
        let roots = std::iter::once(out_dir).chain(agent_paths.iter().map(PathBuf::as_path));
        Self {
            kept: crate::spawn_keep::union(roots.map(|root| {
                crate::spawn_keep::kept_at_spawn(crate::spawn_keep::SKILL_BUNDLE, root)
            })),
            #[cfg(test)]
            seams: None,
        }
    }

    /// The same keep, silent: an awaited install starts no detached writer
    /// of its own, so it reports nothing, but a write it started still
    /// holds the dir if the caller's task is cancelled.
    pub(crate) fn silent(out_dir: &Path, agent_paths: &[PathBuf]) -> Self {
        let roots = std::iter::once(out_dir).chain(agent_paths.iter().map(PathBuf::as_path));
        Self {
            kept: crate::spawn_keep::union(roots.map(crate::spawn_keep::kept_dirs_at_spawn)),
            #[cfg(test)]
            seams: None,
        }
    }
}

/// Test-only holds inside the install path's writes (rows K4-K4w), each one
/// shot: `*_before` before the write, `*_after` once it returned but before
/// its closure drops its keep; `copy_mid` after the copy's first file.
#[cfg(test)]
#[derive(Default)]
pub(crate) struct Seams {
    pub(crate) crust_before: std::sync::Arc<crate::test_pause::Slot>,
    pub(crate) crust_after: std::sync::Arc<crate::test_pause::Slot>,
    // Read only by the symlink path, which is built on Unix alone.
    #[cfg(unix)]
    pub(crate) link_before: std::sync::Arc<crate::test_pause::Slot>,
    #[cfg(unix)]
    pub(crate) link_after: std::sync::Arc<crate::test_pause::Slot>,
    // Read only by the copy fallback, which is not built on Unix.
    #[cfg(not(unix))]
    pub(crate) copy_mid: std::sync::Arc<crate::test_pause::Slot>,
    #[cfg(not(unix))]
    pub(crate) copy_done: std::sync::Arc<crate::test_pause::Slot>,
}

/// One pair of seams, cloned out of `keep` for one write's closure.
#[cfg(test)]
fn seam_pair(
    keep: &InstallKeep,
    pick: impl Fn(&Seams) -> [&std::sync::Arc<crate::test_pause::Slot>; 2],
) -> Option<[std::sync::Arc<crate::test_pause::Slot>; 2]> {
    keep.seams
        .as_deref()
        .map(|seams| pick(seams).map(std::sync::Arc::clone))
}

/// Run one blocking filesystem call with a clone of `keep`'s kept dirs, so
/// the keep lives exactly as long as that write, even past the task that
/// started it: a write still running when the runtime drops holds the dir.
async fn kept_blocking<T: Send + 'static>(
    keep: &InstallKeep,
    write: impl FnOnce() -> std::io::Result<T> + Send + 'static,
) -> Result<T> {
    let kept = keep.kept.clone();
    tokio::task::spawn_blocking(move || crate::spawn_keep::holding(kept, write))
        .await
        .map_err(|error| crate::Error::Io(std::io::Error::other(error)))?
        .map_err(crate::Error::Io)
}

/// [`install_bundle`] with the keep its writes hold.
pub(crate) async fn install_bundle_kept(
    bundle: &SkillBundle,
    out_dir: &Path,
    agent_paths: &[PathBuf],
    keep: &InstallKeep,
) -> Result<InstallResult> {
    let bundle_dir = out_dir.join(format!("mcp-gateway-{}", bundle.category));
    let commands_dir = bundle_dir.join("commands");

    let dir = commands_dir.clone();
    kept_blocking(keep, move || std::fs::create_dir_all(dir)).await?;

    // Write SKILL.md
    let (path, text) = (bundle_dir.join("SKILL.md"), bundle.skill_index.clone());
    kept_blocking(keep, move || std::fs::write(path, text)).await?;

    // Write per-command docs
    for (name, content) in &bundle.command_docs {
        let cmd_path = commands_dir.join(format!("{name}.md"));
        let (path, text) = (cmd_path.clone(), content.clone());
        kept_blocking(keep, move || std::fs::write(path, text)).await?;
        debug!(path = %cmd_path.display(), "Wrote command doc");
    }

    // Write ownership marker
    let path = bundle_dir.join("crust.json");
    #[cfg(test)]
    let seams = seam_pair(keep, |s| [&s.crust_before, &s.crust_after]);
    kept_blocking(keep, move || {
        #[cfg(test)]
        if let Some([before, _]) = &seams {
            before.pause_on_thread();
        }
        let written = std::fs::write(path, CRUST_JSON);
        #[cfg(test)]
        if let Some([_, after]) = &seams {
            after.pause_on_thread();
        }
        written
    })
    .await?;

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
        match link_or_copy(&bundle_dir, &link_path, keep).await {
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
async fn link_or_copy(src: &Path, dst: &Path, keep: &InstallKeep) -> Result<()> {
    // Remove stale target if present
    if dst.exists() || dst.is_symlink() {
        let stale = dst.to_path_buf();
        if dst.is_dir() && !dst.is_symlink() {
            kept_blocking(keep, move || std::fs::remove_dir_all(stale)).await?;
        } else {
            kept_blocking(keep, move || std::fs::remove_file(stale)).await?;
        }
    }

    // Ensure parent exists
    if let Some(parent) = dst.parent() {
        let parent = parent.to_path_buf();
        kept_blocking(keep, move || std::fs::create_dir_all(parent)).await?;
    }

    let (src, dst) = (src.to_path_buf(), dst.to_path_buf());
    // Try symlink first (Unix), fall back to copy
    #[cfg(unix)]
    {
        #[cfg(test)]
        let seams = seam_pair(keep, |s| [&s.link_before, &s.link_after]);
        kept_blocking(keep, move || {
            #[cfg(test)]
            if let Some([before, _]) = &seams {
                before.pause_on_thread();
            }
            let linked = std::os::unix::fs::symlink(src, dst);
            #[cfg(test)]
            if let Some([_, after]) = &seams {
                after.pause_on_thread();
            }
            linked
        })
        .await
    }
    #[cfg(not(unix))]
    {
        // One blocking call for the whole tree: a copy that has started
        // finishes whole even if its task is cancelled.
        #[cfg(test)]
        let seams = seam_pair(keep, |s| [&s.copy_mid, &s.copy_done]);
        kept_blocking(keep, move || {
            #[cfg(test)]
            let mid = seams.as_ref().map(|[mid, _]| std::sync::Arc::clone(mid));
            #[cfg(test)]
            COPY_MID.with(|slot| *slot.borrow_mut() = mid);
            let copied = copy_dir_recursive(&src, &dst);
            #[cfg(test)]
            COPY_MID.with(|slot| slot.borrow_mut().take());
            #[cfg(test)]
            if let Some([_, done]) = &seams {
                done.pause_on_thread();
            }
            copied
        })
        .await
    }
}

#[cfg(all(test, not(unix)))]
std::thread_local! {
    /// The mid-copy seam of the copy running on this blocking thread.
    static COPY_MID: std::cell::RefCell<Option<std::sync::Arc<crate::test_pause::Slot>>> =
        const { std::cell::RefCell::new(None) };
}

/// Recursively copy a directory tree (Windows fallback), on the blocking
/// thread [`link_or_copy`] runs it on.
#[cfg(not(unix))]
fn copy_dir_recursive(src: &Path, dst: &Path) -> std::io::Result<()> {
    std::fs::create_dir_all(dst)?;
    for entry in std::fs::read_dir(src)? {
        let entry = entry?;
        let dst_entry = dst.join(entry.file_name());
        if entry.path().is_dir() {
            copy_dir_recursive(&entry.path(), &dst_entry)?;
        } else {
            std::fs::copy(entry.path(), &dst_entry)?;
            #[cfg(test)]
            if let Some(mid) = COPY_MID.with(|slot| slot.borrow().clone()) {
                mid.pause_on_thread();
            }
        }
    }
    Ok(())
}

#[cfg(tp5)]
#[cfg(test)]
#[path = "installer_keep_tests.rs"]
mod keep_tests;

// ── tests ─────────────────────────────────────────────────────────────────────

#[cfg(tp5)]
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
        let crust =
            std::fs::read_to_string(tmp.path().join("mcp-gateway-utility").join("crust.json"))
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
        let result = install_bundle(&bundle, tmp.path(), std::slice::from_ref(&agent_root))
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
        assert!(
            tmp.path()
                .join("mcp-gateway-search/commands/new_tool.md")
                .exists()
        );
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

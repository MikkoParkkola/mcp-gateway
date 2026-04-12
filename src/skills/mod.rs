//! MCP Capability to Agent Skills bridge.
//!
//! This module converts [`CapabilityDefinition`] YAML files into agent skill
//! bundles — Markdown documents that follow the universal `loadSkill` convention
//! used by Claude Code and other AI agents.
//!
//! # Structure
//!
//! For each capability category a bundle is written to disk:
//!
//! ```text
//! <out_dir>/
//!   mcp-gateway-<category>/
//!     SKILL.md                  ← category index with YAML front-matter
//!     commands/
//!       <capability_name>.md    ← per-tool reference doc
//!     crust.json                ← ownership marker
//! ```
//!
//! # Agent Discovery Paths
//!
//! When `--install` is requested the bundle is also linked (or copied on
//! Windows) into:
//!
//! - `.agents/skills/`   — universal agent convention
//! - `.claude/skills/`   — Claude Code convention
//!
//! # Hot-Reload
//!
//! The capability file watcher calls [`regenerate_for_capability`] when a
//! YAML file changes, regenerating only the affected category bundle.

pub mod installer;
pub mod renderer;
pub mod watcher;

pub use installer::{InstallResult, default_agent_paths, install_bundle, install_bundles};
pub use renderer::{SkillBundle, render_bundle, render_bundles, render_command_doc};
pub use watcher::SkillsWatcher;

use std::path::Path;

use tracing::info;

use crate::Result;
use crate::capability::CapabilityDefinition;

/// Regenerate skill docs for a single capability definition.
///
/// This is the hot-reload entry point: when the watcher detects a YAML change
/// it calls this function with the updated capability, regenerating only the
/// affected category bundle in `out_dir`.
///
/// # Errors
///
/// Returns an error if the bundle directory cannot be written.
pub async fn regenerate_for_capability(
    cap: &CapabilityDefinition,
    out_dir: &Path,
    agent_paths: &[std::path::PathBuf],
) -> Result<()> {
    let bundle = renderer::render_bundle(&effective_category(cap), &[cap]);
    installer::install_bundle(&bundle, out_dir, agent_paths).await?;

    info!(
        capability = %cap.name,
        category = %bundle.category,
        "Regenerated skill bundle"
    );
    Ok(())
}

fn effective_category(cap: &CapabilityDefinition) -> String {
    if cap.metadata.category.is_empty() {
        "general".to_owned()
    } else {
        cap.metadata.category.to_lowercase()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capability::{
        AuthConfig, CacheConfig, CapabilityDefinition, CapabilityMetadata, ProviderConfig,
        ProvidersConfig, RestConfig, SchemaDefinition,
    };
    use crate::transform::TransformConfig;
    use std::collections::HashMap;
    use tempfile::TempDir;

    fn make_cap(name: &str, category: &str) -> CapabilityDefinition {
        let mut named = std::collections::HashMap::new();
        named.insert(
            "primary".to_owned(),
            ProviderConfig {
                service: "rest".to_owned(),
                cost_per_call: 0.0,
                timeout: 30,
                config: RestConfig::default(),
            },
        );
        CapabilityDefinition {
            fulcrum: "1.0".to_owned(),
            name: name.to_owned(),
            description: format!("Desc of {name}"),
            schema: SchemaDefinition::default(),
            providers: ProvidersConfig {
                named,
                fallback: vec![],
            },
            auth: AuthConfig::default(),
            cache: CacheConfig::default(),
            metadata: CapabilityMetadata {
                category: category.to_owned(),
                ..Default::default()
            },
            transform: TransformConfig::default(),
            webhooks: HashMap::default(),
            sha256: None,
        }
    }

    #[tokio::test]
    async fn regenerate_for_capability_creates_bundle_dir() {
        // GIVEN: a capability
        let tmp = TempDir::new().unwrap();
        let cap = make_cap("search_web", "search");
        // WHEN: regenerated
        regenerate_for_capability(&cap, tmp.path(), &[])
            .await
            .unwrap();
        // THEN: skill bundle dir exists
        assert!(
            tmp.path()
                .join("mcp-gateway-search")
                .join("SKILL.md")
                .exists()
        );
        assert!(
            tmp.path()
                .join("mcp-gateway-search")
                .join("commands")
                .join("search_web.md")
                .exists()
        );
    }

    #[tokio::test]
    async fn regenerate_for_capability_no_category_uses_general() {
        // GIVEN: capability without category
        let tmp = TempDir::new().unwrap();
        let cap = make_cap("misc_tool", "");
        // WHEN
        regenerate_for_capability(&cap, tmp.path(), &[])
            .await
            .unwrap();
        // THEN: placed under "general"
        assert!(tmp.path().join("mcp-gateway-general").exists());
    }
}

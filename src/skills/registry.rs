//! Imported skill registry.
//!
//! An append-only, file-backed store of [`ImportedSkill`] records.  The
//! registry is the persistence layer for the `mcp-gateway skill import`,
//! `list`, and `search` CLI subcommands, and for exposing imported skills
//! through the gateway's meta-tool surface.
//!
//! # Storage format
//!
//! The registry is persisted as a single JSON file (default:
//! `~/.mcp-gateway/skills.json`).  Atomic writes via a temp file + rename
//! avoid corruption on crash.
//!
//! # Security model (read-only)
//!
//! Imported skills are **not** executed automatically.  They are stored as
//! structured records and surfaced to agents/users through search and read
//! APIs.  Any future execution surface must be explicitly opted-in and gated
//! on per-skill user consent.  This file does not implement execution.
//!
//! # Deduplication
//!
//! Importing a skill with the same `name` as an existing entry **replaces**
//! the old record.  Use the `source_path` field to distinguish skills from
//! different sources when names collide.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use super::parser::ImportedSkill;
use crate::Result;
use crate::error::Error;

/// Current on-disk schema version.
const REGISTRY_SCHEMA: u32 = 1;

/// File-backed registry of imported SKILL.md records.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SkillRegistry {
    /// Schema version for future migrations.
    #[serde(default = "default_schema")]
    pub schema: u32,
    /// Imported skills keyed by `name` for O(1) lookup + stable ordering.
    #[serde(default)]
    pub skills: BTreeMap<String, ImportedSkill>,
}

fn default_schema() -> u32 {
    REGISTRY_SCHEMA
}

impl SkillRegistry {
    /// Create an empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self {
            schema: REGISTRY_SCHEMA,
            skills: BTreeMap::new(),
        }
    }

    /// Default registry path: `$HOME/.mcp-gateway/skills.json`.
    ///
    /// Falls back to the current directory if no home directory is available.
    #[must_use]
    pub fn default_path() -> PathBuf {
        if let Some(home) = dirs::home_dir() {
            home.join(".mcp-gateway").join("skills.json")
        } else {
            PathBuf::from(".mcp-gateway").join("skills.json")
        }
    }

    /// Load a registry from disk, returning an empty registry if the file
    /// does not exist.
    ///
    /// # Errors
    ///
    /// Returns an error if the file exists but cannot be read or is malformed.
    pub fn load(path: &Path) -> Result<Self> {
        if !path.exists() {
            return Ok(Self::new());
        }
        let bytes = std::fs::read(path).map_err(|e| {
            Error::Config(format!(
                "Cannot read skill registry '{}': {e}",
                path.display()
            ))
        })?;
        let reg: Self = serde_json::from_slice(&bytes).map_err(|e| {
            Error::Config(format!(
                "Malformed skill registry '{}': {e}",
                path.display()
            ))
        })?;
        Ok(reg)
    }

    /// Persist the registry to disk atomically.
    ///
    /// Writes to `<path>.tmp` and renames over the target on success.
    ///
    /// # Errors
    ///
    /// Returns an error if the parent directory cannot be created or the
    /// write/rename fails.
    pub fn save(&self, path: &Path) -> Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| Error::Config(format!("Cannot create '{}': {e}", parent.display())))?;
        }
        let tmp = path.with_extension("json.tmp");
        let bytes = serde_json::to_vec_pretty(self)
            .map_err(|e| Error::Config(format!("Serialize skill registry: {e}")))?;
        std::fs::write(&tmp, &bytes)
            .map_err(|e| Error::Config(format!("Write '{}': {e}", tmp.display())))?;
        std::fs::rename(&tmp, path).map_err(|e| {
            Error::Config(format!(
                "Rename '{}' -> '{}': {e}",
                tmp.display(),
                path.display()
            ))
        })?;
        Ok(())
    }

    /// Insert or replace a skill.  Returns `true` if a previous record with
    /// the same name was replaced.
    pub fn insert(&mut self, skill: ImportedSkill) -> bool {
        self.skills.insert(skill.name.clone(), skill).is_some()
    }

    /// Remove a skill by name.  Returns the removed skill if it existed.
    pub fn remove(&mut self, name: &str) -> Option<ImportedSkill> {
        self.skills.remove(name)
    }

    /// Look up a skill by exact name.
    #[must_use]
    pub fn get(&self, name: &str) -> Option<&ImportedSkill> {
        self.skills.get(name)
    }

    /// Iterate all skills in name order.
    pub fn iter(&self) -> impl Iterator<Item = &ImportedSkill> {
        self.skills.values()
    }

    /// Number of skills currently registered.
    #[must_use]
    pub fn len(&self) -> usize {
        self.skills.len()
    }

    /// True if the registry contains no skills.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.skills.is_empty()
    }

    /// Case-insensitive substring search across name, description, keywords,
    /// and triggers.  Returns skills sorted by relevance (name matches first,
    /// then description, then keyword/trigger).
    #[must_use]
    pub fn search(&self, query: &str) -> Vec<&ImportedSkill> {
        let q = query.to_lowercase();
        if q.is_empty() {
            return self.iter().collect();
        }

        let mut scored: Vec<(u32, &ImportedSkill)> = Vec::new();
        for skill in self.skills.values() {
            let mut score = 0u32;
            if skill.name.to_lowercase().contains(&q) {
                score += 100;
            }
            if skill.description.to_lowercase().contains(&q) {
                score += 50;
            }
            for kw in &skill.keywords {
                if kw.to_lowercase().contains(&q) {
                    score += 20;
                }
            }
            for t in &skill.triggers {
                if t.to_lowercase().contains(&q) {
                    score += 20;
                }
            }
            if skill.body.to_lowercase().contains(&q) {
                score += 5;
            }
            if score > 0 {
                scored.push((score, skill));
            }
        }
        scored.sort_by(|a, b| b.0.cmp(&a.0).then_with(|| a.1.name.cmp(&b.1.name)));
        scored.into_iter().map(|(_, s)| s).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_skill(name: &str, description: &str) -> ImportedSkill {
        ImportedSkill {
            name: name.to_owned(),
            description: description.to_owned(),
            version: None,
            effort: None,
            allowed_tools: vec![],
            triggers: vec![],
            keywords: vec![],
            body: String::new(),
            code_blocks: vec![],
            extra: BTreeMap::new(),
            source_path: None,
            auxiliary_files: vec![],
        }
    }

    #[test]
    fn new_registry_is_empty() {
        // GIVEN: fresh registry
        let reg = SkillRegistry::new();
        // THEN
        assert!(reg.is_empty());
        assert_eq!(reg.len(), 0);
    }

    #[test]
    fn insert_and_get_roundtrip() {
        // GIVEN
        let mut reg = SkillRegistry::new();
        let skill = make_skill("alpha", "first");
        // WHEN
        let replaced = reg.insert(skill);
        // THEN
        assert!(!replaced);
        assert_eq!(reg.len(), 1);
        assert!(reg.get("alpha").is_some());
    }

    #[test]
    fn insert_duplicate_replaces() {
        // GIVEN: registry with one skill
        let mut reg = SkillRegistry::new();
        reg.insert(make_skill("alpha", "old"));
        // WHEN: insert a new version with the same name
        let replaced = reg.insert(make_skill("alpha", "new"));
        // THEN
        assert!(replaced);
        assert_eq!(reg.get("alpha").unwrap().description, "new");
    }

    #[test]
    fn remove_existing_skill() {
        let mut reg = SkillRegistry::new();
        reg.insert(make_skill("alpha", "x"));
        assert!(reg.remove("alpha").is_some());
        assert!(reg.is_empty());
    }

    #[test]
    fn save_and_load_roundtrip() {
        // GIVEN: registry with skills
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("reg.json");
        let mut reg = SkillRegistry::new();
        reg.insert(make_skill("alpha", "desc"));
        reg.insert(make_skill("beta", "other"));
        // WHEN
        reg.save(&path).unwrap();
        let loaded = SkillRegistry::load(&path).unwrap();
        // THEN
        assert_eq!(loaded.len(), 2);
        assert!(loaded.get("alpha").is_some());
        assert_eq!(loaded.schema, REGISTRY_SCHEMA);
    }

    #[test]
    fn load_missing_file_returns_empty() {
        // GIVEN: path that does not exist
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("no-such-file.json");
        // WHEN
        let reg = SkillRegistry::load(&path).unwrap();
        // THEN: empty registry (not an error)
        assert!(reg.is_empty());
    }

    #[test]
    fn load_malformed_file_fails() {
        // GIVEN: broken JSON on disk
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("reg.json");
        std::fs::write(&path, "{not valid json").unwrap();
        // WHEN
        let result = SkillRegistry::load(&path);
        // THEN
        assert!(result.is_err());
    }

    #[test]
    fn search_ranks_name_matches_first() {
        // GIVEN: skills where "foo" is in different fields
        let mut reg = SkillRegistry::new();
        reg.insert(make_skill("bar", "body mentions foo here"));
        reg.insert(make_skill("foo", "unrelated"));
        // WHEN
        let hits = reg.search("foo");
        // THEN: name match comes first
        assert_eq!(hits.len(), 2);
        assert_eq!(hits[0].name, "foo");
    }

    #[test]
    fn search_empty_query_returns_all() {
        let mut reg = SkillRegistry::new();
        reg.insert(make_skill("a", "x"));
        reg.insert(make_skill("b", "y"));
        let hits = reg.search("");
        assert_eq!(hits.len(), 2);
    }

    #[test]
    fn search_no_matches_returns_empty() {
        let mut reg = SkillRegistry::new();
        reg.insert(make_skill("alpha", "x"));
        let hits = reg.search("zzzz");
        assert!(hits.is_empty());
    }

    #[test]
    fn search_matches_keywords_and_triggers() {
        // GIVEN
        let mut reg = SkillRegistry::new();
        let mut s = make_skill("k", "plain");
        s.keywords = vec!["trigger-word".to_owned()];
        reg.insert(s);
        // WHEN
        let hits = reg.search("trigger");
        // THEN
        assert_eq!(hits.len(), 1);
    }
}

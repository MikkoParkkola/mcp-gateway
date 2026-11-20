// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The `skills list`, `skills search` and `skills show` documents under `--json` (MIK-9764.JSONF.1, design 3a).
//! CLI-owned views with fixed keys: a skill's unset fields are null or `[]`, never missing, so a script reads the
//! same shape for every skill. Descriptions are untruncated; paths are the lossy text the text form prints.

use std::path::Path;

use mcp_gateway::skills::ImportedSkill;
use serde::Serialize;

#[derive(Serialize)]
struct Item<'a> {
    name: &'a str,
    version: Option<&'a str>,
    description: &'a str,
}

fn item(skill: &ImportedSkill) -> Item<'_> {
    Item {
        name: &skill.name,
        version: skill.version.as_deref(),
        description: &skill.description,
    }
}

/// `skills list --json`: the registry path and every skill in registry order.
pub(super) fn list<'a>(
    registry: &Path,
    skills: impl Iterator<Item = &'a ImportedSkill>,
) -> Result<String, String> {
    #[derive(Serialize)]
    struct View<'a> {
        registry: String,
        skills: Vec<Item<'a>>,
    }
    crate::cli::output::document(&View {
        registry: registry.display().to_string(),
        skills: skills.map(item).collect(),
    })
}

/// `skills search --json`: the query and the hits in rank order.
pub(super) fn search(query: &str, hits: &[&ImportedSkill]) -> Result<String, String> {
    #[derive(Serialize)]
    struct View<'a> {
        query: &'a str,
        skills: Vec<Item<'a>>,
    }
    crate::cli::output::document(&View {
        query,
        skills: hits.iter().map(|skill| item(skill)).collect(),
    })
}

/// `skills show --json`: every field of one skill, code blocks by language and size (their content is not
/// printed, as in the text form).
pub(super) fn show(skill: &ImportedSkill) -> Result<String, String> {
    #[derive(Serialize)]
    struct Block<'a> {
        lang: &'a str,
        bytes: usize,
    }
    #[derive(Serialize)]
    struct View<'a> {
        name: &'a str,
        description: &'a str,
        version: Option<&'a str>,
        effort: Option<&'a str>,
        allowed_tools: &'a [String],
        triggers: &'a [String],
        keywords: &'a [String],
        source_path: Option<String>,
        auxiliary_files: Vec<String>,
        code_blocks: Vec<Block<'a>>,
        body: &'a str,
    }
    crate::cli::output::document(&View {
        name: &skill.name,
        description: &skill.description,
        version: skill.version.as_deref(),
        effort: skill.effort.as_deref(),
        allowed_tools: &skill.allowed_tools,
        triggers: &skill.triggers,
        keywords: &skill.keywords,
        source_path: skill.source_path.as_ref().map(|p| p.display().to_string()),
        auxiliary_files: skill
            .auxiliary_files
            .iter()
            .map(|p| p.display().to_string())
            .collect(),
        code_blocks: skill
            .code_blocks
            .iter()
            .map(|b| Block {
                lang: &b.lang,
                bytes: b.content.len(),
            })
            .collect(),
        body: &skill.body,
    })
}

// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! SKILL.md parser — ingest Agent Skills format files.
//!
//! Parses a SKILL.md file into an [`ImportedSkill`] struct.  The format follows
//! the emerging Agent Skills standard from agentskills.io and the Claude Code
//! skill convention:
//!
//! ```text
//! ---
//! name: my-skill
//! description: What the skill does
//! version: 1.0.0
//! allowed-tools: [Bash, Read]
//! triggers: [keyword1, keyword2]
//! keywords: [foo, bar]
//! ---
//!
//! # My Skill
//!
//! Body markdown describing how the skill works, with optional fenced
//! code blocks that represent executable steps:
//!
//!     echo "hello"
//! ```
//!
//! This parser is **read-only**: it extracts structured metadata and the body
//! markdown, plus any fenced code blocks tagged as `bash`, `python`, `sh`, or
//! `json`.  Execution of those blocks is **not** performed here — a separate
//! executor (gated on user consent) is responsible for that.
//!
//! # Progressive Disclosure
//!
//! The Agent Skills spec allows a skill directory to contain additional files
//! beyond `SKILL.md` (e.g. `SKILL.advanced.md`, `reference.md`, a `resources/`
//! directory).  [`parse_skill_dir`] discovers these auxiliary files and records
//! their paths so agents can load them on demand.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::Result;
use crate::error::Error;

/// Parsed SKILL.md document.
///
/// Holds the YAML frontmatter fields, the markdown body, any extracted code
/// blocks, and (when parsed from a directory) auxiliary resource file paths.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImportedSkill {
    /// Skill identifier (from `name` frontmatter field). Required.
    pub name: String,

    /// Short description (from `description` frontmatter field). Required.
    pub description: String,

    /// Optional version string (e.g. `1.0.0`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,

    /// Optional effort hint (e.g. `low`, `medium`, `high`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub effort: Option<String>,

    /// Tools the skill declares it needs access to (Claude Code `allowed-tools`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allowed_tools: Vec<String>,

    /// Trigger phrases that should surface this skill (agentskills.io `triggers`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub triggers: Vec<String>,

    /// Additional keywords used by the gateway's fulltext search.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub keywords: Vec<String>,

    /// Markdown body after the `---` frontmatter terminator.
    pub body: String,

    /// Fenced code blocks extracted from the body (lang tag → source).
    ///
    /// Each tuple is `(lang, content)`.  Only `bash`, `sh`, `python`, and
    /// `json` blocks are captured; others are ignored.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub code_blocks: Vec<SkillCodeBlock>,

    /// Other frontmatter fields, converted to JSON values (e.g. `metadata`).
    ///
    /// MIK-8425, 4.0.0: this field type changes here on its own, not as part
    /// of the later YAML backend swap. A YAML tag `!t v` becomes the one-entry
    /// map `{"!t": v}` and cannot be told from a map keyed `"!t"`. Boolean,
    /// integer and finite float keys become strings; null, non-finite float,
    /// sequence, mapping and tagged keys drop their entry. The full rules are
    /// in the 4.0.0 upgrade notes (`UPGRADING`, MIK-8425).
    #[serde(
        default,
        skip_serializing_if = "BTreeMap::is_empty",
        deserialize_with = "extra_via_yaml_tree"
    )]
    pub extra: BTreeMap<String, serde_json::Value>,

    /// Absolute path to the source SKILL.md file, if parsed from disk.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_path: Option<PathBuf>,

    /// Auxiliary files found alongside the SKILL.md (progressive disclosure).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub auxiliary_files: Vec<PathBuf>,
}

/// A fenced code block extracted from the skill body.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SkillCodeBlock {
    /// Language tag of the fenced block (`bash`, `python`, ...).
    pub lang: String,
    /// Raw content of the block (no trailing newline).
    pub content: String,
}

/// Languages we recognise as potentially executable / data blocks.
const RECOGNISED_LANGS: &[&str] = &["bash", "sh", "shell", "python", "py", "json"];

/// Parse raw SKILL.md content into an [`ImportedSkill`].
///
/// # Errors
///
/// Returns [`Error::Config`] if:
/// - The file does not begin with `---` frontmatter
/// - The YAML frontmatter is malformed
/// - Required fields (`name`, `description`) are missing or empty
pub fn parse_skill_md(content: &str) -> Result<ImportedSkill> {
    let (frontmatter, body) = split_frontmatter(content)?;

    let raw: crate::yaml::Value = crate::yaml::from_str(frontmatter)
        .map_err(|e| Error::Config(format!("SKILL.md YAML frontmatter parse error: {e}")))?;

    let mapping = raw
        .as_mapping()
        .ok_or_else(|| Error::Config("SKILL.md frontmatter must be a YAML mapping".to_owned()))?;

    let name = take_required_string(mapping, "name")?;
    let description = take_required_string(mapping, "description")?;
    let version = take_optional_string(mapping, "version");
    let effort = take_optional_string(mapping, "effort");
    let allowed_tools = take_string_list(mapping, "allowed-tools");
    let triggers = take_string_list(mapping, "triggers");
    let keywords = take_string_list(mapping, "keywords");

    // Collect remaining fields into `extra`.
    let reserved: &[&str] = &[
        "name",
        "description",
        "version",
        "effort",
        "allowed-tools",
        "triggers",
        "keywords",
    ];
    let mut extra = BTreeMap::new();
    for (k, v) in mapping {
        if let Some(key) = k.as_str()
            && !reserved.contains(&key)
        {
            extra.insert(key.to_owned(), crate::yaml::to_json(v));
        }
    }

    let code_blocks = extract_code_blocks(body);

    Ok(ImportedSkill {
        name,
        description,
        version,
        effort,
        allowed_tools,
        triggers,
        keywords,
        body: body.to_owned(),
        code_blocks,
        extra,
        source_path: None,
        auxiliary_files: Vec::new(),
    })
}

/// Parse a SKILL.md file from disk.
///
/// Sets `source_path` to the canonical file path on success.
///
/// # Errors
///
/// Returns an error if the file cannot be read or fails validation.
pub fn parse_skill_file(path: &Path) -> Result<ImportedSkill> {
    let content = std::fs::read_to_string(path)
        .map_err(|e| Error::Config(format!("Cannot read SKILL.md '{}': {e}", path.display())))?;
    let mut skill = parse_skill_md(&content)?;
    skill.source_path = Some(path.to_path_buf());
    Ok(skill)
}

/// Parse a skill directory (progressive disclosure).
///
/// Expects `<dir>/SKILL.md` to exist.  Also discovers auxiliary files:
/// `SKILL.advanced.md`, `reference.md`, `README.md`, and any `.md` files under
/// a `resources/` subdirectory.  Auxiliary paths are stored on the returned
/// skill so clients can fetch them later via [`read_auxiliary_file`].
///
/// # Errors
///
/// Returns an error if `<dir>/SKILL.md` is missing or invalid.
pub fn parse_skill_dir(dir: &Path) -> Result<ImportedSkill> {
    let skill_md = dir.join("SKILL.md");
    if !skill_md.is_file() {
        return Err(Error::Config(format!(
            "No SKILL.md found in directory '{}'",
            dir.display()
        )));
    }

    let mut skill = parse_skill_file(&skill_md)?;
    skill.auxiliary_files = discover_auxiliary_files(dir);
    Ok(skill)
}

/// Read an auxiliary file from a skill, with path-traversal protection.
///
/// `relative` must be a file path relative to the skill's source directory
/// and must not escape that directory.
///
/// # Errors
///
/// Returns an error if the skill has no `source_path`, the file is outside
/// the skill directory, or the file cannot be read.
pub fn read_auxiliary_file(skill: &ImportedSkill, relative: &str) -> Result<String> {
    let source = skill
        .source_path
        .as_ref()
        .ok_or_else(|| Error::Config("Skill has no source_path".to_owned()))?;

    let skill_dir = source
        .parent()
        .ok_or_else(|| Error::Config(format!("Invalid source_path '{}'", source.display())))?;

    let requested = skill_dir.join(relative);
    // Canonicalise both to guard against `..` traversal.
    let canon_dir = skill_dir
        .canonicalize()
        .map_err(|e| Error::Config(format!("Cannot canonicalise skill dir: {e}")))?;
    let canon_req = requested.canonicalize().map_err(|e| {
        Error::Config(format!(
            "Cannot canonicalise '{}': {e}",
            requested.display()
        ))
    })?;

    if !canon_req.starts_with(&canon_dir) {
        return Err(Error::Config(format!(
            "Path traversal blocked: '{relative}' is outside skill directory"
        )));
    }

    std::fs::read_to_string(&canon_req)
        .map_err(|e| Error::Config(format!("Cannot read '{}': {e}", canon_req.display())))
}

// ── internals ────────────────────────────────────────────────────────────────

/// Deserialize `extra` through the YAML tree, so one conversion rule covers
/// every input, and `serde_json`'s `raw_value` magic key
/// (`$serde_json::private::RawValue`, live because the crate enables that
/// feature) stays an ordinary map key instead of being interpreted.
fn extra_via_yaml_tree<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> std::result::Result<BTreeMap<String, serde_json::Value>, D::Error> {
    let raw = BTreeMap::<String, crate::yaml::Value>::deserialize(deserializer)?;
    Ok(raw
        .into_iter()
        .map(|(key, value)| (key, crate::yaml::to_json(&value)))
        .collect())
}

/// Split a SKILL.md document into (frontmatter, body).
///
/// Accepts documents that begin with `---\n` and contain a second `---\n`
/// terminator.  Leading BOM and blank lines are ignored.
fn split_frontmatter(content: &str) -> Result<(&str, &str)> {
    let trimmed = content.trim_start_matches('\u{feff}').trim_start();
    let Some(after_open) = trimmed.strip_prefix("---") else {
        return Err(Error::Config(
            "SKILL.md must begin with '---' YAML frontmatter".to_owned(),
        ));
    };
    // Skip the newline after the opening `---`.
    let after_open = after_open.strip_prefix('\n').unwrap_or(after_open);

    // Find the closing `---` on its own line.
    let close_idx = find_frontmatter_end(after_open).ok_or_else(|| {
        Error::Config("SKILL.md frontmatter missing closing '---' delimiter".to_owned())
    })?;

    let frontmatter = &after_open[..close_idx];
    let rest = &after_open[close_idx..];
    // Strip the `---` and any trailing newline.
    let body = rest
        .strip_prefix("---")
        .unwrap_or(rest)
        .strip_prefix('\n')
        .unwrap_or(rest);
    Ok((frontmatter, body))
}

/// Find the byte index of a `---` line after the frontmatter body.
fn find_frontmatter_end(s: &str) -> Option<usize> {
    let mut idx = 0usize;
    for line in s.split_inclusive('\n') {
        let trimmed_end = line.trim_end_matches(['\n', '\r']);
        if trimmed_end == "---" {
            return Some(idx);
        }
        idx += line.len();
    }
    None
}

fn take_required_string(map: &crate::yaml::Mapping, key: &str) -> Result<String> {
    let value = map
        .get(crate::yaml::Value::String(key.to_owned()))
        .ok_or_else(|| Error::Config(format!("SKILL.md missing required field '{key}'")))?;
    let s = value
        .as_str()
        .ok_or_else(|| Error::Config(format!("SKILL.md field '{key}' must be a string")))?
        .trim();
    if s.is_empty() {
        return Err(Error::Config(format!(
            "SKILL.md field '{key}' must not be empty"
        )));
    }
    Ok(s.to_owned())
}

fn take_optional_string(map: &crate::yaml::Mapping, key: &str) -> Option<String> {
    map.get(crate::yaml::Value::String(key.to_owned()))
        .and_then(|v| v.as_str())
        .map(|s| s.trim().to_owned())
        .filter(|s| !s.is_empty())
}

/// Extract a list of strings from either a YAML sequence or a comma-separated
/// string.  Unknown types are silently ignored (returns empty vec).
fn take_string_list(map: &crate::yaml::Mapping, key: &str) -> Vec<String> {
    let Some(value) = map.get(crate::yaml::Value::String(key.to_owned())) else {
        return Vec::new();
    };
    if let Some(seq) = value.as_sequence() {
        return seq
            .iter()
            .filter_map(|v| v.as_str().map(|s| s.trim().to_owned()))
            .filter(|s| !s.is_empty())
            .collect();
    }
    if let Some(s) = value.as_str() {
        return s
            .split(',')
            .map(|s| s.trim().to_owned())
            .filter(|s| !s.is_empty())
            .collect();
    }
    Vec::new()
}

/// Extract fenced code blocks with recognised language tags from the body.
fn extract_code_blocks(body: &str) -> Vec<SkillCodeBlock> {
    let mut blocks = Vec::new();
    let mut in_block = false;
    let mut current_lang = String::new();
    let mut current_buf = String::new();

    for line in body.lines() {
        let trimmed = line.trim_start();
        if let Some(rest) = trimmed.strip_prefix("```") {
            if in_block {
                // Closing fence.
                if RECOGNISED_LANGS.contains(&current_lang.as_str()) {
                    blocks.push(SkillCodeBlock {
                        lang: current_lang.clone(),
                        content: current_buf.trim_end_matches('\n').to_owned(),
                    });
                }
                in_block = false;
                current_lang.clear();
                current_buf.clear();
            } else {
                // Opening fence — capture the language tag.
                current_lang = rest.split_whitespace().next().unwrap_or("").to_lowercase();
                in_block = true;
                current_buf.clear();
            }
            continue;
        }

        if in_block {
            current_buf.push_str(line);
            current_buf.push('\n');
        }
    }

    blocks
}

/// Find auxiliary files in a skill directory (for progressive disclosure).
fn discover_auxiliary_files(dir: &Path) -> Vec<PathBuf> {
    let mut found = Vec::new();
    let candidates = ["SKILL.advanced.md", "reference.md", "README.md"];
    for name in candidates {
        let path = dir.join(name);
        if path.is_file() {
            found.push(path);
        }
    }
    // Walk resources/ if it exists (one level deep, markdown only).
    let resources = dir.join("resources");
    if resources.is_dir()
        && let Ok(entries) = std::fs::read_dir(&resources)
    {
        let mut md_files: Vec<PathBuf> = entries
            .flatten()
            .map(|e| e.path())
            .filter(|p| {
                p.is_file()
                    && p.extension()
                        .and_then(|e| e.to_str())
                        .is_some_and(|e| e.eq_ignore_ascii_case("md"))
            })
            .collect();
        md_files.sort();
        found.extend(md_files);
    }
    found
}

#[cfg(test)]
#[path = "parser_tests.rs"]
mod tests;

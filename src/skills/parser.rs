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

    /// Other frontmatter fields kept verbatim (e.g. `metadata`).
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub extra: BTreeMap<String, serde_yaml::Value>,

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

    let raw: serde_yaml::Value = serde_yaml::from_str(frontmatter)
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
            extra.insert(key.to_owned(), v.clone());
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

fn take_required_string(map: &serde_yaml::Mapping, key: &str) -> Result<String> {
    let value = map
        .get(serde_yaml::Value::String(key.to_owned()))
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

fn take_optional_string(map: &serde_yaml::Mapping, key: &str) -> Option<String> {
    map.get(serde_yaml::Value::String(key.to_owned()))
        .and_then(|v| v.as_str())
        .map(|s| s.trim().to_owned())
        .filter(|s| !s.is_empty())
}

/// Extract a list of strings from either a YAML sequence or a comma-separated
/// string.  Unknown types are silently ignored (returns empty vec).
fn take_string_list(map: &serde_yaml::Mapping, key: &str) -> Vec<String> {
    let Some(value) = map.get(serde_yaml::Value::String(key.to_owned())) else {
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
mod tests {
    use super::*;

    const MINIMAL_SKILL: &str =
        "---\nname: test-skill\ndescription: A test skill\n---\n# Body\nHello world.\n";

    #[test]
    fn parse_minimal_skill_extracts_name_and_description() {
        // GIVEN: minimal valid SKILL.md
        // WHEN
        let skill = parse_skill_md(MINIMAL_SKILL).unwrap();
        // THEN
        assert_eq!(skill.name, "test-skill");
        assert_eq!(skill.description, "A test skill");
        assert!(skill.body.contains("Hello world"));
    }

    #[test]
    fn parse_skill_with_full_frontmatter() {
        // GIVEN: SKILL.md with all optional fields
        let content = "---\n\
            name: full-skill\n\
            description: Full skill\n\
            version: 1.2.3\n\
            effort: medium\n\
            allowed-tools:\n  - Bash\n  - Read\n\
            triggers:\n  - foo\n  - bar\n\
            keywords: [alpha, beta]\n\
            ---\n\
            Body text.\n";
        // WHEN
        let skill = parse_skill_md(content).unwrap();
        // THEN
        assert_eq!(skill.version.as_deref(), Some("1.2.3"));
        assert_eq!(skill.effort.as_deref(), Some("medium"));
        assert_eq!(skill.allowed_tools, vec!["Bash", "Read"]);
        assert_eq!(skill.triggers, vec!["foo", "bar"]);
        assert_eq!(skill.keywords, vec!["alpha", "beta"]);
    }

    #[test]
    fn parse_skill_missing_frontmatter_fails() {
        // GIVEN: no frontmatter delimiters
        let content = "# Just a title\nBody.";
        // WHEN
        let result = parse_skill_md(content);
        // THEN
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(msg.contains("must begin with '---'"), "got: {msg}");
    }

    #[test]
    fn parse_skill_missing_name_fails() {
        // GIVEN: frontmatter without name
        let content = "---\ndescription: no name here\n---\nBody.";
        // WHEN
        let result = parse_skill_md(content);
        // THEN
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("'name'"));
    }

    #[test]
    fn parse_skill_missing_description_fails() {
        // GIVEN: frontmatter without description
        let content = "---\nname: only-name\n---\nBody.";
        // WHEN
        let result = parse_skill_md(content);
        // THEN
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("'description'"));
    }

    #[test]
    fn parse_skill_empty_name_fails() {
        // GIVEN: empty name
        let content = "---\nname: \"\"\ndescription: x\n---\n";
        // WHEN
        let result = parse_skill_md(content);
        // THEN
        assert!(result.is_err());
    }

    #[test]
    fn parse_skill_malformed_yaml_fails() {
        // GIVEN: broken YAML
        let content = "---\nname: [unterminated\ndescription: oops\n---\n";
        // WHEN
        let result = parse_skill_md(content);
        // THEN
        assert!(result.is_err());
    }

    #[test]
    fn parse_skill_missing_closing_delimiter_fails() {
        // GIVEN: open frontmatter never closed
        let content = "---\nname: a\ndescription: b\n# Body with no delimiter\n";
        // WHEN
        let result = parse_skill_md(content);
        // THEN
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("closing '---' delimiter")
        );
    }

    #[test]
    fn extract_code_blocks_captures_bash() {
        // GIVEN: body with a bash fence
        let body = "Run this:\n\n```bash\necho hi\nls -la\n```\n\nAnd done.\n";
        // WHEN
        let blocks = extract_code_blocks(body);
        // THEN
        assert_eq!(blocks.len(), 1);
        assert_eq!(blocks[0].lang, "bash");
        assert_eq!(blocks[0].content, "echo hi\nls -la");
    }

    #[test]
    fn extract_code_blocks_ignores_unknown_langs() {
        // GIVEN: a rust block (not in recognised list)
        let body = "```rust\nfn main() {}\n```\n";
        // WHEN
        let blocks = extract_code_blocks(body);
        // THEN: ignored
        assert_eq!(blocks.len(), 0);
    }

    #[test]
    fn extract_code_blocks_multiple_langs() {
        // GIVEN: bash + python
        let body = "```bash\nls\n```\n\n```python\nprint(1)\n```\n";
        // WHEN
        let blocks = extract_code_blocks(body);
        // THEN
        assert_eq!(blocks.len(), 2);
        assert_eq!(blocks[0].lang, "bash");
        assert_eq!(blocks[1].lang, "python");
    }

    #[test]
    fn parse_skill_captures_code_blocks_in_body() {
        // GIVEN: SKILL.md with an executable block
        let content = "---\nname: exec\ndescription: has code\n---\n```bash\necho hi\n```\n";
        // WHEN
        let skill = parse_skill_md(content).unwrap();
        // THEN
        assert_eq!(skill.code_blocks.len(), 1);
        assert_eq!(skill.code_blocks[0].lang, "bash");
    }

    #[test]
    fn parse_skill_preserves_extra_frontmatter_fields() {
        // GIVEN: a metadata mapping under an unknown key
        let content = "---\nname: meta\ndescription: x\nmetadata:\n  openclaw:\n    category: productivity\n---\nBody\n";
        // WHEN
        let skill = parse_skill_md(content).unwrap();
        // THEN
        assert!(skill.extra.contains_key("metadata"));
    }

    #[test]
    fn parse_skill_dir_discovers_resources() {
        // GIVEN: a temp dir with SKILL.md + resources/topic.md
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("SKILL.md"), MINIMAL_SKILL).unwrap();
        std::fs::create_dir(tmp.path().join("resources")).unwrap();
        std::fs::write(tmp.path().join("resources/topic.md"), "# topic").unwrap();
        // WHEN
        let skill = parse_skill_dir(tmp.path()).unwrap();
        // THEN
        assert_eq!(skill.auxiliary_files.len(), 1);
        assert!(skill.auxiliary_files[0].ends_with("topic.md"));
        assert!(skill.source_path.is_some());
    }

    #[test]
    fn parse_skill_dir_missing_skill_md_fails() {
        // GIVEN: empty dir
        let tmp = tempfile::tempdir().unwrap();
        // WHEN
        let result = parse_skill_dir(tmp.path());
        // THEN
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("No SKILL.md"));
    }

    #[test]
    fn read_auxiliary_file_blocks_traversal() {
        // GIVEN: a skill on disk + an attacker-controlled relative path
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("SKILL.md"), MINIMAL_SKILL).unwrap();
        let skill = parse_skill_dir(tmp.path()).unwrap();
        // WHEN: request a path that escapes the skill dir
        let result = read_auxiliary_file(&skill, "../../../etc/passwd");
        // THEN: blocked
        assert!(result.is_err());
    }

    #[test]
    fn read_auxiliary_file_reads_valid_file() {
        // GIVEN: a skill with a resource
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("SKILL.md"), MINIMAL_SKILL).unwrap();
        std::fs::write(tmp.path().join("reference.md"), "Reference content").unwrap();
        let skill = parse_skill_dir(tmp.path()).unwrap();
        // WHEN
        let content = read_auxiliary_file(&skill, "reference.md").unwrap();
        // THEN
        assert_eq!(content, "Reference content");
    }
}

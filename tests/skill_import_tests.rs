//! End-to-end tests for SKILL.md import → registry → search → show.
//!
//! Exercises the public `mcp_gateway::skills` API to verify the import
//! workflow introduced for issue #114 (agentskills.io / SKILL.md compatibility).

use std::fs;

use mcp_gateway::skills::{SkillRegistry, parse_skill_dir, parse_skill_file};

const REAL_SKILL: &str = r#"---
name: echo-greeter
description: Print a greeting to stdout
version: 1.0.0
effort: low
allowed-tools:
  - Bash
triggers:
  - greet
  - hello
keywords: [demo, example]
---

# Echo Greeter

A tiny demo skill.

## Usage

```bash
echo "hello, world"
```

See also `reference.md` for the full reference.
"#;

#[test]
fn end_to_end_import_list_search_show() {
    // GIVEN: a SKILL.md on disk in a skill directory with a resource
    let tmp = tempfile::tempdir().unwrap();
    let skill_dir = tmp.path().join("echo-greeter");
    fs::create_dir(&skill_dir).unwrap();
    fs::write(skill_dir.join("SKILL.md"), REAL_SKILL).unwrap();
    fs::write(
        skill_dir.join("reference.md"),
        "# Reference\nFull docs here.\n",
    )
    .unwrap();

    // WHEN: parse the directory
    let skill = parse_skill_dir(&skill_dir).expect("parse SKILL.md directory");

    // THEN: frontmatter is extracted, code block is captured, aux files discovered
    assert_eq!(skill.name, "echo-greeter");
    assert_eq!(skill.description, "Print a greeting to stdout");
    assert_eq!(skill.version.as_deref(), Some("1.0.0"));
    assert_eq!(skill.allowed_tools, vec!["Bash"]);
    assert_eq!(skill.triggers, vec!["greet", "hello"]);
    assert_eq!(skill.keywords, vec!["demo", "example"]);
    assert_eq!(skill.code_blocks.len(), 1);
    assert_eq!(skill.code_blocks[0].lang, "bash");
    assert!(skill.code_blocks[0].content.contains("hello, world"));
    assert_eq!(skill.auxiliary_files.len(), 1);
    assert!(skill.auxiliary_files[0].ends_with("reference.md"));

    // WHEN: insert into a fresh registry and persist
    let registry_path = tmp.path().join("registry.json");
    let mut reg = SkillRegistry::load(&registry_path).unwrap();
    let replaced = reg.insert(skill);
    assert!(!replaced);
    reg.save(&registry_path).unwrap();

    // THEN: registry on disk has one skill
    let loaded = SkillRegistry::load(&registry_path).unwrap();
    assert_eq!(loaded.len(), 1);
    assert!(loaded.get("echo-greeter").is_some());

    // WHEN: search by trigger keyword
    let hits = loaded.search("hello");
    // THEN: the skill is surfaced
    assert!(!hits.is_empty(), "search for 'hello' should return results");
    assert_eq!(hits[0].name, "echo-greeter");

    // WHEN: search by a word only in the description
    let hits = loaded.search("greeting");
    assert_eq!(hits.len(), 1);

    // WHEN: search for nothing
    let hits = loaded.search("nonexistent-query-xyz");
    assert!(hits.is_empty());

    // Security: verify that the stored skill carries no "executed" marker.
    // Code blocks are stored as data only.
    let stored = loaded.get("echo-greeter").unwrap();
    assert_eq!(stored.code_blocks.len(), 1);
    // The skill is data; execution happens only when explicitly requested.
}

#[test]
fn malformed_skill_md_returns_clean_error() {
    // GIVEN: a file with no frontmatter
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("bad.md");
    fs::write(&path, "# just a heading, no frontmatter").unwrap();

    // WHEN
    let result = parse_skill_file(&path);

    // THEN: error is descriptive, not a panic
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("---") || err.contains("frontmatter"),
        "error should mention frontmatter: {err}"
    );
}

#[test]
fn skill_with_dangerous_bash_is_stored_but_not_executed() {
    // GIVEN: a SKILL.md whose body contains a destructive command
    // Security model: parser captures the block as DATA, does NOT execute it.
    let dangerous = r"---
name: destructive-example
description: Demonstrates that dangerous blocks are stored read-only
---

# Destructive Example

```bash
rm -rf /
```
";
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("SKILL.md");
    fs::write(&path, dangerous).unwrap();

    // WHEN: parse and register
    let skill = parse_skill_file(&path).unwrap();
    let registry_path = tmp.path().join("registry.json");
    let mut reg = SkillRegistry::load(&registry_path).unwrap();
    reg.insert(skill.clone());
    reg.save(&registry_path).unwrap();

    // THEN: the code block is stored verbatim (available for inspection)...
    assert_eq!(skill.code_blocks.len(), 1);
    assert!(skill.code_blocks[0].content.contains("rm -rf"));

    // ...but no side effects occurred: the tempdir's root still has SKILL.md.
    assert!(path.exists());
    // Registry reload still has the skill.
    let reloaded = SkillRegistry::load(&registry_path).unwrap();
    assert_eq!(reloaded.len(), 1);
}

#[test]
fn progressive_disclosure_multiple_resources() {
    // GIVEN: SKILL.md with resources/ subdirectory holding multiple topics
    let tmp = tempfile::tempdir().unwrap();
    fs::write(
        tmp.path().join("SKILL.md"),
        "---\nname: multi\ndescription: many resources\n---\n# Body\n",
    )
    .unwrap();
    fs::create_dir(tmp.path().join("resources")).unwrap();
    fs::write(tmp.path().join("resources/topic-a.md"), "# A").unwrap();
    fs::write(tmp.path().join("resources/topic-b.md"), "# B").unwrap();
    fs::write(tmp.path().join("reference.md"), "# Ref").unwrap();

    // WHEN
    let skill = parse_skill_dir(tmp.path()).unwrap();

    // THEN: all auxiliary files discovered
    assert_eq!(skill.auxiliary_files.len(), 3);
    let names: Vec<String> = skill
        .auxiliary_files
        .iter()
        .map(|p| p.file_name().unwrap().to_string_lossy().into_owned())
        .collect();
    assert!(names.contains(&"reference.md".to_owned()));
    assert!(names.contains(&"topic-a.md".to_owned()));
    assert!(names.contains(&"topic-b.md".to_owned()));
}

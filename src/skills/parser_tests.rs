// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Tests for the SKILL.md parser.

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

// E1
#[test]
fn extra_nested_metadata_maps_to_json_values() {
    let content = "---\nname: n\ndescription: d\nmetadata:\n  openclaw:\n    category: productivity\n---\nBody\n";
    let skill = parse_skill_md(content).expect("fixture skill parses");
    let extra: &BTreeMap<String, serde_json::Value> = &skill.extra;
    assert_eq!(
        extra["metadata"],
        serde_json::json!({"openclaw": {"category": "productivity"}})
    );
}

// E2
#[test]
fn extra_keeps_yaml_tags_as_one_entry_maps() {
    let content = "---\nname: n\ndescription: d\nx: !custom {a: 1}\ns: [!t 1, plain]\n---\nBody\n";
    let skill = parse_skill_md(content).expect("fixture skill parses");
    assert_eq!(skill.extra["x"], serde_json::json!({"!custom": {"a": 1}}));
    assert_eq!(skill.extra["s"], serde_json::json!([{"!t": 1}, "plain"]));
}

// E3
#[test]
fn extra_stringifies_scalar_keys_and_drops_other_keys() {
    let content = "---\nname: n\ndescription: d\nm: {1: one, true: t, 1.5: f, 1.0: g, 1e3: h, -0.0: z0, two: 2, [a]: z, ~: n, {k: v}: w, !t k: x, .inf: i}\n---\nBody\n";
    let skill = parse_skill_md(content).expect("fixture skill parses");
    assert_eq!(
        skill.extra["m"],
        serde_json::json!({"1": "one", "true": "t", "1.5": "f", "1.0": "g", "1000.0": "h", "-0.0": "z0", "two": 2})
    );
}

// E4
#[test]
fn extra_maps_non_finite_floats_to_null_and_keeps_number_kinds() {
    let content = "---\nname: n\ndescription: d\nf: [.inf, -.inf, .nan, 1.5, 1.0, 18446744073709551615, -9223372036854775808]\n---\nBody\n";
    let skill = parse_skill_md(content).expect("fixture skill parses");
    assert_eq!(
        skill.extra["f"],
        serde_json::json!([
            null,
            null,
            null,
            1.5,
            1.0,
            18_446_744_073_709_551_615_u64,
            -9_223_372_036_854_775_808_i64
        ])
    );
    assert!(skill.extra["f"][4].is_f64());
}

// E5
#[test]
fn extra_later_stringified_key_wins_when_int_comes_first() {
    let content = "---\nname: n\ndescription: d\nm: {1: a, \"1\": b}\n---\nBody\n";
    let skill = parse_skill_md(content).expect("fixture skill parses");
    assert_eq!(skill.extra["m"], serde_json::json!({"1": "b"}));
}

// E5
#[test]
fn extra_later_stringified_key_wins_when_string_comes_first() {
    let content = "---\nname: n\ndescription: d\nm: {\"1\": a, 1: b}\n---\nBody\n";
    let skill = parse_skill_md(content).expect("fixture skill parses");
    assert_eq!(skill.extra["m"], serde_json::json!({"1": "b"}));
}

// E5
#[test]
fn extra_duplicate_yaml_keys_are_still_refused() {
    let content = "---\nname: n\ndescription: d\nm: {a: 1, a: 2}\n---\nBody\n";
    assert!(parse_skill_md(content).is_err());
}

// E8
#[test]
fn extra_deserializing_from_json_keeps_raw_value_magic_key_as_plain_map() {
    let skill: ImportedSkill = serde_json::from_value(serde_json::json!({"name": "n", "description": "d", "body": "b", "extra": {"x": {"$serde_json::private::RawValue": "0"}}})).expect("fixture skill deserializes");
    assert_eq!(
        skill.extra["x"],
        serde_json::json!({"$serde_json::private::RawValue": "0"})
    );
}

// E8
#[test]
fn extra_deserializing_from_yaml_applies_tag_rule() {
    let skill: ImportedSkill = crate::yaml::from_str::<ImportedSkill>(
        "name: n\ndescription: d\nbody: b\nextra:\n  x: !t 1\n",
    )
    .expect("fixture skill deserializes");
    assert_eq!(skill.extra["x"], serde_json::json!({"!t": 1}));
}

// E1b
#[test]
fn extra_null_and_bool_values_map_to_json() {
    let content = "---\nname: n\ndescription: d\nv: {n: ~, t: true, f: false}\n---\nBody\n";
    let skill = parse_skill_md(content).expect("fixture skill parses");
    assert_eq!(
        skill.extra["v"],
        serde_json::json!({"n": null, "t": true, "f": false})
    );
}

// E3b
#[test]
fn extra_negative_and_max_u64_keys_stringify() {
    let content = concat!(
        "---\nname: n\ndescription: d\n",
        "m: {-5: neg, 18446744073709551615: max}\n",
        "---\nBody\n",
    );
    let skill = parse_skill_md(content).expect("fixture skill parses");
    assert_eq!(
        skill.extra["m"],
        serde_json::json!({"-5": "neg", "18446744073709551615": "max"})
    );
}

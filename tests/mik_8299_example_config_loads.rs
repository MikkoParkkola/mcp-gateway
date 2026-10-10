// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8299.DOC.3: `examples/gateway-full.yaml` says "uncomment/modify
//! sections as needed", so every commented block in it must load when
//! uncommented. Unknown keys are a load error (MIK-7570.CONFIG.1), so a block
//! for a setting that does not exist turns into a gateway that refuses to
//! start.
//!
//! Each block is uncommented on its own: several are alternatives to an active
//! line (`warm_start: []`) or to each other (three `security:` blocks), and
//! uncommenting them together would be a duplicate key, not a test of either.
//! No block is skipped: one that needs a variable gets it from the test.

use std::fmt::Write as _;
use std::path::Path;

use mcp_gateway::config::Config;

const EXAMPLE: &str = include_str!("../examples/gateway-full.yaml");

/// One commented block: the line range it spans and its first key.
struct Block {
    lines: std::ops::Range<usize>,
    key: String,
}

/// `(indent, rest)` when `line` is `<indent># <rest>`: one space after `#`.
fn commented(line: &str) -> Option<(usize, &str)> {
    let indent = line.len() - line.trim_start().len();
    line[indent..].strip_prefix("# ").map(|rest| (indent, rest))
}

/// `rest` starts a YAML mapping key: `name:` at its own start.
fn key_of(rest: &str) -> Option<&str> {
    let (key, _) = rest.split_once(':')?;
    (!key.is_empty()
        && key
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_'))
    .then_some(key)
}

/// Every commented block that starts with `# key:` and runs over the lines
/// below it that are commented at the same indent and indented deeper.
fn blocks(lines: &[&str]) -> Vec<Block> {
    let mut found = Vec::new();
    let mut i = 0;
    while i < lines.len() {
        let Some((indent, rest)) = commented(lines[i]) else {
            i += 1;
            continue;
        };
        let Some(key) = key_of(rest) else {
            i += 1;
            continue;
        };
        let start = i;
        i += 1;
        while let Some(line) = lines.get(i) {
            let Some(body) = line.get(indent..).and_then(|l| l.strip_prefix('#')) else {
                break;
            };
            if line[..indent].trim().is_empty() && body.starts_with("  ") {
                i += 1;
            } else {
                break;
            }
        }
        found.push(Block {
            lines: start..i,
            key: key.to_string(),
        });
    }
    found
}

/// `lines` with `block` uncommented and `~/` pointed at `home`, so the test
/// never reads the developer's own env file.
fn with_block(lines: &[&str], block: Option<&Block>, home: &Path) -> String {
    let home = format!("{}/", home.display());
    let mut out = String::new();
    for (n, line) in lines.iter().enumerate() {
        let line = match block {
            Some(b) if b.lines.contains(&n) => {
                let indent = line.len() - line.trim_start().len();
                let body = &line[indent..];
                let body = body
                    .strip_prefix("# ")
                    .or_else(|| body.strip_prefix('#'))
                    .unwrap_or(body);
                format!("{}{}", &line[..indent], body)
            }
            _ => (*line).to_string(),
        };
        out.push_str(&line.replace("~/", &home));
        out.push('\n');
    }
    out
}

/// Every variable `yaml` references as `${NAME}` or `env:NAME`.
fn referenced_vars(yaml: &str) -> Vec<String> {
    let mut names = Vec::new();
    for marker in ["${", "env:"] {
        for (at, _) in yaml.match_indices(marker) {
            let name: String = yaml[at + marker.len()..]
                .chars()
                .take_while(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || *c == '_')
                .collect();
            if !name.is_empty() && !names.contains(&name) {
                names.push(name);
            }
        }
    }
    names
}

/// A value of the shape each referenced variable stands for: a key digest
/// for `*_SHA256`, any non-empty token otherwise.
fn stand_in(name: &str) -> String {
    if name.ends_with("SHA256") {
        // Distinct per name, in the leading bits the gateway compares: two
        // keys sharing them are refused as one principal.
        use std::hash::{Hash as _, Hasher as _};
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        name.hash(&mut hasher);
        format!("sha256:{}", format!("{:016x}", hasher.finish()).repeat(4))
    } else {
        "mik-8299-stand-in-0123456789abcdef".to_string()
    }
}

/// Load `yaml` from `dir`. A block that fails only because a variable it
/// names is unset is not a broken block: the variables come from the
/// example's own `env_files` entry (`~/.mcp-gateway/.env`, with `~` pointed
/// at `dir`), so the gateway's own env-file loading sets them.
fn load(yaml: &str, dir: &Path) -> Result<Config, String> {
    let env_dir = dir.join(".mcp-gateway");
    std::fs::create_dir_all(&env_dir).expect("env dir");
    let mut env = String::new();
    for name in referenced_vars(yaml) {
        writeln!(env, "{name}={}", stand_in(&name)).expect("a String takes the line");
    }
    mcp_gateway::gateway::test_helpers::write_owner_only(env_dir.join(".env"), &env)
        .expect("write env file");
    let path = dir.join("gateway.yaml");
    mcp_gateway::gateway::test_helpers::write_owner_only(&path, yaml).expect("write config");
    Config::load(Some(&path)).map_err(|e| e.to_string())
}

/// Set in the child that runs a test's body.
const CHILD: &str = "MIK_8299_ISOLATED";
/// Printed by the child once the body ran, so a filter matching no test fails.
const CHILD_OK: &str = "mik-8299: the isolated body ran";

/// Run the calling test in a child with an empty environment and a fresh
/// home, so no `MCP_GATEWAY_*` override, env file or home config from the
/// developer's or the CI runner's environment reaches `Config::load` (#3752
/// review). True in the child, which runs the body; the parent returns false
/// once the child has passed.
fn in_clean_child(test: &str) -> bool {
    if std::env::var_os(CHILD).is_some() {
        return true;
    }
    let home = tempfile::tempdir().expect("child home");
    let mut child = std::process::Command::new(std::env::current_exe().expect("test executable"));
    child
        .args(["--exact", test, "--nocapture"])
        .env_clear()
        .env(CHILD, "1")
        .env("HOME", home.path())
        .env("USERPROFILE", home.path());
    // What a process needs to start and make temp dirs, never a config input.
    for keep in ["PATH", "SYSTEMROOT", "SystemRoot", "TEMP", "TMP", "TMPDIR"] {
        if let Some(value) = std::env::var_os(keep) {
            child.env(keep, value);
        }
    }
    let output = child.output().expect("run the isolated child");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success() && stdout.contains(CHILD_OK),
        "isolated `{test}` failed or ran no test:\n{stdout}\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    false
}

/// The `# key:` blocks the example carries, in file order. Pinned, so a
/// block-finder regression that drops one fails here instead of passing.
const EXPECTED_BLOCKS: &[&str] = &[
    "cleartext_http",
    "cluster_domain",
    "bearer_token",
    "api_keys",
    "dashboard_session",
    "security",
    "warm_start",
    "surfaced_tools",
    "cost_governance",
    "security",
    "security",
    "tavily",
    "context7",
    "pieces",
    "gitmcp_mcp_gateway",
    "gitmcp_docs",
    "google",
];

#[test]
fn the_full_example_loads_as_shipped() {
    if !in_clean_child("the_full_example_loads_as_shipped") {
        return;
    }
    let dir = tempfile::tempdir().expect("tempdir");
    let lines: Vec<&str> = EXAMPLE.lines().collect();
    let config = load(&with_block(&lines, None, dir.path()), dir.path())
        .unwrap_or_else(|e| panic!("examples/gateway-full.yaml does not load as shipped: {e}"));
    assert!(
        config.backends.is_empty(),
        "every backend in the example is commented out: {:?}",
        config.backends.keys()
    );
    println!("{CHILD_OK}");
}

#[test]
fn every_commented_block_in_the_full_example_loads_when_uncommented() {
    if !in_clean_child("every_commented_block_in_the_full_example_loads_when_uncommented") {
        return;
    }
    let lines: Vec<&str> = EXAMPLE.lines().collect();
    let all = blocks(&lines);
    let keys: Vec<&str> = all.iter().map(|b| b.key.as_str()).collect();
    assert_eq!(
        keys, EXPECTED_BLOCKS,
        "the commented blocks found in the example"
    );
    let mut refused = Vec::new();
    for block in &all {
        let dir = tempfile::tempdir().expect("tempdir");
        if let Err(error) = load(&with_block(&lines, Some(block), dir.path()), dir.path()) {
            refused.push(format!(
                "`{}` (line {}): {error}",
                block.key,
                block.lines.start + 1
            ));
        }
    }
    assert!(
        refused.is_empty(),
        "examples/gateway-full.yaml has blocks that refuse to load when uncommented:\n{}",
        refused.join("\n")
    );
    println!("{CHILD_OK}");
}

/// Write `yaml` to a fresh `gateway.yaml` and load it, with no env file.
fn load_plain(yaml: &str) -> Result<Config, String> {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("gateway.yaml");
    mcp_gateway::gateway::test_helpers::write_owner_only(&path, yaml).expect("write config");
    Config::load(Some(&path)).map_err(|e| e.to_string())
}

#[test]
fn a_backends_section_with_only_comments_under_it_loads_as_none() {
    if !in_clean_child("a_backends_section_with_only_comments_under_it_loads_as_none") {
        return;
    }
    let config = load_plain("backends:\n  # tavily:\n  #   command: \"true\"\n")
        .unwrap_or_else(|e| panic!("an empty backends section is refused: {e}"));
    assert!(config.backends.is_empty());
    println!("{CHILD_OK}");
}

#[test]
fn a_backends_section_of_the_wrong_type_is_still_refused() {
    if !in_clean_child("a_backends_section_of_the_wrong_type_is_still_refused") {
        return;
    }
    for yaml in [
        "backends: [tavily]\n",
        "backends: tavily\n",
        "backends: 3\n",
    ] {
        assert!(
            load_plain(yaml).is_err(),
            "{yaml:?} loaded; only an empty section may read as none"
        );
    }
    println!("{CHILD_OK}");
}

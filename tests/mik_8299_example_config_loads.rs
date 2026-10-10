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

#[test]
fn the_full_example_loads_as_shipped() {
    let dir = tempfile::tempdir().expect("tempdir");
    let lines: Vec<&str> = EXAMPLE.lines().collect();
    if let Err(error) = load(&with_block(&lines, None, dir.path()), dir.path()) {
        panic!("examples/gateway-full.yaml does not load as shipped: {error}");
    }
}

#[test]
fn every_commented_block_in_the_full_example_loads_when_uncommented() {
    let lines: Vec<&str> = EXAMPLE.lines().collect();
    let all = blocks(&lines);
    assert!(
        all.len() >= 10,
        "the block finder found only {} blocks",
        all.len()
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
    let config = load_plain("backends:\n  # tavily:\n  #   command: \"true\"\n")
        .unwrap_or_else(|e| panic!("an empty backends section is refused: {e}"));
    assert!(config.backends.is_empty());
}

#[test]
fn a_backends_section_of_the_wrong_type_is_still_refused() {
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
}

// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Every gateway.yaml example the docs ship loads on the gateway's own path.
//!
//! A fenced `yaml` block in `README.md`, `docs/*.md`, `upgrading.d/*.md` or the
//! rustdoc under `src/config` is a gateway.yaml example when one of its
//! top-level keys is one the loader reads. Each goes through `Config::load` on a
//! real file, the strict-key check included. A block that shows a config the
//! gateway refuses carries the line `# example: refused` and must be refused.
//!
//! Built only with the features the key check names (`a2a`, `cost-governance`,
//! `firewall`), which release images carry: the docs describe those builds.
#![cfg(all(feature = "a2a", feature = "cost-governance", feature = "firewall"))]

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use mcp_gateway::config::Config;

/// The line that marks a block showing a config the gateway refuses.
const REFUSED: &str = "# example: refused";

/// One fenced block: the `file:line` of its opening fence, and its text.
#[derive(Debug, PartialEq)]
struct Block {
    at: String,
    text: String,
}

/// The fenced `yaml` blocks in `lines`. Each entry is a line's content, or
/// `None` for a line no block can span (code between rustdoc lines), which
/// drops a block left open. The fence's indentation is cut from the body.
fn fenced(file: &str, lines: &[Option<&str>]) -> Vec<Block> {
    let mut blocks = Vec::new();
    let mut open: Option<(usize, usize, Vec<&str>)> = None;
    for (i, line) in lines.iter().enumerate() {
        let Some(line) = *line else {
            open = None;
            continue;
        };
        let trimmed = line.trim_start();
        let fence = trimmed.trim_end();
        if let Some((start, indent, mut body)) = open.take() {
            if fence == "```" {
                let mut text = body.join("\n");
                text.push('\n');
                blocks.push(Block {
                    at: format!("{file}:{start}"),
                    text,
                });
            } else {
                body.push(line.get(indent..).unwrap_or(trimmed));
                open = Some((start, indent, body));
            }
        } else if fence == "```yaml" || fence == "```yml" {
            open = Some((i + 1, line.len() - trimmed.len(), Vec::new()));
        }
    }
    blocks
}

/// The text of a `///` or `//!` line, without the one space after the marker.
fn doc_line(line: &str) -> Option<&str> {
    let line = line.trim_start();
    let rest = line
        .strip_prefix("///")
        .or_else(|| line.strip_prefix("//!"))?;
    Some(rest.strip_prefix(' ').unwrap_or(rest))
}

/// The keys a block sets at column 0.
fn top_keys(text: &str) -> Vec<&str> {
    text.lines()
        .filter(|line| !line.starts_with([' ', '\t', '#', '-']))
        .filter_map(|line| line.split_once(':'))
        .map(|(key, _)| key.trim().trim_matches('"'))
        .filter(|key| !key.is_empty())
        .collect()
}

fn load(yaml: &str) -> mcp_gateway::Result<Config> {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("gateway.yaml");
    mcp_gateway::gateway::test_helpers::write_owner_only(&path, yaml).expect("write config");
    Config::load(Some(&path))
}

/// Whether the loader reads a top-level key named `key`, asked of the loader
/// itself: only a key it reads nowhere is refused as unrecognised.
fn gateway_key(key: &str, known: &mut BTreeMap<String, bool>) -> bool {
    *known
        .entry(key.to_owned())
        .or_insert_with(|| match load(&format!("{key}: {{}}\n")) {
            Ok(_) => true,
            Err(error) => !error.to_string().contains("Unrecognised config key(s)"),
        })
}

/// The gateway.yaml examples among `blocks`, by `at`, and each one that does
/// not do what it shows: an example the loader refuses, with the start of the
/// error, or a marked one that loads.
fn misbehaving(blocks: &[Block], known: &mut BTreeMap<String, bool>) -> (Vec<String>, Vec<String>) {
    let (mut checked, mut wrong) = (Vec::new(), Vec::new());
    for block in blocks {
        if !top_keys(&block.text)
            .into_iter()
            .any(|key| gateway_key(key, known))
        {
            continue;
        }
        checked.push(block.at.clone());
        let marked = block.text.lines().any(|line| line.trim() == REFUSED);
        match (load(&block.text), marked) {
            (Ok(_), true) => wrong.push(format!("{}: marked refused, but loads", block.at)),
            (Err(error), false) => {
                let error: String = error.to_string().chars().take(240).collect();
                wrong.push(format!("{}: {error}", block.at));
            }
            _ => {}
        }
    }
    (checked, wrong)
}

/// The files with extension `ext` in `dir`, and below it when `deep`, sorted.
fn files(dir: &Path, ext: &str, deep: bool) -> Vec<PathBuf> {
    let mut found = Vec::new();
    for entry in std::fs::read_dir(dir).unwrap_or_else(|e| panic!("{}: {e}", dir.display())) {
        let path = entry.expect("dir entry").path();
        if path.is_dir() {
            if deep {
                found.extend(files(&path, ext, deep));
            }
        } else if path.extension().is_some_and(|e| e == ext) {
            found.push(path);
        }
    }
    found.sort();
    found
}

/// Every fenced yaml block the docs ship, CRLF normalised.
fn shipped_blocks(root: &Path) -> Vec<Block> {
    let mut markdown = vec![root.join("README.md")];
    markdown.extend(files(&root.join("docs"), "md", false));
    markdown.extend(files(&root.join("upgrading.d"), "md", false));
    let rustdoc = files(&root.join("src/config"), "rs", true);
    let mut blocks = Vec::new();
    for (path, is_rust) in markdown
        .iter()
        .map(|p| (p, false))
        .chain(rustdoc.iter().map(|p| (p, true)))
    {
        let text = std::fs::read_to_string(path)
            .unwrap_or_else(|e| panic!("{}: {e}", path.display()))
            .replace("\r\n", "\n");
        let rel = path
            .strip_prefix(root)
            .expect("under the root")
            .to_string_lossy()
            .replace('\\', "/");
        let lines: Vec<Option<&str>> = if is_rust {
            text.lines().map(doc_line).collect()
        } else {
            text.lines().map(Some).collect()
        };
        blocks.extend(fenced(&rel, &lines));
    }
    blocks
}

#[test]
fn every_documented_gateway_yaml_example_loads() {
    let blocks = shipped_blocks(Path::new(env!("CARGO_MANIFEST_DIR")));
    let (checked, wrong) = misbehaving(&blocks, &mut BTreeMap::new());
    // Not vacuous: the guide's A2A backend example is found and checked.
    let a2a = blocks
        .iter()
        .find(|b| b.at.starts_with("docs/UPGRADING-4.0.md:") && b.text.contains("a2a_url"))
        .expect("the UPGRADING A2A backend example is a fenced yaml block");
    assert!(checked.contains(&a2a.at), "{} was not checked", a2a.at);
    assert!(
        wrong.is_empty(),
        "{} of {} documented gateway.yaml examples do not do what they show:\n{}",
        wrong.len(),
        checked.len(),
        wrong.join("\n")
    );
}

#[test]
fn fences_are_found_in_markdown_and_rustdoc() {
    let md = "x\n  ```yaml\n  server:\n    port: 1\n  ```\n```json\n{}\n```\n";
    let lines: Vec<Option<&str>> = md.lines().map(Some).collect();
    assert_eq!(
        fenced("a.md", &lines),
        [Block {
            at: "a.md:2".into(),
            text: "server:\n  port: 1\n".into()
        }]
    );
    // The second block is cut by a code line, so it is dropped.
    let rs = "/// ```yaml\n/// backends: {}\n/// ```\nfn f() {}\n/// ```yaml\nconst X: u8 = 0;\n/// cut: 1\n/// ```\n";
    let lines: Vec<Option<&str>> = rs.lines().map(doc_line).collect();
    assert_eq!(
        fenced("b.rs", &lines),
        [Block {
            at: "b.rs:1".into(),
            text: "backends: {}\n".into()
        }]
    );
}

#[test]
fn a_block_that_does_not_do_what_it_shows_is_named() {
    let block = |at: &str, text: String| Block {
        at: at.into(),
        text,
    };
    let blocks = [
        block("loads", "server:\n  port: 39400\n".into()),
        block("typo", "serverr: {}\nbackends: {}\n".into()),
        block("marked-loads", format!("{REFUSED}\nbackends: {{}}\n")),
        block(
            "marked-refused",
            format!("{REFUSED}\nbackends:\n  x:\n    command: y\n    idle_timeout: 1m\n"),
        ),
        block("not-gateway", "apiVersion: v1\nkind: Pod\n".into()),
    ];
    let (checked, wrong) = misbehaving(&blocks, &mut BTreeMap::new());
    assert_eq!(checked, ["loads", "typo", "marked-loads", "marked-refused"]);
    assert_eq!(wrong.len(), 2, "{wrong:?}");
    assert!(
        wrong[0].starts_with("typo: ") && wrong[0].contains("serverr"),
        "{wrong:?}"
    );
    assert_eq!(wrong[1], "marked-loads: marked refused, but loads");
}

// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Every gateway.yaml example the docs ship loads on the gateway's own path.
//!
//! A fenced `yaml` block in `README.md`, `docs/*.md`, `upgrading.d/*.md` or the
//! rustdoc under `src/config` is a gateway.yaml example when one of its
//! top-level keys is one the loader reads. Each goes through `Config::load` on a
//! real file, the strict-key check included. A block that shows a config the
//! gateway refuses carries the line `# example: refused` and must be refused; a
//! block that is another file (a capability, Helm values) carries
//! `# example: not gateway.yaml` and is not loaded.
//!
//! A block that names environment variables (`${NAME}`, `env:NAME`) is right
//! once they are set, so it loads with an `env_files` entry defining each one,
//! as `team_deployment_guide_claims.rs` loads its guide's block. A value whose
//! form the loader checks gets that form (see [`placeholder`]).
//!
//! Built only with the features the key check names (`a2a`, `cost-governance`,
//! `firewall`), which release images carry: the docs describe those builds.
#![cfg(all(feature = "a2a", feature = "cost-governance", feature = "firewall"))]

use std::collections::BTreeMap;
#[cfg(unix)]
use std::path::{Path, PathBuf};

use mcp_gateway::config::Config;
use regex::Regex;

/// The line that marks a block showing a config the gateway refuses.
const REFUSED: &str = "# example: refused";

/// The line that marks a block that is some other file, never loaded.
const NOT_GATEWAY: &str = "# example: not gateway.yaml";

/// An API key digest's form: `sha256:` and 64 lowercase hex characters.
const DIGEST: &str = "sha256:abababababababababababababababababababababababababababababababab";

/// A chain signing key's form: standard base64 of a 32-byte seed.
const SEED: &str = "KioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKio=";

/// Any other variable's value: base64 of 32 bytes, so a key the operator
/// names (an accounts `keys` entry, read as a 32-byte key) loads too, and still
/// an opaque string where a token or secret goes.
const PLACEHOLDER: &str = "ZG9jcy1leGFtcGxlLXBsYWNlaG9sZGVyLTAxMjM0NTY=";

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

/// The value for a variable referenced under `key`. The loader checks the
/// form of a digest and of a seed, so those get that form; the docs that use
/// them are right as written.
fn placeholder(key: &str) -> &'static str {
    match key {
        "key_sha256" | "previous_key_sha256" => DIGEST,
        "signing_key" => SEED,
        _ => PLACEHOLDER,
    }
}

/// Each variable `text` names (`${NAME}`, with or without a default, and
/// `env:NAME`) with its value, by the key on the reference's line.
fn env_values(text: &str) -> BTreeMap<String, &'static str> {
    let name =
        Regex::new(r"\$\{([A-Za-z_][A-Za-z0-9_]*)|env:([A-Za-z_][A-Za-z0-9_]*)").expect("regex");
    let mut values = BTreeMap::new();
    for line in text.lines() {
        let key = line.trim_start().trim_start_matches("- ");
        let key = key.split(':').next().unwrap_or_default().trim();
        for found in name.captures_iter(line) {
            let var = found
                .get(1)
                .or_else(|| found.get(2))
                .expect("one group matched");
            values.insert(var.as_str().to_owned(), placeholder(key));
        }
    }
    values
}

/// `yaml` without its own top-level `env_files` key. One example sets one
/// (docs/OAUTH_CONFIG.md), naming a path under the reader's home; the guard's
/// own file takes that path's place.
fn without_env_files(yaml: &str) -> String {
    let mut kept = String::new();
    let mut inside = false;
    for line in yaml.lines() {
        if line.starts_with("env_files:") {
            inside = true;
            continue;
        }
        if inside && line.starts_with([' ', '\t', '-']) {
            continue;
        }
        inside = false;
        kept.push_str(line);
        kept.push('\n');
    }
    kept
}

/// Load `yaml` as the gateway would, `Err` holding the refusal. A block that
/// names variables or sets `env_files` loads with an `env_files` entry
/// defining each variable it names.
fn load_example(yaml: &str) -> Result<(), String> {
    let values = env_values(yaml);
    if values.is_empty() && !yaml.lines().any(|line| line.starts_with("env_files:")) {
        return load(yaml).map(drop).map_err(|e| e.to_string());
    }
    let dir = tempfile::tempdir().expect("tempdir");
    let env = dir.path().join("example.env");
    let lines: String = values
        .iter()
        .map(|(var, value)| format!("{var}={value}\n"))
        .collect();
    mcp_gateway::gateway::test_helpers::write_owner_only(&env, &lines).expect("write env file");
    let yaml = format!(
        "env_files: ['{}']\n{}",
        env.display(),
        without_env_files(yaml)
    );
    load(&yaml).map(drop).map_err(|e| e.to_string())
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
        if block.text.lines().any(|line| line.trim() == NOT_GATEWAY) {
            continue;
        }
        if !top_keys(&block.text)
            .into_iter()
            .any(|key| gateway_key(key, known))
        {
            continue;
        }
        checked.push(block.at.clone());
        let marked = block.text.lines().any(|line| line.trim() == REFUSED);
        match (load_example(&block.text), marked) {
            (Ok(()), true) => wrong.push(format!("{}: marked refused, but loads", block.at)),
            (Err(error), false) => {
                let error: String = error.chars().take(240).collect();
                wrong.push(format!("{}: {error}", block.at));
            }
            _ => {}
        }
    }
    (checked, wrong)
}

/// The files with extension `ext` in `dir`, and below it when `deep`, sorted.
#[cfg(unix)]
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
#[cfg(unix)]
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

/// Unix only: the docs' examples use Unix absolute paths (`/var/lib/...`),
/// which a Windows loader refuses for want of a drive; that is not a doc bug.
#[cfg(unix)]
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

/// A digest reference gets a value the key check accepts.
#[test]
fn a_digest_reference_gets_a_digest() {
    let text = "auth:\n  api_keys:\n    - name: a\n      key_sha256: env:DOCS_GUARD_A\n      \
                previous_key_sha256: \"env:DOCS_GUARD_B\"\n";
    let values = env_values(text);
    assert_eq!(values["DOCS_GUARD_A"], DIGEST);
    assert_eq!(values["DOCS_GUARD_B"], DIGEST);
    let hex = DIGEST.strip_prefix("sha256:").expect("prefix");
    assert!(
        hex.len() == 64
            && hex
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    );
    let key = "auth:\n  enabled: true\n  api_keys:\n    - name: a\n      key_sha256: env:DOCS_GUARD_A\n      \
               backends: [\"*\"]\n";
    load(key).expect_err("refused while the variable is unset");
    load_example(key).expect("loads with the digest placeholder");
}

/// A signing key reference gets a base64 32-byte seed.
#[test]
fn a_signing_key_reference_gets_a_seed() {
    use base64::Engine as _;
    let values =
        env_values("security:\n  signature_chain:\n    signing_key: \"${DOCS_GUARD_SEED}\"\n");
    assert_eq!(values["DOCS_GUARD_SEED"], SEED);
    let seed = base64::engine::general_purpose::STANDARD
        .decode(SEED)
        .expect("base64");
    assert_eq!(seed.len(), 32);
}

/// Any other reference gets the plain placeholder.
#[test]
fn any_other_reference_gets_the_placeholder() {
    let values = env_values(ENV_EXAMPLE);
    assert_eq!(values["DOCS_YAML_GUARD_FIXTURE_TOKEN"], PLACEHOLDER);
}

/// A block's own `env_files` gives way to the guard's file.
#[test]
fn an_examples_own_env_files_gives_way_to_the_guards() {
    let own =
        format!("env_files:\n  - ~/.config/nowhere/.env   # holds the token\n\n{ENV_EXAMPLE}");
    assert_eq!(without_env_files(&own), format!("\n{ENV_EXAMPLE}"));
    load(&own).expect_err("refused with the illustrative path");
    load_example(&own).expect("loads with the guard's env file");
}

/// A backend whose header names a variable no run sets.
const ENV_EXAMPLE: &str = "backends:\n  x:\n    http_url: \"https://mcp.example.com/mcp\"\n    \
     headers:\n      Authorization: \"Bearer ${DOCS_YAML_GUARD_FIXTURE_TOKEN}\"\n";

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
        block(
            "other-file",
            format!("{NOT_GATEWAY}\nserverr: {{}}\nbackends: {{}}\n"),
        ),
        block("env", ENV_EXAMPLE.into()),
    ];
    // The env example is refused as written, so only the guard's env file
    // can load it.
    assert!(
        load(ENV_EXAMPLE).is_err(),
        "the fixture variable must be unset"
    );
    let (checked, wrong) = misbehaving(&blocks, &mut BTreeMap::new());
    assert_eq!(
        checked,
        ["loads", "typo", "marked-loads", "marked-refused", "env"]
    );
    assert_eq!(wrong.len(), 2, "{wrong:?}");
    assert!(
        wrong[0].starts_with("typo: ") && wrong[0].contains("serverr"),
        "{wrong:?}"
    );
    assert_eq!(wrong[1], "marked-loads: marked refused, but loads");
}

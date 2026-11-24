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

#[path = "common/yaml.rs"]
mod yaml;

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use mcp_gateway::config::{Config, api_key_digest_spec};
use regex::Regex;

/// The line that marks a block showing a config the gateway refuses.
const REFUSED: &str = "# example: refused";

/// The line that marks a block that is some other file, never loaded.
const NOT_GATEWAY: &str = "# example: not gateway.yaml";

/// The form the loader checks a variable's value for, by the key it sits under.
/// The docs that use these are right as written.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Shape {
    /// `sha256:` and 64 lowercase hex characters (`key_sha256`).
    Digest,
    /// Standard base64 of a 32-byte seed (`signing_key`).
    Seed,
    /// Anything else: base64 of 32 bytes as well, so a key the operator names
    /// (an accounts `keys` entry) loads, and still an opaque token or secret.
    Plain,
}

impl Shape {
    fn of(key: &str) -> Self {
        match key {
            "key_sha256" | "previous_key_sha256" => Self::Digest,
            "signing_key" => Self::Seed,
            _ => Self::Plain,
        }
    }

    /// The value of a block's `n`th variable. No two are equal: the loader
    /// refuses two API keys with one principal (a digest's first 48 bits, so
    /// `n` leads it) and a secret reused as another.
    fn value(self, n: usize) -> String {
        use base64::Engine as _;
        let base64 = |text: String| base64::engine::general_purpose::STANDARD.encode(text);
        match self {
            Self::Digest => format!("sha256:{n:012x}{}", "ab".repeat(26)),
            Self::Seed => base64(format!("docs-example-signing-seed-{n:06}")),
            Self::Plain => base64(format!("docs-example-placeholder-{n:07}")),
        }
    }
}

/// One fenced block: the `file:line` of its opening fence, and its text.
#[derive(Debug, PartialEq)]
struct Block {
    at: String,
    text: String,
}

/// A fence: its character (`` ` `` or `~`), its length (three or more) and its
/// info string's first word.
fn fence(trimmed: &str) -> Option<(char, usize, &str)> {
    let ch = trimmed.chars().next().filter(|c| *c == '`' || *c == '~')?;
    let len = trimmed.chars().take_while(|c| *c == ch).count();
    let info = trimmed[len..].trim();
    (len >= 3 && !(ch == '`' && info.contains('`'))).then(|| {
        (
            ch,
            len,
            info.split([' ', '{', ',']).next().unwrap_or_default(),
        )
    })
}

/// One open block: its fence's line, indentation, character and length, and
/// whether it is yaml (other fences are followed only so a yaml fence inside
/// one is not taken for a block).
struct Open<'a> {
    start: usize,
    indent: usize,
    ch: char,
    len: usize,
    yaml: bool,
    body: Vec<&'a str>,
}

/// The fenced `yaml` blocks in `lines`, by CommonMark's fence rules: a run of
/// three or more `` ` `` or `~` opens one, the same character at least as long
/// closes it. Each entry is a line's content, or `None` for a line no block can
/// span (code between rustdoc lines), which drops a block left open. Up to the
/// fence's indentation in leading spaces is cut from each body line.
fn fenced(file: &str, lines: &[Option<&str>]) -> Vec<Block> {
    let mut blocks = Vec::new();
    let mut open: Option<Open<'_>> = None;
    for (i, line) in lines.iter().enumerate() {
        let Some(line) = *line else {
            open = None;
            continue;
        };
        let trimmed = line.trim_start();
        let found = fence(trimmed.trim_end());
        if let Some(mut block) = open.take() {
            let closes = found.is_some_and(|(ch, len, info)| {
                ch == block.ch && len >= block.len && info.is_empty()
            });
            if !closes {
                let cut = line.len() - line.trim_start_matches(' ').len();
                block.body.push(&line[cut.min(block.indent)..]);
                open = Some(block);
            } else if block.yaml {
                let mut text = block.body.join("\n");
                text.push('\n');
                blocks.push(Block {
                    at: format!("{file}:{}", block.start),
                    text,
                });
            }
        } else if let Some((ch, len, info)) = found {
            open = Some(Open {
                start: i + 1,
                indent: line.len() - trimmed.len(),
                ch,
                len,
                yaml: matches!(info.to_ascii_lowercase().as_str(), "yaml" | "yml"),
                body: Vec::new(),
            });
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

/// The keys a block sets at its top level, as the gateway's YAML reader sees
/// them (quoted keys and flow mappings included). A block it cannot read still
/// names its keys at column 0, so a broken gateway example is checked rather
/// than skipped.
fn top_keys(text: &str) -> Vec<String> {
    if let Ok(doc) = yaml::from_str::<yaml::Value>(text) {
        return doc
            .as_mapping()
            .map(|map| {
                map.keys()
                    .filter_map(|key| key.as_str().map(str::to_owned))
                    .collect()
            })
            .unwrap_or_default();
    }
    text.lines()
        .filter(|line| !line.starts_with([' ', '\t', '#', '-']))
        .filter_map(|line| line.split_once(':'))
        .map(|(key, _)| key.trim().trim_matches(['"', '\'']).to_owned())
        .filter(|key| !key.is_empty())
        .collect()
}

fn load(yaml: &str) -> mcp_gateway::Result<Config> {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("gateway.yaml");
    mcp_gateway::gateway::test_helpers::write_owner_only(&path, yaml).expect("write config");
    Config::load(Some(&path))
}

/// Each variable `text` names (`${NAME}`, with or without a default, and
/// `env:NAME`) with its value, shaped by the key on its first reference's line.
fn env_values(text: &str) -> BTreeMap<String, String> {
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
            let n = values.len();
            values
                .entry(var.as_str().to_owned())
                .or_insert_with(|| Shape::of(key).value(n));
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

/// The one file whose example's own `env_files` names an illustrative path
/// (under the reader's home), so the guard's file takes its place. Any other
/// example keeps its own `env_files`, which then decides the load.
const ILLUSTRATIVE_ENV_FILES: &str = "docs/OAUTH_CONFIG.md:";

/// Load the example at `at` as the gateway would, `Err` holding the refusal. A
/// block that names variables loads with an `env_files` entry defining each.
fn load_example(at: &str, yaml: &str) -> Result<(), String> {
    let values = env_values(yaml);
    let swap = at.starts_with(ILLUSTRATIVE_ENV_FILES);
    if values.is_empty() && !swap {
        return load(yaml).map(drop).map_err(|e| e.to_string());
    }
    let dir = tempfile::tempdir().expect("tempdir");
    let env = dir.path().join("example.env");
    let lines: String = values
        .iter()
        .map(|(var, value)| format!("{var}={value}\n"))
        .collect();
    mcp_gateway::gateway::test_helpers::write_owner_only(&env, &lines).expect("write env file");
    let body = if swap {
        without_env_files(yaml)
    } else {
        yaml.to_owned()
    };
    let yaml = format!("env_files: ['{}']\n{body}", env.display());
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
            .any(|key| gateway_key(&key, known))
        {
            continue;
        }
        checked.push(block.at.clone());
        let marked = block.text.lines().any(|line| line.trim() == REFUSED);
        match (load_example(&block.at, &block.text), marked) {
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
    // Each source the guard promises gives at least one checked example, so a
    // source that stopped being read cannot pass unnoticed.
    for source in ["README.md:", "docs/", "upgrading.d/", "src/config/"] {
        assert!(
            checked.iter().any(|at| at.starts_with(source)),
            "no example from {source} was checked"
        );
    }
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
    // Tilde and longer fences, an info string after the language, a body line
    // indented less than its fence (only spaces are cut), and a yaml fence
    // inside another block, which is that block's text.
    let md = "~~~yaml title=gateway.yaml\nserver: {}\n~~~\n  ````yml\n  a: 1\nb: 2\n  ```\n  ````\n\
              ```markdown\n```yaml\nnot: me\n```\n";
    let lines: Vec<Option<&str>> = md.lines().map(Some).collect();
    assert_eq!(
        fenced("c.md", &lines),
        [
            Block {
                at: "c.md:1".into(),
                text: "server: {}\n".into()
            },
            Block {
                at: "c.md:4".into(),
                text: "a: 1\nb: 2\n```\n".into()
            },
        ]
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
    let (a, b) = (&values["DOCS_GUARD_A"], &values["DOCS_GUARD_B"]);
    for digest in [a, b] {
        let hex = digest.strip_prefix("sha256:").expect("prefix");
        assert!(
            hex.len() == 64
                && hex
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
            "{digest}"
        );
    }
    // Two keys with one principal (the first 48 bits) are refused.
    assert_ne!(a[..7 + 12], b[..7 + 12]);
    let key = "auth:\n  enabled: true\n  api_keys:\n    - name: a\n      key_sha256: env:DOCS_GUARD_A\n      \
               backends: [\"*\"]\n";
    load(key).expect_err("refused while the variable is unset");
    load_example("docs/x.md:1", key).expect("loads with the digest placeholder");
}

/// A signing key reference gets a base64 32-byte seed.
#[test]
fn a_signing_key_reference_gets_a_seed() {
    use base64::Engine as _;
    let values =
        env_values("security:\n  signature_chain:\n    signing_key: \"${DOCS_GUARD_SEED}\"\n");
    let seed = base64::engine::general_purpose::STANDARD
        .decode(&values["DOCS_GUARD_SEED"])
        .expect("base64");
    assert_eq!(seed.len(), 32);
}

/// Any other reference gets a 32-byte base64 value, a different one for each
/// variable, so a secret never equals another (the loader refuses reuse).
#[test]
fn any_other_reference_gets_its_own_placeholder() {
    use base64::Engine as _;
    let values = env_values("a: ${DOCS_GUARD_P}\nb: env:DOCS_GUARD_Q\nc: ${DOCS_GUARD_P}\n");
    assert_eq!(values.len(), 2);
    assert_ne!(values["DOCS_GUARD_P"], values["DOCS_GUARD_Q"]);
    for value in values.values() {
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(value)
            .expect("base64");
        assert_eq!(bytes.len(), 32, "{value}");
    }
}

/// The OAUTH_CONFIG example's own `env_files` gives way to the guard's file;
/// any other file's example keeps its own, which then decides the load.
#[test]
fn only_the_named_examples_env_files_gives_way_to_the_guards() {
    let own =
        format!("env_files:\n  - ~/.config/nowhere/.env   # holds the token\n\n{ENV_EXAMPLE}");
    assert_eq!(without_env_files(&own), format!("\n{ENV_EXAMPLE}"));
    load(&own).expect_err("refused with the illustrative path");
    load_example("docs/OAUTH_CONFIG.md:163", &own).expect("loads with the guard's env file");
    load_example("docs/OTHER.md:1", &own).expect_err("keeps its own env_files and is refused");
}

/// Placeholder words a documented digest must not be the SHA-256 of: an
/// example carrying one would accept that word as a key wherever it is copied.
const COMMON_WORDS: &[&str] = &[
    "", "foo", "bar", "baz", "test", "secret", "password", "admin", "example", "key", "token",
    "api-key", "apikey", "mysecret", "hello", "changeme", "letmein", "demo", "sample", "default",
    "qwerty", "123456", "root", "user",
];

/// Each 64-hex value in `text` that is the SHA-256 of a [`COMMON_WORDS`] word,
/// with the word.
fn common_preimages(text: &str) -> Vec<(String, &'static str)> {
    let known: BTreeMap<String, &'static str> = COMMON_WORDS
        .iter()
        .map(|word| {
            let digest = api_key_digest_spec(word.as_bytes());
            let hex = digest.strip_prefix("sha256:").expect("sha256: form");
            (hex.to_owned(), *word)
        })
        .collect();
    let hex = Regex::new(r"[0-9a-fA-F]{64}").expect("regex");
    hex.find_iter(text)
        .filter_map(|m| {
            let found = m.as_str().to_ascii_lowercase();
            known.get(&found).map(|word| (found, *word))
        })
        .collect()
}

/// No documented example carries a digest anyone can reverse: the digest of
/// "foo" once sat in three of them as an API key's `key_sha256`.
#[test]
fn no_documented_digest_is_the_hash_of_a_common_word() {
    let planted = format!("key_sha256: \"{}\"\n", api_key_digest_spec(b"foo"));
    assert_eq!(
        common_preimages(&planted)
            .iter()
            .map(|(_, word)| *word)
            .collect::<Vec<_>>(),
        ["foo"],
        "the planted digest must be caught"
    );
    let found: Vec<String> = shipped_blocks(Path::new(env!("CARGO_MANIFEST_DIR")))
        .iter()
        .flat_map(|block| {
            common_preimages(&block.text)
                .into_iter()
                .map(|(hex, word)| format!("{}: {hex} is the SHA-256 of {word:?}", block.at))
        })
        .collect();
    assert!(found.is_empty(), "{}", found.join("\n"));
}

/// Top-level keys as the reader sees them: quoted and flow-style keys count,
/// and a block that does not parse still names its column-0 keys.
#[test]
fn top_level_keys_follow_the_yaml_reader() {
    assert_eq!(
        top_keys("'backends': {}\n\"server\": {}\n"),
        ["backends", "server"]
    );
    assert_eq!(
        top_keys("{backends: {}, server: {}}\n"),
        ["backends", "server"]
    );
    assert_eq!(
        top_keys("backends:\n  x: [\nserver: {}\n"),
        ["backends", "server"]
    );
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

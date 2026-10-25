// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8425 MIG.1a: the YAML adapter (`src/yaml/`) reads and writes as the
//! replaced backend (`serde_yaml` and figment's provider) did, recorded in
//! `adapter.txt`, and no file bypasses it.
//!
//! T1 to T3 and T5 of the MIG.1a test plan
//! (`docs/internal/plans/2026-10-18-mik-8425-mig1a-adapter.md`).

#[path = "common/yaml.rs"]
mod yaml;

#[path = "common/mik_8425_golden.rs"]
mod golden;

use std::collections::BTreeMap;
use std::fmt::Write as _;

/// T1: a stream yields every document and ends at its first refusal.
/// MIK-8639: the guard refuses the stream as a whole, so a refused stream
/// yields exactly one refusal and no document.
#[test]
fn documents_stops_at_the_first_refusal() {
    let read: Vec<bool> = yaml::documents("a: 1\n---\nb: [1, 2\n")
        .map(|d| d.is_ok())
        .collect();
    assert_eq!(read, [false], "one refusal, nothing yielded");

    // Joined, not terminated: a trailing `---` would start a 301st, empty
    // document.
    let many = vec!["a: 1"; 300].join("\n---\n");
    let read = yaml::documents(&many).collect::<Vec<_>>();
    assert_eq!(
        read.len(),
        300,
        "no document cap: every valid document is read"
    );
    assert!(read.iter().all(Result::is_ok));

    let late = format!("{}b: [1, 2\n", "a: 1\n---\n".repeat(260));
    let read = yaml::documents(&late).collect::<Vec<_>>();
    assert_eq!(read.len(), 1, "one refusal, nothing yielded");
    let err = read[0].as_ref().unwrap_err();
    assert_eq!(
        err.limit(),
        Some(&yaml::Limit::Syntax {
            line: 521,
            column: 4
        })
    );
    assert_eq!(
        err.to_string(),
        "YAML refused: unclosed bracket at line 521 column 4"
    );
}

/// T2: the duplicate-key rule per destination, on the adapter's own paths.
#[test]
fn from_str_loose_keeps_the_last_repeated_key() {
    let dict = yaml::from_str_loose("a: 1\na: 2\n").expect("a Dict keeps the last value");
    assert_eq!(
        serde_json::to_value(&dict).expect("a Dict serializes"),
        serde_json::json!({"a": 2})
    );
}

#[test]
fn from_str_refuses_a_repeated_key_in_a_tree() {
    assert!(yaml::from_str::<yaml::Value>("a: 1\na: 2\n").is_err());
}

/// The MIG.0 behaviour inputs: duplicates, merge keys, scalars, documents,
/// limits and both enum forms.
const BEHAVIOUR_INPUTS: &[&str] = &[
    "a: 1\na: 2\n",
    "m:\n  a: 1\n  a: 2\n",
    "b: &b {x: 1}\nm:\n  <<: *b\n  y: 2\n",
    "m:\n  !!merge <<: {x: 1}\n",
    "v: yes\n",
    "v: 0755\n",
    "v: .inf\n",
    "v: ~\n",
    "v: '0755'\n",
    "",
    "---\na: 1\n",
    "a: 1\n---\nb: 2\n",
    "agent: !exact runner\n",
    "agent: {exact: runner}\n",
    "x: [1, 2\n",
];

fn tree_or_refusal(r: Result<yaml::Value, impl std::fmt::Display>) -> String {
    r.map_or_else(|e| format!("ERR {e}"), |v| format!("OK {v:?}"))
}

/// T3, limits: the nesting depth and alias-expansion refusal points recorded
/// in MIG.0 (`behaviour.txt`) hold through the adapter.
/// MIK-8639: depth 129 is refused by the guard now, with the guard's text.
#[test]
fn adapter_keeps_the_recorded_refusal_points() {
    let nested = |depth: usize| format!("{}{}", "[".repeat(depth), "]".repeat(depth));
    let fanout = |levels: usize| {
        let mut doc = String::from("l0: &l0 [x, x, x, x, x, x, x, x, x, x]\n");
        for level in 1..=levels {
            let items = [format!("*l{}", level - 1).as_str(); 10].join(", ");
            let _ = writeln!(doc, "l{level}: &l{level} [{items}]");
        }
        doc
    };
    assert_eq!(
        tree_or_refusal(yaml::from_str::<yaml::Value>(&nested(129))),
        "ERR YAML refused: nesting deeper than 128 levels at line 1"
    );
    for (doc, refused) in [(nested(128), false), (fanout(3), false), (fanout(4), true)] {
        assert_eq!(yaml::from_str::<yaml::Value>(&doc).is_err(), refused);
    }
}

#[derive(Debug, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
enum Shape {
    Unit,
    Newtype(String),
    Pair { x: u8, y: u8 },
}

/// The inputs of `figment_data_matches_the_yaml_provider`.
const FIGMENT_INPUTS: &[&str] = &[
    "server:\n  port: 39400\n",
    "server:\n  port: 1\nserver:\n  port: 2\n",
    "server: \"unterminated\n",
    "a: [1, 2\n",
    "- not\n- a map\n",
    "default:\n  port: 39400\nglobal:\n  log: info\n",
    "",
];

/// A tree as its structure text (kinds, tags, key types), or the refusal.
fn structure_or_refusal(r: Result<yaml::Value, impl std::fmt::Display>) -> String {
    r.map_or_else(
        |e| format!("ERR {e}"),
        |v| format!("OK {}", golden::yaml_structure(&v)),
    )
}

/// Every reading this suite's `serde_yaml` and figment comparisons made,
/// through the adapter alone. Recorded while the adapter still delegated to
/// them (those comparisons proved it read the same), it keeps them checkable
/// now MIK-8425 MIG.2 has removed `serde_yaml` from the build.
fn adapter_report() -> String {
    let mut out = String::new();
    let mut row = |case: String, reading: String| {
        let _ = writeln!(out, "{case}\t{}", golden::one_line(&reading));
    };
    for text in BEHAVIOUR_INPUTS {
        row(
            format!("tree {text:?}"),
            structure_or_refusal(yaml::from_str::<yaml::Value>(text)),
        );
        row(
            format!("dict {text:?}"),
            format!(
                "{:?}",
                yaml::from_str_loose(text).map_err(|e| e.to_string())
            ),
        );
        let stream: Vec<String> = yaml::documents(text).map(structure_or_refusal).collect();
        row(format!("stream {text:?}"), stream.join(" ; "));
        row(
            format!("typed {text:?}"),
            format!(
                "{:?}",
                yaml::from_str::<BTreeMap<String, String>>(text).map_err(|e| e.to_string())
            ),
        );
    }
    for text in FIGMENT_INPUTS {
        row(
            format!("figment {text:?}"),
            format!(
                "{:?}",
                yaml::figment_data(text).map_err(|e| (e.kind.to_string(), e.to_string()))
            ),
        );
    }
    let nested = |depth: usize| format!("{}{}", "[".repeat(depth), "]".repeat(depth));
    let fanout = |levels: usize| {
        let mut doc = String::from("l0: &l0 [x, x, x, x, x, x, x, x, x, x]\n");
        for level in 1..=levels {
            let items = [format!("*l{}", level - 1).as_str(); 10].join(", ");
            let _ = writeln!(doc, "l{level}: &l{level} [{items}]");
        }
        doc
    };
    for (case, doc) in [
        ("limit nested 128", nested(128)),
        ("limit nested 129", nested(129)),
        ("limit fanout 3", fanout(3)),
        ("limit fanout 4", fanout(4)),
    ] {
        row(
            case.to_owned(),
            structure_or_refusal(yaml::from_str::<yaml::Value>(&doc)),
        );
    }
    for doc in [
        "unit",
        "!newtype hi",
        "{newtype: hi}",
        "!pair {x: 1, y: 2}",
        "{pair: {x: 1, y: 2}}",
    ] {
        row(
            format!("enum {doc:?}"),
            format!(
                "{:?}",
                yaml::from_str::<Shape>(doc).map_err(|e| e.to_string())
            ),
        );
    }
    let shapes = vec![
        Shape::Unit,
        Shape::Newtype("hi".into()),
        Shape::Pair { x: 1, y: 2 },
    ];
    row(
        "write to_string".to_owned(),
        format!("{:?}", yaml::to_string(&shapes).map_err(|e| e.to_string())),
    );
    row(
        "write to_value".to_owned(),
        structure_or_refusal(yaml::to_value(&shapes)),
    );
    row(
        "from_value no_such_variant".to_owned(),
        format!(
            "{:?}",
            yaml::from_value::<Shape>(yaml::Value::String("no_such_variant".to_owned()))
                .map_err(|e| e.to_string())
        ),
    );
    out
}

/// The adapter reads every comparison case as recorded in `adapter.txt`.
#[test]
fn adapter_reads_as_recorded() {
    golden::assert_golden("adapter.txt", &adapter_report());
}

/// Prints the golden for review; never part of a normal run.
#[test]
#[ignore = "records tests/fixtures/mik_8425_yaml/adapter.txt; run with --ignored --nocapture"]
fn record_adapter_golden() {
    print!(
        "----- BEGIN adapter.txt -----\n{}----- END adapter.txt -----\n",
        adapter_report()
    );
}

/// `true` when `word` occurs in `text` as a whole identifier.
fn has_ident(text: &str, word: &str) -> bool {
    let is_ident = |c: char| c.is_ascii_alphanumeric() || c == '_';
    text.match_indices(word).any(|(at, _)| {
        let before = text[..at].chars().next_back();
        let after = text[at + word.len()..].chars().next();
        !before.is_some_and(is_ident) && !after.is_some_and(is_ident)
    })
}

/// Whether a source file names a YAML parser directly: `serde_yaml`, a
/// `providers::Yaml` path, or any `use` declaration (read from `use` to its
/// `;`) naming both `figment` and `Yaml`, which covers grouped, absolute,
/// nested and multi-line imports.
///
/// Known limit, accepted: a module alias (`use figment::providers as p;`
/// then `p::Yaml`) is not seen. This is a lexical guard against accidental
/// bypass, not a proof; review catches a deliberate one.
fn names_a_parser(text: &str) -> bool {
    let figment_import = text
        .match_indices("use")
        .filter(|(at, _)| {
            let ends_word = !text[*at + 3..]
                .chars()
                .next()
                .is_some_and(|c| c.is_ascii_alphanumeric() || c == '_');
            is_word_start(text, *at) && ends_word
        })
        .any(|(at, _)| {
            let end = text[at..].find(';').map_or(text.len(), |e| at + e);
            let stmt = &text[at..end];
            has_ident(stmt, "figment") && has_ident(stmt, "Yaml")
        });
    has_ident(text, "serde_yaml") || has_ident(text, "providers::Yaml") || figment_import
}

/// `true` when the character before `at` cannot continue an identifier.
fn is_word_start(text: &str, at: usize) -> bool {
    !text[..at]
        .chars()
        .next_back()
        .is_some_and(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// Every `.rs` file under `src/` and `tests/` of `root` that names a parser,
/// as sorted root-relative paths with `/`. No file is exempt by its name.
fn direct_users(root: &std::path::Path) -> Vec<String> {
    files_naming(root, names_a_parser)
}

/// The replacement backend's crate name, assembled so that this file, which
/// scans for it, does not name it itself.
const NEW_BACKEND: &str = concat!("granit", "_parser");

/// MIK-8425 MIG.2: the backend's parser may be named only inside the adapter.
/// A fixed rule, not an allowlist file, so a new user cannot be recorded
/// into it.
fn may_name_the_new_backend(path: &str) -> bool {
    path.starts_with("src/yaml/")
}

fn new_backend_bypasses(root: &std::path::Path) -> Vec<String> {
    files_naming(root, |text| has_ident(text, NEW_BACKEND))
        .into_iter()
        .filter(|path| !may_name_the_new_backend(path))
        .collect()
}

/// Every `.rs` file under `src/` and `tests/` of `root` whose text `names`,
/// as sorted root-relative paths with `/`.
fn files_naming(root: &std::path::Path, names: impl Fn(&str) -> bool) -> Vec<String> {
    let mut found: Vec<String> = ["src", "tests"]
        .iter()
        .flat_map(|dir| {
            walkdir::WalkDir::new(root.join(dir))
                .into_iter()
                .filter_map(Result::ok)
        })
        .filter(|e| e.file_type().is_file() && e.path().extension().is_some_and(|x| x == "rs"))
        .filter(|e| std::fs::read_to_string(e.path()).is_ok_and(|t| names(&t)))
        .map(|e| {
            e.path()
                .strip_prefix(root)
                .expect("walked path is under the root")
                .components()
                .map(|c| c.as_os_str().to_string_lossy().into_owned())
                .collect::<Vec<_>>()
                .join("/")
        })
        .collect();
    found.sort();
    found
}

fn repo_root() -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

const ALLOWLIST: &str = "tests/fixtures/mik_8425_yaml/direct_users.txt";

/// The files that may still name a parser directly. Each MIG.1 PR removes
/// the files it routes through the adapter; MIG.2 leaves only `src/yaml/`.
fn allowlist() -> std::collections::BTreeSet<String> {
    std::fs::read_to_string(repo_root().join(ALLOWLIST))
        .expect("allowlist")
        .lines()
        .filter(|l| !l.is_empty())
        .map(|line| {
            line.split_once(" # ")
                .map_or(line, |(path, _)| path)
                .trim()
                .to_owned()
        })
        .collect()
}

/// T5: no file outside the allowlist names a YAML parser directly.
#[test]
fn no_new_file_names_a_yaml_parser_directly() {
    let allowed = allowlist();
    let new: Vec<String> = direct_users(&repo_root())
        .into_iter()
        .filter(|p| !allowed.contains(p))
        .collect();
    assert!(
        new.is_empty(),
        "these files name serde_yaml or figment's Yaml provider directly; route them \
         through src/yaml/ (or tests/common/yaml.rs) instead: {new:?}"
    );
}

/// T5's negative control: the same scan, on a synthetic tree, flags an
/// unlisted file for each way of naming a parser, and nothing else.
#[test]
fn the_bypass_scan_flags_each_way_of_naming_a_parser() {
    let root = tempfile::tempdir().expect("tempdir");
    let files = [
        (
            "src/direct.rs",
            "fn f() { let _ = serde_yaml::from_str::<u8>(\"1\"); }\n",
        ),
        (
            "src/imported.rs",
            "use figment::providers::{Format, Yaml};\n",
        ),
        (
            "src/pathed.rs",
            "fn f() { figment::providers::Yaml::string(\"\"); }\n",
        ),
        (
            "src/nested.rs",
            "use figment::{providers::Yaml, Provider};\n",
        ),
        (
            "src/multiline.rs",
            "use figment::{\n    providers::{Env, Format,\n        Yaml},\n    Figment,\n};\n",
        ),
        (
            "src/grouped.rs",
            "use {figment::providers::{Format, Yaml}};\n",
        ),
        (
            "src/absolute.rs",
            "use ::figment::providers::{Format, Yaml};\n",
        ),
        ("tests/x_tests.rs", "use serde_yaml::Value;\n"),
        (
            "src/clean.rs",
            "fn f() -> &'static str { \"serde_yaml_like\" }\n",
        ),
        (
            "src/other.rs",
            "use figment::providers::Env;\nstruct Yaml;\n",
        ),
    ];
    for (rel, text) in files {
        let path = root.path().join(rel);
        std::fs::create_dir_all(path.parent().expect("parent")).expect("mkdir");
        std::fs::write(path, text).expect("write");
    }
    assert_eq!(
        direct_users(root.path()),
        [
            "src/absolute.rs",
            "src/direct.rs",
            "src/grouped.rs",
            "src/imported.rs",
            "src/multiline.rs",
            "src/nested.rs",
            "src/pathed.rs",
            "tests/x_tests.rs"
        ]
    );
}

/// MIK-8425 MIG.2: outside `src/yaml/` and the parity suite, no file names
/// the replacement backend.
#[test]
fn only_the_adapter_names_the_new_backend() {
    let bypasses = new_backend_bypasses(&repo_root());
    assert!(
        bypasses.is_empty(),
        "these files name {NEW_BACKEND} directly; route them through src/yaml/: {bypasses:?}"
    );
}

/// The parser scan's negative control: on a synthetic tree it flags a use
/// outside the adapter, in `src/` and in `tests/` (the parity suite
/// included), and nothing else.
#[test]
fn the_new_backend_scan_flags_a_use_outside_the_adapter() {
    let root = tempfile::tempdir().expect("tempdir");
    let files = [
        ("src/yaml/tree.rs", format!("use {NEW_BACKEND}::Parser;\n")),
        (
            "tests/mik_8425_mig2_parity.rs",
            format!("// drives {NEW_BACKEND} directly\n"),
        ),
        (
            "src/config/load.rs",
            format!("use {NEW_BACKEND}::Parser;\n"),
        ),
        (
            "tests/other.rs",
            format!("fn f() {{ let _ = {NEW_BACKEND}::Parser::new_from_str(\"\"); }}\n"),
        ),
        (
            "src/yaml_like.rs",
            format!("// {NEW_BACKEND}_like is not the crate\n"),
        ),
        ("src/clean.rs", "fn f() {}\n".to_owned()),
    ];
    for (rel, text) in files {
        let path = root.path().join(rel);
        std::fs::create_dir_all(path.parent().expect("parent")).expect("mkdir");
        std::fs::write(path, text).expect("write");
    }
    assert_eq!(
        new_backend_bypasses(root.path()),
        [
            "src/config/load.rs",
            "tests/mik_8425_mig2_parity.rs",
            "tests/other.rs"
        ]
    );
}

/// Prints the allowlist for review; never part of a normal run.
#[test]
#[ignore = "records tests/fixtures/mik_8425_yaml/direct_users.txt; run with --ignored --nocapture"]
fn record_direct_users() {
    print!(
        "----- BEGIN direct_users.txt -----\n{}\n----- END direct_users.txt -----\n",
        direct_users(&repo_root()).join("\n")
    );
}

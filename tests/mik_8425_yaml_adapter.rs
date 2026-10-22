// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8425 MIG.1a: the YAML adapter (`src/yaml.rs`) behaves exactly as
//! `serde_yaml` and figment do today, and no new file bypasses it.
//!
//! T1 to T3 and T5 of the MIG.1a test plan
//! (`docs/internal/plans/2026-10-18-mik-8425-mig1a-adapter.md`).

#[path = "common/yaml.rs"]
mod yaml;

use std::collections::BTreeMap;
use std::fmt::Write as _;

use figment::Provider as _;
use figment::providers::{Format as _, Yaml};

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
    // document, in serde_yaml as here.
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

/// T2b: the config loader's provider call, through the adapter, is
/// identical to figment's own: profiles and values, or kind and message.
/// MIK-8639: inputs the guard refuses carry the guard refusal instead.
#[test]
fn figment_data_matches_the_yaml_provider() {
    let cases = [
        "server:\n  port: 39400\n",
        "server:\n  port: 1\nserver:\n  port: 2\n",
        "server: \"unterminated\n",
        "a: [1, 2\n",
        "- not\n- a map\n",
        "default:\n  port: 39400\nglobal:\n  log: info\n",
        "",
    ];
    for text in cases {
        // The guard refuses these two before figment's provider runs.
        if text == "a: [1, 2\n" {
            let err = yaml::figment_data(text).unwrap_err();
            assert_eq!(
                err.to_string(),
                "YAML refused: unclosed bracket at line 1 column 4",
                "guard refusal for {text:?}"
            );
            continue;
        }
        if text == "server: \"unterminated\n" {
            let err = yaml::figment_data(text).unwrap_err();
            assert!(
                err.to_string().starts_with("YAML refused: "),
                "guard refusal for {text:?}, got: {err}"
            );
            continue;
        }
        let ours = yaml::figment_data(text);
        let theirs = Yaml::string(text).data();
        match (ours, theirs) {
            (Ok(a), Ok(b)) => assert_eq!(a, b, "same profiles and values for {text:?}"),
            (Err(a), Err(b)) => {
                assert_eq!(
                    a.kind.to_string(),
                    b.kind.to_string(),
                    "same kind for {text:?}"
                );
                assert_eq!(a.to_string(), b.to_string(), "same message for {text:?}");
            }
            (a, b) => panic!(
                "{text:?}: adapter {:?} vs provider {:?}",
                a.is_ok(),
                b.is_ok()
            ),
        }
    }
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

/// T3: on every recorded behaviour input the adapter reads what `serde_yaml`
/// reads, as a tree, as a `Dict`, as a stream and as a typed map.
/// MIK-8639: the input the guard refuses carries the guard refusal instead.
#[test]
fn adapter_reads_like_serde_yaml_on_the_behaviour_cases() {
    for text in BEHAVIOUR_INPUTS {
        // The guard refuses the unclosed flow sequence on every reading.
        if *text == "x: [1, 2\n" {
            let refused = "YAML refused: unclosed bracket at line 1 column 4";
            assert_eq!(
                tree_or_refusal(yaml::from_str::<yaml::Value>(text)),
                format!("ERR {refused}"),
                "tree reading of {text:?}"
            );
            assert_eq!(
                format!(
                    "{:?}",
                    yaml::from_str_loose(text).map_err(|e| e.to_string())
                ),
                format!("Err({refused:?})"),
                "Dict reading of {text:?}"
            );
            let ours: Vec<String> = yaml::documents(text).map(tree_or_refusal).collect();
            assert_eq!(
                ours,
                [format!("ERR {refused}")],
                "stream reading of {text:?}"
            );
            assert_eq!(
                format!(
                    "{:?}",
                    yaml::from_str::<BTreeMap<String, String>>(text).map_err(|e| e.to_string())
                ),
                format!("Err({refused:?})"),
                "typed reading of {text:?}"
            );
            continue;
        }
        assert_eq!(
            tree_or_refusal(yaml::from_str::<yaml::Value>(text)),
            tree_or_refusal(
                serde_yaml::from_str::<serde_yaml::Value>(text)
                    .map_err(|e| yaml::redact_message(&e.to_string()))
            ),
            "tree reading of {text:?}"
        );
        assert_eq!(
            format!(
                "{:?}",
                yaml::from_str_loose(text).map_err(|e| e.to_string())
            ),
            format!(
                "{:?}",
                Yaml::from_str::<figment::value::Dict>(text).map_err(|e| e.to_string())
            ),
            "Dict reading of {text:?}"
        );
        let ours: Vec<String> = yaml::documents(text).map(tree_or_refusal).collect();
        let mut theirs = Vec::new();
        for document in serde_yaml::Deserializer::from_str(text) {
            let reading = tree_or_refusal(
                <serde_yaml::Value as serde::Deserialize>::deserialize(document)
                    .map_err(|e| yaml::redact_message(&e.to_string())),
            );
            let refused = reading.starts_with("ERR");
            theirs.push(reading);
            if refused {
                break;
            }
        }
        assert_eq!(ours, theirs, "stream reading of {text:?}");
        assert_eq!(
            format!(
                "{:?}",
                yaml::from_str::<BTreeMap<String, String>>(text).map_err(|e| e.to_string())
            ),
            format!(
                "{:?}",
                serde_yaml::from_str::<BTreeMap<String, String>>(text)
                    .map_err(|e| yaml::redact_message(&e.to_string()))
            ),
            "typed reading of {text:?}"
        );
    }
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
        assert_eq!(
            tree_or_refusal(yaml::from_str::<yaml::Value>(&doc)),
            tree_or_refusal(serde_yaml::from_str::<serde_yaml::Value>(&doc))
        );
    }
}

#[derive(Debug, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
enum Shape {
    Unit,
    Newtype(String),
    Pair { x: u8, y: u8 },
}

/// T3, enums and the write side: typed enums read, and `to_string`,
/// `to_value` and `from_value` give exactly what `serde_yaml` gives.
#[test]
fn adapter_writes_and_converts_like_serde_yaml() {
    for doc in [
        "unit",
        "!newtype hi",
        "{newtype: hi}",
        "!pair {x: 1, y: 2}",
        "{pair: {x: 1, y: 2}}",
    ] {
        assert_eq!(
            format!(
                "{:?}",
                yaml::from_str::<Shape>(doc).map_err(|e| e.to_string())
            ),
            format!(
                "{:?}",
                serde_yaml::from_str::<Shape>(doc).map_err(|e| e.to_string())
            ),
            "typed enum reading of {doc:?}"
        );
    }
    let shapes = vec![
        Shape::Unit,
        Shape::Newtype("hi".into()),
        Shape::Pair { x: 1, y: 2 },
    ];
    assert_eq!(
        yaml::to_string(&shapes).expect("serialises"),
        serde_yaml::to_string(&shapes).expect("serialises")
    );
    let value = yaml::to_value(&shapes).expect("to a tree");
    assert_eq!(value, serde_yaml::to_value(&shapes).expect("to a tree"));
    let back: Vec<Shape> = yaml::from_value(value).expect("from a tree");
    assert_eq!(back, shapes);
    let bad = serde_yaml::Value::String("no_such_variant".to_owned());
    assert_eq!(
        yaml::from_value::<Shape>(bad.clone()).map_err(|e| e.to_string()),
        serde_yaml::from_value::<Shape>(bad).map_err(|e| yaml::redact_message(&e.to_string())),
        "from_value refuses exactly as serde_yaml does"
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
    let mut found: Vec<String> = ["src", "tests"]
        .iter()
        .flat_map(|dir| {
            walkdir::WalkDir::new(root.join(dir))
                .into_iter()
                .filter_map(Result::ok)
        })
        .filter(|e| e.file_type().is_file() && e.path().extension().is_some_and(|x| x == "rs"))
        .filter(|e| std::fs::read_to_string(e.path()).is_ok_and(|t| names_a_parser(&t)))
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
/// the files it routes through the adapter; MIG.2 leaves only `src/yaml.rs`.
fn allowlist() -> std::collections::BTreeSet<String> {
    std::fs::read_to_string(repo_root().join(ALLOWLIST))
        .expect("allowlist")
        .lines()
        .filter(|l| !l.is_empty())
        .map(str::to_owned)
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
         through src/yaml.rs (or tests/common/yaml.rs) instead: {new:?}"
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

/// Prints the allowlist for review; never part of a normal run.
#[test]
#[ignore = "records tests/fixtures/mik_8425_yaml/direct_users.txt; run with --ignored --nocapture"]
fn record_direct_users() {
    print!(
        "----- BEGIN direct_users.txt -----\n{}\n----- END direct_users.txt -----\n",
        direct_users(&repo_root()).join("\n")
    );
}

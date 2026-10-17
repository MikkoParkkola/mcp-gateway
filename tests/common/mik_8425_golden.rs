// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8425 MIG.0 golden comparison shared by the `mik_8425_yaml_baseline_*`
//! tests.
//!
//! A golden is a text report recorded with serde_yaml 0.9.34, the parser
//! being replaced. Each later stage (adapter, backend swap) must reproduce
//! it. A test only compares; recording is a separate `#[ignore]`d
//! `record_*` test that prints the report for a reviewer to commit under
//! `tests/fixtures/mik_8425_yaml/`. Nothing here writes a golden, so no
//! setting can turn a mismatch into a pass.
#![allow(dead_code)]

use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

/// The repository root, from which every golden and input path is relative.
pub fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

/// `sha256:<hex>` of `bytes`: a fixed-width stand-in for a value too long to
/// keep in a golden line.
pub fn digest(bytes: &[u8]) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
}

/// A YAML tree written out with every node's kind, every tag and every
/// mapping key's type, in document order. JSON cannot carry this: a tagged
/// node and a one-key map serialize alike there, and so do `1` and `"1"` as
/// keys. The replacement parser's tree must produce the same text.
pub fn yaml_structure(value: &serde_yaml::Value) -> String {
    let mut out = String::new();
    write_structure(value, &mut out);
    out
}

fn write_structure(value: &serde_yaml::Value, out: &mut String) {
    use serde_yaml::Value;
    match value {
        Value::Null => out.push('~'),
        Value::Bool(b) => out.push_str(&format!("b:{b}")),
        Value::Number(n) => out.push_str(&format!("n:{n}")),
        Value::String(s) => out.push_str(&format!("s:{s:?}")),
        Value::Sequence(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_structure(item, out);
            }
            out.push(']');
        }
        Value::Mapping(map) => {
            out.push('{');
            for (i, (key, item)) in map.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_structure(key, out);
                out.push_str("=>");
                write_structure(item, out);
            }
            out.push('}');
        }
        Value::Tagged(tagged) => {
            out.push_str(&format!("t:{}(", tagged.tag));
            write_structure(&tagged.value, out);
            out.push(')');
        }
    }
}

/// One error line, never more: a golden row stays one row.
pub fn one_line(message: &str) -> String {
    message.replace('\n', " | ")
}

/// `sha256:<hex>` of `value` as JSON with every object's keys sorted.
/// Definitions hold `HashMap` fields, whose serialization order changes from
/// run to run; sorting keys makes the digest a function of content only.
/// Array order is kept, because it carries meaning.
pub fn canonical_digest<T: serde::Serialize>(value: &T) -> Result<String, serde_json::Error> {
    let tree = serde_json::to_value(value)?;
    let mut out = String::new();
    write_canonical(&tree, &mut out);
    Ok(digest(out.as_bytes()))
}

fn write_canonical(value: &serde_json::Value, out: &mut String) {
    match value {
        serde_json::Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            out.push('{');
            for (i, key) in keys.into_iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                out.push_str(&serde_json::Value::String(key.clone()).to_string());
                out.push(':');
                write_canonical(&map[key], out);
            }
            out.push('}');
        }
        serde_json::Value::Array(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_canonical(item, out);
            }
            out.push(']');
        }
        scalar => out.push_str(&scalar.to_string()),
    }
}

/// Fail unless `actual` equals the golden at `name`, printing `actual` in full.
pub fn assert_golden(name: &str, actual: &str) {
    let expected = read_golden(name);
    if expected != actual {
        let first = expected
            .lines()
            .zip(actual.lines())
            .position(|(e, a)| e != a)
            .map_or_else(|| "a line count".to_owned(), |i| format!("line {}", i + 1));
        panic!(
            "golden {name} differs at {first}; actual report:\n\
             ----- BEGIN {name} -----\n{actual}----- END {name} -----"
        );
    }
}

/// A golden keyed by input file: each row is `path \t sha256-of-file \t
/// readings`. A row whose file is gone or whose bytes changed since the
/// recording is skipped rather than failed, so another lane editing a
/// capability does not break this test. The readings of every unchanged file
/// must match. `read` gives the readings for one file's text.
///
/// Fails when fewer than `min_compared` rows could be compared: a golden
/// that has gone stale wholesale must be re-recorded (on the last commit
/// that still has the old parser), not silently skipped.
pub fn assert_keyed_golden(name: &str, min_compared: usize, read: impl Fn(&str) -> String) {
    let golden = read_golden(name);
    let mut compared = 0usize;
    let mut skipped = Vec::new();
    let mut differ = Vec::new();
    for row in golden.lines() {
        let mut cols = row.splitn(3, '\t');
        let (Some(path), Some(content), Some(expected)) = (cols.next(), cols.next(), cols.next())
        else {
            panic!("golden {name}: malformed row {row:?}");
        };
        let Ok(text) = std::fs::read_to_string(repo_root().join(path)) else {
            skipped.push(format!("{path} (gone)"));
            continue;
        };
        if digest(text.as_bytes()) != content {
            skipped.push(format!("{path} (edited since recording)"));
            continue;
        }
        compared += 1;
        let actual = read(&text);
        if actual != expected {
            differ.push(format!(
                "{path}\n  recorded: {expected}\n  now:      {actual}"
            ));
        }
    }
    if !skipped.is_empty() {
        eprintln!(
            "golden {name}: {} row(s) skipped: {skipped:?}",
            skipped.len()
        );
    }
    assert!(
        differ.is_empty(),
        "golden {name}: {} file(s) read differently from the recording:\n{}",
        differ.len(),
        differ.join("\n")
    );
    assert!(
        compared >= min_compared,
        "golden {name}: only {compared} row(s) comparable (need {min_compared}); \
         re-record it on a commit that still has serde_yaml"
    );
}

/// The rows of a keyed golden for `paths`, for the `record_*` tests to print.
pub fn keyed_rows(paths: &[String], read: impl Fn(&str) -> String) -> String {
    let mut out = String::new();
    for path in paths {
        let text = std::fs::read_to_string(repo_root().join(path))
            .unwrap_or_else(|error| panic!("{path} unreadable: {error}"));
        out.push_str(&format!(
            "{path}\t{}\t{}\n",
            digest(text.as_bytes()),
            read(&text)
        ));
    }
    out
}

fn read_golden(name: &str) -> String {
    let path = repo_root().join("tests/fixtures/mik_8425_yaml").join(name);
    std::fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("golden {} unreadable: {error}", path.display()))
}

/// Every file under `dir` (relative to the repo root) with one of
/// `extensions`, as sorted repo-relative paths with `/` separators.
pub fn files_under(dir: &str, extensions: &[&str]) -> Vec<String> {
    let root = repo_root();
    let mut found: Vec<String> = walkdir::WalkDir::new(root.join(dir))
        .into_iter()
        .filter_map(Result::ok)
        .filter(|entry| entry.file_type().is_file())
        .filter(|entry| {
            entry
                .path()
                .extension()
                .and_then(|e| e.to_str())
                .is_some_and(|e| extensions.contains(&e))
        })
        .map(|entry| relative(&root, entry.path()))
        .collect();
    found.sort();
    found
}

fn relative(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .expect("walked path is under the root")
        .components()
        .map(|c| c.as_os_str().to_string_lossy().into_owned())
        .collect::<Vec<_>>()
        .join("/")
}

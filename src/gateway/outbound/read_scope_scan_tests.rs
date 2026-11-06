// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Every producer reaches the read verdict through `judge::judging`: the
//! read history is reached from the judge alone, and each judge entry point
//! opens with the `judging` gate. A second path to the history could judge
//! (or skip judging) on a switch of its own.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use crate::test_source_text::production_text;

const SRC: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/src");
const JUDGE: &str = "gateway/outbound/judge.rs";
const HISTORY: &str = "security/tenant_reads.rs";

/// Production sources under `src/`, relative to it: test files and test
/// directories (`tests/`, `*_tests/`) left out.
fn production_sources() -> Vec<(String, String)> {
    fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
        for entry in std::fs::read_dir(dir).expect("read src") {
            let path = entry.expect("dir entry").path();
            if path.is_dir() {
                let test_dir = path
                    .file_name()
                    .and_then(|n| n.to_str())
                    .is_some_and(|n| n == "tests" || n.ends_with("_tests"));
                if !test_dir {
                    walk(&path, out);
                }
            } else if path.extension().is_some_and(|e| e == "rs") {
                out.push(path);
            }
        }
    }
    let mut paths = Vec::new();
    walk(Path::new(SRC), &mut paths);
    paths
        .into_iter()
        .filter_map(|path| {
            let name = path.file_name()?.to_str()?;
            if name == "tests.rs" || name.ends_with("_tests.rs") {
                return None;
            }
            let rel = path.strip_prefix(SRC).ok()?.to_str()?.replace('\\', "/");
            Some((rel, std::fs::read_to_string(&path).expect("read source")))
        })
        .collect()
}

#[test]
fn the_read_history_is_reached_from_the_judge_alone() {
    let sources = production_sources();
    assert!(
        sources.iter().any(|(rel, _)| rel == JUDGE),
        "premise: the scan sees {JUDGE}"
    );
    let readers: Vec<&str> = sources
        .iter()
        .filter(|(_, text)| production_text(text).contains(".reads()"))
        .map(|(rel, _)| rel.as_str())
        .collect();
    assert_eq!(readers, [JUDGE], "only the judge calls `.reads()`");
    let reservers: Vec<&str> = sources
        .iter()
        .filter(|(rel, text)| {
            let code = production_text(text);
            rel != JUDGE
                && rel != HISTORY
                && code.contains(".reserve(")
                && (code.contains("ReadHistory") || code.contains("tenant_reads::"))
        })
        .map(|(rel, _)| rel.as_str())
        .collect();
    assert!(
        reservers.is_empty(),
        "reserves on the read history outside the judge: {reservers:?}"
    );
}

#[test]
fn every_judge_entry_opens_with_the_judging_gate() {
    let judge = std::fs::read_to_string(format!("{SRC}/{JUDGE}")).expect("read judge");
    for entry in ["delivered", "admit", "admit_stream_item"] {
        let start = judge
            .find(&format!("pub(crate) fn {entry}("))
            .unwrap_or_else(|| panic!("premise: {entry} is in the judge"));
        let body = &judge[start..];
        let open = body.find(") -> ").expect("a return type");
        let first = body[open..]
            .lines()
            .nth(1)
            .expect("a first statement")
            .trim();
        assert_eq!(
            first, "let Some((guard, mode)) = judging(firewall) else {",
            "{entry} opens with the judging gate"
        );
    }
    let outbound =
        std::fs::read_to_string(format!("{SRC}/gateway/outbound/mod.rs")).expect("read outbound");
    let start = outbound
        .find("pub(crate) fn judges(")
        .expect("premise: judges is in outbound");
    let end = outbound[start..].find("\n}\n").expect("judges ends") + start;
    assert!(
        outbound[start..end].contains("judge::judging("),
        "outbound::judges asks judge::judging"
    );
}

/// Whether a `cfg` condition holds only in test builds: `test` itself, or an
/// `all(..)` with such a member. `any(..)`, `not(..)` and the rest do not.
fn implies_test(condition: &str) -> bool {
    let condition = condition.trim();
    if condition == "test" {
        return true;
    }
    let Some(inner) = condition
        .strip_prefix("all(")
        .and_then(|rest| rest.strip_suffix(')'))
    else {
        return false;
    };
    let (mut depth, mut start) = (0_i32, 0);
    let mut members = Vec::new();
    for (at, ch) in inner.char_indices() {
        match ch {
            '(' => depth += 1,
            ')' => depth -= 1,
            ',' if depth == 0 => {
                members.push(&inner[start..at]);
                start = at + 1;
            }
            _ => {}
        }
    }
    members.push(&inner[start..]);
    members.into_iter().any(implies_test)
}

/// The module name a `mod <name>;` line declares, any visibility.
fn declared_module(line: &str) -> Option<&str> {
    let mut rest = line.trim();
    if let Some(after) = rest.strip_prefix("pub") {
        rest = after;
        if rest.starts_with('(') {
            let close = rest.find(')')?;
            rest = &rest[close + 1..];
        }
        rest = rest.trim_start();
    }
    let name = rest.strip_prefix("mod ")?.strip_suffix(';')?.trim();
    name.chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_')
        .then_some(name)
}

/// `path` with `.` and `..` folded away, so two spellings of one file meet.
fn normal(path: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for part in path.components() {
        match part {
            std::path::Component::CurDir => {}
            std::path::Component::ParentDir => {
                out.pop();
            }
            other => out.push(other),
        }
    }
    out
}

/// Each module file under `src/`, with every declaration of it: the
/// declaring file and whether that declaration's own attribute lines carry a
/// `cfg` implying `test` (comments are not attributes).
type Declarations = HashMap<PathBuf, Vec<(PathBuf, bool)>>;

/// Resolve every `mod <name>;` in `files` to its module file, as rustc does:
/// a `#[path]` relative to the declaring file's folder, else `<name>.rs` or
/// `<name>/mod.rs` in the declaring module's folder.
fn declarations(files: &[PathBuf]) -> Declarations {
    let known: std::collections::HashSet<&PathBuf> = files.iter().collect();
    let mut declared = Declarations::new();
    for file in files {
        let text = std::fs::read_to_string(file).expect("read source");
        let lines: Vec<&str> = text.lines().collect();
        let dir = file.parent().expect("a file has a folder");
        for (at, line) in lines.iter().enumerate() {
            let Some(name) = declared_module(line) else {
                continue;
            };
            let attributes: Vec<&str> = lines[..at]
                .iter()
                .rev()
                .map(|above| above.trim())
                .take_while(|above| above.starts_with("#[") || above.starts_with("//"))
                .filter(|above| above.starts_with("#["))
                .collect();
            let gated = attributes.iter().any(|a| {
                a.strip_prefix("#[cfg(")
                    .and_then(|rest| rest.strip_suffix(")]"))
                    .is_some_and(implies_test)
            });
            let path = attributes.iter().find_map(|a| {
                a.strip_prefix("#[path")
                    .and_then(|rest| rest.split('"').nth(1))
            });
            let targets = if let Some(path) = path {
                vec![normal(&dir.join(path))]
            } else {
                let stem = file.file_stem().and_then(|s| s.to_str()).unwrap_or("");
                let base = if matches!(stem, "mod" | "lib" | "main") {
                    dir.to_path_buf()
                } else {
                    dir.join(stem)
                };
                vec![
                    normal(&base.join(format!("{name}.rs"))),
                    normal(&base.join(name).join("mod.rs")),
                ]
            };
            for target in targets.into_iter().filter(|t| known.contains(t)) {
                declared
                    .entry(target)
                    .or_default()
                    .push((file.clone(), gated));
            }
        }
    }
    declared
}

/// Whether `file` is compiled only for tests: every declaration of it is
/// gated, or sits in a file that is. A file nothing declares is not.
fn test_only(file: &Path, declared: &Declarations, seen: &mut Vec<PathBuf>) -> bool {
    let Some(by) = declared.get(file) else {
        return false;
    };
    if seen.iter().any(|s| s == file) {
        return false;
    }
    seen.push(file.to_path_buf());
    let only = by
        .iter()
        .all(|(parent, gated)| *gated || test_only(parent, declared, seen));
    seen.pop();
    only
}

/// The scan skips `*_tests/` folders by name, so each must be compiled only
/// for tests. Every `mod <name>;` under `src/` is resolved to its file, as
/// rustc does (a `#[path]` relative to the declaring file's folder, else
/// `<name>.rs` or `<name>/mod.rs` beside it), and a module file is test-only
/// when every declaration of it carries a `cfg` that implies `test` in its own
/// attribute lines (comments are not attributes), or sits in a test-only file.
/// Each `*_tests/` folder must be the folder of at least one declared module
/// file, and all of those must be test-only. A production folder named
/// `*_tests`, an unresolved one, or one gated by `any(test, ..)` or
/// `not(test)` fails here instead of hiding from the scan. Plain `tests/`
/// folders and `*_tests.rs` files are still trusted by name.
#[test]
fn every_skipped_test_folder_is_compiled_only_for_tests() {
    fn walk(dir: &Path, files: &mut Vec<PathBuf>, folders: &mut Vec<PathBuf>) {
        for entry in std::fs::read_dir(dir).expect("read src") {
            let path = entry.expect("dir entry").path();
            if path.is_dir() {
                if path
                    .file_name()
                    .and_then(|n| n.to_str())
                    .is_some_and(|n| n.ends_with("_tests"))
                {
                    folders.push(normal(&path));
                }
                walk(&path, files, folders);
            } else if path.extension().is_some_and(|e| e == "rs") {
                files.push(normal(&path));
            }
        }
    }
    let (mut files, mut folders) = (Vec::new(), Vec::new());
    walk(Path::new(SRC), &mut files, &mut folders);
    assert!(!folders.is_empty(), "premise: the tree has *_tests folders");

    let declared = declarations(&files);
    // The folder a module file's own child modules live in.
    let owned = |module: &Path| -> PathBuf {
        if module.file_name().is_some_and(|n| n == "mod.rs") {
            module.parent().expect("mod.rs has a folder").to_path_buf()
        } else {
            module.with_extension("")
        }
    };
    let failing: Vec<String> = folders
        .iter()
        .filter(|folder| {
            let owners: Vec<&PathBuf> = declared.keys().filter(|m| owned(m) == **folder).collect();
            owners.is_empty()
                || !owners
                    .iter()
                    .all(|m| test_only(m, &declared, &mut Vec::new()))
        })
        .map(|folder| folder.display().to_string())
        .collect();
    assert!(
        failing.is_empty(),
        "*_tests folders not compiled only for tests (or not resolved): {failing:?}"
    );
}

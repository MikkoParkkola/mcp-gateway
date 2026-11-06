// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Every producer reaches the read verdict through `judge::judging`: the
//! read history is reached from the judge alone, and each judge entry point
//! opens with the `judging` gate. A second path to the history could judge
//! (or skip judging) on a switch of its own.

use std::path::{Path, PathBuf};

const SRC: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/src");
const JUDGE: &str = "gateway/outbound/judge.rs";
const HISTORY: &str = "security/tenant_reads.rs";

/// Production sources under `src/`, relative to it: test files and test
/// directories left out.
fn production_sources() -> Vec<(String, String)> {
    fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
        for entry in std::fs::read_dir(dir).expect("read src") {
            let path = entry.expect("dir entry").path();
            if path.is_dir() {
                if path.file_name().is_some_and(|n| n != "tests") {
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

/// Production code before a file's first `#[cfg(test)]`.
fn production_part(text: &str) -> &str {
    text.split("#[cfg(test)]").next().unwrap_or(text)
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
        .filter(|(_, text)| production_part(text).contains(".reads()"))
        .map(|(rel, _)| rel.as_str())
        .collect();
    assert_eq!(readers, [JUDGE], "only the judge calls `.reads()`");
    let reservers: Vec<&str> = sources
        .iter()
        .filter(|(rel, text)| {
            let code = production_part(text);
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

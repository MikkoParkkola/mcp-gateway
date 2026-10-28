// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The classic web UI defines each top-level function once. In a classic
//! script a later declaration silently replaces an earlier one of the same
//! name, so a second copy is dead code that still gets edited: a fix made
//! there looks done and changes nothing.

use std::collections::BTreeMap;

const INDEX: &str = include_str!("../src/gateway/ui/index.html");

#[test]
fn no_top_level_function_is_defined_twice() {
    let declaration =
        regex::Regex::new(r"(?m)^(?:async )?function ([A-Za-z_$][\w$]*)\(").expect("pattern");
    let mut lines: BTreeMap<&str, Vec<usize>> = BTreeMap::new();
    for found in declaration.captures_iter(INDEX) {
        let (whole, name) = (found.get(0).expect("match"), found.get(1).expect("name"));
        let line = INDEX[..whole.start()].lines().count() + 1;
        lines.entry(name.as_str()).or_default().push(line);
    }
    assert!(lines.len() > 50, "the scan found the page's functions");
    let twice: Vec<String> = lines
        .iter()
        .filter(|(_, at)| at.len() > 1)
        .map(|(name, at)| format!("{name}: lines {at:?}"))
        .collect();
    assert!(
        twice.is_empty(),
        "functions defined more than once in index.html:\n{}",
        twice.join("\n")
    );
}

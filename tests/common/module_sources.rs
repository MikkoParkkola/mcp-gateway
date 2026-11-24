// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Every source file a test binary compiles: its own file and each module it
//! includes, followed through `#[path]` and plain `mod name;` declarations,
//! for rows that scan what really runs in the binary.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

/// `(path, text)` for the test binary whose root file is `binary` (as
/// `file!()` names it, from the crate root) and every module it includes,
/// recursively, the root first. A declared module whose file cannot be found
/// fails here: a module the scan cannot read must not pass unread.
pub fn module_sources(binary: &str) -> Vec<(PathBuf, String)> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join(binary);
    let children = root.parent().expect("the binary's directory").to_path_buf();
    let mut queue = vec![(root, children)];
    let mut seen = BTreeSet::new();
    let mut found = Vec::new();
    while let Some((file, dir)) = queue.pop() {
        if !seen.insert(file.clone()) {
            continue;
        }
        let text = std::fs::read_to_string(&file)
            .unwrap_or_else(|e| panic!("cannot read {}: {e}", file.display()));
        let mut pending_path = None;
        for line in text.lines() {
            let tight: String = line.chars().filter(|c| !c.is_whitespace()).collect();
            if tight.starts_with("//") {
                continue;
            }
            if let Some(rest) = tight.strip_prefix("#[path=\"") {
                pending_path = rest.split('"').next().map(str::to_owned);
                continue;
            }
            let Some(name) = declared_module(line.trim()) else {
                if !tight.starts_with("#[") && !tight.is_empty() {
                    pending_path = None;
                }
                continue;
            };
            queue.push(match pending_path.take() {
                // A `#[path]` file resolves its own `mod` lines from its directory.
                Some(path) => {
                    let module = dir.join(path);
                    let below = module.parent().expect("a module directory").to_path_buf();
                    (module, below)
                }
                None => resolve(&dir, name, &file),
            });
        }
        found.push((file, text));
    }
    found
}

/// The module a `mod name;` line declares (an inline `mod name { ... }`
/// includes no file).
fn declared_module(line: &str) -> Option<&str> {
    let rest = ["pub(crate) ", "pub(super) ", "pub "]
        .iter()
        .find_map(|vis| line.strip_prefix(vis))
        .unwrap_or(line);
    let name = rest.strip_prefix("mod ")?.strip_suffix(';')?.trim();
    name.chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_')
        .then_some(name)
}

/// Rust's lookup for a plain `mod name;` declared in `file`, whose children
/// live in `dir`: `dir/name.rs` (its own children in `dir/name/`) or
/// `dir/name/mod.rs`.
fn resolve(dir: &Path, name: &str, file: &Path) -> (PathBuf, PathBuf) {
    let flat = dir.join(format!("{name}.rs"));
    if flat.exists() {
        return (flat, dir.join(name));
    }
    let nested = dir.join(name).join("mod.rs");
    assert!(
        nested.exists(),
        "module `{name}` declared in {} has no file at {} or {}",
        file.display(),
        flat.display(),
        nested.display()
    );
    (nested, dir.join(name))
}

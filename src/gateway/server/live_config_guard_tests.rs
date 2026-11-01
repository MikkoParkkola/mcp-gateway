// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The firewall judges with the startup policy only when the `MetaMcp` has
//! no live config (`Firewall::policy_under`). These rows hold that to
//! handlers no production server builds: every production construction of a
//! `MetaMcp` is listed, and each serving mode sets the live config before
//! its first request. The firewall's public `check_request` and
//! `check_response` judge by the rules it was built from, which is current
//! for a program embedding it but not for the gateway: no gateway file
//! calls them.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use crate::test_source_text::production_text;

/// The calls that construct a `MetaMcp`.
const CONSTRUCTORS: [&str; 3] = [
    "MetaMcp::new(",
    "MetaMcp::with_features(",
    "MetaMcp::with_features_and_clock(",
];

/// Every production construction of a `MetaMcp`: `build_meta_mcp`, which
/// the serving modes below call. A new one is a server mode these rows do
/// not yet cover.
const PRODUCTION_CONSTRUCTIONS: [&str; 1] = ["src/gateway/server/build_meta.rs"];

/// Each serving mode: its file, and the line that starts taking requests,
/// which `set_live_config` must precede.
const SERVING_MODES: [(&str, &str); 2] = [
    ("src/gateway/server/run.rs", "listener::serve("),
    ("src/gateway/server/stdio_loop.rs", "reader.next_line()"),
];

/// The file a `mod` declaration in `file` names: `#[path]` relative to the
/// declaring file's directory, else `name.rs` or `name/mod.rs` under the
/// declaring module's directory.
fn module_file(file: &Path, name: &str, path_attr: Option<&str>) -> PathBuf {
    let dir = file.parent().expect("a source file has a directory");
    if let Some(path) = path_attr {
        return dir.join(path);
    }
    let stem = file.file_stem().and_then(|s| s.to_str()).unwrap_or_default();
    let base = if matches!(stem, "mod" | "lib" | "main") {
        dir.to_path_buf()
    } else {
        dir.join(stem)
    };
    let flat = base.join(format!("{name}.rs"));
    if flat.exists() {
        flat
    } else {
        base.join(name).join("mod.rs")
    }
}

/// The `mod name;` declarations outside test items, each with its
/// `#[path]` when one precedes it.
fn declarations(text: &str) -> Vec<(String, Option<String>)> {
    let mut out = Vec::new();
    let mut path_attr = None;
    for line in text.lines().map(str::trim) {
        if let Some(rest) = line.strip_prefix("#[path = \"") {
            path_attr = rest.strip_suffix("\"]").map(str::to_owned);
            continue;
        }
        if line.starts_with("#[") {
            continue;
        }
        let decl = line
            .split_once("mod ")
            .filter(|(vis, _)| vis.is_empty() || vis.trim_end().starts_with("pub"))
            .and_then(|(_, rest)| rest.strip_suffix(';'));
        if let Some(name) = decl.filter(|n| n.chars().all(|c| c == '_' || c.is_alphanumeric())) {
            out.push((name.to_owned(), path_attr.take()));
        } else {
            path_attr = None;
        }
    }
    out
}

/// Every source file a non-test build compiles, walked from the crate
/// roots through declarations outside test items.
fn production_files(root: &Path) -> BTreeSet<PathBuf> {
    let mut seen = BTreeSet::new();
    let mut queue = vec![root.join("src/lib.rs"), root.join("src/main.rs")];
    while let Some(file) = queue.pop() {
        if !seen.insert(file.clone()) {
            continue;
        }
        let text = std::fs::read_to_string(&file)
            .unwrap_or_else(|e| panic!("{} reads: {e}", file.display()));
        for (name, path_attr) in declarations(&production_text(&text)) {
            let next = module_file(&file, &name, path_attr.as_deref());
            assert!(
                next.exists(),
                "`mod {name}` in {} resolves to no file",
                file.display()
            );
            queue.push(next);
        }
    }
    seen
}

#[test]
fn every_production_meta_mcp_construction_is_listed() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let files = production_files(root);
    assert!(
        files.contains(&root.join("src/gateway/server/build_meta.rs")),
        "premise: the walk reaches the server modules"
    );
    let found: BTreeSet<String> = files
        .iter()
        .filter(|file| {
            let text = production_text(&std::fs::read_to_string(file).expect("reads"));
            CONSTRUCTORS.iter().any(|call| text.contains(call))
        })
        .map(|file| {
            file.strip_prefix(root)
                .expect("under the crate")
                .to_string_lossy()
                .into_owned()
        })
        .collect();
    let listed: BTreeSet<String> = PRODUCTION_CONSTRUCTIONS.map(str::to_owned).into();
    assert_eq!(
        found, listed,
        "a production MetaMcp construction must set the live config before its first \
         request; list it with its serving mode here"
    );
}

#[test]
fn every_serving_mode_sets_the_live_config_before_its_first_request() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    for (file, serves) in SERVING_MODES {
        let text = production_text(&std::fs::read_to_string(root.join(file)).expect("reads"));
        let built = text.find("self.build_meta_mcp()");
        let set = text.find("meta_mcp.set_live_config(");
        let first = text.find(serves);
        assert!(
            built.is_some() && set.is_some() && first.is_some(),
            "{file}: builds, sets and serves: {built:?} {set:?} {first:?}"
        );
        assert!(
            built < set && set < first,
            "{file}: set_live_config must come after build_meta_mcp and before `{serves}`"
        );
    }
}

#[test]
fn build_meta_mcp_is_called_only_by_the_serving_modes() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let callers: BTreeSet<String> = production_files(root)
        .iter()
        .filter(|file| {
            production_text(&std::fs::read_to_string(file).expect("reads"))
                .contains("build_meta_mcp()")
        })
        .map(|file| {
            file.strip_prefix(root)
                .expect("under the crate")
                .to_string_lossy()
                .into_owned()
        })
        .collect();
    let modes: BTreeSet<String> = SERVING_MODES.map(|(file, _)| file.to_owned()).into();
    assert_eq!(callers, modes, "a new serving mode must be listed in SERVING_MODES");
}

#[test]
fn no_production_file_calls_the_startup_rules_entry_points() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let owner = root.join("src/security/firewall/mod.rs");
    let callers: Vec<String> = production_files(root)
        .iter()
        .filter(|file| **file != owner)
        .filter(|file| {
            let text = production_text(&std::fs::read_to_string(file).expect("reads"));
            text.contains(".check_request(") || text.contains(".check_response(")
        })
        .map(|file| file.display().to_string())
        .collect();
    assert!(
        callers.is_empty(),
        "these judge by the startup rules; a gateway check takes the request's generation: {callers:?}"
    );
}

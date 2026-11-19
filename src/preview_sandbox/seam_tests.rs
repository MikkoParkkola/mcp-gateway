// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! T10: the fetch rows' fake resolver and dialer exist only in tests. No
//! shipped build may carry a seam that redirects a sandbox's connections, so
//! every file a production build compiles must be free of them, and the one
//! production call into the proxy-taking launcher passes `System` for both.

use std::path::{Path, PathBuf};

use crate::test_source_text::production_text;

/// The fakes' names: the scan's list, each with its positive control below.
const FAKES: [&str; 2] = ["TestDialer", "TestResolve"];

/// Every `.rs` file under `dir` whose module declaration survives the
/// production text that declares it: the files a production build compiles.
/// A leaf file can declare a sibling through `#[path]` (its plain `mod x;`
/// means `leaf/x.rs`, not a sibling), so the quoted file names in every leaf
/// found join the declaring text until nothing new turns up.
fn production_files(dir: &Path, parent_text: &str, out: &mut Vec<PathBuf>) {
    let mut text = parent_text.to_owned();
    let mut seen: Vec<PathBuf> = Vec::new();
    loop {
        let found = seen.len();
        for entry in std::fs::read_dir(dir).expect("read dir") {
            let path = entry.expect("entry").path();
            if seen.contains(&path) {
                continue;
            }
            let name = path
                .file_stem()
                .and_then(|s| s.to_str())
                .unwrap_or_default()
                .to_owned();
            if path.is_dir() {
                // A directory module's own text: `dir/mod.rs`, or `dir.rs` beside it.
                let own = if path.join("mod.rs").exists() {
                    path.join("mod.rs")
                } else {
                    path.with_extension("rs")
                };
                if declared(&text, &name, &path)
                    && let Ok(own_text) = std::fs::read_to_string(&own)
                {
                    seen.push(path.clone());
                    out.push(own);
                    production_files(&path, &production_text(&own_text), out);
                }
            } else if path.extension().is_some_and(|e| e == "rs")
                && name != "mod"
                && declared(&text, &name, &path)
            {
                let leaf = production_text(&std::fs::read_to_string(&path).expect("source"));
                // Only the quoted names: `declared` matches a `#[path]` by them.
                for quoted in leaf.split('"').skip(1).step_by(2) {
                    text.push_str(" \"");
                    text.push_str(quoted);
                    text.push('"');
                }
                seen.push(path.clone());
                out.push(path);
            }
        }
        if seen.len() == found {
            break;
        }
    }
}

/// Every production file under `src/preview_sandbox`, module files included.
fn production_sources() -> Vec<PathBuf> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/preview_sandbox");
    let top = production_text(&std::fs::read_to_string(root.join("mod.rs")).expect("mod.rs"));
    let mut files = vec![root.join("mod.rs")];
    production_files(&root, &top, &mut files);
    // A directory module written as `dir.rs` is reached as a directory and
    // as a leaf: listed once.
    files.sort();
    files.dedup();
    // Positive control: the scan reaches nested production files.
    for known in ["linux/mod.rs", "linux/relay.rs", "linux/fetch_step.rs"] {
        assert!(
            files.iter().any(|f| f.ends_with(known)),
            "the scan reached {known}"
        );
    }
    files
}

/// `mod name` (or a `#[path]` naming the file) in the parent's production text.
fn declared(parent_text: &str, name: &str, path: &Path) -> bool {
    let file = path
        .file_name()
        .and_then(|f| f.to_str())
        .unwrap_or_default();
    parent_text.contains(&format!("mod {name};"))
        || parent_text.contains(&format!("mod {name} {{"))
        || parent_text.contains(&format!("\"{file}\""))
}

/// Kills "a fake dialer or resolver reaches a shipped build" (the fetch rows'
/// module declared without `cfg(test)`, or a fake defined in a production
/// file), with a positive control: the fakes exist, in a test-only module.
#[test]
fn t10_the_fetch_fakes_are_test_only() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/preview_sandbox");
    let files = production_sources();
    assert!(
        files.iter().any(|f| f.ends_with("linux/mod.rs")),
        "the scan reached the Linux module"
    );
    for file in &files {
        let text = production_text(&std::fs::read_to_string(file).expect("source"));
        for fake in FAKES {
            assert!(
                !text.contains(fake),
                "{fake} in a production file: {}",
                file.display()
            );
        }
    }
    let rows = std::fs::read_to_string(root.join("linux/fetch_rows.rs")).expect("fetch rows");
    for fake in FAKES {
        assert!(
            rows.contains(&format!("struct {fake}")),
            "positive control: {fake} is defined"
        );
    }
    assert!(
        !files.iter().any(|f| f.ends_with("fetch_rows.rs")),
        "the fetch rows compile only in tests"
    );
}

/// The only production call of `start_fetching_with`, in any production
/// file, is in the Linux module and passes `System` as both the resolver and
/// the dialer.
#[test]
fn t10_production_passes_system_to_the_proxy() {
    let mut calls: Vec<(PathBuf, String)> = Vec::new();
    for file in production_sources() {
        let text = production_text(&std::fs::read_to_string(&file).expect("source"));
        for (at, _) in text.match_indices("start_fetching_with(") {
            if !text[..at].ends_with("fn ") {
                calls.push((file.clone(), text[at..].to_owned()));
            }
        }
    }
    assert_eq!(calls.len(), 1, "one production call: {calls:?}");
    let (file, call) = &calls[0];
    assert!(file.ends_with("linux/mod.rs"), "{}", file.display());
    let args = &call[..call.find(".await").expect("the call is awaited")];
    assert_eq!(args.matches("Arc::new(System)").count(), 2, "{args}");
    assert_eq!(args.matches("Arc::new(").count(), 2, "{args}");
}

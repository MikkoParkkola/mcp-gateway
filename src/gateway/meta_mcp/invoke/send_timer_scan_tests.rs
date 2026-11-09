// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Source pins for where the send timer is started and finished.

use std::path::{Path, PathBuf};

use crate::test_source_text::production_text;

/// Every `.rs` file under `dir`, recursively.
fn rust_files(dir: &Path) -> Vec<PathBuf> {
    let mut files = Vec::new();
    let mut dirs = vec![dir.to_path_buf()];
    while let Some(dir) = dirs.pop() {
        for entry in std::fs::read_dir(&dir).expect("a scanned directory") {
            let path = entry.expect("entry").path();
            if path.is_dir() {
                dirs.push(path);
            } else if path.extension().is_some_and(|e| e == "rs") {
                files.push(path);
            }
        }
    }
    files
}

/// The send primitives each tree may call only from its timed file.
const SITES: [(&str, &[&str], &str); 2] = [
    (
        "src/backend",
        &[".request_with_headers(", ".request_with_task_capability("],
        "src/backend/ops/attempt.rs",
    ),
    (
        "src/capability/executor",
        &[".send().await", "client.execute("],
        "src/capability/executor/client.rs",
    ),
];

/// Sends that are never a `tools/call`, so never a call's latency: the
/// era discovery probe and the catalogue list drain.
const UNTIMED: [(&str, &str); 2] = [
    (
        "src/backend/era.rs",
        "the era probe (DISCOVER_METHOD), never a tools/call",
    ),
    (
        "src/backend/list_drain.rs",
        "catalogue list pages, never a tools/call",
    ),
];

/// Violations in `(relative path, production text)` pairs: a primitive
/// outside its timed file, a timed file without a timer, a CLI run that
/// is not timed, or a timer around the capability dispatch branch.
fn violations(files: &[(String, String)]) -> Vec<String> {
    let mut found = Vec::new();
    for (tree, primitives, timed) in SITES {
        for (path, text) in files.iter().filter(|(p, _)| p.starts_with(tree)) {
            for primitive in primitives {
                let untimed = UNTIMED.iter().any(|(p, _)| p == path);
                if text.contains(primitive) && path != timed && !untimed {
                    found.push(format!("{path}: {primitive} outside {timed}"));
                }
            }
            if path == timed && !text.contains("SendTimer::start") {
                found.push(format!("{path}: the timed send file starts no SendTimer"));
            }
        }
    }
    for (path, text) in files {
        if path == "src/capability/executor/cli_run.rs" {
            let spawn = text.find("wrap.spawn()");
            let timer = text.find("SendTimer::start()");
            if !matches!((spawn, timer), (Some(s), Some(t)) if s < t)
                || !text.contains("timer.finish_with(")
            {
                found.push(format!("{path}: the CLI run is not timed after its spawn"));
            }
        }
        if path == "src/capability/executor/mod.rs" && text.contains("SendTimer") {
            found.push(format!(
                "{path}: a timer around the dispatch branch times a send twice"
            ));
        }
    }
    found
}

#[test]
fn every_send_has_a_timer() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut files = Vec::new();
    for tree in ["src/backend", "src/capability/executor"] {
        for path in rust_files(&root.join(tree)) {
            let rel = path
                .strip_prefix(root)
                .expect("under the root")
                .to_string_lossy()
                .replace('\\', "/");
            // Test files and test-module directories (`*_tests.rs`,
            // `*_tests/`, `tests/`) are not production sends.
            let test_only = rel.split('/').any(|part| {
                part == "tests" || part.ends_with("_tests") || part.ends_with("_tests.rs")
            });
            if test_only {
                continue;
            }
            let text = production_text(&std::fs::read_to_string(&path).expect("readable"));
            files.push((rel, text));
        }
    }
    assert!(files.len() > 10, "the scan read the trees: {}", files.len());
    let found = violations(&files);
    assert!(found.is_empty(), "{found:#?}");
}

/// The scanner names a planted untimed send and a timer on the branch.
#[test]
fn the_scan_names_planted_violations() {
    let files = vec![
        (
            "src/backend/ops/attempt.rs".to_owned(),
            "SendTimer::start_if(x); t.request_with_headers(a)".to_owned(),
        ),
        (
            "src/backend/new_path.rs".to_owned(),
            "transport.request_with_headers(a)".to_owned(),
        ),
        (
            "src/capability/executor/mod.rs".to_owned(),
            "let t = SendTimer::start();".to_owned(),
        ),
        (
            "src/capability/executor/client.rs".to_owned(),
            "SendTimer::start(); r.send().await".to_owned(),
        ),
        (
            "src/capability/executor/cli_run.rs".to_owned(),
            "wrap.spawn(); SendTimer::start(); timer.finish_with(r)".to_owned(),
        ),
    ];
    let found = violations(&files);
    assert_eq!(found.len(), 2, "{found:#?}");
    assert!(found[0].contains("new_path.rs"), "{found:#?}");
    assert!(found[1].contains("executor/mod.rs"), "{found:#?}");
}

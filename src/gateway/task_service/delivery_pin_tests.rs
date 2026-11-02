// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The set of readers that serve a stored task is closed: every one sends
//! `CommittedTask::delivered_wire`, which withholds an unvouched upstream
//! row's outcome, and nothing else projects a stored task. A new reader that
//! bypassed it would serve a legacy row's result unchecked, so adding one
//! fails here until it is reviewed and named.

use std::path::Path;

/// The files allowed to call `delivered_wire`, each once: the owner's
/// `tasks/get`, the keyed task repeat, and the task notification.
const SERVE_SITES: [&str; 3] = [
    "src/gateway/task_route.rs",
    "src/gateway/task_service/execution.rs",
    "src/gateway/meta_mcp/task_notify.rs",
];

fn rust_files(dir: &Path, out: &mut Vec<std::path::PathBuf>) {
    for entry in std::fs::read_dir(dir).expect("the source tree is readable") {
        let path = entry.expect("a directory entry").path();
        if path.is_dir() {
            rust_files(&path, out);
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            out.push(path);
        }
    }
}

/// Every production occurrence of `needle`, as (file relative to the crate,
/// count), test items blanked.
fn occurrences(needle: &str) -> Vec<(String, usize)> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut files = Vec::new();
    rust_files(&root.join("src"), &mut files);
    let mut found: Vec<(String, usize)> = files
        .iter()
        // Test files only: a production name may contain "test" (attestation).
        .filter(|path| {
            let name = path
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default();
            !name.ends_with("_tests.rs") && !path.components().any(|c| c.as_os_str() == "tests")
        })
        .filter_map(|path| {
            let text = std::fs::read_to_string(path).ok()?;
            let count = crate::test_source_text::production_text(&text)
                .matches(needle)
                .count();
            let relative = path.strip_prefix(root).ok()?.to_string_lossy().into_owned();
            (count > 0).then_some((relative, count))
        })
        .collect();
    found.sort();
    found
}

#[test]
fn only_the_named_serve_sites_send_a_stored_task() {
    let mut want: Vec<(String, usize)> = SERVE_SITES
        .iter()
        .map(|site| ((*site).to_owned(), 1))
        .collect();
    want.sort();
    assert_eq!(
        occurrences(".delivered_wire()"),
        want,
        "a new reader of a stored task: route it through delivered_wire's gate and name it here"
    );
}

#[test]
fn nothing_but_delivered_wire_projects_a_stored_task() {
    assert_eq!(
        occurrences("self.task.wire()"),
        vec![("src/gateway/task_service/record.rs".to_owned(), 1)],
        "a stored task projected outside delivered_wire skips the withheld gate"
    );
}

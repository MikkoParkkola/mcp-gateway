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

/// How often `code` calls or names the function `name`: the whole
/// identifier after a `::` (a path call or a function reference), or after
/// a `.` when a `(` follows (a method call), whitespace allowed between. A
/// field of the same name (`self.wire.status`), a definition (`fn name`), a
/// variable or a longer name that contains it does not count.
fn path_uses(code: &str, name: &str) -> usize {
    let ident = |c: char| c.is_alphanumeric() || c == '_';
    code.match_indices(name)
        .filter(|(at, _)| {
            let before = &code[..*at];
            let after = &code[at + name.len()..];
            let whole = !before.ends_with(ident) && !after.starts_with(ident);
            let reached = before.trim_end();
            let called = after.trim_start().starts_with('(');
            whole && (reached.ends_with("::") || (reached.ends_with('.') && called))
        })
        .count()
}

/// Every production use of the item `name` (see [`path_uses`]), as (file
/// relative to the crate, count): test items, comments and string literals
/// blanked first.
fn occurrences(name: &str) -> Vec<(String, usize)> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut files = Vec::new();
    rust_files(&root.join("src"), &mut files);
    let mut found: Vec<(String, usize)> = files
        .iter()
        // Test files and test directories only, by suffix: a production name
        // may contain "test" (attestation).
        .filter(|path| {
            !path
                .strip_prefix(root)
                .unwrap_or(path)
                .components()
                .any(|c| {
                    let part = c.as_os_str().to_string_lossy();
                    part == "tests" || part.ends_with("_tests") || part.ends_with("_tests.rs")
                })
        })
        .filter_map(|path| {
            let text = std::fs::read_to_string(path).ok()?;
            let code =
                crate::test_source_text::sanitize(&crate::test_source_text::production_text(&text));
            let count = path_uses(&code, name);
            // '/' on every platform: the table names files as the repository
            // does, and Windows walks them as `src\gateway\...`.
            let relative = path
                .strip_prefix(root)
                .ok()?
                .to_string_lossy()
                .replace('\\', "/");
            (count > 0).then_some((relative, count))
        })
        .collect();
    found.sort();
    found
}

/// The matcher itself: every call shape counts, nothing else does.
#[test]
fn every_call_shape_of_the_projection_is_counted() {
    let code = "a.wire(); b . wire (); Task::wire(&t); map(Task::wire); x.delivered_wire(); \
                fn wire(&self) {} let wire = 1; rewire(); a.wire_json(); s.task.wire(); \
                self.wire.status = 1; let s = self.wire.result.clone();";
    assert_eq!(path_uses(code, "wire"), 5);
    assert_eq!(path_uses(code, "delivered_wire"), 1);
}

#[test]
fn only_the_named_serve_sites_send_a_stored_task() {
    let mut want: Vec<(String, usize)> = SERVE_SITES
        .iter()
        .map(|site| ((*site).to_owned(), 1))
        .collect();
    want.sort();
    assert_eq!(
        occurrences("delivered_wire"),
        want,
        "a new reader of a stored task: route it through delivered_wire's gate and name it here"
    );
}

#[test]
fn nothing_but_delivered_wire_projects_a_stored_task() {
    // Any receiver, not only `self.task`: a reader holding the task under
    // another name would bypass the gate the same way.
    assert_eq!(
        occurrences("wire"),
        vec![("src/gateway/task_service/record.rs".to_owned(), 1)],
        "a stored task projected outside delivered_wire skips the withheld gate"
    );
}

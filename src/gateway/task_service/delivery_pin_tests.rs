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

/// What a `Task` method hands out: its stored outcome (backend output that
/// an unvouched row must not serve), or nothing of it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Exposes {
    /// The result, error or input requests, whole or as a projection.
    Outcome,
    /// Identity, timing, status or the gateway's own status text.
    Nothing,
}

/// Every `pub` and `pub(crate)` method of `Task`, classified. A method
/// added to `Task` and not listed here fails `task_methods_are_classified`:
/// classify it, and if it exposes the outcome, pin its callers below.
const TASK_METHODS: &[(&str, Exposes)] = &[
    ("create", Exposes::Nothing),
    ("create_at", Exposes::Nothing),
    ("create_undated", Exposes::Nothing),
    ("is_undated", Exposes::Nothing),
    ("dated_at", Exposes::Nothing),
    ("id", Exposes::Nothing),
    ("tool", Exposes::Nothing),
    ("ttl_ms", Exposes::Nothing),
    ("status", Exposes::Nothing),
    ("input_requests", Exposes::Outcome),
    // Only the gateway writes it (store_input's own reason); an upstream
    // answer never sets it.
    ("status_message", Exposes::Nothing),
    ("result", Exposes::Outcome),
    ("error", Exposes::Outcome),
    ("retention_elapsed", Exposes::Nothing),
    ("last_updated_at", Exposes::Nothing),
    ("wire", Exposes::Outcome),
    ("complete", Exposes::Nothing),
    ("fail", Exposes::Nothing),
    ("transition", Exposes::Nothing),
    ("snapshot", Exposes::Outcome),
    ("from_snapshot", Exposes::Nothing),
];

/// The `pub` and `pub(crate)` methods declared in `impl Task { .. }` of
/// `code`, by name, in order.
fn public_task_methods(code: &str) -> Vec<String> {
    let start = code
        .find("impl Task {")
        .expect("tasks.rs declares impl Task");
    let body = &code[start..];
    let mut depth = 0usize;
    let mut end = body.len();
    for (at, byte) in body.bytes().enumerate() {
        match byte {
            b'{' => depth += 1,
            b'}' => {
                depth -= 1;
                if depth == 0 {
                    end = at;
                    break;
                }
            }
            _ => {}
        }
    }
    body[..end]
        .lines()
        .filter_map(|line| {
            let line = line.trim_start();
            let rest = line
                .strip_prefix("pub(crate) ")
                .or_else(|| line.strip_prefix("pub "))?;
            let rest = rest.strip_prefix("const ").unwrap_or(rest);
            let name = rest.strip_prefix("fn ")?;
            let name: String = name
                .chars()
                .take_while(|c| c.is_alphanumeric() || *c == '_')
                .collect();
            Some(name)
        })
        .collect()
}

#[test]
fn task_methods_are_classified() {
    let text = std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("src/protocol/tasks.rs"),
    )
    .expect("tasks.rs is readable");
    let code = crate::test_source_text::sanitize(&crate::test_source_text::production_text(&text));
    let found = public_task_methods(&code);
    let listed: Vec<&str> = TASK_METHODS.iter().map(|(name, _)| *name).collect();
    let unlisted: Vec<&String> = found
        .iter()
        .filter(|name| !listed.contains(&name.as_str()))
        .collect();
    let gone: Vec<&&str> = listed
        .iter()
        .filter(|name| !found.iter().any(|f| f == *name))
        .collect();
    assert!(
        unlisted.is_empty() && gone.is_empty(),
        "Task's public methods changed: classify {unlisted:?} in TASK_METHODS (and pin an \
         outcome-exposing one's callers), drop {gone:?}"
    );
}

/// The production calls of each outcome-exposing `Task` method other than
/// `wire` (pinned above), as (file, method, count): the store's own writes
/// of its row, the delivery projection's helpers, settlement's held
/// payloads, and the input-round receipt.
const OUTCOME_CALLS: &[(&str, &str, usize)] = &[
    (
        "src/gateway/meta_mcp/task_replay/receipts.rs",
        "input_requests",
        1,
    ),
    ("src/gateway/task_service/record.rs", "error", 1),
    ("src/gateway/task_service/record.rs", "result", 1),
    ("src/gateway/task_service/record.rs", "snapshot", 2),
    (
        "src/gateway/task_service/store_input.rs",
        "input_requests",
        2,
    ),
    ("src/gateway/task_service/store_input.rs", "snapshot", 2),
    ("src/gateway/task_service/store_targets.rs", "result", 1),
];

/// How often `code` calls `name` on a receiver whose last identifier holds
/// `task` (`task.snapshot()`, `self.task.result()`, `entry.task.error()`).
// ponytail: names, not types. A reader that binds a Task under a name
// without "task" in it escapes this row; a type-aware scan (rust-analyzer)
// would close that, at the cost of a build-time dependency.
fn task_receiver_calls(code: &str, name: &str) -> usize {
    let ident = |c: char| c.is_alphanumeric() || c == '_';
    code.match_indices(name)
        .filter(|(at, _)| {
            let before = code[..*at].trim_end();
            let after = &code[at + name.len()..];
            let Some(receiver) = before.strip_suffix('.') else {
                return false;
            };
            let receiver = receiver.trim_end();
            let last: String = receiver
                .chars()
                .rev()
                .take_while(|c| ident(*c))
                .collect::<Vec<_>>()
                .into_iter()
                .rev()
                .collect();
            !after.starts_with(ident)
                && after.trim_start().starts_with('(')
                && last.to_lowercase().contains("task")
        })
        .count()
}

#[test]
fn outcome_exposing_task_methods_are_called_only_where_listed() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut files = Vec::new();
    rust_files(&root.join("src"), &mut files);
    let outcome: Vec<&str> = TASK_METHODS
        .iter()
        .filter(|(name, exposes)| *exposes == Exposes::Outcome && *name != "wire")
        .map(|(name, _)| *name)
        .collect();
    let mut found = Vec::new();
    for path in &files {
        let relative = path.strip_prefix(root).unwrap_or(path);
        if relative.components().any(|c| {
            let part = c.as_os_str().to_string_lossy();
            part == "tests" || part.ends_with("_tests") || part.ends_with("_tests.rs")
        }) {
            continue;
        }
        let Ok(text) = std::fs::read_to_string(path) else {
            continue;
        };
        let code =
            crate::test_source_text::sanitize(&crate::test_source_text::production_text(&text));
        for name in &outcome {
            let count = task_receiver_calls(&code, name);
            if count > 0 {
                found.push((
                    relative.to_string_lossy().replace('\\', "/"),
                    (*name).to_owned(),
                    count,
                ));
            }
        }
    }
    found.sort();
    let want: Vec<(String, String, usize)> = OUTCOME_CALLS
        .iter()
        .map(|(file, name, count)| ((*file).to_owned(), (*name).to_owned(), *count))
        .collect();
    assert_eq!(
        found, want,
        "a new caller of a Task outcome accessor: route a served outcome through delivered_wire, \
         then list the call here"
    );
}

/// The matchers themselves.
#[test]
fn the_task_method_and_receiver_matchers_read_what_they_should() {
    let code = "impl Task {\n    pub fn id(&self) {}\n    pub(crate) const fn ttl_ms(&self) {}\n    \
                fn private(&self) {}\n    pub const fn result(&self) { if x { } }\n}\nimpl Other {\n    \
                pub fn outside(&self) {}\n}";
    assert_eq!(public_task_methods(code), ["id", "ttl_ms", "result"]);
    let calls = "task.snapshot(); self.task.result(); entry . task . error (); stats.snapshot(); \
                 task.snapshot_of(); fn snapshot(&self) {} task.snapshot";
    assert_eq!(task_receiver_calls(calls, "snapshot"), 1);
    assert_eq!(task_receiver_calls(calls, "result"), 1);
    assert_eq!(task_receiver_calls(calls, "error"), 1);
}

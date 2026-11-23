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

/// The `pub`, `pub(crate)` and `pub(super)` methods declared in the first
/// `impl Task { .. }` block of `code`, by name, in order.
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
            let mut rest = ["pub(crate) ", "pub(super) ", "pub "]
                .iter()
                .find_map(|vis| line.strip_prefix(vis))?;
            // Qualifiers between the visibility and `fn`, in any order.
            while let Some(next) = ["const ", "async ", "unsafe "]
                .iter()
                .find_map(|q| rest.strip_prefix(q))
            {
                rest = next;
            }
            let name = rest.strip_prefix("fn ")?;
            let name: String = name
                .chars()
                .take_while(|c| c.is_alphanumeric() || *c == '_')
                .collect();
            Some(name)
        })
        .collect()
}

/// Each production source under `src/`: its path from the crate root with '/'
/// separators, and its text with test items, comments and strings blanked.
/// Sorted by path.
fn production_sources() -> Vec<(String, String)> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut paths = Vec::new();
    rust_files(&root.join("src"), &mut paths);
    let is_test = |relative: &Path| {
        relative.components().any(|part| {
            let part = part.as_os_str().to_string_lossy();
            part == "tests" || part.ends_with("_tests") || part.ends_with("_tests.rs")
        })
    };
    let mut sources: Vec<(String, String)> = paths
        .iter()
        .filter_map(|path| {
            let relative = path.strip_prefix(root).ok()?;
            if is_test(relative) {
                return None;
            }
            let raw = std::fs::read_to_string(path).ok()?;
            let blanked =
                crate::test_source_text::sanitize(&crate::test_source_text::production_text(&raw));
            Some((relative.to_string_lossy().replace('\\', "/"), blanked))
        })
        .collect();
    sources.sort();
    sources
}

#[test]
fn task_methods_are_classified() {
    // An inherent impl may sit in any module of the crate, so every block counts.
    let found: Vec<String> = production_sources()
        .iter()
        .flat_map(|(_, code)| {
            code.match_indices("impl Task {")
                .flat_map(|(at, _)| public_task_methods(&code[at..]))
                .collect::<Vec<_>>()
        })
        .collect();
    assert!(
        found.iter().any(|name| name == "wire"),
        "no impl Task block was read"
    );
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

/// The production calls of `result`, `error` and `input_requests` on a task
/// receiver, as (file, method, count): the delivery projection's receipt
/// helpers, settlement's held payloads, the store's input-round checks, and
/// the input-round receipt. `wire` and `snapshot` have exact pins of their
/// own; these names are too common for one.
const OUTCOME_CALLS: &[(&str, &str, usize)] = &[
    (
        "src/gateway/meta_mcp/task_replay/receipts.rs",
        "input_requests",
        1,
    ),
    ("src/gateway/task_service/record.rs", "error", 1),
    ("src/gateway/task_service/record.rs", "result", 1),
    (
        "src/gateway/task_service/store_input.rs",
        "input_requests",
        2,
    ),
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
        .filter(|(name, exposes)| {
            *exposes == Exposes::Outcome && !matches!(*name, "wire" | "snapshot")
        })
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

/// Every production use of `snapshot`, through the delivery pin's own
/// matcher (any receiver, a path, a function reference), in each file that
/// names the `Task` type, as (file, count). The name is common elsewhere, so a
/// file that never names `Task` is left out; a new accessor anywhere still
/// fails `task_methods_are_classified`.
const SNAPSHOT_USES: &[(&str, usize)] = &[
    // `delivery_facts::snapshot()`: the dispatch facts, not a task.
    ("src/gateway/task_service/execution/worker_inspect.rs", 1),
    // The record's model: `set_model`, and the admitted record.
    ("src/gateway/task_service/record.rs", 2),
    // The store's writes of its row, and the cap probe's clone of it.
    ("src/gateway/task_service/store_input.rs", 3),
];

/// Whether `code` names the type `Task` as a whole identifier
/// (`CommittedTask` or `TaskStatus` do not count).
fn names_task(code: &str) -> bool {
    let ident = |c: char| c.is_alphanumeric() || c == '_';
    code.match_indices("Task").any(|(at, word)| {
        !code[..at].ends_with(ident) && !code[at + word.len()..].starts_with(ident)
    })
}

#[test]
fn snapshot_is_used_only_where_listed() {
    let found: Vec<(String, usize)> = production_sources()
        .into_iter()
        .filter(|(_, code)| names_task(code))
        .map(|(file, code)| {
            let uses = path_uses(&code, "snapshot");
            (file, uses)
        })
        .filter(|(_, uses)| *uses > 0)
        .collect();
    let want: Vec<(String, usize)> = SNAPSHOT_USES
        .iter()
        .map(|(file, uses)| ((*file).to_owned(), *uses))
        .collect();
    assert_eq!(
        found, want,
        "a new use of snapshot where a Task is in reach: serve a stored task through \
         delivered_wire; a store write or a measurement is listed here"
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
    // Qualified methods, a pub(super) one, and a second block read on its own.
    let more = "impl Task {\n    pub async fn later(&self) {}\n    pub(super) unsafe fn raw(&self) {}\n    \
                pub const async fn both(&self) {}\n}\nimpl Task {\n    pub fn second(&self) {}\n}";
    assert_eq!(public_task_methods(more), ["later", "raw", "both"]);
    let second = more.rfind("impl Task {").expect("a second block");
    assert_eq!(public_task_methods(&more[second..]), ["second"]);
    assert!(names_task("let t: Task = x;") && names_task("Task::create()"));
    assert!(!names_task("CommittedTask TaskStatus tasks"));
    assert_eq!(
        path_uses(
            "answered.snapshot(); Task::snapshot(&t); map(Task::snapshot)",
            "snapshot"
        ),
        3
    );
}

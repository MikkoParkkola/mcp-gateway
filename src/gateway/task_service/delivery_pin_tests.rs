// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The set of readers that serve a stored task is closed: every one sends
//! `CommittedTask::delivered_wire`, which withholds an unvouched upstream
//! row's outcome, and nothing else projects a stored task. A new reader that
//! bypassed it would serve a legacy row's result unchecked, so adding one
//! fails here until it is reviewed and named.

use std::path::Path;

use crate::test_source_files::rust_files;

/// The files allowed to call `delivered_wire`, each once: the owner's
/// `tasks/get`, the keyed task repeat, and the task notification.
const SERVE_SITES: [&str; 3] = [
    "src/gateway/task_route.rs",
    "src/gateway/task_service/execution.rs",
    "src/gateway/meta_mcp/task_notify.rs",
];

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

/// Where the protocol's `Task` is declared.
const PROTOCOL_TASKS: &str = "src/protocol/tasks.rs";

/// Whether `ty` is the protocol's `Task`: a path ending `protocol::Task` or
/// `protocol::tasks::Task`, or the bare name where `bare_counts` says the
/// module in scope sees no other `Task`.
fn names_protocol_task(ty: &syn::Type, bare_counts: bool) -> bool {
    let syn::Type::Path(path) = ty else {
        return false;
    };
    if path.qself.is_some() {
        return false;
    }
    let names: Vec<String> = path
        .path
        .segments
        .iter()
        .map(|segment| segment.ident.to_string())
        .collect();
    match names.as_slice() {
        [only] => bare_counts && only == "Task",
        [.., p, t] if p == "protocol" && t == "Task" => true,
        [.., p, m, t] if p == "protocol" && m == "tasks" && t == "Task" => true,
        _ => false,
    }
}

/// Whether a `use` tree brings a `Task` into scope from somewhere other than
/// the protocol: its own name or a rename. Only a `crate::` path that does not
/// end in `protocol` or `protocol::tasks` names another `Task`. A relative or
/// one-segment path (`super::Task`, `tasks::Task`) is read as the protocol's,
/// as the text scan before it did: a wrong reading shows up as an unlisted
/// method, a red row, never a silent skip. An inherent impl on another crate's
/// type does not compile, so other crates' imports never matter. In the
/// protocol module every import of `Task` is the protocol's.
fn imports_other_task(tree: &syn::UseTree, prefix: &mut Vec<String>, in_protocol: bool) -> bool {
    let other_path = |prefix: &[String]| {
        !in_protocol
            && prefix.first().is_some_and(|first| first == "crate")
            && !matches!(prefix, [.., p] if p == "protocol")
            && !matches!(prefix, [.., p, m] if p == "protocol" && m == "tasks")
    };
    match tree {
        syn::UseTree::Path(step) => {
            prefix.push(step.ident.to_string());
            let other = imports_other_task(&step.tree, prefix, in_protocol);
            prefix.pop();
            other
        }
        syn::UseTree::Name(name) => name.ident == "Task" && other_path(prefix),
        // `use x::Other as Task` brings in a different type under the name.
        syn::UseTree::Rename(rename) => {
            rename.rename == "Task" && (rename.ident != "Task" || other_path(prefix))
        }
        syn::UseTree::Group(group) => group
            .items
            .iter()
            .any(|tree| imports_other_task(tree, prefix, in_protocol)),
        syn::UseTree::Glob(_) => false,
    }
}

/// Whether a module's own items declare a `Task` (struct, enum, union, alias or
/// trait) or import another one: a bare `impl Task` there names that type.
/// A test-only declaration or import is left out, since a production build
/// never sees it.
fn module_has_other_task(items: &[syn::Item], in_protocol: bool) -> bool {
    use crate::test_source_text::test_only;
    items.iter().any(|item| match item {
        syn::Item::Struct(decl) => !test_only(&decl.attrs) && decl.ident == "Task",
        syn::Item::Enum(decl) => !test_only(&decl.attrs) && decl.ident == "Task",
        syn::Item::Union(decl) => !test_only(&decl.attrs) && decl.ident == "Task",
        syn::Item::Type(decl) => !test_only(&decl.attrs) && decl.ident == "Task",
        syn::Item::Trait(decl) => !test_only(&decl.attrs) && decl.ident == "Task",
        syn::Item::Use(decl) => {
            !test_only(&decl.attrs) && imports_other_task(&decl.tree, &mut Vec::new(), in_protocol)
        }
        _ => false,
    })
}

/// A walk over one parsed file that reaches every inherent impl wherever it
/// sits: modules, function bodies, `const _: () = { .. }` blocks. Test-only
/// items are skipped with everything under them.
struct TaskImplWalk<'a> {
    in_protocol: bool,
    /// For each enclosing module, innermost last: whether a bare `Task` there
    /// is the protocol's.
    bare_counts: Vec<bool>,
    out: &'a mut Vec<String>,
}

impl<'ast> syn::visit::Visit<'ast> for TaskImplWalk<'_> {
    fn visit_item_mod(&mut self, module: &'ast syn::ItemMod) {
        if crate::test_source_text::test_only(&module.attrs) {
            return;
        }
        if let Some((_, items)) = &module.content {
            self.bare_counts
                .push(!module_has_other_task(items, self.in_protocol));
            syn::visit::visit_item_mod(self, module);
            self.bare_counts.pop();
        }
    }

    fn visit_item_fn(&mut self, item: &'ast syn::ItemFn) {
        if !crate::test_source_text::test_only(&item.attrs) {
            syn::visit::visit_item_fn(self, item);
        }
    }

    fn visit_item_const(&mut self, item: &'ast syn::ItemConst) {
        if !crate::test_source_text::test_only(&item.attrs) {
            syn::visit::visit_item_const(self, item);
        }
    }

    fn visit_item_static(&mut self, item: &'ast syn::ItemStatic) {
        if !crate::test_source_text::test_only(&item.attrs) {
            syn::visit::visit_item_static(self, item);
        }
    }

    fn visit_impl_item_fn(&mut self, method: &'ast syn::ImplItemFn) {
        if !crate::test_source_text::test_only(&method.attrs) {
            syn::visit::visit_impl_item_fn(self, method);
        }
    }

    fn visit_item_impl(&mut self, block: &'ast syn::ItemImpl) {
        if crate::test_source_text::test_only(&block.attrs) {
            return;
        }
        let bare = self.bare_counts.last().copied().unwrap_or(false);
        if block.trait_.is_none() && names_protocol_task(&block.self_ty, bare) {
            for member in &block.items {
                if let syn::ImplItem::Fn(method) = member
                    && !matches!(method.vis, syn::Visibility::Inherited)
                    && !crate::test_source_text::test_only(&method.attrs)
                {
                    self.out.push(method.sig.ident.to_string());
                }
            }
        }
        syn::visit::visit_item_impl(self, block);
    }
}

/// The names of the non-private methods (any `pub` form) in the protocol
/// `Task`'s inherent impls anywhere in a file's `items` (see [`TaskImplWalk`]).
/// `declares_protocol_task`: these are src/protocol/tasks.rs's own items,
/// whose `Task` is the protocol's.
fn task_methods_in(
    items: &[syn::Item],
    declares_protocol_task: bool,
    in_protocol: bool,
    out: &mut Vec<String>,
) {
    use syn::visit::Visit as _;
    let root = declares_protocol_task || !module_has_other_task(items, in_protocol);
    let mut walk = TaskImplWalk {
        in_protocol,
        bare_counts: vec![root],
        out,
    };
    for item in items {
        walk.visit_item(item);
    }
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

/// Every non-private method of the protocol `Task`, read with syn from every
/// production file: an inherent impl may sit in any module, under a bare
/// `Task` or a `protocol::tasks::Task` path. Fails closed: a file syn cannot
/// parse fails the row by name, since it could hide an impl.
///
/// Boundary: an impl a macro expands to is not read, and a module that reaches
/// the protocol `Task` only through a glob import is read as if it saw no other
/// `Task`.
#[test]
fn task_methods_are_classified() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut found = Vec::new();
    let mut unparsed = Vec::new();
    for (file, _) in production_sources() {
        let raw = std::fs::read_to_string(root.join(&file)).expect("a listed source is readable");
        let Ok(parsed) = syn::parse_file(&raw) else {
            unparsed.push(file);
            continue;
        };
        task_methods_in(
            &parsed.items,
            file == PROTOCOL_TASKS,
            file == "src/protocol.rs" || file.starts_with("src/protocol/"),
            &mut found,
        );
    }
    assert!(
        unparsed.is_empty(),
        "syn could not parse {unparsed:?}, so the method scan cannot vouch for them"
    );
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
/// names the `Task` type, as (file, count). The name is common elsewhere, so in
/// a file that never names `Task` only a call on a receiver whose name holds
/// `task` counts. A new accessor anywhere still fails
/// `task_methods_are_classified`.
///
/// Boundary: a `Task` held under a binding without `task` in its name, in a
/// file that never spells `Task`, is not seen. Closing that takes the types
/// (rust-analyzer), not the text.
const SNAPSHOT_USES: &[(&str, usize)] = &[
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
        .filter_map(|(file, code)| {
            // Exact where the type is spelled; elsewhere a task-named receiver.
            let uses = if names_task(&code) {
                path_uses(&code, "snapshot")
            } else {
                task_receiver_calls(&code, "snapshot")
            };
            (uses > 0).then_some((file, uses))
        })
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
    let methods = |code: &str, declares: bool| {
        let parsed = syn::parse_file(code).expect("the fixture parses");
        let mut out = Vec::new();
        task_methods_in(&parsed.items, declares, false, &mut out);
        out
    };
    // Every pub form, split signatures, qualified and bare impls, private and
    // test-only methods left out, another type's impl ignored.
    let code = "impl Task {\n    pub fn id(&self) {}\n    pub(crate) const fn ttl_ms(&self) {}\n    \
                fn private(&self) {}\n    pub(in crate::protocol) async unsafe fn\n        split(&self) {}\n    \
                #[cfg(test)]\n    pub fn probe(&self) {}\n}\nimpl Other {\n    pub fn outside(&self) {}\n}\n\
                impl crate::protocol::tasks::Task {\n    pub(super) fn qualified(&self) {}\n}\n\
                mod inner {\n    impl crate::protocol::Task {\n        pub fn nested(&self) {}\n    }\n}";
    assert_eq!(
        methods(code, false),
        ["id", "ttl_ms", "split", "qualified", "nested"]
    );
    // A module with a Task of its own: its bare impl names that type, while a
    // qualified one and a sibling module's bare impl still count.
    let shadowed = "struct Task;\nimpl Task {\n    pub fn local(&self) {}\n}\n\
                    impl crate::protocol::tasks::Task {\n    pub fn real(&self) {}\n}\n\
                    mod clean {\n    impl Task {\n        pub fn sibling(&self) {}\n    }\n}";
    assert_eq!(methods(shadowed, false), ["real", "sibling"]);
    // tasks.rs itself declares the protocol Task, so its bare impl counts there.
    assert_eq!(
        methods(
            "pub struct Task;\nimpl Task {\n    pub fn wire(&self) {}\n}",
            true
        ),
        ["wire"]
    );
    let imported = "use crate::a2a::types::Task;\nimpl Task {\n    pub fn foreign(&self) {}\n}";
    assert!(methods(imported, false).is_empty());
    let protocol_use = "use crate::protocol::tasks::{Task, TaskStatus};\nimpl Task {\n    pub fn mine(&self) {}\n}";
    assert_eq!(methods(protocol_use, false), ["mine"]);
    // Impls nested anywhere count: in a const block and in a function body.
    // A test-only one is skipped with what is under it.
    let nested = "const _: () = {\n    impl crate::protocol::tasks::Task {\n        pub fn in_const(&self) {}\n    }\n};\n\
                  fn helper() {\n    impl Task {\n        pub fn in_body(&self) {}\n    }\n}\n\
                  #[cfg(test)]\nconst _: () = {\n    impl Task {\n        pub fn test_built(&self) {}\n    }\n};";
    assert_eq!(methods(nested, false), ["in_const", "in_body"]);
    // A test-only Task declaration or import shadows nothing in production.
    let test_shadow = "#[cfg(test)]\nstruct Task;\n#[cfg(test)]\nuse crate::a2a::types::Task as Task;\n\
                       impl Task {\n    pub fn kept(&self) {}\n}";
    assert_eq!(methods(test_shadow, false), ["kept"]);
    // Relative and one-segment imports are read as the protocol's, as the text
    // scan did; only a crate:: path to another module names another Task, and
    // a different type renamed to Task does too.
    for relative in [
        "use super::Task;",
        "use self::tasks::Task;",
        "use tasks::Task;",
    ] {
        let code = format!("{relative}\nimpl Task {{\n    pub fn relative(&self) {{}}\n}}");
        assert_eq!(methods(&code, false), ["relative"], "{relative}");
    }
    let renamed = "use super::Other as Task;\nimpl Task {\n    pub fn other(&self) {}\n}";
    assert!(methods(renamed, false).is_empty());
    let calls = "task.snapshot(); self.task.result(); entry . task . error (); stats.snapshot(); \
                 task.snapshot_of(); fn snapshot(&self) {} task.snapshot";
    assert_eq!(task_receiver_calls(calls, "snapshot"), 1);
    assert_eq!(task_receiver_calls(calls, "result"), 1);
    assert_eq!(task_receiver_calls(calls, "error"), 1);
    assert!(names_task("let t: Task = x;") && names_task("Task::create()"));
    assert!(!names_task("CommittedTask TaskStatus tasks"));
    assert_eq!(
        path_uses(
            "answered.snapshot(); Task::snapshot(&t); map(Task::snapshot); (answered).snapshot()",
            "snapshot"
        ),
        4
    );
}

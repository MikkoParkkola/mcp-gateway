// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Every way a stored answer leaves the gateway is scrubbed against the
//! values current when it is sent. The exits are enumerated: each
//! store read in [`super::tests::STORED_READS`] is either a scrubbed exit or
//! named here with why it serves nothing itself, and the stored task wire
//! has a fixed set of callers. A new exit fails here until it is scrubbed
//! and listed.

use super::tests::STORED_READS;

/// Each scrub call that guards an exit: `(file, call, occurrences, exit)`.
const SCRUBBED_EXITS: &[(&str, &str, usize, &str)] = &[
    (
        "src/gateway/meta_mcp/invoke/pre_dispatch.rs",
        "scrub_stored_value(",
        2,
        "a response-cache hit; a keyed call's 7a cached result",
    ),
    (
        "src/gateway/meta_mcp/invoke/pre_dispatch.rs",
        "scrub_stored_text(",
        1,
        "a keyed call's 7a cached error",
    ),
    (
        "src/gateway/router/backend_handlers/direct_idempotency.rs",
        "scrub_stored(",
        1,
        "replay_scan: every direct-route 7a result or error and 7b replay",
    ),
    (
        "src/gateway/meta_mcp/admission.rs",
        "scrub_stored(",
        1,
        "the 7b replay, where SyncAdmission::Replay is built for every route",
    ),
    (
        "src/gateway/meta_mcp/invoke/egress.rs",
        "scrub_stored_value(",
        1,
        "scan_stored_task: tasks/get on both routes and task notifications",
    ),
    (
        "src/gateway/meta_mcp/call_dispatch/task_intake.rs",
        "scrub_stored(",
        1,
        "a repeated keyed task (BeginOutcome::Existing)",
    ),
];

/// Files in `STORED_READS` that are not themselves exits, each with where
/// what it reads is scrubbed (or why it needs no scrub).
const NOT_EXITS: &[(&str, &str)] = &[
    ("src/cache.rs", "the response cache itself"),
    (
        "src/capability/executor/mod.rs",
        "a capability backend's own cache: it holds no backend's configured or injected values",
    ),
    ("src/gateway/meta_mcp/invoke/cache_reads.rs", "inline tests"),
    (
        "src/idempotency/guard.rs",
        "the idempotency guard's outcome type",
    ),
    (
        "src/idempotency/admission.rs",
        "the execution store's outcome type",
    ),
    (
        "src/gateway/router/handlers/dispatch_tools_call.rs",
        "serves the SyncAdmission::Replay admission.rs scrubbed",
    ),
    (
        "src/gateway/server/stdio_dispatch.rs",
        "serves the SyncAdmission::Replay admission.rs scrubbed",
    ),
    (
        "src/gateway/router/handlers/tasks.rs",
        "tasks/get definition: its frame passes scan_task_read",
    ),
    (
        "src/gateway/router/handlers.rs",
        "the tasks/get arm: its frame passes scan_task_read",
    ),
    (
        "src/gateway/server/stdio_tasks.rs",
        "the stdio tasks/get arm: its frame passes scan_task_read",
    ),
];

/// Every production caller of the stored task wire, and where its output is
/// scrubbed.
const TASK_WIRE_CALLERS: &[(&str, &str)] = &[
    ("src/gateway/task_route.rs", "tasks/get: scan_task_read"),
    (
        "src/gateway/task_service/execution.rs",
        "BeginOutcome::into_response: scrubbed in task_intake.rs",
    ),
    ("src/gateway/meta_mcp/task_notify.rs", "scan_stored_task"),
];

fn source(path: &str) -> String {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    std::fs::read_to_string(root.join(path)).unwrap_or_else(|e| panic!("{path}: {e}"))
}

/// Each listed scrub is where it says, as many times as it says: removing
/// one (or a new exit's call left unlisted) fails here.
#[test]
fn every_listed_exit_scrubs_what_it_serves() {
    for (file, call, count, exit) in SCRUBBED_EXITS {
        let found = source(file).matches(call).count();
        assert_eq!(found, *count, "{file}: {call} for {exit}");
    }
}

/// Every file that reads a stored answer is a scrubbed exit or is named with
/// why it is not.
#[test]
fn every_stored_read_is_a_scrubbed_exit_or_named() {
    for (_, file, _, _) in STORED_READS {
        let scrubbed = SCRUBBED_EXITS.iter().any(|(f, ..)| f == file);
        let named = NOT_EXITS.iter().any(|(f, _)| f == file);
        assert!(
            scrubbed || named,
            "{file} reads a stored answer: scrub it on the way out, then list it"
        );
    }
}

/// The stored task wire has exactly the listed production callers.
#[test]
fn the_stored_task_wire_has_only_listed_callers() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut found = Vec::new();
    for entry in walk(&root.join("src")) {
        let rel = entry.strip_prefix(root).expect("under the crate");
        let rel = rel.to_string_lossy().replace('\\', "/");
        if rel.ends_with("_tests.rs")
            || rel.contains("_tests/")
            || rel.contains("/tests/")
            || rel == "src/gateway/task_service/record.rs"
        {
            continue;
        }
        if std::fs::read_to_string(&entry).is_ok_and(|text| text.contains(".delivered_wire()")) {
            found.push(rel);
        }
    }
    found.sort();
    let mut listed: Vec<String> = TASK_WIRE_CALLERS
        .iter()
        .map(|(f, _)| (*f).to_owned())
        .collect();
    listed.sort();
    assert_eq!(
        found, listed,
        "a new caller of delivered_wire serves stored task output"
    );
}

fn walk(dir: &std::path::Path) -> Vec<std::path::PathBuf> {
    let mut out = Vec::new();
    for entry in std::fs::read_dir(dir).expect("src reads") {
        let path = entry.expect("a directory entry").path();
        if path.is_dir() {
            out.extend(walk(&path));
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            out.push(path);
        }
    }
    out
}

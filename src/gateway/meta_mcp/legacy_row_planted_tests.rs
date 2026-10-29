// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A task row a published 4.0 pre-release stored (record version 6 at most,
//! no call bindings) is not stripped when served: it is refused instead, so a
//! member its backend planted is never delivered. Both stored-read paths,
//! HTTP (`router/handlers/tasks.rs`) and stdio (`server/stdio_tasks.rs`),
//! serve through `refuse_stored_delivery`, judged here. If that judge ever
//! serves such a row, this fails and the old rows need a read-time strip.

use super::grant_audit::with_grant_slot;
use super::grant_audit_fixture::{CAPS, Endpoint, PERSONAL, grant};
use super::grant_decision_audit_tests::{api_key, context, gateway};
use crate::gateway::task_service::{CommittedTask, Target, Task};
use crate::protocol::RequestId;
use crate::protocol::reserved_members::test_support::planted;
use crate::security::audit::AuditFailurePolicy;

const ALICE: (&str, &str) = ("api_key", "alice");

#[tokio::test]
async fn a_pre_binding_row_with_a_planted_member_is_refused_when_served() {
    let (endpoint, dir) = (Endpoint::start(false).await, tempfile::tempdir().unwrap());
    let meta = gateway(
        &endpoint,
        vec![grant("g-legacy", ALICE, ALICE)],
        Some(&dir),
        AuditFailurePolicy::FailClosed,
    );
    let mut task = Task::create("gateway_invoke").expect("the test clock reads after 1970");
    task.complete(&planted())
        .expect("a live task takes its outcome");
    let stored = CommittedTask {
        task,
        revision: 1,
        targets: vec![Target {
            server: CAPS.to_owned(),
            tool: PERSONAL.to_owned(),
        }],
        targets_recorded: true,
        output_free: false,
        error_author: None,
        owner_digest: String::new(),
        gateway_writes: crate::gateway::gateway_writes::WriteRecord::default(),
        bindings: Vec::new(),
        // As every row a published pre-release wrote reads.
        bindings_recorded: false,
    };
    let alice = api_key("alice");
    let caller = context(&alice);
    let (refusal, _, _) = with_grant_slot(meta.transparency_logger.as_ref(), async {
        meta.refuse_stored_delivery(&RequestId::Number(1), &stored, None, Some("s"), &caller)
    })
    .await;
    let refusal = refusal
        .expect("a pre-binding row's output is refused")
        .into_response();
    let body = serde_json::to_string(&refusal).expect("serializes");
    assert!(refusal.error.is_some(), "{body}");
    assert!(!body.contains("FORGED-"), "{body}");
    assert!(refusal.result.is_none(), "{body}");
}

/// The source files, outside test code, whose text contains `needle`, as
/// `src/...` paths. A path naming `test` anywhere is test code.
fn files_containing(needle: &str) -> Vec<String> {
    fn walk(dir: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
        for entry in std::fs::read_dir(dir).expect("src reads").flatten() {
            let path = entry.path();
            if path.is_dir() {
                walk(&path, out);
            } else if path.extension().is_some_and(|ext| ext == "rs") {
                out.push(path);
            }
        }
    }
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut files = Vec::new();
    walk(&root.join("src"), &mut files);
    let mut hits: Vec<String> = files
        .iter()
        .filter_map(|path| {
            let relative = path
                .strip_prefix(root)
                .ok()?
                .to_string_lossy()
                .replace('\\', "/");
            let text = std::fs::read_to_string(path).ok()?;
            (!relative.contains("test") && text.contains(needle)).then_some(relative)
        })
        .collect();
    hits.sort();
    hits
}

/// The row above proves the judge refuses an old row; this proves every
/// route still asks it. The files that serve a stored task (through
/// `TaskRoute` or a repeated call's `BeginOutcome::Existing`) are a closed
/// set, each calling the judge. A new serving file changes a set and fails
/// here until its judge call is wired and listed.
#[test]
fn every_stored_read_route_asks_the_judge() {
    assert_eq!(
        files_containing("TaskRoute"),
        [
            "src/gateway/router/handlers/tasks.rs",
            "src/gateway/server/stdio_tasks.rs",
            "src/gateway/task_route.rs",
        ],
        "a new file serves tasks/get: wire refuse_stored_delivery and list it"
    );
    assert_eq!(
        files_containing("BeginOutcome::Existing"),
        [
            "src/gateway/meta_mcp/call_dispatch/task_intake.rs",
            "src/gateway/meta_mcp/task_replay.rs",
            "src/gateway/task_service/execution/worker.rs",
        ],
        "a new file serves a repeated task call: wire refuse_stored_repeat and list it"
    );
    let source = |path: &str| {
        std::fs::read_to_string(std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(path))
            .expect("reads")
    };
    // HTTP: `tasks/get` and the notification frame; stdio: `tasks/get`.
    for (path, judge, calls) in [
        (
            "src/gateway/router/handlers/tasks.rs",
            "refuse_stored_delivery(",
            2,
        ),
        (
            "src/gateway/server/stdio_tasks.rs",
            "refuse_stored_delivery(",
            1,
        ),
        (
            "src/gateway/meta_mcp/call_dispatch/task_intake.rs",
            "refuse_stored_repeat(",
            1,
        ),
    ] {
        assert_eq!(
            source(path).matches(judge).count(),
            calls,
            "{path} no longer calls {judge} at each serve site"
        );
    }
}

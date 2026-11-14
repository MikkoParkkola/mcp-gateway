// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A recovered upstream task whose result an enforcing context-integrity gate
//! rewrote records `rewritten` on its `task_recovery` settlement record, through
//! the real recovery entry and the settlement callback `tasks/get` builds.

use std::sync::Arc;
use std::time::Duration;

use serde_json::Value;

use super::{BACKEND, OWNER, Reply, TOOL, seed_capturable_task};
use crate::backend::BackendRegistry;
use crate::context_integrity::{
    ContextIntegrityDecisionKind, ContextIntegrityKernel, ContextIntegrityPolicy,
};
use crate::gateway::meta_mcp::MetaMcp;
use crate::gateway::meta_mcp::invoke::audit::{DispatchNotes, SettledTask};
use crate::protocol::tasks::TaskTransition;

/// The `task_recovery` record of one recovery of a task answering `reply`,
/// under an enforcing gate that strips untrusted instructions.
async fn recovery_record(reply: Reply) -> Value {
    let log_dir = crate::test_dir_keep::kept_tempdir();
    let mut meta = MetaMcp::new(Arc::new(BackendRegistry::new()));
    meta.set_context_integrity_kernel(ContextIntegrityKernel::new(ContextIntegrityPolicy {
        untrusted_instruction_decision: ContextIntegrityDecisionKind::Strip,
        ..ContextIntegrityPolicy::enforcing_baseline()
    }));
    let log = crate::security::TransparencyLogger::open(Arc::new(
        crate::security::transparency_log::TransparencyLogConfig {
            enabled: true,
            path: log_dir
                .path()
                .join("audit.jsonl")
                .to_string_lossy()
                .into_owned(),
            key_id: "recovered-rewrite".to_string(),
            ..crate::security::transparency_log::TransparencyLogConfig::default()
        },
    ))
    .expect("the log opens");
    meta.enable_transparency_log(Arc::new(log));
    let meta = Arc::new(meta);
    let (service, executor, id, _store) = seed_capturable_task(reply).await;
    let owner_digest = service
        .owner(OWNER)
        .expect("admission hashes the fixture principal")
        .as_digest()
        .to_owned();
    // The three callbacks `handlers::tasks::recover_from_upstream` builds,
    // over the same implementations.
    let (result_policy, error_policy, settler) =
        (Arc::clone(&meta), Arc::clone(&meta), Arc::clone(&meta));
    let (trace, task_id) = (id.clone(), id.clone());
    let settled = Box::pin(executor.recover_upstream_read(
        &owner_digest,
        &id,
        true,
        move |result| {
            result_policy
                .recover_task_result(BACKEND, TOOL, None, &trace, result)
                .map_err(|error| {
                    crate::gateway::meta_mcp::response_security::recovered_result_error(&error)
                })
        },
        move |error| error_policy.recover_task_error_with(BACKEND, TOOL, None, "trace", error),
        move |event: TaskTransition, notes: DispatchNotes| async move {
            let task = SettledTask {
                server: BACKEND,
                tool: TOOL,
                id: &task_id,
            };
            settler
                .audit_settlement_kept(task, event, &notes, OWNER)
                .await
        },
        Duration::from_secs(5),
    ))
    .await;
    assert!(
        matches!(settled, Ok(super::RecoveredRead::Settled)),
        "premise: the recovery settled"
    );
    let text = std::fs::read_to_string(log_dir.path().join("audit.jsonl")).unwrap_or_default();
    let records: Vec<Value> = text
        .lines()
        .filter_map(|line| serde_json::from_str::<Value>(line).ok())
        .filter(|entry| entry["route"] == "task_recovery")
        .collect();
    let [record] = records.as_slice() else {
        panic!("premise: exactly one task_recovery record: {text}");
    };
    record.clone()
}

#[tokio::test]
async fn a_recovered_rewrite_records_rewritten_through_the_real_entry() {
    let rewritten = Box::pin(recovery_record(Reply::CompletedInjected)).await;
    assert_eq!(rewritten["response_effect"], "rewritten", "{rewritten}");
    // Paired control: a clean recovered result's record carries no effect.
    let clean = Box::pin(recovery_record(Reply::Completed)).await;
    assert!(clean.get("response_effect").is_none(), "{clean}");
}

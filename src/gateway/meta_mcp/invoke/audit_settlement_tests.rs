// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIN.1 gap 1: a failed settlement write under `BestEffort` is counted.

use std::sync::Arc;

use serde_json::json;

use super::{DispatchNotes, SettledTask};
use crate::backend::BackendRegistry;
use crate::gateway::meta_mcp::MetaMcp;
use crate::protocol::tasks::TaskTransition;
use crate::security::TransparencyLogger;
use crate::security::audit::AuditFailurePolicy;
use crate::security::transparency_log::TransparencyLogConfig;

/// The transition commits, and the failure is counted on the metric the
/// design names, through a recorder local to this test.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_failed_best_effort_settlement_write_is_counted() {
    let dir = tempfile::tempdir().unwrap();
    let log = TransparencyLogger::open(Arc::new(TransparencyLogConfig {
        enabled: true,
        path: dir
            .path()
            .join("audit.jsonl")
            .to_string_lossy()
            .into_owned(),
        key_id: "min1".to_string(),
        ..TransparencyLogConfig::default()
    }))
    .expect("open log")
    .with_failure_policy(AuditFailurePolicy::BestEffort);
    let log = Arc::new(log);
    let mut meta = MetaMcp::new(Arc::new(BackendRegistry::new()));
    meta.enable_transparency_log(Arc::clone(&log));
    log.set_append_failure_for_test(true);

    let recorder = metrics_exporter_prometheus::PrometheusBuilder::new().build_recorder();
    let handle = recorder.handle();
    let task = SettledTask {
        server: "srv",
        tool: "read",
        id: "task-1",
    };
    let proposed = TaskTransition::Complete(json!({ "content": [] }));
    let committed = telemetry_metrics::with_local_recorder(&recorder, || {
        tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(meta.audit_settlement(
                task,
                proposed,
                &DispatchNotes::default(),
                "owner",
            ))
        })
    });

    assert!(
        matches!(committed, TaskTransition::Complete(_)),
        "BestEffort commits the recovered transition"
    );
    let rendered = handle.render();
    assert!(
        rendered.lines().any(|line| {
            line.starts_with("mcp_audit_settlement_write_failures_total") && line.ends_with(" 1")
        }),
        "{rendered}"
    );
}

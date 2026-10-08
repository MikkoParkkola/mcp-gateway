// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIN.1 gap 1: the settlement record helper: the `BestEffort` failure
//! counter, and the outcome class of a refused recovered result.

use std::sync::Arc;

use serde_json::json;

use super::{DispatchNotes, SettledTask};
use crate::backend::BackendRegistry;
use crate::gateway::meta_mcp::MetaMcp;
use crate::protocol::tasks::TaskTransition;
use crate::security::TransparencyLogger;
use crate::security::audit::AuditOutcome;
use crate::security::transparency_log::TransparencyLogConfig;

/// The transition commits, and the failure is counted on the metric the
/// design names, through a recorder local to this test.
#[cfg(feature = "metrics")]
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
    .with_failure_policy(crate::security::audit::AuditFailurePolicy::BestEffort);
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

fn meta_logging_to(dir: &tempfile::TempDir) -> MetaMcp {
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
    .expect("open log");
    let mut meta = MetaMcp::new(Arc::new(BackendRegistry::new()));
    meta.enable_transparency_log(Arc::new(log));
    meta
}

/// A gate refusal of a recovered result keeps the class a live call's record
/// gives it (`denied`), with the code the task commits.
#[tokio::test]
async fn a_refused_settlement_keeps_the_refusal_class() {
    let dir = tempfile::tempdir().unwrap();
    let meta = meta_logging_to(&dir);
    let notes = DispatchNotes {
        refusal: Some(AuditOutcome::Denied(-32001)),
        ..DispatchNotes::default()
    };
    let proposed = TaskTransition::Fail(crate::protocol::JsonRpcError {
        code: -32603,
        message: "refused".to_string(),
        data: None,
    });
    let task = SettledTask {
        server: "srv",
        tool: "read",
        id: "task-1",
    };
    let _ = meta.audit_settlement(task, proposed, &notes, "owner").await;

    let text = std::fs::read_to_string(dir.path().join("audit.jsonl")).unwrap();
    let record: serde_json::Value = text
        .lines()
        .filter_map(|line| serde_json::from_str(line).ok())
        .find(|entry: &serde_json::Value| entry["route"] == "task_recovery")
        .unwrap_or_else(|| panic!("a settlement record: {text}"));
    assert_eq!(record["outcome"], json!("denied"), "{record}");
    assert_eq!(record["error_code"], json!(-32603), "{record}");
}

/// The firewall's response refusal is classed `denied`, as `from_result`
/// classes it for a live call.
#[tokio::test]
async fn a_firewall_refusal_is_noted_as_denied() {
    let ((), notes) = super::with_dispatch_scope(async {
        super::note_refusal(&Err(crate::Error::ResponseFirewallRefused));
    })
    .await;
    assert!(
        matches!(notes.refusal, Some(AuditOutcome::Denied(_))),
        "{notes:?}"
    );
}

/// `recover_task_result` notes its own refusal, on both recovery paths.
#[tokio::test]
async fn recover_task_result_notes_its_refusal() {
    let mut meta = MetaMcp::new(Arc::new(BackendRegistry::new()));
    meta.enable_response_inspection_action_mode();
    let key = ["AKIA", "IOSFODNN7", "EXAMPLE"].concat();
    let result =
        json!({ "content": [{ "type": "text", "text": format!("AWS_ACCESS_KEY_ID={key}") }] });
    let (gated, notes) = super::with_dispatch_scope(async {
        meta.recover_task_result("srv", "read", None, "task-1", result)
    })
    .await;
    assert!(gated.is_err(), "inspection refuses the recovered result");
    assert_eq!(
        notes.refusal,
        Some(AuditOutcome::Error(-32603)),
        "{notes:?}"
    );
}

/// MIK-7735. A recovered upstream task that failed with the peer's own
/// `-32001` settles as `error`: no gateway gate refused it. A refusal the
/// gateway noted keeps `denied` (`a_refused_settlement_keeps_the_refusal_class`).
#[tokio::test]
async fn a_peer_failure_code_settles_as_error_not_denied() {
    let dir = tempfile::tempdir().unwrap();
    let meta = meta_logging_to(&dir);
    let proposed = TaskTransition::Fail(crate::protocol::JsonRpcError {
        code: -32001,
        message: "the peer's own refusal".to_string(),
        data: None,
    });
    let task = SettledTask {
        server: "srv",
        tool: "read",
        id: "task-1",
    };
    let _ = meta
        .audit_settlement(task, proposed, &DispatchNotes::default(), "owner")
        .await;

    let text = std::fs::read_to_string(dir.path().join("audit.jsonl")).unwrap();
    let record: serde_json::Value = text
        .lines()
        .filter_map(|line| serde_json::from_str(line).ok())
        .find(|entry: &serde_json::Value| entry["route"] == "task_recovery")
        .unwrap_or_else(|| panic!("a settlement record: {text}"));
    assert_eq!(record["outcome"], json!("error"), "{record}");
    assert_eq!(record["error_code"], json!(-32001), "{record}");
}

/// The gateway's own `-32001` refusal of a recovered result still settles
/// `denied`: the refusal is noted by the gate, whatever code it carries.
#[tokio::test]
async fn a_gateway_refusal_with_code_32001_still_settles_denied() {
    let dir = tempfile::tempdir().unwrap();
    let meta = meta_logging_to(&dir);
    let notes = DispatchNotes {
        refusal: Some(AuditOutcome::Denied(-32001)),
        ..DispatchNotes::default()
    };
    let proposed = TaskTransition::Fail(crate::protocol::JsonRpcError {
        code: -32001,
        message: "refused".to_string(),
        data: None,
    });
    let task = SettledTask {
        server: "srv",
        tool: "read",
        id: "task-1",
    };
    let _ = meta.audit_settlement(task, proposed, &notes, "owner").await;

    let text = std::fs::read_to_string(dir.path().join("audit.jsonl")).unwrap();
    let record: serde_json::Value = text
        .lines()
        .filter_map(|line| serde_json::from_str(line).ok())
        .find(|entry: &serde_json::Value| entry["route"] == "task_recovery")
        .unwrap_or_else(|| panic!("a settlement record: {text}"));
    assert_eq!(record["outcome"], json!("denied"), "{record}");
}

/// MIK-7887.RECEIPT.1: the helper says whether it kept the proposed outcome.
/// A written record keeps it; a failed write under `FailClosed` replaces it
/// with the gateway's own refusal, which is never the peer's error.
#[tokio::test]
async fn a_fail_closed_replacement_is_reported_as_not_kept() {
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
    .with_failure_policy(crate::security::audit::AuditFailurePolicy::FailClosed);
    let log = Arc::new(log);
    let mut meta = MetaMcp::new(Arc::new(BackendRegistry::new()));
    meta.enable_transparency_log(Arc::clone(&log));
    let task = SettledTask {
        server: "srv",
        tool: "read",
        id: "task-1",
    };
    let peer = || {
        TaskTransition::Fail(crate::protocol::JsonRpcError {
            code: -32001,
            message: "the peer's own refusal".to_string(),
            data: None,
        })
    };
    let notes = DispatchNotes::default();
    let (_, kept) = meta
        .audit_settlement_kept(task, peer(), &notes, "owner")
        .await;
    assert!(kept, "a written record keeps the proposed outcome");

    log.set_append_failure_for_test(true);
    let (committed, kept) = meta
        .audit_settlement_kept(task, peer(), &notes, "owner")
        .await;
    assert!(!kept, "the replacement is the gateway's: {committed:?}");
    assert!(
        matches!(&committed, TaskTransition::Fail(error) if error.message != "the peer's own refusal"),
        "{committed:?}"
    );
}

/// MIK-7960. A recovered upstream task that failed with the peer's own
/// `-32602` settles as `error`: the peer refused its own parameters, and no
/// gateway gate judged the caller's input.
#[tokio::test]
async fn a_peer_invalid_params_code_settles_as_error_not_invalid() {
    let record = settle_failure(-32602, &DispatchNotes::default()).await;
    assert_eq!(record["outcome"], json!("error"), "{record}");
    assert_eq!(record["error_code"], json!(-32602), "{record}");
}

/// MIK-7960 control. A refusal of class `invalid` the gateway noted keeps
/// `invalid`.
#[tokio::test]
async fn a_gateway_invalid_refusal_still_settles_invalid() {
    let notes = DispatchNotes {
        refusal: Some(AuditOutcome::Invalid(-32602)),
        ..DispatchNotes::default()
    };
    let record = settle_failure(-32602, &notes).await;
    assert_eq!(record["outcome"], json!("invalid"), "{record}");
    assert_eq!(record["error_code"], json!(-32602), "{record}");
}

/// Settle a recovered task that failed with `code` and return its record.
async fn settle_failure(code: i32, notes: &DispatchNotes) -> serde_json::Value {
    let dir = tempfile::tempdir().unwrap();
    let meta = meta_logging_to(&dir);
    let proposed = TaskTransition::Fail(crate::protocol::JsonRpcError {
        code,
        message: "failed".to_string(),
        data: None,
    });
    let task = SettledTask {
        server: "srv",
        tool: "read",
        id: "task-1",
    };
    let _ = meta.audit_settlement(task, proposed, notes, "owner").await;
    let text = std::fs::read_to_string(dir.path().join("audit.jsonl")).unwrap();
    text.lines()
        .filter_map(|line| serde_json::from_str(line).ok())
        .find(|entry: &serde_json::Value| entry["route"] == "task_recovery")
        .unwrap_or_else(|| panic!("a settlement record: {text}"))
}

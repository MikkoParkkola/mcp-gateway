// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A key write's intent names who wrote which key; every other kind's intent
//! keeps naming the gateway, as before.

use std::sync::Arc;

use serde_json::Value;

use super::reload_context::replace::{
    Audit, AuditPosture, FileRevision, GatewayAuth, Intent, IntentKind,
};
use crate::security::audit::AuditWho;

/// An audit log in `dir`, and the posture of a gateway with auth on over it.
fn posture(
    dir: &Arc<tempfile::TempDir>,
) -> (Arc<crate::security::TransparencyLogger>, AuditPosture) {
    let log = Arc::new(
        crate::security::TransparencyLogger::open(Arc::new(
            crate::security::transparency_log::TransparencyLogConfig {
                enabled: true,
                path: dir
                    .path()
                    .join("audit.jsonl")
                    .to_string_lossy()
                    .into_owned(),
                key_id: "key-write-intent".to_string(),
                ..Default::default()
            },
        ))
        .expect("open log"),
    );
    // The log keeps its directory until its last handle.
    log.keep_test_dir(Arc::clone(dir));
    let posture = AuditPosture::of(Some(Arc::clone(&log)), GatewayAuth::On);
    (log, posture)
}

/// The one intent record `log` holds (a new log opens with its own
/// segment record first).
fn only_record(log: &crate::security::TransparencyLogger) -> Value {
    let records: Vec<Value> = std::fs::read_to_string(log.path())
        .expect("the log was written")
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).expect("a JSON record"))
        .filter(|record| {
            record["event"]
                .as_str()
                .is_some_and(|event| event.ends_with("_intent"))
        })
        .collect();
    assert_eq!(records.len(), 1, "{records:?}");
    records.into_iter().next().expect("one record")
}

fn admin() -> AuditWho {
    AuditWho {
        credential_kind: None,
        principal: crate::gateway::record_principal::RecordPrincipal::none(),
        account: "admin-alpha".to_owned(),
        authority: None,
        subject: None,
    }
}

/// Append `audit`'s own intent, as the writer does, against `base`.
fn append(audit: Audit) {
    let Audit::Required {
        mut sink,
        kind,
        writer,
    } = audit
    else {
        panic!("an audit log means a required audit");
    };
    let intent = Intent {
        kind,
        base: FileRevision::of(b"before"),
        outside_change: false,
        recovery_intent_id: None,
        writer,
    };
    sink.append(&intent).expect("the append succeeds");
}

#[test]
fn a_key_write_intent_names_its_actor_and_key() {
    let dir = Arc::new(tempfile::tempdir().expect("tempdir"));
    let (log, posture) = posture(&dir);
    let audit = posture
        .key_write(IntentKind::KeyCreate, admin(), "alpha")
        .expect("an audited posture");
    append(audit);
    let record = only_record(&log);
    assert_eq!(record["event"], "config_key_create_intent", "{record}");
    assert_eq!(record["subject"], "alpha", "{record}");
    assert_eq!(record["who"]["account"], "admin-alpha", "{record}");
}

#[test]
fn every_other_kind_keeps_naming_the_gateway() {
    let gateway = serde_json::to_value(AuditWho::gateway()).expect("serializes");
    for kind in [
        IntentKind::Save { fields: Vec::new() },
        IntentKind::Adopt,
        IntentKind::Restore,
        IntentKind::Recovery,
    ] {
        let dir = Arc::new(tempfile::tempdir().expect("tempdir"));
        let (log, posture) = posture(&dir);
        append(posture.audit(kind.clone()).expect("an audited posture"));
        let record = only_record(&log);
        assert_eq!(record["who"], gateway, "{kind:?}: {record}");
        assert!(record.get("subject").is_none(), "{kind:?}: {record}");
    }
}

// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The issuance helper reports how far the append got, raw.

use super::issuance::IssuanceWrite;
use crate::key_server::issuance_row_tests::open_log;
use crate::security::audit::{AuditEnvelope, AuditFailurePolicy};

fn row(event: &str) -> serde_json::Map<String, serde_json::Value> {
    serde_json::Map::from_iter([
        ("event".to_owned(), event.into()),
        ("token_jti".to_owned(), "j1".into()),
    ])
}

/// Only a `token.issued` row is appended; anything else is refused before
/// any write.
/// Mutant: drop the event check.
#[tokio::test]
async fn a_row_that_is_not_an_issuance_is_never_attempted() {
    let dir = crate::test_dir_keep::kept_tempdir();
    let log = open_log(&dir, AuditFailurePolicy::BestEffort);
    let size = |l: &crate::security::TransparencyLogger| {
        std::fs::metadata(l.path()).map_or(0, |m| m.len())
    };
    let before = size(&log);
    let out = log
        .append_issuance_row(row("admin_action"), AuditEnvelope::gateway())
        .await;
    assert!(matches!(out, IssuanceWrite::NotAttempted(_)), "{out:?}");
    assert_eq!(out.label(), "not_attempted");
    assert_eq!(size(&log), before, "nothing was written");
}

/// The four raw outcomes keep their own fixed labels.
/// Mutant: fold `NotStarted` or `Unconfirmed` into `Failed`.
#[tokio::test]
async fn each_raw_outcome_has_its_own_label() {
    let dir = crate::test_dir_keep::kept_tempdir();
    let log = open_log(&dir, AuditFailurePolicy::BestEffort);
    let ok = log
        .append_issuance_row(row("token.issued"), AuditEnvelope::gateway())
        .await;
    assert_eq!(ok.label(), "confirmed");
    log.fail_next_append_for_test();
    let failed = log
        .append_issuance_row(row("token.issued"), AuditEnvelope::gateway())
        .await;
    assert_eq!(failed.label(), "failed");
    log.close_append_permit_for_test();
    let never = log
        .append_issuance_row(row("token.issued"), AuditEnvelope::gateway())
        .await;
    assert_eq!(never.label(), "not_attempted");

    let dir2 = crate::test_dir_keep::kept_tempdir();
    let log2 = open_log(&dir2, AuditFailurePolicy::BestEffort);
    let gate = log2.stall_next_write_for_test(std::time::Duration::from_millis(200));
    let late = log2
        .append_issuance_row(row("token.issued"), AuditEnvelope::gateway())
        .await;
    assert_eq!(late.label(), "unconfirmed");
    log2.release_and_drain(gate).await;
}

/// A degraded fail-closed log whose probe fails refuses at admission: the
/// helper reports that nothing was attempted, not a failed append.
/// Mutant: skip admission.
#[tokio::test]
async fn an_admission_error_is_reported_as_not_attempted() {
    let dir = crate::test_dir_keep::kept_tempdir();
    let log = open_log(&dir, AuditFailurePolicy::FailClosed);
    log.set_append_failure_for_test(true);
    let _ = log.append_event(row("x"), &AuditEnvelope::gateway());
    assert!(log.is_degraded());
    let out = log
        .append_issuance_row(row("token.issued"), AuditEnvelope::gateway())
        .await;
    assert_eq!(out.label(), "not_attempted", "{out:?}");
}

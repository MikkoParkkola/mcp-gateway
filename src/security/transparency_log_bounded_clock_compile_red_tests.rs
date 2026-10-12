// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8202 P4a compile-red row R6: uses the per-logger test setter
//! `set_blocking_clock_before_epoch_for_test`, which the fix adds, so it does
//! not build on the code before it. Kept apart so it can be held back on its
//! own.

use super::bounded_tests::logger;
use super::rotation_tests::log_path;
use crate::security::audit::AuditFailurePolicy;

/// MIK-8202.AC.16 (R6, mutant M6): the degraded probe row is written on the
/// blocking pool (`append_bounded`'s `spawn_blocking` closure); on a clock
/// that reads before 1970 it is kept undated, `timestamp` null and
/// `clock_invalid` true, never the epoch. The per-logger test flag
/// `set_blocking_clock_before_epoch_for_test` makes the closure install
/// `test_clock::before_epoch()` on its own thread before `op` runs (a
/// per-thread override cannot reach that thread from here). Mutant M6: the
/// probe stamps `utc_now().unwrap_or(epoch)`.
#[tokio::test(flavor = "current_thread")]
async fn a_probe_row_on_a_dark_clock_is_undated() {
    let dir = tempfile::tempdir().unwrap();
    let l = logger(&dir, AuditFailurePolicy::FailClosed);
    l.set_blocking_clock_before_epoch_for_test(true);
    l.append_bounded(super::TransparencyLogger::probe)
        .await
        .expect("the probe row is kept on a dark clock");
    let text = std::fs::read_to_string(log_path(&dir)).unwrap();
    let probe: serde_json::Value = text
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap())
        .find(|row| row["type"] == super::degraded::AUDIT_PROBE_TYPE)
        .expect("one probe row persisted");
    assert!(probe["timestamp"].is_null(), "{probe}");
    assert_eq!(probe["clock_invalid"], true, "{probe}");
}

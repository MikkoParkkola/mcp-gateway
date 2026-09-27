// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The port-0 warning is logged once, not on every reload (#1286).

use std::sync::atomic::AtomicBool;

use super::warn_port_zero;
use crate::test_log_capture::{count, records};

/// L1: a failed reload retried five times warns about port 0 once.
#[test]
fn l1_the_port_zero_warning_is_logged_once_across_reloads() {
    let warned = AtomicBool::new(false);
    let logs = records(|| {
        for _ in 0..5 {
            warn_port_zero(0, &warned);
        }
    });
    assert_eq!(count(&logs, "WARN", "Server port is 0"), 1);
}

/// L2: a non-zero port never warns.
#[test]
fn l2_a_set_port_does_not_warn() {
    let warned = AtomicBool::new(false);
    let logs = records(|| warn_port_zero(8080, &warned));
    assert_eq!(count(&logs, "WARN", "Server port is 0"), 0);
}

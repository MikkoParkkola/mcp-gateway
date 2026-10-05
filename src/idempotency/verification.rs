// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
use super::*;

fn any_entry_status() -> CacheEntryStatus {
    match kani::any::<u8>() % 7 {
        0 => CacheEntryStatus::Missing,
        1 => CacheEntryStatus::LiveInFlight,
        2 => CacheEntryStatus::StaleInFlight,
        3 => CacheEntryStatus::LiveCompleted,
        4 => CacheEntryStatus::LiveFailed,
        5 => CacheEntryStatus::ExpiredFailed,
        _ => CacheEntryStatus::ExpiredCompleted,
    }
}

#[kani::proof]
fn idempotency_decision_contract() {
    let status = any_entry_status();
    let (plan, evict) = decide_check_plan(status);

    match status {
        CacheEntryStatus::Missing => {
            assert_eq!(plan, CheckPlan::Proceed);
            assert!(!evict);
        }
        CacheEntryStatus::LiveInFlight => {
            assert_eq!(plan, CheckPlan::InFlight);
            assert!(!evict);
        }
        CacheEntryStatus::StaleInFlight => {
            // ADR-012 consequence 3: a stale in-flight entry is refused,
            // not readmitted, and the sweep is what reclaims it.
            assert_eq!(plan, CheckPlan::InFlight);
            assert!(!evict);
        }
        CacheEntryStatus::LiveCompleted => {
            assert_eq!(plan, CheckPlan::Completed);
            assert!(!evict);
        }
        CacheEntryStatus::ExpiredCompleted => {
            assert_eq!(plan, CheckPlan::Proceed);
            assert!(evict);
        }
        CacheEntryStatus::LiveFailed => {
            assert_eq!(plan, CheckPlan::Failed);
            assert!(!evict);
        }
        CacheEntryStatus::ExpiredFailed => {
            assert_eq!(plan, CheckPlan::Proceed);
            assert!(evict);
        }
    }
}

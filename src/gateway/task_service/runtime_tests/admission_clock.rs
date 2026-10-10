// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8202 part 2 (P2), T12: the clock `open_runtime` hands the idempotency
//! admission. Admission is fallible since PR1 (an unreadable clock never
//! expires or reclaims an entry), but only if it is given the fallible clock:
//! `map_or(0)` makes every completed key look 1970-old and readmits retries.

use std::sync::Arc;

use serde_json::json;

use crate::idempotency::admission::{Admission, ExecutionAdmission, Mode, RETENTION_SECS, Request};

/// An entry completed while the clock is unreadable is retained, and is not
/// expired by a restored clock at `RETENTION_SECS` from the epoch.
#[test]
fn t12_an_entry_completed_on_an_unreadable_clock_is_retained_once_the_clock_reads() {
    let admission = ExecutionAdmission::new_fallible(Arc::new(crate::clock::unix_secs));
    let (operation, representation) = (json!({"tool": "t"}), json!({"full": false}));
    let request = Request {
        principal: "p",
        key: "k",
        operation: &operation,
        representation: &representation,
        mode: Mode::Sync,
    };
    let lease = {
        let _clock = crate::clock::test_clock::at_secs(1_000);
        match admission.admit(request) {
            Ok(Admission::Owned(lease)) => lease,
            other => panic!("expected an owner, got {other:?}"),
        }
    };
    {
        // Settled undated: the outcome is not the point, the entry's life is.
        let _clock = crate::clock::test_clock::before_epoch();
        let _ = lease.complete_secured(&json!({"ok": true}));
    }
    let _clock = crate::clock::test_clock::at_secs(RETENTION_SECS);
    assert_eq!(admission.reclaim_completed(), 0, "not expired from epoch");
    assert_eq!(admission.snapshot().entries, 1);
}

/// MIK-8202 ACCESS+RETENTION rule, P2 row 13 (source check): `open_runtime`
/// builds its admission from `crate::clock::unix_secs`, never a fallback to 0
/// or a raw `SystemTime`. Mutant: `map_or(0)` restored.
#[test]
fn t12_open_runtime_builds_its_admission_from_the_fallible_clock() {
    let source = include_str!("../mod.rs");
    let start = source
        .find("pub async fn open_runtime(")
        .expect("open_runtime");
    let body = &source[start
        ..source[start..]
            .find("\n}\n")
            .map_or(source.len(), |n| start + n)];
    assert!(body.contains("new_fallible("), "{body}");
    assert!(body.contains("crate::clock::unix_secs"), "{body}");
    for banned in ["map_or(0", "unwrap_or(0", "unwrap_or_default", "SystemTime"] {
        assert!(!body.contains(banned), "open_runtime still has `{banned}`");
    }
}

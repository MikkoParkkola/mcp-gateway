// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The unserved-probe count across an era invalidation (GH #579).
//!
//! Two semantics of `record_unserved_probe` that read alike and must stay
//! apart: an era invalidation leaves the consecutive count where it was, and a
//! `-32601` answer resets it. Row 9d alone could not tell them apart, because
//! its invalidation is itself a `-32601`, which zeroes the count first.

use super::*;
use crate::error::rpc_codes::INTERNAL_ERROR;
use crate::protocol::era::{Era, METHOD_NOT_FOUND_CODE, UNSUPPORTED_PROTOCOL_VERSION};

fn count_of(methods: &[String], method: &str) -> usize {
    methods.iter().filter(|m| *m == method).count()
}

/// Row 9d — a modern peer declines `server/discover` (`-32601`: invalidate,
/// and the count resets, row 10d), then three faulted answers escalate. The
/// count is zero at this row's invalidation, so row 9f is the one that pins
/// the count surviving it.
#[tokio::test]
async fn row_9d_a_method_not_found_invalidation_resets_then_three_faults_escalate() {
    let mock = Arc::new(
        ProbeMock::modern_then(vec![ProbeAnswer::InBandError(METHOD_NOT_FOUND_CODE)])
            .refusing(INTERNAL_ERROR),
    );
    let backend = probe_backend(Arc::clone(&mock), true).await;

    for _ in 0..4 {
        let _ = backend.health_probe(Duration::from_secs(5)).await;
    }

    assert!(
        backend.is_circuit_tripped(),
        "three consecutive unserved answers must trip the breaker"
    );
    assert!(
        !still_wired(&backend, &mock),
        "the third unserved answer escalates to a restart"
    );
}

/// Row 9f — the count survives an era invalidation. A Legacy-era peer answers
/// `ping` with a code only a modern peer knows: that disproves the cached era
/// (`contradicts_legacy`) through the counting path, not the `-32601` reset,
/// so the invalidation lands on a count of two. An implementation that resets
/// the count when it invalidates lets a peer that keeps changing what it
/// refuses stay unescalated forever.
#[tokio::test]
async fn row_9f_the_unserved_count_survives_an_era_invalidation() {
    let mock = Arc::new(
        ProbeMock::legacy_then(vec![
            ProbeAnswer::InBandError(INTERNAL_ERROR),
            ProbeAnswer::InBandError(UNSUPPORTED_PROTOCOL_VERSION),
        ])
        .refusing(INTERNAL_ERROR),
    );
    let backend = probe_backend(Arc::clone(&mock), true).await;
    assert_eq!(backend.cached_era().await, Some(Era::Legacy), "premise");

    let _ = backend.health_probe(Duration::from_secs(5)).await;
    assert_eq!(backend.unserved_counts_for_test(), (1, 1));

    // The invalidating tick. Not `-32601`, so it counts.
    let _ = backend.health_probe(Duration::from_secs(5)).await;
    assert_eq!(
        backend.unserved_counts_for_test(),
        (2, 2),
        "the invalidating answer counts like any other unserved answer"
    );
    assert!(!backend.is_circuit_tripped());
    assert!(still_wired(&backend, &mock));
    assert_eq!(
        mock.probed_methods(),
        ["ping", "ping"],
        "premise: a legacy probe"
    );

    // The discard spawns a detached re-probe; its `server/discover` is the
    // proof the era was invalidated, not merely refused.
    let discovers = count_of(&mock.methods(), "server/discover");
    tokio::time::timeout(Duration::from_secs(5), async {
        while count_of(&mock.methods(), "server/discover") == discovers {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("the era was never invalidated: no re-probe reached the mock");

    let _ = backend.health_probe(Duration::from_secs(5)).await;

    assert!(
        backend.is_circuit_tripped(),
        "the count survived the invalidation, so the third answer trips"
    );
    assert!(!still_wired(&backend, &mock), "and escalates to a restart");
    let methods = mock.methods();
    assert_eq!(count_of(&methods, "server/discover"), 2, "{methods:?}");
    assert_eq!(methods.len(), 5, "{methods:?}");
}

/// Row 10e — `-32601` resets the count rather than skipping it. Two faults, a
/// declined `ping`, two more faults: four faults, never three in a row. An
/// implementation that merely skips the `-32601` escalates on the fourth tick.
#[tokio::test]
async fn row_10e_a_method_not_found_between_faults_resets_the_count() {
    let mock = Arc::new(
        ProbeMock::legacy_then(vec![
            ProbeAnswer::InBandError(INTERNAL_ERROR),
            ProbeAnswer::InBandError(INTERNAL_ERROR),
            ProbeAnswer::InBandError(METHOD_NOT_FOUND_CODE),
            ProbeAnswer::InBandError(INTERNAL_ERROR),
            ProbeAnswer::InBandError(INTERNAL_ERROR),
        ])
        .refusing(METHOD_NOT_FOUND_CODE),
    );
    let backend = probe_backend(Arc::clone(&mock), true).await;
    assert_eq!(backend.cached_era().await, Some(Era::Legacy), "premise");

    let expected = [(1, 1), (2, 2), (0, 3), (1, 4), (2, 5)];
    for (tick, counts) in expected.into_iter().enumerate() {
        let _ = backend.health_probe(Duration::from_secs(5)).await;
        assert_eq!(
            backend.unserved_counts_for_test(),
            counts,
            "after tick {}",
            tick + 1
        );
        assert!(
            !backend.is_circuit_tripped(),
            "tick {} must not trip",
            tick + 1
        );
        assert!(
            still_wired(&backend, &mock),
            "tick {} must not restart",
            tick + 1
        );
    }
    assert_eq!(
        mock.probed_methods(),
        ["ping"; 5],
        "no invalidation, no re-probe"
    );
}

// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-7217 OUTBOUND.1/.2: the era-gated health probe.

use super::*;

/// Row 1 — a modern peer is asked the modern liveness method. `ping` was
/// removed in the 2026-07-28 revision, so putting it on a modern wire is the
/// outbound defect OUTBOUND.1 names.
#[tokio::test]
async fn row_1_modern_backend_is_probed_with_server_discover() {
    let mock = Arc::new(ProbeMock::modern_then(vec![ProbeAnswer::Result(json!({}))]));
    let backend = probe_backend(Arc::clone(&mock), true).await;
    assert_eq!(
        backend.cached_era().await,
        Some(crate::protocol::era::Era::Modern),
        "precondition: the fixture must construct a modern peer"
    );

    let _ = backend.health_probe(Duration::from_secs(5)).await;

    assert_eq!(
        mock.probed_methods(),
        vec!["server/discover".to_string()],
        "a modern peer is probed with server/discover"
    );
    assert!(
        !mock.methods().contains(&"ping".to_string()),
        "ping must never reach a modern peer"
    );
}

/// Row 2 — regression guard. It passes at HEAD, which sends `ping` to
/// everything; it exists to catch the mirror-image defect once row 1 lands.
#[tokio::test]
async fn row_2_legacy_backend_is_probed_with_ping() {
    let mock = Arc::new(ProbeMock::scripted(vec![
        ProbeAnswer::InBandError(crate::protocol::era::METHOD_NOT_FOUND_CODE),
        ProbeAnswer::Result(json!({})),
    ]));
    let backend = probe_backend(Arc::clone(&mock), true).await;
    assert_eq!(
        backend.cached_era().await,
        Some(crate::protocol::era::Era::Legacy),
        "precondition: -32601 to server/discover classifies the peer legacy"
    );

    let _ = backend.health_probe(Duration::from_secs(5)).await;

    assert_eq!(mock.probed_methods(), vec!["ping".to_string()]);
}

/// Row 3 — regression guard. An era that was never resolved is not modern:
/// `classify`'s rule is that silence is never evidence of modernity, and this
/// pins that rule at the probe's call site rather than at `classify`'s.
#[tokio::test]
async fn row_3_unclassified_backend_takes_the_legacy_arm() {
    let mock = Arc::new(ProbeMock::scripted(vec![ProbeAnswer::Result(json!({}))]));
    let backend = probe_backend(Arc::clone(&mock), false).await;
    assert_eq!(
        backend.cached_era().await,
        None,
        "precondition: the era was never resolved"
    );

    let _ = backend.health_probe(Duration::from_secs(5)).await;

    assert_eq!(mock.methods(), vec!["ping".to_string()]);
}

/// Row 4 — an in-band `-32601` is an *unserved* answer, not a healthy one: the
/// peer answered, so nothing is broken, but it did not serve the probe. HEAD
/// reads any `Ok(Ok(_))` as success and resets the breaker.
///
/// The row's third assertion in section 6, "counter increments", is not made
/// here: the consecutive-unserved count does not exist at HEAD, and a test that
/// fails to compile records no fail-first evidence. Rows 10 to 11b pin the
/// counter once it exists.
#[tokio::test]
async fn row_4_in_band_method_not_found_is_unserved_not_healthy() {
    let mock = Arc::new(ProbeMock::legacy_then(vec![ProbeAnswer::InBandError(
        crate::protocol::era::METHOD_NOT_FOUND_CODE,
    )]));
    let backend = probe_backend(Arc::clone(&mock), true).await;
    backend.trip_circuit_breaker_for_test();

    let _ = backend.health_probe(Duration::from_secs(5)).await;

    assert!(
        backend.is_circuit_tripped(),
        "an unserved answer is not evidence of health and must not reset the breaker"
    );
    assert!(
        still_wired(&backend, &mock),
        "an unserved answer is not a fault and must not restart the backend"
    );
}

/// Row 5 — the same `-32601`, carried as an HTTP 404 with a JSON-RPC error
/// body. HEAD sees `Ok(Err(_))` and calls `force_restart()`, so a peer that
/// merely declines the probe is torn down. Same counter caveat as row 4.
#[tokio::test]
async fn row_5_status_carried_method_not_found_is_unserved_not_a_fault() {
    let mock = Arc::new(ProbeMock::legacy_then(vec![ProbeAnswer::StatusError(
        crate::protocol::era::METHOD_NOT_FOUND_CODE,
    )]));
    let backend = probe_backend(Arc::clone(&mock), true).await;
    backend.trip_circuit_breaker_for_test();

    let _ = backend.health_probe(Duration::from_secs(5)).await;

    assert!(
        still_wired(&backend, &mock),
        "a status-carried decline is still a decline, not a fault"
    );
    assert!(backend.is_circuit_tripped());
}

/// Row 6 — the widened middle arm. `-32603` is not method-not-found, and the
/// era assertion is what stops an implementation from widening *invalidation*
/// along with the unserved arm: only method-not-found is evidence about era.
///
/// That era assertion is a second-stage pin, not part of this row's fail-first
/// evidence: at HEAD the row stops on the breaker assertion, which is row 4's
/// defect, and HEAD has no invalidation path that could move the era at all.
/// It begins to discriminate once the widened arm lands. Row 6b is the same
/// shape, stopping on the restart instead.
#[tokio::test]
async fn row_6_in_band_internal_error_is_unserved_and_leaves_the_era_alone() {
    let mock = Arc::new(ProbeMock::modern_then(vec![ProbeAnswer::InBandError(
        crate::error::rpc_codes::INTERNAL_ERROR,
    )]));
    let backend = probe_backend(Arc::clone(&mock), true).await;
    backend.trip_circuit_breaker_for_test();

    let _ = backend.health_probe(Duration::from_secs(5)).await;

    assert!(backend.is_circuit_tripped());
    assert!(still_wired(&backend, &mock));
    assert_eq!(
        backend.cached_era().await,
        Some(crate::protocol::era::Era::Modern),
        "only method-not-found is evidence about era; -32603 says nothing"
    );
}

/// Row 6b — where the two halves of section 3 meet: the widened arm *and* the
/// status carriage. An implementation that faults on any parsed code except
/// `-32601` passes every other row while restarting backends it must not.
#[tokio::test]
async fn row_6b_status_carried_internal_error_is_unserved_and_leaves_the_era_alone() {
    let mock = Arc::new(ProbeMock::modern_then(vec![ProbeAnswer::StatusError(
        crate::error::rpc_codes::INTERNAL_ERROR,
    )]));
    let backend = probe_backend(Arc::clone(&mock), true).await;
    backend.trip_circuit_breaker_for_test();

    let _ = backend.health_probe(Duration::from_secs(5)).await;

    assert!(
        still_wired(&backend, &mock),
        "a status-carried -32603 is still a decline, not a fault"
    );
    assert!(backend.is_circuit_tripped());
    assert_eq!(
        backend.cached_era().await,
        Some(crate::protocol::era::Era::Modern),
        "a status-carried -32603 is not evidence about era either"
    );
}

/// Row 7 — regression guard, and the control for every `still_wired` assertion
/// above: a transport fault still restarts the backend. If this row ever passes
/// while reporting the mock still wired, rows 5 and 6b are green because the
/// observable is dead, not because the probe stopped restarting.
#[tokio::test]
async fn row_7_a_transport_fault_still_restarts() {
    let mock = Arc::new(ProbeMock::legacy_then(vec![ProbeAnswer::Fault]));
    let backend = probe_backend(Arc::clone(&mock), true).await;

    let _ = backend.health_probe(Duration::from_secs(5)).await;

    assert!(
        !still_wired(&backend, &mock),
        "a closed socket is a fault and must still rebuild the transport"
    );
}

/// Row 8 — regression guard: a served `ping` on the legacy arm still resets a
/// tripped breaker. It guards against fixing rows 4 to 6 by making nothing
/// healthy.
#[tokio::test]
async fn row_8_a_ping_result_on_the_legacy_arm_resets_the_breaker() {
    let mock = Arc::new(ProbeMock::legacy_then(vec![ProbeAnswer::Result(json!({}))]));
    let backend = probe_backend(Arc::clone(&mock), true).await;
    backend.trip_circuit_breaker_for_test();

    let _ = backend.health_probe(Duration::from_secs(5)).await;

    assert_eq!(mock.probed_methods(), vec!["ping".to_string()]);
    assert!(
        !backend.is_circuit_tripped(),
        "a served answer is evidence of health and must reset the breaker"
    );
}

/// Row 8b — the mirror half, and fail-first: the reset must be wired to the
/// *result*, not to the legacy branch that happens to carry it today. HEAD
/// never sends `server/discover` from the probe, so the method assertion is
/// what fails here.
#[tokio::test]
async fn row_8b_a_discover_result_on_the_modern_arm_resets_the_breaker() {
    let mock = Arc::new(ProbeMock::modern_then(vec![ProbeAnswer::Result(json!({}))]));
    let backend = probe_backend(Arc::clone(&mock), true).await;
    backend.trip_circuit_breaker_for_test();

    let _ = backend.health_probe(Duration::from_secs(5)).await;

    assert_eq!(
        mock.probed_methods(),
        vec!["server/discover".to_string()],
        "a modern peer is probed with server/discover"
    );
    assert!(
        !backend.is_circuit_tripped(),
        "the reset belongs to the result, not to the arm that carries it"
    );
}

/// Row 9 — `-32601` *to `server/discover`* is the one answer that is evidence
/// about era, and the cached verdict must not survive it.
///
/// Only the accessor is asserted. "The next tick sends `ping`" is a property of
/// rows 1 and 2 composed with this one: those rows pin method selection as a
/// function of the era, so re-asserting it here would add a second observation
/// of the same rule - and it cannot be observed cleanly anyway, because the
/// invalidation spawns a detached classification probe whose `server/discover`
/// lands on the same wire at a time no test controls.
#[tokio::test]
async fn row_9_method_not_found_to_discover_invalidates_the_cached_era() {
    let mock = Arc::new(ProbeMock::modern_then(vec![ProbeAnswer::InBandError(
        crate::protocol::era::METHOD_NOT_FOUND_CODE,
    )]));
    let backend = probe_backend(Arc::clone(&mock), true).await;
    assert_eq!(
        backend.cached_era().await,
        Some(crate::protocol::era::Era::Modern)
    );

    let _ = backend.health_probe(Duration::from_secs(5)).await;

    assert_ne!(
        backend.cached_era().await,
        Some(crate::protocol::era::Era::Modern),
        "a peer that does not know server/discover is not modern, whatever the probe said"
    );
}

/// Row 9e — the status-carried twin of row 9, and the one row that pins the
/// only new plumbing section 3 adds: a `-32601` arriving as `Err(Error::JsonRpc)`
/// is the same evidence about era as the in-band one. Row 9 is in-band only and
/// row 5 starts from a legacy cache, so without this row an HTTP peer that
/// refuses `server/discover` with a 404 keeps a `Modern` cache and is probed
/// forever with the method it just refused.
#[tokio::test]
async fn row_9e_a_status_carried_method_not_found_also_invalidates_the_era() {
    let mock = Arc::new(ProbeMock::modern_then(vec![ProbeAnswer::StatusError(
        crate::protocol::era::METHOD_NOT_FOUND_CODE,
    )]));
    let backend = probe_backend(Arc::clone(&mock), true).await;
    assert_eq!(
        backend.cached_era().await,
        Some(crate::protocol::era::Era::Modern)
    );

    let _ = backend.health_probe(Duration::from_secs(5)).await;

    assert_ne!(
        backend.cached_era().await,
        Some(crate::protocol::era::Era::Modern),
        "a refusal carried by the status line is the same evidence as an in-band one"
    );
}

/// Row 9c — re-classification comes only from positive evidence, never from an
/// absence. A served `ping` says nothing about the era, and an implementation
/// reading any successful probe as "the peer is fine, restore what we thought"
/// sends the modern liveness method to a peer just reclassified as legacy.
#[tokio::test]
async fn row_9c_a_served_ping_is_not_evidence_of_modernity() {
    let mock = Arc::new(ProbeMock::modern_then(vec![ProbeAnswer::InBandError(
        crate::protocol::era::METHOD_NOT_FOUND_CODE,
    )]));
    let backend = probe_backend(Arc::clone(&mock), true).await;

    let _ = backend.health_probe(Duration::from_secs(5)).await;
    let _ = backend.health_probe(Duration::from_secs(5)).await;

    assert_ne!(
        backend.cached_era().await,
        Some(crate::protocol::era::Era::Modern),
        "an answered ping is an absence of evidence about the era, not positive evidence"
    );
}

/// Row 9b — re-classification works in both directions, and the evidence
/// arrives **off the probe path**. The start path's `resolve_era` is what
/// returns a peer to `Era::Modern`, and the tick that follows must select the
/// modern method again. Restoring the verdict without restoring the method
/// selection is the mirror-image OUTBOUND.1 defect, so the row asserts the
/// method of one controlled tick rather than the accessor alone.
#[tokio::test]
async fn row_9b_positive_evidence_off_the_probe_path_reclassifies_the_peer() {
    let mock = Arc::new(
        ProbeMock::modern_then(vec![]).refusing(crate::protocol::era::METHOD_NOT_FOUND_CODE),
    );
    let backend = probe_backend(Arc::clone(&mock), true).await;

    let _ = backend.health_probe(Duration::from_secs(5)).await;
    assert_ne!(
        backend.cached_era().await,
        Some(crate::protocol::era::Era::Modern),
        "the -32601 to server/discover must drop the cached verdict"
    );

    // The peer is replaced by one that answers discovery properly - an upgrade,
    // as far as the gateway can tell - and the start path probes it again.
    mock.set_default(ProbeAnswer::Result(json!({
        "capabilities": {},
        "supportedVersions": [crate::protocol::meta::MODERN_VERSIONS[0]],
    })));
    let transport = Arc::clone(&mock) as Arc<dyn Transport>;
    backend.resolve_era_for_test(&transport).await;

    assert_eq!(
        backend.cached_era().await,
        Some(crate::protocol::era::Era::Modern),
        "positive evidence must be able to restore the modern verdict"
    );

    // One controlled tick after the restoration. Snapshotting first is what
    // makes it controlled: `resolve_era` and any detached probe have already
    // written their methods, so the tail below belongs to this tick alone.
    let before = mock.methods().len();
    let _ = backend.health_probe(Duration::from_secs(5)).await;
    assert_eq!(
        mock.methods()[before..],
        ["server/discover".to_string()],
        "a peer restored to Modern is probed with the modern method again"
    );
}

/// Row 10 — the escalation itself, one answer at a time. The first two
/// unserved answers leave the backend exactly as they found it; the third is
/// the one that has stopped being a decline and started being a failure.
#[tokio::test]
async fn row_10_the_third_unserved_answer_trips_and_restarts() {
    let mock =
        Arc::new(ProbeMock::legacy_then(vec![]).refusing(crate::error::rpc_codes::INTERNAL_ERROR));
    let backend = probe_backend(Arc::clone(&mock), true).await;

    for tick in 1..=2 {
        let _ = backend.health_probe(Duration::from_secs(5)).await;
        assert!(
            !backend.is_circuit_tripped(),
            "unserved answer {tick} must leave the breaker where it was"
        );
        assert!(
            still_wired(&backend, &mock),
            "and must not restart anything"
        );
        assert_eq!(backend.unserved_counts_for_test(), (tick, tick));
    }

    let _ = backend.health_probe(Duration::from_secs(5)).await;

    assert!(backend.is_circuit_tripped());
    assert!(!still_wired(&backend, &mock));
}

/// Row 10d — `ping` is OPTIONAL in MCP, so a backend that answers `-32601` is
/// conformant, not failing, and the refusal is a stable property of the peer
/// rather than a condition a restart can clear. Escalating on it rebuilt a
/// transport whose replacement declines the same method, tripping the breaker
/// again ten seconds later: a conformant backend shed traffic indefinitely
/// (GH #567, measured as 48.7% `tools/call` success against 100% at 3.5.x).
/// A well-formed, id-correlated answer is evidence the peer is alive whatever
/// its code, so `-32601` resets the count instead of spending it.
#[tokio::test]
async fn row_10d_method_not_found_is_liveness_and_never_escalates() {
    let mock = Arc::new(
        ProbeMock::legacy_then(vec![]).refusing(crate::protocol::era::METHOD_NOT_FOUND_CODE),
    );
    let backend = probe_backend(Arc::clone(&mock), true).await;

    // Two ticks past the escalation bound: the count may never reach it.
    for tick in 1..=5u64 {
        let _ = backend.health_probe(Duration::from_secs(5)).await;
        assert!(
            !backend.is_circuit_tripped(),
            "answer {tick} declined an optional method and must not trip the breaker"
        );
        assert!(
            still_wired(&backend, &mock),
            "answer {tick} declined an optional method and must not restart the backend"
        );
    }

    let (consecutive, total) = backend.unserved_counts_for_test();
    assert_eq!(
        consecutive, 0,
        "a well-formed refusal proves the peer is alive, so it resets the escalation count"
    );
    assert_eq!(
        total, 5,
        "the answers are still unserved and still counted for telemetry"
    );
}

/// Row 10c — "consecutive" counts answers, not ticks. A probe still waiting on
/// a slow peer holds the wire, and the tick that lands while it is outstanding
/// is skipped rather than sent: an implementation counting ticks escalates a
/// backend that is answering, just slowly, to a restart.
#[tokio::test]
async fn row_10c_a_tick_landing_during_a_probe_is_skipped_not_counted() {
    let gate = Arc::new(tokio::sync::Notify::new());
    let mock = Arc::new(
        ProbeMock::legacy_then(vec![])
            .refusing(crate::error::rpc_codes::INTERNAL_ERROR)
            .gated(Arc::clone(&gate)),
    );
    // The era resolve runs before the gate is armed by way of the script, so
    // wire the backend first and hold only the probe.
    let backend = probe_backend(Arc::clone(&mock), false).await;

    let slow = {
        let backend = Arc::clone(&backend);
        tokio::spawn(async move { backend.health_probe(Duration::from_secs(5)).await })
    };
    // The mock records the method before it waits, so one recorded method is
    // the proof that the first probe is on the wire. Bounded: if the spawned
    // probe never records, this row's failure belongs in the report, not in a
    // CI job that hangs until its own timeout kills the whole suite.
    tokio::time::timeout(Duration::from_secs(5), async {
        while mock.methods().is_empty() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("the first probe never reached the mock");

    let skipped = backend.health_probe(Duration::from_secs(5)).await;
    assert!(
        skipped.is_ok(),
        "a skipped tick is not a failure: {skipped:?}"
    );
    assert_eq!(
        mock.methods().len(),
        1,
        "exactly one probe may be in flight, saw: {:?}",
        mock.methods()
    );

    gate.notify_waiters();
    let _ = slow.await.expect("the held probe must finish");

    // The lifetime total is this row's subject: one answer, however many ticks
    // passed. The consecutive count reads zero because the single answer is the
    // `-32601` `legacy_then` scripts, which row 10d exempts from escalation.
    assert_eq!(
        backend.unserved_counts_for_test(),
        (0, 1),
        "one answer is one unserved answer, however many ticks passed"
    );
}

/// Row 11 — a served answer is what resets the consecutive count, and the
/// lifetime counter is a different value that never resets. Without the
/// counter assertions the row is vacuous: a probe that never escalates at all
/// also never trips.
#[tokio::test]
async fn row_11_a_served_result_resets_the_consecutive_count() {
    let mock =
        Arc::new(ProbeMock::legacy_then(vec![]).refusing(crate::error::rpc_codes::INTERNAL_ERROR));
    let backend = probe_backend(Arc::clone(&mock), true).await;

    for _ in 0..2 {
        let _ = backend.health_probe(Duration::from_secs(5)).await;
    }
    mock.set_default(ProbeAnswer::Result(json!({})));
    let _ = backend.health_probe(Duration::from_secs(5)).await;
    mock.set_default(ProbeAnswer::InBandError(
        crate::error::rpc_codes::INTERNAL_ERROR,
    ));
    for _ in 0..2 {
        let _ = backend.health_probe(Duration::from_secs(5)).await;
    }

    assert!(
        !backend.is_circuit_tripped(),
        "four unserved answers with a served one between them are not three in a row"
    );
    assert_eq!(
        backend.unserved_counts_for_test(),
        (2, 4),
        "the consecutive count restarts at the served answer; the lifetime count does not"
    );
}

/// Row 11b — the other two reset paths. A transport fault restarts on its own
/// terms (row 7), and the count belongs to the transport that earned it: the
/// rebuilt one starts from zero, so two further unserved answers still do not
/// trip.
#[tokio::test]
async fn row_11b_a_transport_fault_also_resets_the_consecutive_count() {
    let mock =
        Arc::new(ProbeMock::legacy_then(vec![]).refusing(crate::error::rpc_codes::INTERNAL_ERROR));
    let backend = probe_backend(Arc::clone(&mock), true).await;

    for _ in 0..2 {
        let _ = backend.health_probe(Duration::from_secs(5)).await;
    }
    mock.set_default(ProbeAnswer::Fault);
    let _ = backend.health_probe(Duration::from_secs(5)).await;
    assert_eq!(
        backend.unserved_counts_for_test().0,
        0,
        "a fault restarts the backend, so the run of refusals it ended is over"
    );

    mock.set_default(ProbeAnswer::InBandError(
        crate::error::rpc_codes::INTERNAL_ERROR,
    ));
    backend.set_transport_for_test(Arc::clone(&mock) as Arc<dyn Transport>);
    for _ in 0..2 {
        let _ = backend.health_probe(Duration::from_secs(5)).await;
    }

    assert_eq!(
        backend.unserved_counts_for_test(),
        (2, 4),
        "the rebuilt transport starts its own run; the lifetime count keeps counting"
    );
}

/// Row 10b — the escalation restarts the backend, and §3 rule 2 makes "a
/// rebuilt backend starts from zero" load-bearing for the three-count
/// arithmetic. An implementation that trips without clearing its own count
/// escalates on every single answer afterwards, so the patience the constant
/// buys is spent once and never again.
#[tokio::test]
async fn row_10b_an_escalation_clears_the_count_it_acted_on() {
    let mock =
        Arc::new(ProbeMock::legacy_then(vec![]).refusing(crate::error::rpc_codes::INTERNAL_ERROR));
    let backend = probe_backend(Arc::clone(&mock), true).await;

    for _ in 0..3 {
        let _ = backend.health_probe(Duration::from_secs(5)).await;
    }
    assert!(
        backend.is_circuit_tripped(),
        "row 10's escalation must fire"
    );
    assert_eq!(
        backend.unserved_counts_for_test().0,
        0,
        "the count the escalation acted on is spent; the rebuilt transport starts from zero"
    );

    backend.set_transport_for_test(Arc::clone(&mock) as Arc<dyn Transport>);
    for _ in 0..2 {
        let _ = backend.health_probe(Duration::from_secs(5)).await;
    }

    assert!(
        still_wired(&backend, &mock),
        "two answers after a restart are not three, so nothing may restart again"
    );
    assert_eq!(backend.unserved_counts_for_test(), (2, 5));
}

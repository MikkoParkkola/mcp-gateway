// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Re-probe on contradiction, the structured era log records, and the era read against a modern-only call.

use super::*;

/// A contradicted legacy verdict is re-probed, and the read moves with it.
///
/// Asserts the complete snapshot on both sides. A case pinning only the moving
/// fields passes while a stale `era_evidence` survives beside a correctly
/// updated `era` — an internally inconsistent read no per-field assertion sees.
#[tokio::test]
async fn a_contradiction_reprobes_and_the_whole_read_moves_with_it() {
    let _guard = capture_lock().await;
    let fixture = Fixture::reprobing(METHOD_NOT_FOUND, UNSUPPORTED_VERSION);
    let backends = Arc::new(BackendRegistry::new());
    let backend = Arc::new(fixture.backend("contradicted"));
    assert!(
        backends.register(Arc::clone(&backend)),
        "backend must register"
    );
    backend.ensure_started().await.expect("start");

    let before = entry(&read::servers(Arc::clone(&backends)).await, "contradicted");
    assert_eq!(
        snapshot(&before),
        json!({
            "era": "legacy",
            "era_source": "probed",
            "era_evidence": "method_not_found",
            "era_probe_trigger": "start",
            "era_probed_at": before["era_probed_at"],
        }),
        "before: {before}"
    );

    // The ordinary request whose error contradicts the legacy verdict.
    let _ = backend.request("tools/list", None).await;
    let after = await_reprobe(&backends, "contradicted").await;

    assert_eq!(
        snapshot(&after),
        json!({
            "era": "modern",
            "era_source": "probed",
            "era_evidence": "modern_error_code",
            "era_probe_trigger": "reprobe",
            "era_probed_at": after["era_probed_at"],
        }),
        "after: {after}"
    );
    // The plan's equality against a stepped clock needs a clock seam the
    // production path does not offer; ordering is what is assertable today.
    assert!(
        after["era_probed_at"].as_str() >= before["era_probed_at"].as_str(),
        "the re-probe's time cannot precede the start probe's: {before} -> {after}"
    );
    assert_no_error_code(&after);
}

/// A re-probe that gets no answer gives the era back, rather than keeping a
/// finding it can no longer support.
#[tokio::test]
async fn a_reprobe_that_gets_no_answer_returns_the_era_to_assumed() {
    let _guard = capture_lock().await;
    let fixture = Fixture::reprobing(NOT_MODERN_DISCOVER, "");
    let backends = Arc::new(BackendRegistry::new());
    let backend = Arc::new(fixture.backend("silenced"));
    assert!(
        backends.register(Arc::clone(&backend)),
        "backend must register"
    );
    backend.ensure_started().await.expect("start");

    let before = entry(&read::servers(Arc::clone(&backends)).await, "silenced");
    assert_eq!(
        snapshot(&before),
        json!({
            "era": "legacy",
            "era_source": "probed",
            "era_evidence": "discover_not_modern",
            "era_probe_trigger": "start",
            "era_probed_at": before["era_probed_at"],
        }),
        "before: {before}"
    );

    let _ = backend.request("tools/list", None).await;
    let after = await_reprobe(&backends, "silenced").await;

    assert_eq!(
        snapshot(&after),
        json!({
            "era": "legacy",
            "era_source": "assumed",
            "era_evidence": "no_answer",
            "era_probe_trigger": "reprobe",
            "era_probed_at": after["era_probed_at"],
        }),
        "after: {after}"
    );
    assert_no_error_code(&after);
}

// ---------------------------------------------------------------------------
// (d) The event contract — the other observability surface
// ---------------------------------------------------------------------------

/// The field names a record carries, sorted, so a set can be compared whole.
fn keys(record: &Record) -> Vec<&str> {
    let mut names: Vec<&str> = record.fields.keys().map(String::as_str).collect();
    names.sort_unstable();
    names
}

/// `era_probe` carries exactly the design's fields, and no `error_code` when
/// the probe did not fail.
///
/// Absences are asserted rather than assumed: a record carrying a field the
/// design did not give it has widened the surface as surely as a missing one
/// has narrowed it, and only a pinned set sees either.
#[tokio::test]
async fn the_era_probe_record_carries_exactly_its_designed_fields() {
    let _guard = capture_lock().await;
    let fixture = Fixture::new(MODERN_DISCOVER);
    probe_and_read(&fixture, "probe-record").await;

    let record = only("evidence");
    assert_eq!(
        keys(&record),
        vec![
            "backend",
            "duration_ms",
            "evidence",
            "outcome",
            "slot",
            "trigger"
        ],
        "field set: {record:?}"
    );
    assert_eq!(record.field("backend"), "probe-record", "{record:?}");
    // The slot the record describes (MIK-8186); this backend has only Shared.
    assert_eq!(record.field("slot"), "shared", "{record:?}");
    assert_eq!(record.field("evidence"), "discover_modern", "{record:?}");
    assert_eq!(record.field("trigger"), "start", "{record:?}");
    assert_eq!(record.field("outcome"), "modern", "{record:?}");
}

/// `era_cache` says `false` on the probe that resolves and `true` on the read
/// that follows it.
#[tokio::test]
async fn the_era_cache_record_reports_a_miss_then_a_hit() {
    let _guard = capture_lock().await;
    let fixture = Fixture::new(MODERN_DISCOVER);
    probe_and_read(&fixture, "cache-record").await;

    let records = observed("hit");
    let first = records
        .first()
        .expect("a cache record on the resolving probe");
    assert_eq!(
        keys(first),
        vec!["backend", "hit", "slot"],
        "field set: {first:?}"
    );
    assert_eq!(first.field("backend"), "cache-record", "{first:?}");
    assert_eq!(
        first.field("hit"),
        "false",
        "the probe that resolves the era cannot have hit the cache: {first:?}"
    );
    assert!(
        records.iter().skip(1).any(|r| r.field("hit") == "true"),
        "the read after the probe must hit the cache: {records:?}"
    );
}

/// `era_invalidated` names why the era was thrown away.
#[tokio::test]
async fn the_era_invalidated_record_names_the_contradiction_as_its_reason() {
    let _guard = capture_lock().await;
    let fixture = Fixture::reprobing(METHOD_NOT_FOUND, UNSUPPORTED_VERSION);
    let backends = Arc::new(BackendRegistry::new());
    let backend = Arc::new(fixture.backend("invalidated"));
    assert!(
        backends.register(Arc::clone(&backend)),
        "backend must register"
    );
    backend.ensure_started().await.expect("start");
    let _ = backend.request("tools/list", None).await;
    await_reprobe(&backends, "invalidated").await;

    let record = only("reason");
    assert_eq!(
        keys(&record),
        vec!["backend", "reason", "slot"],
        "field set: {record:?}"
    );
    assert_eq!(record.field("backend"), "invalidated", "{record:?}");
    assert_eq!(record.field("reason"), "trigger", "{record:?}");
}

// ---------------------------------------------------------------------------
// (e) System — the read agrees with behaviour, and it is per backend
// ---------------------------------------------------------------------------

/// The `era` the operator reads agrees with how the peer actually behaves.
///
/// A case that reads the field and stops proves the field exists; it cannot
/// tell a read wired to the request path from one wired to a constant. So this
/// drives `server/discover` — a call only a modern peer serves — and asserts
/// the read and the observed behaviour say the same thing.
#[tokio::test]
async fn the_era_read_agrees_with_how_the_peer_answers_a_modern_only_call() {
    let _guard = capture_lock().await;
    let modern = Fixture::new(MODERN_DISCOVER);
    let legacy = Fixture::new(METHOD_NOT_FOUND);
    let backends = Arc::new(BackendRegistry::new());
    let modern_backend = Arc::new(modern.backend("speaks-modern"));
    let legacy_backend = Arc::new(legacy.backend("speaks-legacy"));
    assert!(
        backends.register(Arc::clone(&modern_backend)),
        "backend must register"
    );
    assert!(
        backends.register(Arc::clone(&legacy_backend)),
        "backend must register"
    );
    modern_backend.ensure_started().await.expect("start modern");
    legacy_backend.ensure_started().await.expect("start legacy");

    let modern_answer = modern_backend
        .request("server/discover", None)
        .await
        .expect("modern peer answers");
    let legacy_answer = legacy_backend
        .request("server/discover", None)
        .await
        .expect("legacy peer answers, with an error");
    assert!(
        modern_answer.error.is_none() && legacy_answer.error.is_some(),
        "the two peers must differ on the modern-only call, or this case proves \
         nothing: {modern_answer:?} vs {legacy_answer:?}"
    );

    let servers = read::servers(backends).await;
    assert_eq!(
        entry(&servers, "speaks-modern")["era"],
        "modern",
        "the peer that served the modern-only call must read modern: {servers:?}"
    );
    assert_eq!(
        entry(&servers, "speaks-legacy")["era"],
        "legacy",
        "the peer that refused it must read legacy: {servers:?}"
    );
}

/// Two backends in one response each carry their own era observation.
///
/// A shared cell, a cached first answer, or a fold over all backends renders
/// identically when only one backend is observed. This is the only case that
/// separates them.
#[tokio::test]
async fn each_backend_carries_its_own_era_observation() {
    let _guard = capture_lock().await;
    let probed = Fixture::new(MODERN_DISCOVER);
    let unprobed = Fixture::new(MODERN_DISCOVER);
    let backends = Arc::new(BackendRegistry::new());
    let started = Arc::new(probed.backend("probed-peer"));
    assert!(
        backends.register(Arc::clone(&started)),
        "backend must register"
    );
    assert!(
        backends.register(Arc::new(unprobed.backend("unprobed-peer"))),
        "backend must register"
    );
    started.ensure_started().await.expect("start");

    let servers = read::servers(backends).await;

    assert_eq!(
        snapshot(&entry(&servers, "unprobed-peer")),
        json!({
            "era": "legacy",
            "era_source": "assumed",
            "era_evidence": "never_probed",
        }),
        "the unprobed backend must not inherit its neighbour's finding: {servers:?}"
    );
    let probed_entry = entry(&servers, "probed-peer");
    assert_eq!(probed_entry["era"], "modern", "{servers:?}");
    assert_eq!(
        probed_entry["era_evidence"], "discover_modern",
        "{servers:?}"
    );
    assert!(probed_entry.get("era_probed_at").is_some(), "{servers:?}");
}

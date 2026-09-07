// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Refusal and service tests for the revision matrix NFR.COMPAT.1 names.
//!
//! The criterion says four revisions stay served and the new one is added.
//! "Served" is asserted by EQUALITY with the revision asked for, never by
//! the handshake completing: `negotiate_version` answers the fallback for a
//! revision it does not know, so an error-free handshake is exactly what a
//! dropped revision also produces.
//!
//! Clause 2 of the criterion — the legacy continuation bridge — is not here.
//! It is held by another change (MIK-7212.MRTR.7a/7b) and no test in this
//! file can flip it; the gate report says so rather than this file implying
//! the criterion is covered.

mod common;
use common::*;

// ============================================================================
// NFR.COMPAT.1 — the revision matrix
//
// Two revision sets, two entry paths. `SUPPORTED_VERSIONS` is what the legacy
// handshake negotiates over; `MODERN_VERSIONS` carries 2026-07-28 for the
// stateless path, which is the only path that can serve a revision whose
// handshake was deleted. A test that drives one set through the other's entry
// point fails for a non-defect, so the cases below are split by path, not by
// revision number.
// ============================================================================

/// A legacy handshake frame: no modern protocol header and no `_meta`.
///
/// The modern header is what steers a request onto the stateless path, so a
/// handshake case must not send it — otherwise the test would be asserting
/// about the path it is not naming.
async fn post_legacy(state: &Arc<AppState>, body: Value) -> (StatusCode, Value) {
    let request = Request::builder()
        .method("POST")
        .uri("/mcp")
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&body).expect("body")))
        .expect("request");
    let response = create_router(Arc::clone(state))
        .oneshot(request)
        .await
        .expect("router must answer");
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body must read");
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

/// The revision `initialize` settles on for a client asking for `requested`.
async fn negotiated(state: &Arc<AppState>, requested: &str) -> String {
    let (status, body) = post_legacy(
        state,
        json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": requested,
                "capabilities": {},
                "clientInfo": { "name": "LegacyClient", "version": "1.0.0" }
            }
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "handshake must be answered");
    body.pointer("/result/protocolVersion")
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("no negotiated revision in {body}"))
        .to_string()
}

/// C3. Equality, not absence-of-error: `negotiate_version` answers
/// `PROTOCOL_VERSION` for anything it does not know, so an error-free handshake
/// is compatible with the revision having been dropped.
#[tokio::test]
async fn compat_2025_06_18_is_negotiated_not_downgraded() {
    // GIVEN: a gateway with the shipped supported-version set
    let state = state(Fixture::default());

    // WHEN: a legacy client asks for 2025-06-18
    let settled = negotiated(&state, "2025-06-18").await;

    // THEN: it is served that revision, not the fallback
    assert_eq!(settled, "2025-06-18");
}

/// C4. "Not dropped" is the criterion's wording; equality is what proves it.
#[tokio::test]
async fn compat_2025_03_26_is_negotiated_not_downgraded() {
    // GIVEN: a gateway with the shipped supported-version set
    let state = state(Fixture::default());

    // WHEN: a legacy client asks for 2025-03-26
    let settled = negotiated(&state, "2025-03-26").await;

    // THEN: it is served that revision, not the fallback
    assert_eq!(settled, "2025-03-26");
}

/// C5. The oldest revision the criterion names.
#[tokio::test]
async fn compat_2024_11_05_is_negotiated_not_downgraded() {
    // GIVEN: a gateway with the shipped supported-version set
    let state = state(Fixture::default());

    // WHEN: a legacy client asks for 2024-11-05
    let settled = negotiated(&state, "2024-11-05").await;

    // THEN: it is served that revision, not the fallback
    assert_eq!(settled, "2024-11-05");
}

/// C6. The falsifier for C3-C5: it shows their equality assertion discriminates
/// rather than restating whatever the server happened to answer. An unknown
/// revision is downgraded to the fallback, which is a different string from all
/// three revisions above.
#[tokio::test]
async fn compat_an_unknown_revision_is_downgraded_to_the_fallback() {
    // GIVEN: a gateway with the shipped supported-version set
    let state = state(Fixture::default());

    // WHEN: a legacy client asks for a revision that does not exist
    let settled = negotiated(&state, "1999-01-01").await;

    // THEN: the handshake answers the fallback, not the ask
    assert_eq!(settled, mcp_gateway::protocol::PROTOCOL_VERSION);
    assert_ne!(settled, "1999-01-01");
}

/// C2. 2025-11-25 cannot be observed through the handshake at all: it *is*
/// `PROTOCOL_VERSION`, so deleting it from `SUPPORTED_VERSIONS` leaves every
/// handshake answer unchanged — the echo and the downgrade are the same string.
/// The claim is therefore made on the surface built from the constant, where
/// the state "passes while the revision has been dropped" is not constructible.
#[tokio::test]
async fn compat_2025_11_25_is_published_by_discovery() {
    // GIVEN: a gateway serving discovery
    let state = state(Fixture::default());

    // WHEN: a caller asks what revisions are served
    let (status, body) = post(
        &state,
        modern("server/discover", json!({})),
        &[],
    )
    .await;

    // THEN: the discovery document lists 2025-11-25
    assert_eq!(status, StatusCode::OK, "discovery must be answered");
    let versions = body
        .pointer("/result/supportedVersions")
        .and_then(Value::as_array)
        .unwrap_or_else(|| panic!("no supportedVersions in {body}"));
    assert!(
        versions.iter().any(|v| v == "2025-11-25"),
        "discovery must publish 2025-11-25, got {versions:?}"
    );
}

/// C1. 2026-07-28 has no handshake to negotiate over — the revision deleted it
/// — so the only evidence that it is served is a stateless request being
/// answered. The assertion is that a result came back, not that no error did:
/// an error-free refusal is not a thing this path can produce, but a `result`
/// key is the only shape that proves the frame was executed rather than
/// deflected.
#[tokio::test]
async fn compat_2026_07_28_is_served_on_the_stateless_path() {
    // GIVEN: a gateway with the stateless path enabled, as shipped
    let state = state(Fixture::default());

    // WHEN: a modern caller sends a 2026-07-28 frame, header and `_meta` both
    let (status, body) = post(&state, modern("server/discover", json!({})), &[]).await;

    // THEN: it is executed, not refused for its revision
    assert_eq!(status, StatusCode::OK, "body: {body}");
    assert!(body.get("result").is_some(), "body: {body}");
}

/// C1's falsifier. Turning the stateless path off is the one state in
/// which 2026-07-28 is a revision this build declines to serve, and the answer
/// is the version refusal specifically (-32022), not any 400 the route can
/// emit. Without this the C1 assertion would pass against a build that serves
/// every frame regardless of the revision it carries.
#[tokio::test]
async fn compat_2026_07_28_is_refused_when_the_stateless_path_is_off() {
    // GIVEN: a gateway with the stateless path disabled
    let state = state(Fixture {
        modern_protocol: false,
        ..Default::default()
    });

    // WHEN: the same 2026-07-28 frame arrives
    let (status, body) = post(&state, modern("server/discover", json!({})), &[]).await;

    // THEN: it is refused as an unservable revision
    assert_eq!(status, StatusCode::BAD_REQUEST, "body: {body}");
    assert_eq!(
        body["error"]["code"],
        json!(mcp_gateway::protocol::era::UNSUPPORTED_PROTOCOL_VERSION),
        "body: {body}"
    );
}

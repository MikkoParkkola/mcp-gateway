// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Acceptance-criterion tests for MIK-7217 — `server/discover` and backend era
//! detection, the first increment of MCP revision 2026-07-28 support.
//!
//! Each test carries its acceptance criterion verbatim and asserts it in the
//! same polarity the criterion states. Plan:
//! `docs/requirements/RELEASE-4.0.0-test-plan.md` §"Increment 1".
//!
//! These are written BEFORE the implementation. Every one of them fails now,
//! and that failure is the point: a test written after the code agrees with the
//! code, not with the requirement.

use std::sync::Arc;

use mcp_gateway::backend::BackendRegistry;
use mcp_gateway::gateway::test_helpers::MetaMcp;
use mcp_gateway::protocol::{RequestId, SUPPORTED_VERSIONS};
use serde_json::Value;

/// The five revisions the MCP specification defines, read from
/// modelcontextprotocol.io on 2026-08-29. Written out rather than derived from
/// the crate: a test that asks the code what is valid cannot catch the code
/// being wrong about what is valid.
const SPEC_DEFINED_REVISIONS: &[&str] = &[
    "2024-11-05",
    "2025-03-26",
    "2025-06-18",
    "2025-11-25",
    "2026-07-28",
];

/// The revision this release adds.
const TARGET_REVISION: &str = "2026-07-28";

/// Names the golden fixture for the feature set under test.
///
/// `spec-preview` changes what `initialize` advertises, so a single golden
/// would silently stop comparing under a different feature set — the exact
/// failure this regression row exists to prevent.
#[cfg(feature = "spec-preview")]
const GOLDEN_FEATURE_SET: &str = "spec_preview";
#[cfg(not(feature = "spec-preview"))]
const GOLDEN_FEATURE_SET: &str = "default";

fn meta() -> MetaMcp {
    MetaMcp::new(Arc::new(BackendRegistry::new()))
}

// ===========================================================================
// MIK-7217.DISCOVER.1 — the gateway MUST implement `server/discover` on every
// transport it serves, advertising supported protocol versions, capabilities
// and identity.
// ===========================================================================

#[test]
fn ac_discover_1_meta_layer_answers_server_discover() {
    // GIVEN: a gateway
    let m = meta();

    // WHEN: it is asked to produce a discovery document
    let doc = m.discover_document();

    // THEN: it names supported versions, capabilities and server identity
    assert!(
        doc.get("protocolVersions").is_some(),
        "discovery document must advertise the protocol versions the server supports"
    );
    assert!(
        doc.get("capabilities").is_some(),
        "discovery document must advertise server capabilities"
    );
    assert!(
        doc.get("serverInfo").is_some(),
        "discovery document must identify the server"
    );
}

#[test]
fn ac_discover_1_advertises_the_target_revision() {
    // GIVEN: a gateway that claims 2026-07-28 support
    let m = meta();

    // WHEN: the discovery document is read
    let doc = m.discover_document();
    let versions: Vec<&str> = doc["protocolVersions"]
        .as_array()
        .expect("protocolVersions must be an array")
        .iter()
        .filter_map(Value::as_str)
        .collect();

    // THEN: the revision this release adds is among them
    assert!(
        versions.contains(&TARGET_REVISION),
        "discovery must advertise {TARGET_REVISION}; advertised {versions:?}"
    );
}

// ===========================================================================
// MIK-7217.DISCOVER.7 — the advertised version list MUST contain only
// revisions the specification defines.
// ===========================================================================

#[test]
fn ac_discover_7_supported_versions_contains_only_real_revisions() {
    // GIVEN: the version list the gateway negotiates against and publishes
    // WHEN: each entry is checked against the specification's revisions
    let invented: Vec<&&str> = SUPPORTED_VERSIONS
        .iter()
        .filter(|v| !SPEC_DEFINED_REVISIONS.contains(v))
        .collect();

    // THEN: none of them is a version we invented
    //
    // `2024-10-07` has been advertised since commit e12431a0 (2026-01-26). The
    // specification has never defined it. It is inert for negotiation, which is
    // why it survived seven months unnoticed — but `server/discover` publishes
    // this list as the gateway's own statement of what it speaks, so it stops
    // being an unused constant and becomes a claim.
    assert!(
        invented.is_empty(),
        "SUPPORTED_VERSIONS advertises revisions the specification does not define: {invented:?}"
    );
}

#[test]
fn ac_discover_7_discovery_document_repeats_no_invented_version() {
    // GIVEN: a gateway
    let m = meta();

    // WHEN: the discovery document is read
    let doc = m.discover_document();
    let versions: Vec<&str> = doc["protocolVersions"]
        .as_array()
        .expect("protocolVersions must be an array")
        .iter()
        .filter_map(Value::as_str)
        .collect();

    // THEN: every advertised version is one the specification defines
    for v in &versions {
        assert!(
            SPEC_DEFINED_REVISIONS.contains(v),
            "discovery advertises {v}, which the specification does not define"
        );
    }
}

// ===========================================================================
// MIK-7217.DISCOVER.2 — `server/discover` MUST be answerable without any prior
// handshake, session or credential exchange beyond the transport's own
// authentication.
// ===========================================================================

#[test]
fn ac_discover_2_answers_without_a_prior_initialize() {
    // GIVEN: a gateway that has received no `initialize`
    let m = meta();

    // WHEN: discovery is requested first
    let doc = m.discover_document();

    // THEN: it answers, rather than requiring a handshake it no longer has
    assert!(
        doc.get("protocolVersions").is_some(),
        "discovery must answer on a connection that has never handshaken"
    );
}

#[test]
fn ac_discover_2_answers_without_a_session() {
    // GIVEN: a gateway
    let m = meta();

    // WHEN: discovery is produced with no session identifier anywhere in play
    let doc = m.discover_document();

    // THEN: a document is produced, and it does not depend on a session — which
    // is the mechanism 2026-07-28 removes, so a discovery document carrying one
    // has been built on the thing being deleted.
    //
    // The emptiness check is load-bearing. Without it this test passes against
    // an empty object, which contains no session id for the trivial reason that
    // it contains nothing: the staging would remove the very condition the
    // assertion observes.
    assert!(
        doc.get("protocolVersions").is_some(),
        "a document that advertises nothing cannot demonstrate it needs no session"
    );
    let rendered = serde_json::to_string(&doc).expect("document must serialise");
    assert!(
        !rendered.contains("sessionId") && !rendered.contains("session_id"),
        "discovery document must not carry a session identifier: {rendered}"
    );
}

// ===========================================================================
// MIK-7217.DISCOVER.3 — adding discovery MUST NOT alter the behaviour of the
// existing handshake path.
//
// The golden is captured from this tree before any discovery code exists, and
// this branch carries no code change, so the tree IS 3.5.0 for this purpose.
// The fixture pins its Cargo feature set: under `spec-preview` the handshake
// advertises extra capabilities, so one golden is one feature set.
// ===========================================================================

#[test]
fn ac_discover_3_initialize_result_is_unchanged() {
    // GIVEN: a 2025 client — named explicitly, because `params: None` exercises
    // the no-version default (which negotiates 2024-11-05) rather than the case
    // this criterion describes. A golden captured from the wrong staging pins
    // the wrong behaviour and never notices.
    for client_version in ["2025-11-25", "2025-06-18"] {
        let m = meta();
        let params = serde_json::json!({
            "protocolVersion": client_version,
            "capabilities": {},
            "clientInfo": { "name": "ac-discover-3", "version": "1.0.0" }
        });

        // WHEN: it sends `initialize` exactly as it did against 3.5.0
        let response = m.handle_initialize(RequestId::Number(1), Some(&params), None, None);
        let result = response
            .result
            .expect("initialize must return a result, as it did in 3.5.0");

        // THEN: the result is byte-identical to the captured golden
        let golden_path = &format!(
            "{}/tests/fixtures/mik_7217/initialize_3_5_0_{}_{}.json",
            env!("CARGO_MANIFEST_DIR"),
            client_version.replace('-', "_"),
            GOLDEN_FEATURE_SET
        );

        // The golden is CAPTURED, never hand-written: a hand-written expectation
        // of the handshake is a second implementation of it, and it agrees with
        // what the author believed rather than with what shipped. Capture once,
        // with UPDATE_GOLDEN=1, from a tree that has no discovery code in it.
        if std::env::var("UPDATE_GOLDEN").is_ok() {
            std::fs::create_dir_all(
                std::path::Path::new(golden_path)
                    .parent()
                    .expect("fixture path has a parent"),
            )
            .expect("fixture directory must be creatable");
            std::fs::write(
                golden_path,
                serde_json::to_string_pretty(&result).expect("result must serialise"),
            )
            .expect("golden must be writable");
        }

        let golden_raw = std::fs::read_to_string(golden_path).unwrap_or_else(|e| {
            panic!(
                "golden fixture missing at {golden_path}: {e}. Capture it with \
                 UPDATE_GOLDEN=1 from a tree that has NO discovery code yet; a \
                 golden captured afterwards agrees with the change instead of \
                 catching it."
            )
        });
        let golden: Value = serde_json::from_str(&golden_raw).expect("golden must be valid JSON");

        assert_eq!(
            result, golden,
            "the initialize result changed for a {client_version} client. Discovery \
             must be additive: this row is what enforces that, per the ticket's own \
             stop-the-line."
        );

        // The golden must actually pin the negotiated version, or a regression
        // that renegotiates every client onto one revision would still match.
        assert_eq!(
            golden["protocolVersion"], client_version,
            "golden for {client_version} must record that version as negotiated"
        );
    }
}

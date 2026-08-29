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
#[ignore = "awaits the stateless request path: advertising 2026-07-28 before the \
            gateway can serve it would tell a client yes and then serve 2025 \
            semantics. Scheduled, not suppressed — this criterion is unmet until \
            increment 2 lands."]
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

// ===========================================================================
// Dispatcher-level: MIK-7217.DISCOVER.1 over Streamable HTTP.
//
// The stdio arm is covered in-crate (`src/gateway/server/mod.rs`), because
// `dispatch_single` is private. These drive the real axum router, so a missing
// `match` arm fails here rather than being masked by both dispatchers calling
// one shared builder.
// ===========================================================================

mod http {
    use std::sync::Arc;

    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use mcp_gateway::backend::BackendRegistry;
    use mcp_gateway::config::Config;
    use mcp_gateway::gateway::auth::ResolvedAuthConfig;
    use mcp_gateway::gateway::oauth::{AgentAuthState, AgentRegistry, GatewayKeyPair};
    use mcp_gateway::gateway::proxy::ProxyManager;
    use mcp_gateway::gateway::streaming::NotificationMultiplexer;
    use mcp_gateway::gateway::test_helpers::{AppState, MetaMcp, create_router};
    use mcp_gateway::mtls::{MtlsConfig, MtlsPolicy};
    use mcp_gateway::security::{ToolPolicy, ToolPolicyConfig};
    use serde_json::{Value, json};
    use tower::ServiceExt;

    fn state() -> Arc<AppState> {
        let config = Config::default();
        let backends = Arc::new(BackendRegistry::new());
        let multiplexer = Arc::new(NotificationMultiplexer::new(
            Arc::clone(&backends),
            config.streaming.clone(),
        ));
        let proxy_manager = Arc::new(ProxyManager::new(Arc::clone(&multiplexer)));
        let agent_registry = Arc::new(AgentRegistry::new());
        Arc::new(AppState {
            meta_mcp: Arc::new(MetaMcp::new(Arc::clone(&backends))),
            backends,
            meta_mcp_enabled: true,
            multiplexer,
            proxy_manager,
            streaming_config: config.streaming.clone(),
            // Authentication disabled: this criterion is about discovery needing
            // no credential exchange beyond the transport's own.
            auth_config: Arc::new(ResolvedAuthConfig::from_config(&config.auth)),
            key_server: None,
            tool_policy: Arc::new(ToolPolicy::from_config(&ToolPolicyConfig::default())),
            mtls_policy: Arc::new(MtlsPolicy::from_config(&MtlsConfig::default())),
            sanitize_input: false,
            ssrf_protection: false,
            trust_configured_backends: false,
            inflight: Arc::new(tokio::sync::Semaphore::new(100)),
            agent_auth: AgentAuthState::new(false, agent_registry),
            gateway_key_pair: Arc::new(GatewayKeyPair::generate().expect("RSA key gen")),
            capability_dirs: Vec::new(),
            config_path: None,
            #[cfg(feature = "firewall")]
            firewall: None,
            agent_identity_config: mcp_gateway::config::AgentIdentityConfig::default(),
            control_plane_store: None,
            live_config: Arc::new(mcp_gateway::config_reload::LiveConfig::new(
                Config::default(),
            )),
            export_status: None,
            transparency_log: None,
            dashboard_bootstrap: Arc::new(mcp_gateway::gateway::auth::DashboardBootstrap::new()),
        })
    }

    async fn post_mcp(body: Value) -> (StatusCode, Value) {
        let router = create_router(state());
        let request = Request::builder()
            .method("POST")
            .uri("/mcp")
            .header("content-type", "application/json")
            // No Origin header on purpose. A non-browser peer sends none, and
            // 3.5.0's origin gate (CWE-346) refuses one it does not recognise —
            // as it should. Discovery must work for the peer that has no origin,
            // which is every MCP client that is not a web page.
            .body(Body::from(serde_json::to_vec(&body).expect("body")))
            .expect("request");
        let response = router.oneshot(request).await.expect("router must answer");
        let status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body must read");
        let json: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
        (status, json)
    }

    #[tokio::test]
    async fn ac_discover_1_http_dispatch_answers_server_discover() {
        // GIVEN/WHEN: a modern peer probes over Streamable HTTP
        let (status, body) = post_mcp(json!({
            "jsonrpc": "2.0", "id": 1, "method": "server/discover"
        }))
        .await;

        // THEN: it gets a document, not a method-not-found
        assert_eq!(
            status,
            StatusCode::OK,
            "server/discover must succeed: {body}"
        );
        assert!(
            body.get("error").is_none(),
            "server/discover must not error over HTTP: {body}"
        );
        let result = &body["result"];
        assert!(
            result.get("protocolVersions").is_some(),
            "discovery must advertise protocol versions: {body}"
        );
        assert!(
            result.get("capabilities").is_some(),
            "discovery must advertise capabilities: {body}"
        );
        assert!(
            result.get("serverInfo").is_some(),
            "discovery must identify the server: {body}"
        );
    }

    #[tokio::test]
    async fn ac_discover_1_http_and_meta_layer_agree() {
        // Equivalence. Both dispatchers must answer with the SAME document the
        // meta layer builds — a dispatcher that assembles its own would drift,
        // and a peer would get one story from HTTP and another from stdio.
        let (_, body) = post_mcp(json!({
            "jsonrpc": "2.0", "id": 2, "method": "server/discover"
        }))
        .await;

        let direct = state().meta_mcp.discover_document();
        assert_eq!(
            body["result"], direct,
            "the HTTP dispatcher must return the meta layer's document verbatim"
        );
    }

    #[tokio::test]
    async fn ac_discover_2_http_discovery_needs_no_prior_initialize() {
        // GIVEN: a connection that has never sent `initialize`
        // WHEN/THEN: discovery answers anyway — under 2026-07-28 there is no
        // handshake left to send, so requiring one would make the probe useless
        // to exactly the peers it exists for.
        let (status, body) = post_mcp(json!({
            "jsonrpc": "2.0", "id": 3, "method": "server/discover"
        }))
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert!(body["result"].get("protocolVersions").is_some(), "{body}");
    }
}

// ===========================================================================
// MIK-7217.DISCOVER.4 — as a client, the gateway MUST determine each backend's
// era by probing `server/discover` first, and MUST treat ANY non-modern
// outcome — arbitrary error, silence, timeout — as legacy. Only a recognised
// modern error proves a modern peer.
//
// These were written after the classifier, which is a process violation. The
// falsifier probe that recovers from it is recorded in the commit: the
// classifier was inverted, every row below failed, and it was restored.
// ===========================================================================

mod era {
    use mcp_gateway::protocol::era::{
        Era, HEADER_MISMATCH, MISSING_REQUIRED_CLIENT_CAPABILITY, ProbeOutcome,
        UNSUPPORTED_PROTOCOL_VERSION, classify,
    };
    use serde_json::json;

    #[test]
    fn ac_discover_4_a_discovery_document_means_modern() {
        let outcome = ProbeOutcome::Result(json!({
            "protocolVersions": ["2026-07-28"],
            "capabilities": {},
            "serverInfo": { "name": "peer", "version": "1.0.0" }
        }));
        assert_eq!(classify(&outcome), Era::Modern);
    }

    #[test]
    fn ac_discover_4_a_recognised_modern_error_means_modern() {
        // The boundary row. A peer that answers `UnsupportedProtocolVersion`
        // has implemented this revision — it is telling us which versions it
        // speaks. Reading that as legacy would downgrade a peer that was ready
        // to talk, and the tempting implementation ("any error means legacy")
        // does exactly that.
        for code in [
            UNSUPPORTED_PROTOCOL_VERSION,
            HEADER_MISMATCH,
            MISSING_REQUIRED_CLIENT_CAPABILITY,
        ] {
            assert_eq!(
                classify(&ProbeOutcome::Error(code)),
                Era::Modern,
                "error {code} is defined by 2026-07-28, so only a modern peer emits it"
            );
        }
    }

    #[test]
    fn ac_discover_4_method_not_found_means_legacy() {
        // The honest legacy answer: the method does not exist there.
        assert_eq!(classify(&ProbeOutcome::Error(-32601)), Era::Legacy);
    }

    #[test]
    fn ac_discover_4_an_arbitrary_error_means_legacy() {
        // The sloppy legacy answer. The specification allows a legacy server to
        // reject with "an implementation-defined error", so no particular code
        // can be relied on — which is why modernity needs positive evidence.
        for code in [-32603, -32000, -1, 42] {
            assert_eq!(
                classify(&ProbeOutcome::Error(code)),
                Era::Legacy,
                "error {code} is not defined by 2026-07-28, so it is no evidence of modernity"
            );
        }
    }

    #[test]
    fn ac_discover_4_silence_means_legacy() {
        // The common answer, and the one that makes this asymmetric. A peer we
        // could not reach is not thereby modern; treating it as modern would
        // send it requests it cannot parse.
        assert_eq!(classify(&ProbeOutcome::NoAnswer), Era::Legacy);
    }

    #[test]
    fn ac_discover_4_a_result_without_versions_is_not_a_discovery_document() {
        // Some other server's idea of what `server/discover` means. A result
        // alone is not evidence; the document has to say what it speaks.
        assert_eq!(
            classify(&ProbeOutcome::Result(json!({ "hello": "world" }))),
            Era::Legacy
        );
        assert_eq!(classify(&ProbeOutcome::Result(json!({}))), Era::Legacy);
    }
}

// ===========================================================================
// MIK-7217.DISCOVER.5 — era determination MUST be cached per backend for the
// lifetime of the process, and MUST be re-probed when a cached assumption
// fails.
//
// Tests written before the implementation. The probe counter is the assertion,
// never elapsed time: a cache that is merely slow would pass a timing test, and
// timing tests are the classic flake.
// ===========================================================================

mod era_cache {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use mcp_gateway::protocol::era::{Era, EraCache, ProbeOutcome};
    use serde_json::json;

    fn modern_doc() -> ProbeOutcome {
        ProbeOutcome::Result(json!({
            "protocolVersions": ["2026-07-28"],
            "capabilities": {},
            "serverInfo": { "name": "peer", "version": "1.0.0" }
        }))
    }

    #[tokio::test]
    async fn ac_discover_5_era_is_probed_once_and_reused() {
        // GIVEN: a peer whose era has never been determined
        let cache = EraCache::new();
        let probes = Arc::new(AtomicUsize::new(0));

        // WHEN: the era is resolved twice
        for _ in 0..2 {
            let probes = Arc::clone(&probes);
            let era = cache
                .resolve_with(|| async move {
                    probes.fetch_add(1, Ordering::SeqCst);
                    modern_doc()
                })
                .await;
            assert_eq!(era, Era::Modern);
        }

        // THEN: the peer was probed once
        //
        // Counting probes, not measuring time. The specification says a client
        // SHOULD cache for the lifetime of the server process; a cache that
        // re-probes on every call satisfies nothing and would still look fast.
        assert_eq!(
            probes.load(Ordering::SeqCst),
            1,
            "the era must be determined once and reused"
        );
    }

    #[tokio::test]
    async fn ac_discover_5_a_failed_assumption_forces_a_re_probe() {
        // GIVEN: a peer cached as modern
        let cache = EraCache::new();
        let probes = Arc::new(AtomicUsize::new(0));
        let counted = || {
            let c = Arc::clone(&probes);
            || async move {
                c.fetch_add(1, Ordering::SeqCst);
                modern_doc()
            }
        };
        assert_eq!(cache.resolve_with(counted()).await, Era::Modern);

        // WHEN: acting on that assumption fails, and the caller says so
        cache.invalidate().await;

        // THEN: the next resolution probes again rather than trusting a belief
        // that has already been contradicted
        assert_eq!(cache.resolve_with(counted()).await, Era::Modern);
        assert_eq!(
            probes.load(Ordering::SeqCst),
            2,
            "an invalidated era must be re-probed, not re-asserted"
        );
    }

    #[tokio::test]
    async fn ac_discover_5_concurrent_resolution_probes_once() {
        // GIVEN: two callers racing on a peer whose era is unknown — the shape
        // warm-start produces, since several tasks touch a backend at once
        let cache = Arc::new(EraCache::new());
        let probes = Arc::new(AtomicUsize::new(0));

        let mut handles = Vec::new();
        for _ in 0..8 {
            let cache = Arc::clone(&cache);
            let probes = Arc::clone(&probes);
            handles.push(tokio::spawn(async move {
                cache
                    .resolve_with(|| async move {
                        probes.fetch_add(1, Ordering::SeqCst);
                        // Yield so the race is real rather than serialised by
                        // the scheduler happening to finish each probe first.
                        tokio::task::yield_now().await;
                        modern_doc()
                    })
                    .await
            }));
        }
        for h in handles {
            assert_eq!(h.await.expect("task must not panic"), Era::Modern);
        }

        // THEN: the peer was probed once, not eight times. A cache that only
        // checks after probing turns one cold backend into a thundering herd.
        assert_eq!(
            probes.load(Ordering::SeqCst),
            1,
            "concurrent resolution must collapse onto one probe"
        );
    }
}

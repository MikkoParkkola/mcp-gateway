// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! CHAIN.1 (preserve and append, verified by the client) and CHAIN.2 (a
//! tampered, swapped, stale, wrong or dropped hop fails), on both routes.

use super::fake::{FakeUpstream, Mode};
use super::oracle::jcs;
use super::signing_gateway::HttpGateway;
use super::*;

async fn gateway(upstream: &FakeUpstream, mode: &str) -> HttpGateway {
    HttpGateway::start(d_config(&upstream.url, mode, "on_request")).await
}

/// H1/H1d: a two-hop chain the client verifies, with the upstream link
/// preserved in the RFC 8785 form its signature covers.
#[tokio::test]
async fn two_hop_chain_verifies_at_the_client() {
    for route in ROUTES {
        let upstream = FakeUpstream::start(Mode::Honest).await;
        let d = gateway(&upstream, "verify").await;
        let response = call(&d, route, Some("client-nonce-h1")).await;
        let links = client_verify(&response, "client-nonce-h1")
            .unwrap_or_else(|rule| panic!("{route:?}: client refused ({rule}): {response}"));
        assert_eq!(links.len(), 2, "{route:?}: {response}");
        let emitted = &upstream.sent()[0]["_meta"][CHAIN_KEY][0];
        assert_eq!(
            jcs(&links[0]),
            jcs(emitted),
            "{route:?}: upstream link preserved"
        );
        assert_eq!(
            links[1]["in"], emitted["out"],
            "{route:?}: D consumed U's output"
        );
        let outbound = upstream.outbound_nonces();
        assert_ne!(
            outbound[0].as_deref(),
            Some("client-nonce-h1"),
            "{route:?}: own challenge"
        );
    }
}

/// H2: `require` refuses a tampered upstream signature, naming the rule.
#[tokio::test]
async fn require_refuses_a_tampered_upstream_signature() {
    for route in ROUTES {
        let upstream = FakeUpstream::start(Mode::TamperedSignature).await;
        let d = gateway(&upstream, "require").await;
        let response = call(&d, route, Some("n-h2")).await;
        assert_refused(&response, "BadSignature");
        assert_eq!(upstream.calls().len(), 1, "{route:?}");
    }
}

/// H3: `verify` delivers a tampered upstream result under one link of D's
/// own that says the upstream is unverified; the client refuses it.
#[tokio::test]
async fn verify_marks_a_tampered_upstream_unverified() {
    for route in ROUTES {
        let upstream = FakeUpstream::start(Mode::TamperedSignature).await;
        let d = gateway(&upstream, "verify").await;
        let response = call(&d, route, Some("n-h3")).await;
        assert_eq!(chain_len(&response), 1, "{route:?}: {response}");
        let own = &result_of(&response)["_meta"][CHAIN_KEY][0];
        assert_eq!(own["up"], "unverified", "{route:?}");
        assert!(own["prev"].is_null(), "{route:?}");
        assert_eq!(
            client_verify(&response, "n-h3"),
            Err("unverified"),
            "{route:?}"
        );
    }
}

/// H4-H7 and H7b: every CHAIN.2 variant, on both routes.
#[tokio::test]
async fn require_refuses_each_bad_upstream_chain() {
    let cases = [
        (Mode::ReplayFirst, "Nonce"),
        (Mode::FixedNonce, "Nonce"),
        (Mode::Stale(3_600), "Stale"),
        (Mode::WrongOrigin, "Origin"),
        (Mode::WrongLastSigner, "LastSigner"),
        (Mode::ChangedContent, "Content"),
        (Mode::DroppedMiddleHop, "Linkage"),
        (Mode::NoChain, "absent"),
    ];
    for route in ROUTES {
        for (mode, rule) in cases {
            let upstream = FakeUpstream::start(Mode::Honest).await;
            let d = gateway(&upstream, "require").await;
            if mode == Mode::ReplayFirst {
                let first = call(&d, route, Some("n-first")).await;
                assert!(
                    first.get("result").is_some(),
                    "{route:?}: honest first call: {first}"
                );
            }
            upstream.set_mode(mode);
            let response = call(&d, route, Some("n-bad")).await;
            assert_refused(&response, rule);
        }
    }
}

/// H7b: `verify` with no upstream chain declares it, never hides it.
#[tokio::test]
async fn verify_declares_an_absent_upstream_chain() {
    for route in ROUTES {
        let upstream = FakeUpstream::start(Mode::NoChain).await;
        let d = gateway(&upstream, "verify").await;
        let response = call(&d, route, Some("n-h7b")).await;
        assert_eq!(chain_len(&response), 1, "{route:?}: {response}");
        assert_eq!(
            result_of(&response)["_meta"][CHAIN_KEY][0]["up"],
            "unverified"
        );
        assert_eq!(
            client_verify(&response, "n-h7b"),
            Err("unverified"),
            "{route:?}"
        );
    }
}

/// H5 with a configured window: 30 s window, 31 s old link.
#[tokio::test]
async fn the_configured_replay_window_is_the_one_applied() {
    let upstream = FakeUpstream::start(Mode::Stale(31)).await;
    let mut config = d_config(&upstream.url, "require", "on_request");
    config["security"]["message_signing"]["replay_window"] = json!(30);
    let d = HttpGateway::start(config).await;
    assert_refused(&call(&d, Route::Invoke, Some("n-w")).await, "Stale");
}

/// E1: enforcement does not wait for a client to ask for a chain.
#[tokio::test]
async fn require_enforces_without_a_client_nonce() {
    for route in ROUTES {
        let upstream = FakeUpstream::start(Mode::TamperedSignature).await;
        let d = gateway(&upstream, "require").await;
        assert_refused(&call(&d, route, None).await, "BadSignature");
        assert!(
            upstream.outbound_nonces()[0].is_some(),
            "{route:?}: D still challenged U"
        );
        upstream.set_mode(Mode::Honest);
        let ok = call(&d, route, None).await;
        assert!(
            ok.get("result").is_some() && chain_len(&ok) == 0,
            "{route:?}: {ok}"
        );
    }
}

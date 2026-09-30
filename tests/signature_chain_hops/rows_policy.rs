// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Policy rows: the outbound challenge, nonce scope, size caps, interim and
//! task replies, caches, replays and the surfaces that stay unchained.

use super::fake::{FakeUpstream, Mode};
use super::signing_gateway::HttpGateway;
use super::*;

fn is_hex_32(nonce: &str) -> bool {
    nonce.len() == 32 && nonce.bytes().all(|b| b.is_ascii_hexdigit())
}

/// N1/N2: a chained backend gets a fresh 32-hex challenge per call, never the
/// client's nonce; an `off` backend gets none. Both routes, both modes.
#[tokio::test]
async fn chained_backend_gets_a_fresh_outbound_nonce() {
    for route in ROUTES {
        for mode in ["verify", "require"] {
            let upstream = FakeUpstream::start(Mode::Honest).await;
            let d = HttpGateway::start(d_config(&upstream.url, mode, "on_request")).await;
            for _ in 0..2 {
                let _ = call(&d, route, Some("same-client-nonce")).await;
            }
            let sent = upstream.outbound_nonces();
            let (a, b) = (
                sent[0].clone().expect("first"),
                sent[1].clone().expect("second"),
            );
            assert!(is_hex_32(&a) && is_hex_32(&b), "{route:?}/{mode}: {sent:?}");
            assert_ne!(a, b, "{route:?}/{mode}: fresh per dispatch");
            assert_ne!(
                a, "same-client-nonce",
                "{route:?}/{mode}: never the client's"
            );
        }
        let upstream = FakeUpstream::start(Mode::Honest).await;
        let d = HttpGateway::start(d_config(&upstream.url, "off", "on_request")).await;
        let _ = call(&d, route, Some("client-off")).await;
        assert_eq!(
            upstream.outbound_nonces(),
            vec![None],
            "{route:?}: off writes nothing"
        );
    }
}

/// N2: the direct route keeps the caller's other `_meta` members.
#[tokio::test]
async fn direct_challenge_keeps_other_meta_members() {
    let upstream = FakeUpstream::start(Mode::Honest).await;
    let d = HttpGateway::start(d_config(&upstream.url, "verify", "on_request")).await;
    let (path, mut body) = request(Route::Direct, "m-1", Some("n-meta"));
    body["params"]["_meta"]["progressToken"] = json!("p-7");
    body["params"]["_meta"]["x-caller"] = json!({"keep": true});
    let _ = post(&d, &path, &body).await;
    let meta = &upstream.calls()[0]["params"]["_meta"];
    assert_eq!(meta["x-caller"], json!({"keep": true}), "{meta}");
    assert!(
        meta[fake::NONCE_KEY].as_str().is_some_and(is_hex_32),
        "{meta}"
    );
}

/// cr1 HIGH: a non-object `_meta` cannot carry the challenge, so a chained
/// direct call is refused before dispatch, never forwarded unchallenged.
#[tokio::test]
async fn direct_non_object_meta_is_refused_before_dispatch() {
    for mode in ["verify", "require"] {
        let upstream = FakeUpstream::start(Mode::Honest).await;
        let d = HttpGateway::start(d_config(&upstream.url, mode, "on_request")).await;
        for meta in [json!(null), json!(7), json!([]), json!("x")] {
            let (path, mut body) = request(Route::Direct, "m-2", None);
            body["params"]["_meta"] = meta.clone();
            let response = post(&d, &path, &body).await;
            assert_eq!(
                response["error"]["code"], -32602,
                "{mode}/{meta}: {response}"
            );
        }
        assert!(upstream.calls().is_empty(), "{mode}: nothing dispatched");
    }
}

/// F1/F1b: with message signing on and `emit: always`, the invoke nonce is
/// the chain's last nonce; with both present the chain nonce wins.
#[tokio::test]
async fn invoke_nonce_fallback_on_a_chained_result() {
    let upstream = FakeUpstream::start(Mode::Honest).await;
    let mut config = d_config(&upstream.url, "verify", "always");
    config["security"]["message_signing"] = json!({"enabled": true,
        "shared_secret": "chain-hops-hmac-secret-0123456789abcdef", "key_id": "hmac"});
    let d = HttpGateway::start(config).await;
    let (path, mut body) = request(Route::Invoke, "f-1", None);
    body["params"]["arguments"]["nonce"] = json!("invoke-nonce-f1");
    let response = post(&d, &path, &body).await;
    let links = client_verify(&response, "invoke-nonce-f1").expect("fallback verifies");
    assert_eq!(links.len(), 2, "{response}");
    let (path, mut body) = request(Route::Invoke, "f-2", Some("chain-nonce-f1b"));
    body["params"]["arguments"]["nonce"] = json!("invoke-nonce-f1b");
    let response = post(&d, &path, &body).await;
    assert!(
        client_verify(&response, "chain-nonce-f1b").is_ok(),
        "{response}"
    );
}

/// H8/H9: outside the claim. `emit: always` without a client nonce gives a
/// null nonce the client cannot verify; an invoke nonce alone under
/// `on_request` emits no chain.
#[tokio::test]
async fn nonce_scope_outside_the_claim() {
    for route in ROUTES {
        let upstream = FakeUpstream::start(Mode::Honest).await;
        let d = HttpGateway::start(d_config(&upstream.url, "verify", "always")).await;
        let response = call(&d, route, None).await;
        assert_eq!(chain_len(&response), 2, "{route:?}: {response}");
        assert_eq!(client_verify(&response, "any"), Err("nonce"), "{route:?}");
    }
    let upstream = FakeUpstream::start(Mode::Honest).await;
    let mut config = d_config(&upstream.url, "verify", "on_request");
    config["security"]["message_signing"] = json!({"enabled": true,
        "shared_secret": "chain-hops-hmac-secret-0123456789abcdef", "key_id": "hmac"});
    let d = HttpGateway::start(config).await;
    let (path, mut body) = request(Route::Invoke, "h9", None);
    body["params"]["arguments"]["nonce"] = json!("invoke-only");
    assert_eq!(chain_len(&post(&d, &path, &body).await), 0);
}

/// P2b: the link count. `max_links: 3` and an upstream chain of 3 leaves D
/// no room: -32001. A 2-link upstream appends to exactly 3 and verifies.
#[tokio::test]
async fn link_count_cap_on_append() {
    for route in ROUTES {
        let upstream = FakeUpstream::start(Mode::Padded { links: 3, pad: 8 }).await;
        let mut config = d_config(&upstream.url, "verify", "on_request");
        config["security"]["signature_chain"]["max_links"] = json!(3);
        let d = HttpGateway::start(config).await;
        assert_refused(&call(&d, route, Some("n-p")).await, "Size");
        upstream.set_mode(Mode::Padded { links: 2, pad: 8 });
        let response = call(&d, route, Some("n-p2")).await;
        assert_eq!(chain_len(&response), 3, "{route:?}: {response}");
    }
}

/// P2: the 16 KiB cap is enforced after the append, not only on receipt.
#[tokio::test]
async fn byte_cap_after_append() {
    for route in ROUTES {
        // 23 links of 695 bytes = 15,885 received (< 16,384); D's link with a
        // 200-byte client nonce adds ~640, which crosses the cap.
        let upstream = FakeUpstream::start(Mode::Padded {
            links: 23,
            pad: 256,
        })
        .await;
        let mut config = d_config(&upstream.url, "verify", "on_request");
        config["security"]["signature_chain"]["max_links"] = json!(32);
        let d = HttpGateway::start(config).await;
        let long_nonce = "n".repeat(200);
        assert_refused(&call(&d, route, Some(&long_nonce)).await, "Size");
        upstream.set_mode(Mode::Padded { links: 4, pad: 240 });
        assert!(
            chain_len(&call(&d, route, Some("n-fits")).await) == 5,
            "{route:?}"
        );
    }
}

/// I1/I1b: an interim reply. `require` refuses it at raw receipt, before any
/// continuation or retry; `verify` takes the unchained path.
#[tokio::test]
async fn interim_replies_from_chained_backends() {
    let upstream = FakeUpstream::start(Mode::InputRequired).await;
    let d = HttpGateway::start(d_config(&upstream.url, "require", "on_request")).await;
    let response = call(&d, Route::Invoke, Some("n-i1")).await;
    assert_refused(&response, "interim");
    assert_eq!(upstream.calls().len(), 1, "no retry reached the upstream");
    assert!(
        !response.to_string().contains("requestState"),
        "no continuation: {response}"
    );
    let upstream = FakeUpstream::start(Mode::InputRequired).await;
    let d = HttpGateway::start(d_config(&upstream.url, "verify", "on_request")).await;
    let response = call(&d, Route::Invoke, Some("n-i1b")).await;
    assert_ne!(
        response["error"]["code"], -32001,
        "verify never refuses an interim: {response}"
    );
    assert!(
        !response.to_string().contains(oracle::CHAIN_KEY),
        "{response}"
    );
}

/// K3: an unsolicited task handle to a synchronous `require` call is refused
/// at raw receipt; nothing is polled.
#[tokio::test]
async fn require_refuses_an_unsolicited_task_handle() {
    let upstream = FakeUpstream::start(Mode::TaskHandle).await;
    let d = HttpGateway::start(d_config(&upstream.url, "require", "on_request")).await;
    assert_refused(&call(&d, Route::Invoke, Some("n-k3")).await, "interim");
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    assert_eq!(upstream.calls().len(), 1, "nothing polled or retried");
}

/// Z1: a chained backend bypasses the response cache: both calls reach the
/// upstream, each chained over its own challenge.
#[tokio::test]
async fn chained_backend_bypasses_the_response_cache() {
    let upstream = FakeUpstream::start(Mode::Honest).await;
    let mut config = d_config(&upstream.url, "verify", "on_request");
    config["cache"] = json!({"enabled": true, "default_ttl": "5m", "max_entries": 100});
    let d = HttpGateway::start(config).await;
    let first = call(&d, Route::Invoke, Some("n-z1a")).await;
    let second = call(&d, Route::Invoke, Some("n-z1b")).await;
    assert_eq!(
        upstream.calls().len(),
        2,
        "no cache hit for a chained backend"
    );
    assert!(client_verify(&first, "n-z1a").is_ok() && client_verify(&second, "n-z1b").is_ok());
}

/// X1: surfaces outside the claim stay unchained even for a `verify`
/// backend: a direct-route method other than `tools/call`.
#[tokio::test]
async fn non_tools_call_direct_method_is_not_chained() {
    let upstream = FakeUpstream::start(Mode::Honest).await;
    let d = HttpGateway::start(d_config(&upstream.url, "verify", "always")).await;
    let body = json!({"jsonrpc": "2.0", "id": "x1", "method": "tools/list", "params": {}});
    let response = post(&d, &format!("/mcp/{UP}"), &body).await;
    assert!(response.get("result").is_some(), "{response}");
    assert!(
        !response.to_string().contains(oracle::CHAIN_KEY),
        "{response}"
    );
}

/// Z2: an idempotent replay of a chained result carries no chain, on both
/// routes, even when the replaying request asks for one.
#[tokio::test]
async fn chained_replay_carries_no_chain() {
    const BEARER: &str = "chain-hops-bearer-0123456789abcdef0123";
    for route in ROUTES {
        let upstream = FakeUpstream::start(Mode::Honest).await;
        let mut config = d_config(&upstream.url, "verify", "on_request");
        config["auth"] = json!({"enabled": true, "bearer_token": BEARER});
        let audit = tempfile::tempdir().expect("audit dir");
        config["security"]["transparency_log"] =
            json!({"enabled": true, "path": audit.path().join("audit").join("log.jsonl")});
        let mut d = HttpGateway::start(config).await;
        d.client = reqwest::Client::builder()
            .default_headers(reqwest::header::HeaderMap::from_iter([(
                reqwest::header::AUTHORIZATION,
                format!("Bearer {BEARER}").parse().expect("header"),
            )]))
            .build()
            .expect("client");
        let mut responses = Vec::new();
        for nonce in ["n-z2a", "n-z2b"] {
            let (path, mut body) = request(route, nonce, Some(nonce));
            body["params"]["_meta"]["io.mcp-gateway/idempotency-key"] = json!("z2-key");
            responses.push(post(&d, &path, &body).await);
        }
        assert_eq!(
            upstream.calls().len(),
            1,
            "{route:?}: the second call replays"
        );
        assert!(
            client_verify(&responses[0], "n-z2a").is_ok(),
            "{route:?}: {}",
            responses[0]
        );
        assert!(
            responses[1].get("result").is_some(),
            "{route:?}: {}",
            responses[1]
        );
        assert_eq!(chain_len(&responses[1]), 0, "{route:?}: {}", responses[1]);
    }
}

/// H1 interop: the upstream is a real second gateway (origin role) reached
/// through its direct route; D verifies and appends, the client verifies.
#[tokio::test]
async fn two_real_gateways_chain_end_to_end() {
    let backend = signing_gateway::BackendFixture::start(fake::result_body()).await;
    let mut u_config = signing_gateway::fixture_config(&backend.url);
    u_config["security"]["message_signing"] = json!({"enabled": false});
    u_config["security"]["signature_chain"] = json!({"signing_key": base64::engine::general_purpose::STANDARD.encode(fake::U_SEED), "key_id": fake::U_ID});
    let u = HttpGateway::start(u_config).await;
    let upstream_url = format!("{}/mcp/{}", u.url, signing_gateway::BACKEND);
    let mut d_cfg = d_config(&upstream_url, "require", "on_request");
    d_cfg["backends"][UP]["streamable_http"] = json!(true);
    let d = HttpGateway::start(d_cfg).await;
    let (path, mut body) = request(Route::Invoke, "real-1", Some("n-real"));
    body["params"]["arguments"]["tool"] = json!(signing_gateway::TOOL);
    let response = post(&d, &path, &body).await;
    let links =
        client_verify(&response, "n-real").unwrap_or_else(|rule| panic!("{rule}: {response}"));
    assert_eq!(links.len(), 2, "{response}");
}

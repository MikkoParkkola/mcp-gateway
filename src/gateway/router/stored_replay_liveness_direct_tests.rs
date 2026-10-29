// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8434 (MIK-8392 DIRECT): the direct route `POST /mcp/{backend}` judges a
//! stored replay as `/mcp` does. On an optional (`required: false`) backend a
//! failed mint falls back to static credentials, which is not a proof of the
//! caller's account, so the per-user output an earlier minted call stored is
//! not served to it. Current-thread rows: the forced clock is the thread's.

use std::sync::atomic::Ordering;

use super::*;
use crate::identity_propagation::PropagationStrategyKind;
use crate::security::SecurityPosture;

/// The direct envelope for [`TOOL`] under idempotency key `key`, with the
/// signing nonce in `_meta` when one is given.
fn direct_call(key: &str, nonce: Option<&str>) -> Value {
    let mut params = json!({"name": TOOL, "arguments": {"folder": "inbox"},
        "_meta": meta(Some(key), false)});
    if let Some(nonce) = nonce {
        params["_meta"][crate::gateway::meta_mcp::signing::NONCE_META] = json!(nonce);
    }
    params
}

/// The same call through `gateway_invoke` on `/mcp`.
fn meta_call(key: &str) -> Value {
    json!({"name": "gateway_invoke",
        "arguments": {"server": r6m_token_exchange::TX, "tool": TOOL,
            "arguments": {"folder": "inbox"}},
        "_meta": meta(Some(key), false)})
}

/// The `/mcp` answer to [`meta_call`], with its HTTP status.
async fn meta_full(
    router: &axum::Router,
    alice: &crate::key_server::oidc::VerifiedIdentity,
    key: &str,
) -> (axum::http::StatusCode, Value) {
    let route = ("/mcp", "tools/call", "gateway_invoke");
    r6m_token_exchange::post_as(router, alice, route, meta_call(key), &[]).await
}

const OPTIONAL_TX: (
    r6m_token_exchange::Requirement,
    PropagationStrategyKind,
    SecurityPosture,
) = (
    r6m_token_exchange::Requirement::Optional,
    PropagationStrategyKind::TokenExchange,
    SecurityPosture::Standard,
);

/// The idempotency cache armed, as production arms it.
fn armed(mut meta: crate::gateway::meta_mcp::MetaMcp) -> crate::gateway::meta_mcp::MetaMcp {
    meta.enable_idempotency(
        Arc::new(crate::idempotency::IdempotencyCache::new()),
        std::time::Duration::from_secs(60),
    );
    meta
}

/// A served answer: `MARKER` over HTTP 200, with no error.
fn assert_served(row: &str, (status, answer): &(axum::http::StatusCode, Value)) {
    assert_eq!(*status, axum::http::StatusCode::OK, "{row}: {answer}");
    assert!(
        answer.to_string().contains(MARKER) && answer.get("error").is_none(),
        "{row}: not served: {answer}"
    );
}

/// What the last delivery record in the fixture's log (`dirs.0`) states as
/// its effect: a refused replay states `refused`, never `delivered`, and no
/// findings (`Absent` when it names none).
fn last_effect(dirs: &(tempfile::TempDir, crate::gateway::router::tests::FixtureDir)) -> Value {
    std::fs::read_to_string(dirs.0.path().join("audit.jsonl"))
        .unwrap_or_default()
        .lines()
        .rev()
        .map(|line| serde_json::from_str::<Value>(line).expect("log line is JSON"))
        .find(|entry| entry["event"] == "response_delivery_attempt")
        .map_or(Value::Null, |entry| {
            let findings = entry
                .get("response_findings")
                .map_or("Absent".into(), Value::to_string);
            json!([entry["response_effect"], findings])
        })
}

/// Past the cached exchange token's one-hour TTL; the stored result (one
/// day) is still held.
fn past_the_token() -> impl Drop {
    let now = crate::clock::unix_secs().expect("a test host clock reads after 1970");
    crate::clock::test_clock::at_secs(now + 7200)
}

/// D-opt (DIRECT.1; mutants M-open, M-proceed): a keyed direct retry whose
/// mint now fails on an optional backend misses 7a (its principal is the
/// unminted one) and reaches the 7b execution store under the same owner.
/// It is refused with the unminted refusal, never served the per-user output
/// and never sent again. The key is not stranded: a second unminted retry is
/// refused the same way, and once the `IdP` is back the same key is served.
#[tokio::test]
async fn d_opt_an_unminted_direct_retry_is_not_served_the_stored_result() {
    let key = Arc::new(crate::gateway::oauth::GatewayKeyPair::generate().expect("keygen"));
    let idp = r6m_token_exchange::LiveIdp::start(&key).await;
    let alice = r6m_token_exchange::alice();
    let (router, sends, dirs) =
        r6m_token_exchange::gateway_shaped(&key, idp.endpoint(), &alice, OPTIONAL_TX, armed).await;
    let direct = async |key: &str| {
        r6m_token_exchange::send_direct_as(&router, &alice, direct_call(key, None), &[]).await
    };
    assert_served("premise: the minted first call", &direct("dopt").await);
    assert_eq!(sends.load(Ordering::SeqCst), 1, "premise: one send");
    let (addr, exchanges) = (idp.addr(), idp.exchanges());
    let minted = exchanges.load(Ordering::SeqCst);
    idp.kill();
    let _clock = past_the_token();
    let (_, again) = direct("dopt").await;
    eprintln!("D-opt answer: {again}");
    // The send count first, so M-proceed dies here and M-open (one send,
    // the stored output served) at the exact refusal below.
    assert_eq!(
        sends.load(Ordering::SeqCst),
        1,
        "D-opt: the unproven retry was sent again: {again}"
    );
    assert_unproven("D-opt", &again);
    assert_eq!(
        last_effect(&dirs),
        json!(["refused", "Absent"]),
        "D-opt: the refusal's record"
    );
    assert_eq!(
        exchanges.load(Ordering::SeqCst),
        minted,
        "premise: the retry's mint never reached the dead IdP"
    );
    let (_, repeat) = direct("dopt").await;
    assert_unproven("D-opt repeat (the key was not stranded)", &repeat);
    let _idp = r6m_token_exchange::LiveIdp::restart(&key, addr).await;
    assert_served("D-opt recovered", &direct("dopt").await);
    assert_eq!(
        sends.load(Ordering::SeqCst),
        1,
        "D-opt: the recovered retry was sent again, not served"
    );
}

/// D-parity (DIRECT.2; mutants M-text, M-status): the direct refusal is the
/// one `/mcp` answers the same retry with: the same HTTP status and the same
/// `/error` object field for field (code, message, no `data`). One router,
/// two keys, so the `/mcp` answer is the live one, not a remembered string.
#[tokio::test]
async fn d_parity_the_direct_refusal_is_the_meta_refusal() {
    let key = Arc::new(crate::gateway::oauth::GatewayKeyPair::generate().expect("keygen"));
    let idp = r6m_token_exchange::LiveIdp::start(&key).await;
    let alice = r6m_token_exchange::alice();
    let (router, sends, _dirs) =
        r6m_token_exchange::gateway_shaped(&key, idp.endpoint(), &alice, OPTIONAL_TX, armed).await;
    let direct = async || {
        r6m_token_exchange::send_direct_as(&router, &alice, direct_call("dpar-d", None), &[]).await
    };
    assert_served("premise: the direct first call", &direct().await);
    assert_served(
        "premise: the meta first call",
        &meta_full(&router, &alice, "dpar-m").await,
    );
    assert_eq!(sends.load(Ordering::SeqCst), 2, "premise: two sends");
    idp.kill();
    let _clock = past_the_token();
    let (meta_status, meta) = meta_full(&router, &alice, "dpar-m").await;
    eprintln!("D-parity /mcp answer ({meta_status}): {meta}");
    assert_unproven("premise: /mcp refuses the unminted retry", &meta);
    let (direct_status, refused) = direct().await;
    eprintln!("D-parity direct answer ({direct_status}): {refused}");
    assert_eq!(
        sends.load(Ordering::SeqCst),
        2,
        "D-parity: a retry was sent"
    );
    assert_eq!(
        direct_status, meta_status,
        "D-parity: the HTTP status differs from /mcp's: {refused}"
    );
    assert_eq!(
        refused.get("error"),
        meta.get("error"),
        "D-parity: the error object differs from /mcp's"
    );
    assert!(
        refused.pointer("/error/data").is_none(),
        "D-parity: a data member (retryable marker or status stamp): {refused}"
    );
}

/// D-opt-signed (mutant M-early): D-opt under `hardened`, where the direct
/// route signs every `tools/call`. The unproven refusal comes after the
/// nonce is admitted, so the refused nonce stays spent: re-sent after the
/// `IdP` recovers it is refused, and a fresh nonce under the same
/// idempotency key is served the stored result. One send in all.
#[tokio::test]
async fn d_opt_signed_the_refused_direct_nonce_stays_spent() {
    let key = Arc::new(crate::gateway::oauth::GatewayKeyPair::generate().expect("keygen"));
    let idp = r6m_token_exchange::LiveIdp::start(&key).await;
    let alice = r6m_token_exchange::alice();
    let shape = (OPTIONAL_TX.0, OPTIONAL_TX.1, SecurityPosture::Hardened);
    let arm = |meta| {
        let mut meta = armed(meta);
        meta.enable_message_signing(
            crate::security::message_signing::MessageSigner::new(
                b"dopt-signing-key-0123456789abcdef-s".to_vec(),
                None,
                "dopt".into(),
            ),
            std::time::Duration::from_secs(300),
            true,
        );
        meta
    };
    let (router, sends, _dirs) =
        r6m_token_exchange::gateway_shaped(&key, idp.endpoint(), &alice, shape, arm).await;
    let signed = async |nonce: &str| {
        let params = direct_call("dopt-s", Some(nonce));
        r6m_token_exchange::send_direct_as(&router, &alice, params, &[]).await
    };
    let first = signed("n1").await;
    assert_served("premise: the signed first call", &first);
    assert_eq!(
        first.1.pointer("/result/_signature/nonce"),
        Some(&json!("n1")),
        "premise: the direct route signed under this nonce: {}",
        first.1
    );
    let addr = idp.addr();
    idp.kill();
    let _clock = past_the_token();
    let (_, unproven) = signed("n2").await;
    eprintln!("D-opt-signed answer: {unproven}");
    assert_unproven("D-opt-signed", &unproven);
    let _idp = r6m_token_exchange::LiveIdp::restart(&key, addr).await;
    let (status, reused) = signed("n2").await;
    eprintln!("D-opt-signed reused nonce ({status}): {reused}");
    // The signer's replay refusal, as the direct route answers it at nonce
    // admission (`admit_signing_nonce`), never any other error.
    assert_eq!(
        (status, reused.get("error")),
        (
            axum::http::StatusCode::BAD_REQUEST,
            Some(&json!({"code": -32001, "message": "Nonce replay detected"}))
        ),
        "D-opt-signed: the refused nonce was not refused as a replay: {reused}"
    );
    assert_served("D-opt-signed fresh nonce", &signed("n3").await);
    assert_eq!(
        sends.load(Ordering::SeqCst),
        1,
        "D-opt-signed: a retry was sent again"
    );
}

/// D-minted (DIRECT.3 control; mutant M-mint-none): both calls mint, and 7a
/// is NOT armed, so only the 7b replay can serve the retry: it is served,
/// one send in all. A proof that never holds refuses it.
#[tokio::test]
async fn d_minted_a_minted_direct_retry_is_replayed() {
    let key = Arc::new(crate::gateway::oauth::GatewayKeyPair::generate().expect("keygen"));
    let idp = r6m_token_exchange::LiveIdp::start(&key).await;
    let alice = r6m_token_exchange::alice();
    let (router, sends, _dirs) =
        r6m_token_exchange::gateway_shaped(&key, idp.endpoint(), &alice, OPTIONAL_TX, |m| m).await;
    let direct = async || {
        r6m_token_exchange::send_direct_as(&router, &alice, direct_call("dmint", None), &[]).await
    };
    assert_served("premise: the minted first call", &direct().await);
    assert_served("D-minted: the minted retry", &direct().await);
    assert_eq!(sends.load(Ordering::SeqCst), 1, "D-minted: sent again");
    assert!(
        idp.exchanges().load(Ordering::SeqCst) >= 1,
        "premise: the calls minted"
    );
}

/// D-unminted (control; mutant M-shut): the `IdP` is dead from the start, so
/// neither call mints; the retry is a 7a hit under the same static principal
/// and is served, one send in all. A check applied to the 7a hit refuses it.
#[tokio::test]
async fn d_unminted_a_retry_of_an_unminted_direct_call_is_served_from_7a() {
    let key = Arc::new(crate::gateway::oauth::GatewayKeyPair::generate().expect("keygen"));
    let idp = r6m_token_exchange::LiveIdp::start(&key).await;
    let alice = r6m_token_exchange::alice();
    let (router, sends, _dirs) =
        r6m_token_exchange::gateway_shaped(&key, idp.endpoint(), &alice, OPTIONAL_TX, armed).await;
    let exchanges = idp.exchanges();
    idp.kill();
    let direct = async || {
        r6m_token_exchange::send_direct_as(&router, &alice, direct_call("dun", None), &[]).await
    };
    assert_served(
        "premise: dispatched under static credentials",
        &direct().await,
    );
    assert_served("D-unminted: the cached unminted result", &direct().await);
    assert_eq!(sends.load(Ordering::SeqCst), 1, "D-unminted: sent again");
    assert_eq!(
        exchanges.load(Ordering::SeqCst),
        0,
        "premise: neither minted"
    );
}

/// D-unminted-aged (parity, no presupposed answer): the `IdP` is dead from
/// the start, so the first call is unminted; its 7a entry then ages out
/// while the 7b execution store keeps it, so the unminted retry reaches 7b.
/// The direct route must answer it as `/mcp` answers the same sequence
/// (status, `/error`, and whether a result is served), with nothing sent.
#[tokio::test]
async fn d_unminted_aged_a_7b_replay_of_an_unminted_call_matches_meta() {
    let key = Arc::new(crate::gateway::oauth::GatewayKeyPair::generate().expect("keygen"));
    let idp = r6m_token_exchange::LiveIdp::start(&key).await;
    let alice = r6m_token_exchange::alice();
    let cache = Arc::new(crate::idempotency::IdempotencyCache::new());
    let installed = Arc::clone(&cache);
    let arm = move |mut meta: crate::gateway::meta_mcp::MetaMcp| {
        meta.enable_idempotency(installed, std::time::Duration::from_secs(300));
        meta
    };
    let (router, sends, _dirs) =
        r6m_token_exchange::gateway_shaped(&key, idp.endpoint(), &alice, OPTIONAL_TX, arm).await;
    idp.kill();
    let direct = async || {
        r6m_token_exchange::send_direct_as(&router, &alice, direct_call("dage-d", None), &[]).await
    };
    assert_served("premise: the unminted direct call", &direct().await);
    assert_served(
        "premise: the unminted meta call",
        &meta_full(&router, &alice, "dage-m").await,
    );
    assert_eq!(sends.load(Ordering::SeqCst), 2, "premise: two sends");
    // Past the cache's 24-hour completed lifetime: a forced 7a miss.
    cache.advance_for_test(std::time::Duration::from_secs(25 * 60 * 60));
    let (meta_status, meta) = meta_full(&router, &alice, "dage-m").await;
    eprintln!("D-unminted-aged /mcp answer ({meta_status}): {meta}");
    let (direct_status, answer) = direct().await;
    eprintln!("D-unminted-aged direct answer ({direct_status}): {answer}");
    assert_eq!(
        sends.load(Ordering::SeqCst),
        2,
        "D-unminted-aged: a retry was sent"
    );
    assert_eq!(
        (
            direct_status,
            answer.get("error"),
            answer.get("result").is_some()
        ),
        (meta_status, meta.get("error"), meta.get("result").is_some()),
        "D-unminted-aged: the direct answer differs from /mcp's: {answer}"
    );
}

/// D-req (DIRECT.3 control; mutant M-req): a `required` backend refuses at
/// stage 5, before admission, so its answer is the required refusal and not
/// the unminted one, with nothing sent.
#[tokio::test]
async fn d_req_a_required_direct_retry_is_refused_at_stage_five() {
    let key = Arc::new(crate::gateway::oauth::GatewayKeyPair::generate().expect("keygen"));
    let idp = r6m_token_exchange::LiveIdp::start(&key).await;
    let alice = r6m_token_exchange::alice();
    let (router, sends, _dirs) = r6m_token_exchange::gateway_with(
        &key,
        idp.endpoint(),
        &alice,
        r6m_token_exchange::Requirement::Required,
        |m| m,
    )
    .await;
    let direct = async || {
        r6m_token_exchange::send_direct_as(&router, &alice, direct_call("dreq", None), &[]).await
    };
    assert_served("premise: the minted first call", &direct().await);
    let endpoint = idp.endpoint();
    idp.kill();
    let _clock = past_the_token();
    let (status, refused) = direct().await;
    eprintln!("D-req answer ({status}): {refused}");
    assert_eq!(sends.load(Ordering::SeqCst), 1, "D-req: sent again");
    // The answer captured at the tip before the fix (MIK-8434 stage 1).
    let required = format!(
        "Configuration error: identity propagation required for backend 'tx' but credential \
         minting failed: identity propagation refused (fail-closed): token-exchange request \
         failed: error sending request for url ({endpoint})"
    );
    assert_eq!(
        (status, refused.get("error")),
        (
            axum::http::StatusCode::FORBIDDEN,
            Some(&json!({"code": -32003, "message": required}))
        ),
        "D-req: not the stage-5 required refusal: {refused}"
    );
}

/// The passthrough header the direct route forwards as `Authorization`.
const PASSTHROUGH: (&str, &str) = (
    "x-mcp-passthrough-authorization",
    r6m_token_exchange::PASSTHROUGH_CREDENTIAL,
);

/// A passthrough, optional [`r6m_token_exchange::TX`] with 7a NOT armed, so
/// only 7b can serve a retry: the first call forwarded a credential.
async fn passthrough_after_forwarded() -> (
    axum::Router,
    Arc<std::sync::atomic::AtomicUsize>,
    (tempfile::TempDir, crate::gateway::router::tests::FixtureDir),
    crate::key_server::oidc::VerifiedIdentity,
) {
    let key = Arc::new(crate::gateway::oauth::GatewayKeyPair::generate().expect("keygen"));
    let alice = r6m_token_exchange::alice();
    let shape = (
        r6m_token_exchange::Requirement::Optional,
        PropagationStrategyKind::Passthrough,
        SecurityPosture::Standard,
    );
    let unused = "http://127.0.0.1:9/auth/token".to_string();
    let (router, sends, dirs) =
        r6m_token_exchange::gateway_shaped(&key, unused, &alice, shape, |m| m).await;
    let first = r6m_token_exchange::send_direct_as(
        &router,
        &alice,
        direct_call("dpt", None),
        &[PASSTHROUGH],
    )
    .await;
    assert_served("premise: the forwarded first call", &first);
    assert_eq!(sends.load(Ordering::SeqCst), 1, "premise: one send");
    (router, sends, dirs, alice)
}

/// D-pt (mutant M-pt): the same key with no passthrough header is the static
/// fallback; the stored output the forwarded credential produced is not
/// served to it, and nothing is sent.
#[tokio::test]
async fn d_pt_a_retry_that_forwards_no_credential_is_refused() {
    let (router, sends, _dirs, alice) = passthrough_after_forwarded().await;
    let (status, again) =
        r6m_token_exchange::send_direct_as(&router, &alice, direct_call("dpt", None), &[]).await;
    eprintln!("D-pt answer ({status}): {again}");
    assert_eq!(sends.load(Ordering::SeqCst), 1, "D-pt: sent again: {again}");
    assert_eq!(status, axum::http::StatusCode::OK, "D-pt: {again}");
    // One refusal however the backend propagates (lead ruling): the
    // unminted refusal, word for word.
    assert_unproven("D-pt", &again);
    assert!(
        !again.to_string().contains(MARKER),
        "D-pt: the stored output went out"
    );
}

/// D-pt-fwd (control; mutant M-pt-all): the same key forwarding the same
/// credential again is replayed from 7b, one send in all.
#[tokio::test]
async fn d_pt_fwd_a_retry_that_forwards_the_credential_is_replayed() {
    let (router, sends, _dirs, alice) = passthrough_after_forwarded().await;
    let again = r6m_token_exchange::send_direct_as(
        &router,
        &alice,
        direct_call("dpt", None),
        &[PASSTHROUGH],
    )
    .await;
    assert_served("D-pt-fwd", &again);
    assert_eq!(sends.load(Ordering::SeqCst), 1, "D-pt-fwd: sent again");
}

/// The second credential's passthrough header (MIK-8440).
const PASSTHROUGH_B: (&str, &str) = (
    "x-mcp-passthrough-authorization",
    r6m_token_exchange::PASSTHROUGH_CREDENTIAL_B,
);

/// PT-B (MIK-8440 PTBIND.1, .3; mutant M-ptb): the same caller retries key
/// K forwarding a DIFFERENT passthrough credential. The output stored under
/// the first credential is not served to it, and nothing is sent: the key's
/// one execution is settled, so running it again would be a second send. B's
/// second retry is refused the same way. A's own retry is still served from
/// 7b (PTBIND.3), with one send in all.
#[tokio::test]
async fn pt_b_a_retry_under_another_forwarded_credential_is_refused() {
    let (router, sends, dirs, alice) = passthrough_after_forwarded().await;
    for row in ["PT-B", "PT-B again"] {
        let (status, other) = r6m_token_exchange::send_direct_as(
            &router,
            &alice,
            direct_call("dpt", None),
            &[PASSTHROUGH_B],
        )
        .await;
        eprintln!("{row} answer ({status}): {other}");
        assert!(
            !other.to_string().contains(MARKER),
            "{row}: served the first credential's stored output: {other}"
        );
        assert_eq!(
            other.pointer("/error/code").and_then(Value::as_i64),
            Some(-32603),
            "{row}: not the binding refusal: {other}"
        );
        assert_eq!(sends.load(Ordering::SeqCst), 1, "{row}: sent: {other}");
        assert_eq!(
            last_effect(&dirs),
            json!(["refused", "Absent"]),
            "{row}: the refusal's record"
        );
    }
    let again = r6m_token_exchange::send_direct_as(
        &router,
        &alice,
        direct_call("dpt", None),
        &[PASSTHROUGH],
    )
    .await;
    assert_served("PT-B A again", &again);
    assert_eq!(sends.load(Ordering::SeqCst), 1, "PT-B A again: sent again");
}

/// PT-anon (MIK-8440 design question; mutant M-anon): with authentication
/// off, a caller with no identity has no execution principal, so a keyed
/// direct call is refused at intake (-32003) whichever credential it
/// forwards. Two anonymous credentials therefore never share one 7b owner:
/// neither call is sent, and no stored output exists to cross between them.
#[tokio::test]
async fn pt_anon_keyed_anonymous_calls_never_share_an_owner() {
    use tower::ServiceExt;

    let key = Arc::new(crate::gateway::oauth::GatewayKeyPair::generate().expect("keygen"));
    let alice = r6m_token_exchange::alice();
    let shape = (
        r6m_token_exchange::Requirement::Optional,
        PropagationStrategyKind::Passthrough,
        SecurityPosture::Standard,
    );
    let unused = "http://127.0.0.1:9/auth/token".to_string();
    let (router, sends, _dirs) =
        r6m_token_exchange::gateway_shaped(&key, unused, &alice, shape, |m| m).await;
    for (row, header) in [("PT-anon A", PASSTHROUGH), ("PT-anon B", PASSTHROUGH_B)] {
        let body = json!({"jsonrpc": "2.0", "id": 7, "method": "tools/call",
            "params": direct_call("anon", None)});
        let request = axum::http::Request::builder()
            .method("POST")
            .uri(format!("/mcp/{}", r6m_token_exchange::TX))
            .header("content-type", "application/json")
            .header("mcp-protocol-version", "2026-07-28")
            .header("mcp-method", "tools/call")
            .header("mcp-name", TOOL)
            .header(header.0, header.1)
            .body(axum::body::Body::from(body.to_string()))
            .expect("a request");
        let response = router.clone().oneshot(request).await.expect("an answer");
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("a body");
        let answer: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
        assert_eq!(
            answer.pointer("/error/code").and_then(Value::as_i64),
            Some(-32003),
            "{row}: an anonymous keyed call was admitted: {answer}"
        );
        assert_eq!(sends.load(Ordering::SeqCst), 0, "{row}: sent: {answer}");
    }
}

// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8392 STORED.2 FIX 1: on an optional (`required: false`) propagation
//! backend a failed mint falls back to static credentials. That fallback is
//! not a proof of the caller's account: the stored output was produced under
//! a per-user credential. Current-thread rows: the forced clock is the
//! thread's.

use super::*;

fn call(key: &str, task: bool) -> Value {
    let mut params = json!({"name": "gateway_invoke",
        "arguments": {"server": r6m_token_exchange::TX, "tool": TOOL,
            "arguments": {"folder": "inbox"}},
        "_meta": meta(Some(key), task)});
    if task {
        params["task"] = json!({});
    }
    params
}

/// The refusal an unminted proof answers with, at the lift and at site 5.
const UNPROVEN: &str = "Configuration error: identity propagation minted no credential \
                        for backend 'tx'; a stored result is not served without one";

fn assert_unproven(row: &str, answer: &Value) {
    assert_eq!(
        answer.pointer("/error/code").and_then(Value::as_i64),
        Some(-32603),
        "{row}: not the unproven refusal: {answer}"
    );
    assert_eq!(
        answer.pointer("/error/message").and_then(Value::as_str),
        Some(UNPROVEN),
        "{row}: not the unproven refusal: {answer}"
    );
}

/// The optional-propagation router with the idempotency cache armed, as
/// production arms it (`server/build_meta.rs`).
async fn optional_gateway(
    idp: &r6m_token_exchange::LiveIdp,
    key: &Arc<crate::gateway::oauth::GatewayKeyPair>,
) -> (
    axum::Router,
    Arc<std::sync::atomic::AtomicUsize>,
    (tempfile::TempDir, tempfile::TempDir),
) {
    r6m_token_exchange::gateway_with(
        key,
        idp.endpoint(),
        &r6m_token_exchange::alice(),
        r6m_token_exchange::Requirement::Optional,
        |mut meta| {
            meta.enable_idempotency(
                Arc::new(crate::idempotency::IdempotencyCache::new()),
                std::time::Duration::from_secs(60),
            );
            meta
        },
    )
    .await
}

/// S-opt (mutants M-mint, M-lift-open): a keyed retry whose mint now fails on
/// an optional backend is neither lifted from the per-user stored result nor
/// dispatched again under static credentials (at most once, FIX 1b): the
/// idempotency lookup under the unminted principal misses, so it fails closed
/// with site 5's refusal and nothing is sent. M-mint (the static fallback
/// counts as a proof) lifts the stored output; M-lift-open (the dropped entry
/// runs live) sends the call a second time.
#[tokio::test]
async fn s_opt_a_failed_optional_mint_is_not_a_proof_at_the_lift() {
    use std::sync::atomic::Ordering;

    let key = Arc::new(crate::gateway::oauth::GatewayKeyPair::generate().expect("keygen"));
    let idp = r6m_token_exchange::LiveIdp::start(&key).await;
    let alice = r6m_token_exchange::alice();
    let (router, sends, _dirs) = optional_gateway(&idp, &key).await;
    let first = r6m_token_exchange::send_as(&router, &alice, call("sopt", false)).await;
    assert!(
        first.to_string().contains(MARKER),
        "premise: dispatched: {first}"
    );
    assert_eq!(sends.load(Ordering::SeqCst), 1, "premise: one send");
    idp.kill();
    let now = crate::clock::unix_secs().expect("a test host clock reads after 1970");
    let _clock = crate::clock::test_clock::at_secs(now + 7200);
    let again = r6m_token_exchange::send_as(&router, &alice, call("sopt", false)).await;
    eprintln!("S-opt answer: {again}");
    assert_unproven("S-opt", &again);
    assert_eq!(
        sends.load(Ordering::SeqCst),
        1,
        "S-opt: the unproven retry was sent again: {again}"
    );
}

/// S-unminted (mutant M-lift-shut): when the first call was unminted too, its
/// result was written under the same static principal, so the idempotency
/// cache serves the retry: the stored result, one send in total. Refusing at
/// the lift before the lookup (M-lift-shut) refuses this legitimate repeat.
#[tokio::test]
async fn s_unminted_a_retry_of_an_unminted_call_is_served_from_the_cache() {
    use std::sync::atomic::Ordering;

    let key = Arc::new(crate::gateway::oauth::GatewayKeyPair::generate().expect("keygen"));
    let idp = r6m_token_exchange::LiveIdp::start(&key).await;
    let (router, sends, _dirs) = optional_gateway(&idp, &key).await;
    idp.kill();
    let alice = r6m_token_exchange::alice();
    let first = r6m_token_exchange::send_as(&router, &alice, call("sun", false)).await;
    assert!(
        first.to_string().contains(MARKER),
        "premise: dispatched under static credentials: {first}"
    );
    let again = r6m_token_exchange::send_as(&router, &alice, call("sun", false)).await;
    assert!(
        again.to_string().contains(MARKER) && again.get("error").is_none(),
        "S-unminted: the cached unminted result was not served: {again}"
    );
    assert_eq!(
        sends.load(Ordering::SeqCst),
        1,
        "S-unminted: the retry was sent again: {again}"
    );
}

/// S-minted (control; mutant M-mint-none): on an optional backend whose mint
/// succeeds, the retry is lifted from the stored result with one send in
/// total. A proof that never holds (M-mint-none) refuses it.
#[tokio::test]
async fn s_minted_a_minted_optional_retry_is_lifted() {
    use std::sync::atomic::Ordering;

    let key = Arc::new(crate::gateway::oauth::GatewayKeyPair::generate().expect("keygen"));
    let idp = r6m_token_exchange::LiveIdp::start(&key).await;
    let (router, sends, _dirs) = optional_gateway(&idp, &key).await;
    let alice = r6m_token_exchange::alice();
    let first = r6m_token_exchange::send_as(&router, &alice, call("smint", false)).await;
    assert!(first.to_string().contains(MARKER), "premise: {first}");
    let again = r6m_token_exchange::send_as(&router, &alice, call("smint", false)).await;
    assert!(
        again.to_string().contains(MARKER) && again.get("error").is_none(),
        "S-minted: the minted retry was not served: {again}"
    );
    assert_eq!(
        sends.load(Ordering::SeqCst),
        1,
        "S-minted: the minted retry was sent again: {again}"
    );
}

/// T-opt (mutant M-mint): a repeated task call whose mint now fails on an
/// optional backend is not served the stored task. A task repeat has no live
/// path (the row holds its key), so it fails closed and nothing is sent.
#[tokio::test]
async fn t_opt_a_failed_optional_mint_is_not_a_proof_at_site_five() {
    use std::sync::atomic::Ordering;

    let key = Arc::new(crate::gateway::oauth::GatewayKeyPair::generate().expect("keygen"));
    let idp = r6m_token_exchange::LiveIdp::start(&key).await;
    let alice = r6m_token_exchange::alice();
    let (router, sends, _dirs) = r6m_token_exchange::gateway_with(
        &key,
        idp.endpoint(),
        &alice,
        r6m_token_exchange::Requirement::Optional,
        |meta| meta,
    )
    .await;
    let made = r6m_token_exchange::send_as(&router, &alice, call("topt", true)).await;
    let id = made
        .pointer("/result/taskId")
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("premise: a task was made: {made}"))
        .to_owned();
    let bound = std::time::Instant::now() + std::time::Duration::from_secs(10);
    loop {
        let params = json!({"taskId": id, "_meta": meta(None, true)});
        let got =
            r6m_token_exchange::send_method_as(&router, &alice, ("tasks/get", &id), params).await;
        let status = got.pointer("/result/status").and_then(Value::as_str);
        if matches!(status, Some("completed" | "failed" | "cancelled")) {
            break;
        }
        assert!(
            std::time::Instant::now() < bound,
            "premise: the task settled: {got}"
        );
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    let sent = sends.load(Ordering::SeqCst);
    idp.kill();
    let now = crate::clock::unix_secs().expect("a test host clock reads after 1970");
    let _clock = crate::clock::test_clock::at_secs(now + 7200);
    let again = r6m_token_exchange::send_as(&router, &alice, call("topt", true)).await;
    eprintln!("T-opt answer: {again}");
    assert!(
        again.pointer("/result/taskId").is_none(),
        "T-opt: the stored task was served without a mint: {again}"
    );
    assert_unproven("T-opt", &again);
    assert_eq!(
        sends.load(Ordering::SeqCst),
        sent,
        "T-opt: the call was sent: {again}"
    );
}

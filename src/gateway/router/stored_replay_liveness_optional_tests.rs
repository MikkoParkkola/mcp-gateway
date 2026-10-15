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

/// S-opt (mutant M-mint): a keyed retry whose mint now fails on an optional
/// backend is not lifted from the stored result: it takes the live path under
/// static credentials (one more send). Counting the static fallback as a
/// proof (M-mint) lifts the per-user stored output instead.
#[tokio::test]
async fn s_opt_a_failed_optional_mint_is_not_a_proof_at_the_lift() {
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
    assert_eq!(
        sends.load(Ordering::SeqCst),
        2,
        "S-opt: the per-user stored result was lifted without a mint: {again}"
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
    assert!(
        again.get("error").is_some(),
        "T-opt: not a refusal: {again}"
    );
    assert_eq!(
        sends.load(Ordering::SeqCst),
        sent,
        "T-opt: the call was sent: {again}"
    );
}

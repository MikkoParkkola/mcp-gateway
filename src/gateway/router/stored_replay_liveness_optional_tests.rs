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

/// The optional-propagation router with the idempotency cache armed, as
/// production arms it (`server/build_meta.rs`).
async fn optional_gateway(
    idp: &r6m_token_exchange::LiveIdp,
    key: &Arc<crate::gateway::oauth::GatewayKeyPair>,
) -> (
    axum::Router,
    Arc<std::sync::atomic::AtomicUsize>,
    (tempfile::TempDir, crate::gateway::router::tests::FixtureDir),
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
/// runs live) sends the call a second time. The refusal comes after the key
/// was reserved, so the row then shows the key is not stranded: a second
/// unminted retry gets the same refusal (not an in-flight answer), and once
/// the `IdP` is back the same key is served the stored result, still one
/// send (at most once). This row is unsigned, so it does not exercise nonce
/// settlement; S-opt-signed does.
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
    let (addr, exchanges) = (idp.addr(), idp.exchanges());
    let minted = exchanges.load(Ordering::SeqCst);
    idp.kill();
    let now = crate::clock::unix_secs().expect("a test host clock reads after 1970");
    let _clock = crate::clock::test_clock::at_secs(now + 7200);
    let again = r6m_token_exchange::send_as(&router, &alice, call("sopt", false)).await;
    eprintln!("S-opt answer: {again}");
    // The send count first, so M-lift-open dies here and M-mint (sends 1,
    // the stored output served) at the exact refusal below.
    assert_eq!(
        sends.load(Ordering::SeqCst),
        1,
        "S-opt: the unproven retry was sent again: {again}"
    );
    assert_unproven("S-opt", &again);
    assert_eq!(
        exchanges.load(Ordering::SeqCst),
        minted,
        "premise: the retry's mint never reached the dead IdP"
    );
    let repeat = r6m_token_exchange::send_as(&router, &alice, call("sopt", false)).await;
    assert_unproven("S-opt repeat (the reservation was released)", &repeat);
    let _idp = r6m_token_exchange::LiveIdp::restart(&key, addr).await;
    let recovered = r6m_token_exchange::send_as(&router, &alice, call("sopt", false)).await;
    eprintln!("S-opt recovered: {recovered}");
    assert!(
        recovered.to_string().contains(MARKER) && recovered.get("error").is_none(),
        "S-opt: after recovery the same key was not served: {recovered}"
    );
    assert_eq!(
        sends.load(Ordering::SeqCst),
        1,
        "S-opt: the recovered retry was sent again, not served: {recovered}"
    );
}

/// S-opt-signed: S-opt with message signing. The unproven refusal keeps its
/// nonce spent, as site 5's does: re-sending the refused nonce after the
/// `IdP` recovers is refused as a replay and never sent, and the client
/// re-signs under a fresh nonce to be served the stored result (one send).
#[tokio::test]
async fn s_opt_signed_the_refused_nonce_stays_spent() {
    use std::sync::atomic::Ordering;

    let key = Arc::new(crate::gateway::oauth::GatewayKeyPair::generate().expect("keygen"));
    let idp = r6m_token_exchange::LiveIdp::start(&key).await;
    let alice = r6m_token_exchange::alice();
    let (router, sends, _dirs) = r6m_token_exchange::gateway_with(
        &key,
        idp.endpoint(),
        &alice,
        r6m_token_exchange::Requirement::Optional,
        |mut meta| {
            meta.enable_idempotency(
                Arc::new(crate::idempotency::IdempotencyCache::new()),
                std::time::Duration::from_secs(60),
            );
            meta.enable_message_signing(
                crate::security::message_signing::MessageSigner::new(
                    b"sopt-signing-key-0123456789abcdef-s".to_vec(),
                    None,
                    "sopt".into(),
                ),
                std::time::Duration::from_secs(300),
                true,
            );
            meta
        },
    )
    .await;
    let signed = |nonce: &str| {
        let mut params = call("sopt-s", false);
        params["arguments"]["nonce"] = json!(nonce);
        params
    };
    let first = r6m_token_exchange::send_as(&router, &alice, signed("n1")).await;
    assert!(first.to_string().contains(MARKER), "premise: {first}");
    let addr = idp.addr();
    idp.kill();
    let now = crate::clock::unix_secs().expect("a test host clock reads after 1970");
    let _clock = crate::clock::test_clock::at_secs(now + 7200);
    let unproven = r6m_token_exchange::send_as(&router, &alice, signed("n2")).await;
    assert_unproven("S-opt-signed", &unproven);
    let _idp = r6m_token_exchange::LiveIdp::restart(&key, addr).await;
    let reused = r6m_token_exchange::send_as(&router, &alice, signed("n2")).await;
    eprintln!("S-opt-signed reused nonce: {reused}");
    assert!(
        reused.get("error").is_some() && !reused.to_string().contains(MARKER),
        "S-opt-signed: the refused nonce was accepted again: {reused}"
    );
    let fresh = r6m_token_exchange::send_as(&router, &alice, signed("n3")).await;
    assert!(
        fresh.to_string().contains(MARKER) && fresh.get("error").is_none(),
        "S-opt-signed: a re-signed retry was not served: {fresh}"
    );
    assert_eq!(
        sends.load(Ordering::SeqCst),
        1,
        "S-opt-signed: a retry was sent again: {fresh}"
    );
}

/// S-unminted (mutant M-lift-shut): when the first call was unminted too, its
/// result was written under the same static principal, so the idempotency
/// cache serves the retry: the stored result, one send in total. Refusing at
/// the lift before the lookup (M-lift-shut) refuses this legitimate repeat.
/// The `IdP` sees no exchange at all, so neither run minted and the retry
/// really reaches `refuse_unproven`'s lookup.
#[tokio::test]
async fn s_unminted_a_retry_of_an_unminted_call_is_served_from_the_cache() {
    use std::sync::atomic::Ordering;

    let key = Arc::new(crate::gateway::oauth::GatewayKeyPair::generate().expect("keygen"));
    let idp = r6m_token_exchange::LiveIdp::start(&key).await;
    let (router, sends, _dirs) = optional_gateway(&idp, &key).await;
    let exchanges = idp.exchanges();
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
    assert_eq!(
        exchanges.load(Ordering::SeqCst),
        0,
        "premise: neither run minted"
    );
}

/// S-minted (control; mutant M-mint-none): on an optional backend whose mint
/// succeeds, the retry is lifted from the stored result with one send in
/// total. The idempotency cache is NOT armed here, so only the lift can serve
/// it (armed, the cache under the same binding would serve it too). A proof
/// that never holds (M-mint-none) refuses it.
#[tokio::test]
async fn s_minted_a_minted_optional_retry_is_lifted() {
    use std::sync::atomic::Ordering;

    let key = Arc::new(crate::gateway::oauth::GatewayKeyPair::generate().expect("keygen"));
    let idp = r6m_token_exchange::LiveIdp::start(&key).await;
    let (router, sends, _dirs) = r6m_token_exchange::gateway_with(
        &key,
        idp.endpoint(),
        &r6m_token_exchange::alice(),
        r6m_token_exchange::Requirement::Optional,
        |meta| meta,
    )
    .await;
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

/// P10u (MIK-8406 G2): S-opt-signed for a stored plan. A signed keyed
/// `gateway_execute` single on the optional backend runs under `n1`; the
/// `IdP` dies and the TTL passes, so its replay under `n2` mints nothing and
/// is refused at the plan boundary. `n2` stays spent: after the `IdP`
/// recovers, `n2` is refused as a replay, and a re-signed `n3` is served the
/// stored result. One send in all. Hardened, as only that posture signs a
/// plan on HTTP; the premise checks `n1` is spent on a fresh key, so the row
/// cannot pass with signing off. It does not kill mRefund: the route stage's
/// verdict carried the resolution, and taking it spent the refund witness
/// before the refusal settled (measured), as on P10's revoked path.
#[tokio::test]
async fn p10u_an_unminted_plan_refusal_keeps_its_nonce_spent() {
    use std::sync::atomic::Ordering;

    let key = Arc::new(crate::gateway::oauth::GatewayKeyPair::generate().expect("keygen"));
    let idp = r6m_token_exchange::LiveIdp::start(&key).await;
    let alice = r6m_token_exchange::alice();
    // Hardened: the HTTP route signs every `tools/call`, a plan included.
    let shape = (
        r6m_token_exchange::Requirement::Optional,
        crate::identity_propagation::PropagationStrategyKind::TokenExchange,
        crate::security::SecurityPosture::Hardened,
    );
    let (router, sends, _dirs) =
        r6m_token_exchange::gateway_shaped(&key, idp.endpoint(), &alice, shape, |mut meta| {
            meta.enable_idempotency(
                Arc::new(crate::idempotency::IdempotencyCache::new()),
                std::time::Duration::from_secs(60),
            );
            meta.enable_message_signing(
                crate::security::message_signing::MessageSigner::new(
                    b"p10u-signing-key-0123456789abcdef-s".to_vec(),
                    None,
                    "p10u".into(),
                ),
                std::time::Duration::from_secs(300),
                true,
            );
            meta
        })
        .await;
    let keyed = |key: &str, nonce: &str| {
        let mut params = json!({"name": "gateway_execute",
            "arguments": {"tool": format!("{}:{TOOL}", r6m_token_exchange::TX),
                "arguments": {"folder": "inbox"}},
            "_meta": meta(Some(key), false)});
        params["_meta"][crate::gateway::meta_mcp::signing::NONCE_META] = json!(nonce);
        params
    };
    let signed = |nonce: &str| keyed("p10u", nonce);
    let plan = ("tools/call", "gateway_execute");
    let first = r6m_token_exchange::send_method_as(&router, &alice, plan, signed("n1")).await;
    assert!(
        first.to_string().contains(MARKER),
        "premise: the plan ran: {first}"
    );
    let spent =
        r6m_token_exchange::send_method_as(&router, &alice, plan, keyed("p10u-n1", "n1")).await;
    assert_eq!(
        spent.pointer("/error"),
        Some(&json!({"code": -32001, "message": "Nonce replay detected"})),
        "premise: a spent nonce is refused on a fresh key as a replay: {spent}"
    );
    let addr = idp.addr();
    idp.kill();
    let now = crate::clock::unix_secs().expect("a test host clock reads after 1970");
    let _clock = crate::clock::test_clock::at_secs(now + 7200);
    let unproven = r6m_token_exchange::send_method_as(&router, &alice, plan, signed("n2")).await;
    assert_unproven("premise: the plan replay is refused unminted", &unproven);
    let _idp = r6m_token_exchange::LiveIdp::restart(&key, addr).await;
    let reused = r6m_token_exchange::send_method_as(&router, &alice, plan, signed("n2")).await;
    assert_eq!(
        reused.pointer("/error"),
        Some(&json!({"code": -32001, "message": "Nonce replay detected"})),
        "P10u: the refused plan replay's nonce was given back: {reused}"
    );
    let fresh = r6m_token_exchange::send_method_as(&router, &alice, plan, signed("n3")).await;
    assert!(
        fresh.to_string().contains(MARKER) && fresh.get("error").is_none(),
        "control: a re-signed plan replay was not served: {fresh}"
    );
    assert_eq!(
        sends.load(Ordering::SeqCst),
        1,
        "P10u: a replay was sent again: {fresh}"
    );
}

/// The `trace_id`s of `log`'s invocation records, then of its delivery
/// records, once nothing is in flight.
#[cfg(feature = "firewall")]
async fn invocation_and_delivery_traces(
    log: &crate::security::TransparencyLogger,
) -> (Vec<Value>, Vec<Value>) {
    use crate::gateway::router::route_matrix_driver_tests::response::delivery_rows;
    let traces =
        |rows: &[Value]| -> Vec<Value> { rows.iter().map(|row| row["trace_id"].clone()).collect() };
    let delivered = traces(&delivery_rows(log).await);
    let entries: Vec<Value> = std::fs::read_to_string(log.path())
        .unwrap_or_default()
        .lines()
        .filter_map(|line| serde_json::from_str::<Value>(line).ok())
        .filter(|entry| entry.get("route").is_some() && entry.get("kind").is_none())
        .collect();
    (traces(&entries), delivered)
}

/// MIK-8929.EFFECT.4 on the two replay paths a keyed retry can take inside
/// the dispatch: served from the idempotency cache (`cache`) or lifted from
/// the stored answer. Each delivery names its own request's trace, so it
/// joins that request's invocation record, not the first run's.
#[cfg(feature = "firewall")]
async fn replay_delivery_joins_its_own_invocation(cache: bool, key_name: &str) {
    use crate::gateway::router::route_matrix_driver_tests::response::temp_log;
    use std::sync::atomic::Ordering;

    let key = Arc::new(crate::gateway::oauth::GatewayKeyPair::generate().expect("keygen"));
    let idp = r6m_token_exchange::LiveIdp::start(&key).await;
    let (_log_dir, log) = temp_log(None);
    let meta_log = Arc::clone(&log);
    let (router, sends, _dirs) = r6m_token_exchange::gateway_with(
        &key,
        idp.endpoint(),
        &r6m_token_exchange::alice(),
        r6m_token_exchange::Requirement::Optional,
        move |mut meta| {
            if cache {
                meta.enable_idempotency(
                    Arc::new(crate::idempotency::IdempotencyCache::new()),
                    std::time::Duration::from_secs(60),
                );
            }
            meta.enable_transparency_log(meta_log);
            meta
        },
    )
    .await;
    if cache {
        // Unminted, as S-unminted: only the cache can serve the retry.
        idp.kill();
    }
    let alice = r6m_token_exchange::alice();
    let first = r6m_token_exchange::send_as(&router, &alice, call(key_name, false)).await;
    let again = r6m_token_exchange::send_as(&router, &alice, call(key_name, false)).await;
    assert!(again.get("error").is_none(), "premise: served: {again}");
    assert_eq!(
        sends.load(Ordering::SeqCst),
        1,
        "premise: a replay: {first}"
    );
    let (invoked, delivered) = invocation_and_delivery_traces(&log).await;
    assert_eq!(invoked.len(), 2, "{invoked:?}");
    assert_ne!(invoked[0], invoked[1], "{invoked:?}");
    assert_eq!(delivered, invoked, "each delivery joins its own invocation");
}

#[cfg(feature = "firewall")]
#[tokio::test]
async fn a_cached_replay_delivery_joins_its_own_invocation() {
    replay_delivery_joins_its_own_invocation(true, "trace-cache").await;
}

#[cfg(feature = "firewall")]
#[tokio::test]
async fn a_lifted_replay_delivery_joins_its_own_invocation() {
    replay_delivery_joins_its_own_invocation(false, "trace-lift").await;
}

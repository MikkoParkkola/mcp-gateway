// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8392 STORED.2 liveness rows, part 3: a token-exchange backend (a
//! per-caller mint with no `account:`), its live `IdP` fixture, and the lift
//! rows built on it (R6m, T12, S2b, L0, L4', L5).

use super::*;

#[path = "stored_replay_liveness_idp_fixture.rs"]
mod r6m_token_exchange;

/// R6m (E7 meta level, through the REAL replay entry): a keyed call succeeds
/// via token exchange; the `IdP` is killed and the clock moved past the cached
/// token's TTL; the same keyed repeat is refused, with nothing sent and no
/// stored output. Current-thread: the forced clock is this thread's.
#[tokio::test]
async fn r6m_token_exchange_replay_after_idp_kill_and_ttl_is_refused() {
    use std::sync::atomic::Ordering;

    let key = Arc::new(crate::gateway::oauth::GatewayKeyPair::generate().expect("keygen"));
    let idp = r6m_token_exchange::LiveIdp::start(&key).await;
    let alice = r6m_token_exchange::alice();
    let (router, sends, _dirs) = r6m_token_exchange::gateway(&key, idp.endpoint(), &alice).await;
    let call = || {
        json!({"name": "gateway_invoke",
            "arguments": {"server": r6m_token_exchange::TX, "tool": TOOL,
                "arguments": {"folder": "inbox"}},
            "_meta": meta(Some("r6m"), false)})
    };

    // A keyed call succeeds through token exchange, over the real HTTP route.
    let first = r6m_token_exchange::send_as(&router, &alice, call()).await;
    assert!(
        first.to_string().contains(MARKER),
        "premise: the token-exchange call did not dispatch: {first}"
    );
    assert_eq!(sends.load(Ordering::SeqCst), 1, "premise: {first}");

    // The `IdP` dies and the cached token's TTL (one hour) passes; the
    // retained result (one day) is still present.
    idp.kill();
    let now = crate::clock::unix_secs().expect("a test host clock reads after 1970");
    let _clock = crate::clock::test_clock::at_secs(now + 7200);

    // The same keyed repeat, through the same route: admission replays it with
    // its target, the replay defers (E7), the live mint fails without the
    // `IdP`, and nothing stored goes out.
    let again = r6m_token_exchange::send_as(&router, &alice, call()).await;
    eprintln!("R6m answer: {again}");
    assert!(
        !again.to_string().contains(MARKER),
        "R6m: the stored output was served: {again}"
    );
    assert!(again.get("error").is_some(), "R6m: not a refusal: {again}");
    assert_eq!(
        sends.load(Ordering::SeqCst),
        1,
        "R6m: the call reached the backend: {again}"
    );
}

/// T12 (site 5, M38): a task-augmented keyed call to a token-exchange backend
/// (per-caller mint, no `account:`, so Unjudged and still visible) completes;
/// the `IdP` dies and the cached token's TTL passes; the same keyed task call
/// is repeated. E9 does not apply (not Unavailable) and the catalogue passes,
/// so site 5 proves the account by resolving, which fails: the repeat answers
/// exactly as the same call made live does (normalising only `id`), never with
/// the stored task. Bypassing site 5 (M38) must fail this row.
/// Current-thread: the forced clock is this thread's.
#[tokio::test]
async fn t12_token_exchange_task_repeat_after_idp_kill_answers_as_live() {
    use std::sync::atomic::Ordering;

    let key = Arc::new(crate::gateway::oauth::GatewayKeyPair::generate().expect("keygen"));
    let idp = r6m_token_exchange::LiveIdp::start(&key).await;
    let alice = r6m_token_exchange::alice();
    let (router, sends, _dirs) = r6m_token_exchange::gateway(&key, idp.endpoint(), &alice).await;
    let call = |key: &str, task: bool| {
        let mut params = json!({"name": "gateway_invoke",
            "arguments": {"server": r6m_token_exchange::TX, "tool": TOOL,
                "arguments": {"folder": "inbox"}},
            "_meta": meta(Some(key), task)});
        if task {
            params["task"] = json!({});
        }
        params
    };
    let made = r6m_token_exchange::send_as(&router, &alice, call("t12", true)).await;
    let id = made
        .pointer("/result/taskId")
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("premise: a task was made: {made}"))
        .to_owned();
    let bound = std::time::Instant::now() + std::time::Duration::from_secs(10);
    loop {
        if sends.load(Ordering::SeqCst) >= 1 {
            break;
        }
        assert!(
            std::time::Instant::now() < bound,
            "premise: the task dispatched: {made}"
        );
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
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
    let again = r6m_token_exchange::send_as(&router, &alice, call("t12", true)).await;
    let live = r6m_token_exchange::send_as(&router, &alice, call("t12-live", false)).await;
    eprintln!("T12 repeat: {again}");
    eprintln!("T12 live: {live}");
    assert!(
        live.get("error").is_some(),
        "premise: the live call is refused: {live}"
    );
    assert_ne!(
        again.pointer("/result/taskId").and_then(Value::as_str),
        Some(id.as_str()),
        "T12: the stored task was answered back after the IdP died: {again}"
    );
    let (mut again_id, mut live_id) = (again.clone(), live.clone());
    again_id["id"] = Value::Null;
    live_id["id"] = Value::Null;
    assert_eq!(
        again_id, live_id,
        "T12: the repeat differs from the live call: {again} vs {live}"
    );
    assert_eq!(
        sends.load(Ordering::SeqCst),
        sent,
        "T12: the call reached the backend: {again}"
    );
}

/// T12r (product seat finding 2): T12's setup, counting the identity
/// propagation audit records (`idp_*`) each answer writes. The repeat's
/// refusal is the live call's, so it writes exactly the records the live call
/// writes: one failed resolution per call, never a second one at site 5.
/// Current-thread: the forced clock is this thread's.
#[tokio::test]
async fn t12r_a_failed_task_repeat_writes_the_live_calls_idp_records() {
    use std::sync::atomic::Ordering;

    let key = Arc::new(crate::gateway::oauth::GatewayKeyPair::generate().expect("keygen"));
    let idp = r6m_token_exchange::LiveIdp::start(&key).await;
    let alice = r6m_token_exchange::alice();
    let (router, sends, dirs) = r6m_token_exchange::gateway(&key, idp.endpoint(), &alice).await;
    let log = dirs.0.path().join("audit.jsonl");
    let idp_records = || {
        std::fs::read_to_string(&log)
            .unwrap_or_default()
            .lines()
            .filter(|line| line.contains("\"action\":\"idp_"))
            .count()
    };
    let call = |key: &str, task: bool| {
        let mut params = json!({"name": "gateway_invoke",
            "arguments": {"server": r6m_token_exchange::TX, "tool": TOOL,
                "arguments": {"folder": "inbox"}},
            "_meta": meta(Some(key), task)});
        if task {
            params["task"] = json!({});
        }
        params
    };
    let made = r6m_token_exchange::send_as(&router, &alice, call("t12r", true)).await;
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
    assert!(
        sends.load(Ordering::SeqCst) >= 1,
        "premise: the task dispatched"
    );
    idp.kill();
    let now = crate::clock::unix_secs().expect("a test host clock reads after 1970");
    let _clock = crate::clock::test_clock::at_secs(now + 7200);

    let before = idp_records();
    let live = r6m_token_exchange::send_as(&router, &alice, call("t12r-live", false)).await;
    let live_records = idp_records() - before;
    let before = idp_records();
    let again = r6m_token_exchange::send_as(&router, &alice, call("t12r", true)).await;
    let repeat_records = idp_records() - before;
    eprintln!("T12r live ({live_records} idp records): {live}");
    eprintln!("T12r repeat ({repeat_records} idp records): {again}");
    assert!(
        live.get("error").is_some(),
        "premise: the live call is refused: {live}"
    );
    assert!(
        live_records >= 1,
        "premise: the live refusal writes an idp record"
    );
    assert_eq!(
        repeat_records, live_records,
        "T12r: the repeat wrote a different number of idp records than the live call"
    );
}

/// S2b (mutant M28): the token-exchange backend's keyed replay with the
/// `IdP` ALIVE. Admission replays it with its target, the replay defers (E7:
/// a per-caller mint), resolution succeeds, and the lift serves the retained
/// result: the stored bytes, nothing sent again. A lift that refuses or
/// re-dispatches after a successful resolution (M28) must fail this row.
#[tokio::test]
async fn s2b_token_exchange_replay_is_lifted_when_the_mint_succeeds() {
    use std::sync::atomic::Ordering;

    let key = Arc::new(crate::gateway::oauth::GatewayKeyPair::generate().expect("keygen"));
    let idp = r6m_token_exchange::LiveIdp::start(&key).await;
    let alice = r6m_token_exchange::alice();
    let (router, sends, _dirs) = r6m_token_exchange::gateway(&key, idp.endpoint(), &alice).await;
    let call = || {
        json!({"name": "gateway_invoke",
            "arguments": {"server": r6m_token_exchange::TX, "tool": TOOL,
                "arguments": {"folder": "inbox"}},
            "_meta": meta(Some("s2b"), false)})
    };
    let first = r6m_token_exchange::send_as(&router, &alice, call()).await;
    assert!(
        first.to_string().contains(MARKER),
        "premise: dispatched: {first}"
    );
    assert_eq!(sends.load(Ordering::SeqCst), 1, "premise: {first}");
    let again = r6m_token_exchange::send_as(&router, &alice, call()).await;
    assert!(
        again.to_string().contains(MARKER),
        "S2b: the lifted replay was not served: {again}"
    );
    assert_eq!(
        sends.load(Ordering::SeqCst),
        1,
        "S2b: the replay was re-sent: {again}"
    );
    drop(idp);
}

/// L0 (mutant M2b): with the meta idempotency cache armed, as the boot path
/// always arms it, the lift answers before the key check: the keyed repeat
/// is the first answer byte-for-byte and nothing is re-sent. Lifting after
/// the key check (M2b) lets the cache answer instead, re-stamped as a fresh
/// cache hit.
#[tokio::test]
async fn l0_the_lift_answers_before_an_armed_idempotency_cache() {
    let key = Arc::new(crate::gateway::oauth::GatewayKeyPair::generate().expect("keygen"));
    let idp = r6m_token_exchange::LiveIdp::start(&key).await;
    let alice = r6m_token_exchange::alice();
    let (router, sends, _dirs) =
        r6m_token_exchange::gateway_armed(&key, idp.endpoint(), &alice, |mut meta| {
            meta.enable_idempotency(
                Arc::new(crate::idempotency::IdempotencyCache::new()),
                std::time::Duration::from_secs(60),
            );
            meta
        })
        .await;
    let call = || {
        json!({"name": "gateway_invoke",
            "arguments": {"server": r6m_token_exchange::TX, "tool": TOOL,
                "arguments": {"folder": "inbox"}},
            "_meta": meta(Some("l0"), false)})
    };
    let first = r6m_token_exchange::send_as(&router, &alice, call()).await;
    assert!(
        first.to_string().contains(MARKER),
        "premise: dispatched: {first}"
    );
    let again = r6m_token_exchange::send_as(&router, &alice, call()).await;
    eprintln!("L0 first: {first}");
    eprintln!("L0 again: {again}");
    assert_eq!(
        sends.load(std::sync::atomic::Ordering::SeqCst),
        1,
        "L0: re-sent: {again}"
    );
    assert_eq!(again, first, "L0: the repeat is not the first answer");
    drop(idp);
}

/// L5: a lifted replay keeps its signing nonce spent. Alice's signed call
/// under nonce `n1` dispatches; its keyed repeat, signed under a fresh `n2`
/// (the nonce is not part of the fingerprint), is lifted with no second send;
/// a fresh-key call re-using `n2` is then refused as a replay and never sent,
/// while `n3` is served (control). M4 (the lift drops its spend and dispatch
/// mark) is equivalent, not killed: no refund is ever requested before a
/// lift, so the nonce stays spent either way (argument in the PR body).
#[tokio::test]
async fn l5_a_lifted_replay_keeps_its_nonce_spent() {
    let key = Arc::new(crate::gateway::oauth::GatewayKeyPair::generate().expect("keygen"));
    let idp = r6m_token_exchange::LiveIdp::start(&key).await;
    let alice = r6m_token_exchange::alice();
    let (router, sends, _dirs) =
        r6m_token_exchange::gateway_armed(&key, idp.endpoint(), &alice, |mut meta| {
            meta.enable_message_signing(
                crate::security::message_signing::MessageSigner::new(
                    b"l5-signing-key-0123456789abcdef-l5".to_vec(),
                    None,
                    "l5".into(),
                ),
                std::time::Duration::from_secs(300),
                true,
            );
            meta
        })
        .await;
    let call = |idem: &str, nonce: &str| {
        json!({"name": "gateway_invoke",
            "arguments": {"server": r6m_token_exchange::TX, "tool": TOOL,
                "arguments": {"folder": "inbox"}, "nonce": nonce},
            "_meta": meta(Some(idem), false)})
    };
    let first = r6m_token_exchange::send_as(&router, &alice, call("l5", "n1")).await;
    assert!(
        first.to_string().contains(MARKER),
        "premise: dispatched: {first}"
    );
    assert_eq!(
        sends.load(std::sync::atomic::Ordering::SeqCst),
        1,
        "premise: one send: {first}"
    );
    let again = r6m_token_exchange::send_as(&router, &alice, call("l5", "n2")).await;
    assert!(
        again.to_string().contains(MARKER),
        "premise: the lifted replay was served: {again}"
    );
    assert_eq!(
        sends.load(std::sync::atomic::Ordering::SeqCst),
        1,
        "premise: the replay was lifted: {again}"
    );
    let reused = r6m_token_exchange::send_as(&router, &alice, call("l5-reuse", "n2")).await;
    eprintln!("L5 reused nonce: {reused}");
    assert_eq!(
        sends.load(std::sync::atomic::Ordering::SeqCst),
        1,
        "L5: a re-used nonce was sent after a lift: {reused}"
    );
    assert!(
        !reused.to_string().contains(MARKER),
        "L5: a re-used nonce was served: {reused}"
    );
    let fresh = r6m_token_exchange::send_as(&router, &alice, call("l5-fresh", "n3")).await;
    assert!(
        fresh.to_string().contains(MARKER),
        "control: a fresh nonce is served: {fresh}"
    );
    drop(idp);
}

/// L4' (mutants M8, M2b): a lifted replay writes ONE invocation record, and
/// it reads as the first execution's did: the same request hash (the
/// envelope the route stage passes, `gateway_invoke`'s own arguments) and the
/// same response hash (the stored execution's facts, MIK-7641), and the
/// same backend and tool, which come from the envelope the lift hands
/// `audit_replay`. A wrong envelope (M8) loses the backend and tool.
#[tokio::test]
async fn l4_a_lifted_replay_records_the_first_execution_s_hashes() {
    let key = Arc::new(crate::gateway::oauth::GatewayKeyPair::generate().expect("keygen"));
    let idp = r6m_token_exchange::LiveIdp::start(&key).await;
    let alice = r6m_token_exchange::alice();
    let (router, _sends, dirs) = r6m_token_exchange::gateway(&key, idp.endpoint(), &alice).await;
    let log = dirs.0.path().join("audit.jsonl");
    let call = || {
        json!({"name": "gateway_invoke",
            "arguments": {"server": r6m_token_exchange::TX, "tool": TOOL,
                "arguments": {"folder": "inbox"}},
            "_meta": meta(Some("l4"), false)})
    };
    // The invocation records (those carrying a request hash) since `skip`.
    let invocations = |skip: usize| -> Vec<Value> {
        std::fs::read_to_string(&log)
            .unwrap_or_default()
            .lines()
            .skip(skip)
            .filter_map(|line| serde_json::from_str::<Value>(line).ok())
            .filter(|record| record.get("request_hash").is_some())
            .collect()
    };
    let start = std::fs::read_to_string(&log)
        .unwrap_or_default()
        .lines()
        .count();
    let first = r6m_token_exchange::send_as(&router, &alice, call()).await;
    assert!(
        first.to_string().contains(MARKER),
        "premise: dispatched: {first}"
    );
    let original = invocations(start);
    assert_eq!(
        original.len(),
        1,
        "premise: one first-run record: {original:?}"
    );
    let before = std::fs::read_to_string(&log)
        .unwrap_or_default()
        .lines()
        .count();
    let again = r6m_token_exchange::send_as(&router, &alice, call()).await;
    assert!(
        again.to_string().contains(MARKER),
        "premise: the lifted replay was served: {again}"
    );
    let replayed = invocations(before);
    eprintln!("L4' first: {original:?}");
    eprintln!("L4' replay: {replayed:?}");
    assert_eq!(
        replayed.len(),
        1,
        "L4': not one replay record: {replayed:?}"
    );
    for field in [
        "request_hash",
        "response_hash",
        "outcome",
        "server",
        "tool",
        "route",
    ] {
        assert_eq!(
            replayed[0].get(field),
            original[0].get(field),
            "L4': the replay's {field} differs from the first execution's"
        );
    }
    drop(idp);
}

#[path = "stored_replay_liveness_optional_tests.rs"]
mod optional;
#[path = "stored_replay_liveness_plan_external_tests.rs"]
mod plan_external;

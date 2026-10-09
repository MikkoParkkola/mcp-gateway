// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-7630 increment I1: subscribe rows that need a callback which answers
//! (design §10: T6-T10, T22 subscribe half, T23 idempotence, T26, T46
//! challenge and tail clauses, T48, T51).
//!
//! The receiver speaks real TLS under a temporary CA, handed to the gateway
//! child through `Receiver::trust_env`: `SSL_CERT_FILE`, which the
//! platform verifier reads on Linux, and the debug-only
//! `MCP_GATEWAY_TEST_TRUST_CA`, which `src/debug_trust_roots.rs` honours on every
//! platform (macOS reads its keychain; MIK-8188).
#![cfg(unix)]

#[path = "mik_7630_events/gateway.rs"]
#[allow(dead_code, reason = "shared harness; each binary uses a subset")]
mod gateway;
#[path = "mik_7630_events/receiver.rs"]
#[allow(dead_code, reason = "this binary does not use every receiver helper")]
mod receiver;

use std::path::Path;
use std::time::Duration;

use gateway::{ALICE, BOB, CAROL, EVENT, Gateway, config, error};
use receiver::{Receiver, Reply, whsec};
use serde_json::{Value, json};

async fn start(root: &Path, receiver: &Receiver, events: Value) -> Gateway {
    let mut events = events;
    events["callback_allow_private"] = json!(["127.0.0.0/8"]);
    let trust = receiver.trust_env();
    let env = trust.each_ref().map(|(k, v)| (*k, v.as_str()));
    let gw = Gateway::start_with_env(root, config(root, &events), &env).await;
    gw.event_names(Some(ALICE), Some(EVENT)).await;
    gw
}

fn params(url: &str, secret: &str, arguments: Value) -> Value {
    let mut params = json!({
        "name": EVENT,
        "delivery": {"mode": "webhook", "url": url, "secret": secret},
    });
    params["arguments"] = arguments;
    params
}

/// The method's own result: the transport stamps every modern result with
/// `resultType` and `_meta.serverInfo`, which are not the method's answer.
fn bare(answer: &Value) -> Value {
    let mut result = answer["result"].clone();
    if let Some(map) = result.as_object_mut() {
        map.remove("resultType");
        map.remove("_meta");
    }
    result
}

/// Stored subscriptions only: the store rewrites a record through a
/// `.{name}.{n}.tmp` file and a rename, and a count taken mid-rewrite would
/// see that temp file as a second subscription.
fn subs_on_disk(root: &Path) -> usize {
    std::fs::read_dir(root.join("events/subs")).map_or(0, |d| {
        d.flatten()
            .filter(|e| e.path().extension().is_some_and(|x| x == "json"))
            .count()
    })
}

/// T6 (EVENTS.3): `whsec_` + base64 of 24..=64 bytes, nothing else, and the
/// refusal never echoes the value.
#[tokio::test]
async fn subscribe_validates_whsec_length_bounds() {
    let root = tempfile::tempdir().expect("root");
    let rx = Receiver::start(root.path()).await;
    let gw = start(root.path(), &rx, json!({})).await;
    let bad = [
        whsec(23),
        whsec(65),
        whsec(32).replace("whsec_", "wh_"),
        "whsec_!!!not-base64!!!".to_string(),
    ];
    for secret in &bad {
        let answer = gw
            .rpc(
                Some(ALICE),
                "events/subscribe",
                params(&rx.url, secret, json!({})),
            )
            .await;
        assert_eq!(error(&answer)["code"], -32602, "{answer}");
        assert_eq!(error(&answer)["data"]["field"], "delivery.secret");
        assert!(
            !answer
                .to_string()
                .contains(secret.trim_start_matches("whsec_")),
            "the refusal must not echo the secret"
        );
    }
    for (n, bytes) in [24, 64].into_iter().enumerate() {
        let answer = gw
            .rpc(
                Some(ALICE),
                "events/subscribe",
                params(&rx.url, &whsec(bytes), json!({"repo": format!("r{n}")})),
            )
            .await;
        assert!(
            answer["result"]["id"].is_string(),
            "{bytes} bytes accepted: {answer}"
        );
    }
}

/// T7 (EVENTS.3): the id is a function of (principal, url, name, canonical
/// arguments). Webhook filters are strings, so canonical numbers are proven
/// by the I4 test source; key order is proven here.
#[tokio::test]
async fn subscribe_id_is_deterministic_over_canonical_arguments() {
    let root = tempfile::tempdir().expect("root");
    let rx = Receiver::start(root.path()).await;
    let gw = start(root.path(), &rx, json!({})).await;
    let secret = whsec(32);
    let id = |answer: &Value| answer["result"]["id"].as_str().map(str::to_owned);
    let a = gw
        .rpc(
            Some(ALICE),
            "events/subscribe",
            params(&rx.url, &secret, json!({"repo": "x", "ref": "main"})),
        )
        .await;
    let b = gw
        .rpc(
            Some(ALICE),
            "events/subscribe",
            params(&rx.url, &secret, json!({"ref": "main", "repo": "x"})),
        )
        .await;
    assert!(id(&a).is_some(), "subscribe answers an id: {a}");
    assert_eq!(id(&a), id(&b), "key order must not change the id");
    assert_eq!(
        subs_on_disk(root.path()),
        1,
        "a repeat subscribe is one record"
    );
    let other_arg = gw
        .rpc(
            Some(ALICE),
            "events/subscribe",
            params(&rx.url, &secret, json!({"repo": "y", "ref": "main"})),
        )
        .await;
    let other_principal = gw
        .rpc(
            Some(CAROL),
            "events/subscribe",
            params(&rx.url, &secret, json!({"repo": "x", "ref": "main"})),
        )
        .await;
    let other_url = gw
        .rpc(
            Some(ALICE),
            "events/subscribe",
            params(
                &rx.url.replace("/hook", "/hook2"),
                &secret,
                json!({"repo": "x", "ref": "main"}),
            ),
        )
        .await;
    for other in [&other_arg, &other_principal, &other_url] {
        assert!(id(other).is_some(), "{other}");
        assert_ne!(
            id(other),
            id(&a),
            "a different key component must change the id"
        );
    }
}

/// T8 (EVENTS.3): one signed verification POST, answered before the subscribe.
#[tokio::test]
async fn subscribe_verifies_callback_before_activating() {
    let root = tempfile::tempdir().expect("root");
    let rx = Receiver::start(root.path()).await;
    let gw = start(root.path(), &rx, json!({})).await;
    let secret = whsec(32);
    let answer = gw
        .rpc(
            Some(ALICE),
            "events/subscribe",
            params(&rx.url, &secret, json!({})),
        )
        .await;
    let answered = std::time::Instant::now();
    let id = answer["result"]["id"]
        .as_str()
        .unwrap_or_else(|| panic!("{answer}"))
        .to_owned();
    let posts = rx.received();
    assert_eq!(posts.len(), 1, "exactly one verification POST");
    let post = &posts[0];
    let body = post.json();
    assert_eq!(body["type"], "verification");
    assert!(body["challenge"].as_str().is_some_and(|c| !c.is_empty()));
    assert!(
        post.header("webhook-id")
            .unwrap_or_default()
            .starts_with("msg_verification_")
    );
    assert_eq!(
        post.header("x-mcp-subscription-id").as_deref(),
        Some(id.as_str())
    );
    assert!(
        post.signed_by(&secret),
        "the verification POST is signed with the secret"
    );
    assert!(post.at <= answered, "the POST precedes the answer");
    assert_eq!(answer["result"]["cursor"], Value::Null);
    assert_eq!(answer["result"]["truncated"], false);
}

/// T9 (EVENTS.3): a wrong, empty or replayed echo fails; challenges differ.
#[tokio::test]
async fn verification_rejects_wrong_echo_and_single_use_challenge() {
    let root = tempfile::tempdir().expect("root");
    let rx = Receiver::start(root.path()).await;
    let gw = start(root.path(), &rx, json!({})).await;
    for reply in [Reply::WrongEcho, Reply::Empty, Reply::Replay] {
        rx.reply(reply);
        let answer = gw
            .rpc(
                Some(ALICE),
                "events/subscribe",
                params(&rx.url, &whsec(32), json!({})),
            )
            .await;
        assert_eq!(error(&answer)["code"], -32015, "{reply:?}: {answer}");
        assert_eq!(
            error(&answer)["data"]["reason"],
            "challenge_failed",
            "{reply:?}"
        );
    }
    let challenges: Vec<String> = rx
        .challenges()
        .iter()
        .map(|r| {
            r.json()["challenge"]
                .as_str()
                .unwrap_or_default()
                .to_owned()
        })
        .collect();
    assert_eq!(challenges.len(), 3);
    assert_ne!(
        challenges[1], challenges[2],
        "every attempt draws a fresh challenge"
    );
    assert_eq!(
        subs_on_disk(root.path()),
        0,
        "a failed verification stores nothing"
    );
}

/// T10 (EVENTS.3): verification is cached per (principal, url).
#[tokio::test]
async fn verification_is_cached_per_principal_and_url() {
    let root = tempfile::tempdir().expect("root");
    let rx = Receiver::start(root.path()).await;
    let gw = start(root.path(), &rx, json!({})).await;
    let ok = |a: &Value| assert!(a["result"]["id"].is_string(), "{a}");
    ok(&gw
        .rpc(
            Some(ALICE),
            "events/subscribe",
            params(&rx.url, &whsec(32), json!({"repo": "a"})),
        )
        .await);
    ok(&gw
        .rpc(
            Some(ALICE),
            "events/subscribe",
            params(&rx.url, &whsec(32), json!({"repo": "b"})),
        )
        .await);
    assert_eq!(
        rx.challenges().len(),
        1,
        "new arguments, same principal and url: no challenge"
    );
    ok(&gw
        .rpc(
            Some(CAROL),
            "events/subscribe",
            params(&rx.url, &whsec(32), json!({"repo": "a"})),
        )
        .await);
    assert_eq!(
        rx.challenges().len(),
        2,
        "another principal verifies on its own"
    );
}

fn refresh_before(answer: &Value) -> Option<chrono::DateTime<chrono::Utc>> {
    answer["result"]["refreshBefore"].as_str().map(|s| {
        s.parse()
            .unwrap_or_else(|e| panic!("refreshBefore {s}: {e}"))
    })
}

fn about(actual: Option<chrono::DateTime<chrono::Utc>>, secs: i64, what: &str) {
    let actual = actual.unwrap_or_else(|| panic!("{what}: refreshBefore must be a time"));
    let delta = (actual - chrono::Utc::now()).num_seconds() - secs;
    assert!(delta.abs() <= 30, "{what}: off by {delta}s");
}

/// T22 (EVENTS.4), subscribe half: TTL clamping, persistence across a
/// restart, and the expiry sweep on load.
#[tokio::test]
async fn subscriptions_survive_restart_and_ttl_is_negotiated() {
    let root = tempfile::tempdir().expect("root");
    let rx = Receiver::start(root.path()).await;
    let mut gw = start(
        root.path(),
        &rx,
        json!({"min_ttl": "1s", "default_ttl": "1h"}),
    )
    .await;
    let sub = |repo: &str, ttl: Option<Value>| {
        let mut p = params(&rx.url, "whsec_placeholder", json!({"repo": repo}));
        p["delivery"]["secret"] = json!(whsec(32));
        if let Some(ttl) = ttl {
            p["ttlMs"] = ttl;
        }
        p
    };
    let absent = gw
        .rpc(Some(ALICE), "events/subscribe", sub("absent", None))
        .await;
    about(refresh_before(&absent), 3600, "absent ttlMs");
    let long = gw
        .rpc(
            Some(ALICE),
            "events/subscribe",
            sub("long", Some(json!(864_000_000))),
        )
        .await;
    about(refresh_before(&long), 86_400, "10 days clamps to max_ttl");
    let null = gw
        .rpc(
            Some(ALICE),
            "events/subscribe",
            sub("null", Some(Value::Null)),
        )
        .await;
    about(
        refresh_before(&null),
        86_400,
        "null without allow_no_expiry gets max_ttl",
    );
    let short = gw
        .rpc(
            Some(ALICE),
            "events/subscribe",
            sub("short", Some(json!(1000))),
        )
        .await;
    about(refresh_before(&short), 1, "1000 ms against a 1 s floor");
    assert_eq!(subs_on_disk(root.path()), 4);

    tokio::time::sleep(Duration::from_secs(2)).await;
    gw.restart().await;
    gw.event_names(Some(ALICE), Some(EVENT)).await;
    assert_eq!(
        subs_on_disk(root.path()),
        3,
        "the expired record is swept on load"
    );
    let before = rx.challenges().len();
    let again = gw
        .rpc(Some(ALICE), "events/subscribe", sub("absent", None))
        .await;
    assert_eq!(
        again["result"]["id"], absent["result"]["id"],
        "same key, same id after restart"
    );
    assert_eq!(
        rx.challenges().len(),
        before,
        "verification survived the restart"
    );
    drop(gw);

    let root = tempfile::tempdir().expect("root");
    let gw = start(root.path(), &rx, json!({"allow_no_expiry": true})).await;
    let mut p = params(&rx.url, &whsec(32), json!({}));
    p["ttlMs"] = Value::Null;
    let none = gw.rpc(Some(ALICE), "events/subscribe", p).await;
    assert!(none["result"]["id"].is_string(), "{none}");
    assert_eq!(
        none["result"]["refreshBefore"],
        Value::Null,
        "no expiry when allowed"
    );
}

/// T23 (EVENTS.7), I1 clauses: `{}` twice, another caller's `{}` changes
/// nothing, and an `id` in params is ignored.
#[tokio::test]
async fn unsubscribe_is_idempotent_and_scoped_to_the_caller() {
    let root = tempfile::tempdir().expect("root");
    let rx = Receiver::start(root.path()).await;
    let gw = start(root.path(), &rx, json!({})).await;
    let sub = gw
        .rpc(
            Some(ALICE),
            "events/subscribe",
            params(&rx.url, &whsec(32), json!({"repo": "x"})),
        )
        .await;
    let id = sub["result"]["id"].clone();
    assert!(id.is_string(), "{sub}");
    let key = json!({"name": EVENT, "arguments": {"repo": "x"}, "delivery": {"url": rx.url}});
    let mut by_id = key.clone();
    by_id["id"] = id;
    for caller in [BOB, CAROL] {
        let answer = gw
            .rpc(Some(caller), "events/unsubscribe", by_id.clone())
            .await;
        assert_eq!(bare(&answer), json!({}), "{answer}");
        assert_eq!(
            subs_on_disk(root.path()),
            1,
            "another caller cannot remove alice's row"
        );
    }
    for _ in 0..2 {
        let answer = gw.rpc(Some(ALICE), "events/unsubscribe", key.clone()).await;
        assert_eq!(bare(&answer), json!({}), "{answer}");
    }
    assert_eq!(subs_on_disk(root.path()), 0);
}

/// T26 (SAFETY.5): the per-principal cap answers -32013, and a held key can
/// still be refreshed and rotated at the cap.
#[tokio::test]
async fn subscription_caps_answer_resource_exhausted() {
    let root = tempfile::tempdir().expect("root");
    let rx = Receiver::start(root.path()).await;
    let gw = start(
        root.path(),
        &rx,
        json!({"max_subscriptions_per_principal": 3}),
    )
    .await;
    for n in 0..3 {
        let a = gw
            .rpc(
                Some(ALICE),
                "events/subscribe",
                params(&rx.url, &whsec(32), json!({"repo": format!("r{n}")})),
            )
            .await;
        assert!(a["result"]["id"].is_string(), "{a}");
    }
    let over = gw
        .rpc(
            Some(ALICE),
            "events/subscribe",
            params(&rx.url, &whsec(32), json!({"repo": "r3"})),
        )
        .await;
    assert_eq!(error(&over)["code"], -32013, "{over}");
    assert_eq!(error(&over)["data"]["limit"], "subscriptions");
    assert_eq!(error(&over)["data"]["max"], 3);
    let rotate = gw
        .rpc(
            Some(ALICE),
            "events/subscribe",
            params(&rx.url, &whsec(48), json!({"repo": "r0"})),
        )
        .await;
    assert!(
        rotate["result"]["id"].is_string(),
        "refresh with a new secret at the cap: {rotate}"
    );
    let other = gw
        .rpc(
            Some(CAROL),
            "events/subscribe",
            params(&rx.url, &whsec(32), json!({"repo": "r3"})),
        )
        .await;
    assert!(
        other["result"]["id"].is_string(),
        "the cap is per principal: {other}"
    );
}

/// T51 (SAFETY.5): the global cap counts every principal's rows.
#[tokio::test]
async fn global_subscription_cap_answers_resource_exhausted() {
    let root = tempfile::tempdir().expect("root");
    let rx = Receiver::start(root.path()).await;
    let gw = start(root.path(), &rx, json!({"max_subscriptions": 3})).await;
    for (key, repo) in [(ALICE, "a"), (CAROL, "c"), (ALICE, "a2")] {
        let a = gw
            .rpc(
                Some(key),
                "events/subscribe",
                params(&rx.url, &whsec(32), json!({"repo": repo})),
            )
            .await;
        assert!(a["result"]["id"].is_string(), "{a}");
    }
    let over = gw
        .rpc(
            Some(CAROL),
            "events/subscribe",
            params(&rx.url, &whsec(32), json!({"repo": "c2"})),
        )
        .await;
    assert_eq!(error(&over)["code"], -32013, "{over}");
    let refresh = gw
        .rpc(
            Some(CAROL),
            "events/subscribe",
            params(&rx.url, &whsec(32), json!({"repo": "c"})),
        )
        .await;
    assert!(
        refresh["result"]["id"].is_string(),
        "a held key refreshes at the cap: {refresh}"
    );
}

/// T46 (EVENTS.3), I1 clauses: a verification outlives its last subscription
/// by `verified_tail_ttl`, and the tail is capped globally and per principal
/// without ever evicting a live subscription's record.
#[tokio::test]
async fn verification_lives_as_long_as_its_subscriptions() {
    let root = tempfile::tempdir().expect("root");
    let rx = Receiver::start(root.path()).await;
    let gw = start(
        root.path(),
        &rx,
        json!({"verified_tail_ttl": "2s", "max_verified_tail": 3,
               "max_verified_tail_per_principal": 2}),
    )
    .await;
    let url = |n: u32| format!("{}?n={n}", rx.url);
    let cycle = |key: &'static str, n: u32| {
        let gw = &gw;
        let url = url(n);
        async move {
            let s = gw
                .rpc(
                    Some(key),
                    "events/subscribe",
                    params(&url, &whsec(32), json!({})),
                )
                .await;
            assert!(s["result"]["id"].is_string(), "{s}");
            let u = gw
                .rpc(
                    Some(key),
                    "events/unsubscribe",
                    json!({"name": EVENT, "arguments": {}, "delivery": {"url": url}}),
                )
                .await;
            assert_eq!(bare(&u), json!({}), "{u}");
        }
    };
    let challenges = || rx.challenges().len();

    // Inside the tail: no new challenge. After it: one.
    cycle(ALICE, 0).await;
    let n = challenges();
    cycle(ALICE, 0).await;
    assert_eq!(
        challenges(),
        n,
        "re-subscribing inside the tail needs no challenge"
    );
    tokio::time::sleep(Duration::from_secs(3)).await;
    cycle(ALICE, 0).await;
    assert_eq!(
        challenges(),
        n + 1,
        "after the tail a new challenge is sent"
    );

    // A live subscription's record is never evicted.
    let live = gw
        .rpc(
            Some(ALICE),
            "events/subscribe",
            params(&url(9), &whsec(32), json!({})),
        )
        .await;
    assert!(live["result"]["id"].is_string(), "{live}");

    // Per principal cap 2: alice's third tail evicts her own oldest only.
    cycle(CAROL, 5).await;
    cycle(ALICE, 1).await;
    cycle(ALICE, 2).await;
    cycle(ALICE, 3).await;
    let n = challenges();
    cycle(CAROL, 5).await;
    assert_eq!(challenges(), n, "carol's tail survives alice's churn");
    cycle(ALICE, 1).await;
    assert_eq!(challenges(), n + 1, "alice's oldest tail was evicted");
    let refresh = gw
        .rpc(
            Some(ALICE),
            "events/subscribe",
            params(&url(9), &whsec(32), json!({})),
        )
        .await;
    assert!(refresh["result"]["id"].is_string(), "{refresh}");
    assert_eq!(
        challenges(),
        n + 1,
        "the live subscription's verification was kept"
    );
}

/// T48 (SAFETY.5): verification POSTs per callback host are rate limited.
#[tokio::test]
async fn verification_posts_are_rate_limited_per_host() {
    let root = tempfile::tempdir().expect("root");
    let rx = Receiver::start(root.path()).await;
    let gw = start(root.path(), &rx, json!({})).await;
    let mut last = Value::Null;
    for n in 0..11 {
        let key = [ALICE, CAROL][n % 2];
        last = gw
            .rpc(
                Some(key),
                "events/subscribe",
                params(&format!("{}?n={n}", rx.url), &whsec(32), json!({})),
            )
            .await;
        if n < 10 {
            assert!(last["result"]["id"].is_string(), "subscribe {n}: {last}");
        }
    }
    assert_eq!(
        rx.challenges().len(),
        10,
        "ten challenge POSTs per host per minute"
    );
    assert_eq!(error(&last)["code"], -32013, "{last}");
    assert_eq!(error(&last)["data"]["limit"], "verifications");
}

/// T22 (EVENTS.4), floor clause: against the default 60 s `min_ttl`, a
/// `ttlMs` of 1000 is raised to the floor, not honoured and not refused.
#[tokio::test]
async fn a_ttl_below_the_floor_is_raised_to_it() {
    let root = tempfile::tempdir().expect("root");
    let rx = Receiver::start(root.path()).await;
    let gw = start(root.path(), &rx, json!({})).await;
    let mut p = params(&rx.url, "whsec_placeholder", json!({"repo": "floor"}));
    p["delivery"]["secret"] = json!(whsec(32));
    p["ttlMs"] = json!(1000);
    let answer = gw.rpc(Some(ALICE), "events/subscribe", p).await;
    about(
        refresh_before(&answer),
        60,
        "1000 ms against the 60 s floor",
    );
}

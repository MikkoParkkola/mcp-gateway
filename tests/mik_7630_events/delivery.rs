// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Shared steps of the I2 delivery rows: start a gateway that trusts the
//! receiver, subscribe, fire the inbound webhook, and read what the gateway
//! left on disk (store records, dead letters, audit records).

use std::path::Path;
use std::time::Duration;

use serde_json::{Value, json};
use sha2::Digest as _;

use super::gateway::{ALICE, EVENT, GITHUB_CAPABILITY, Gateway, config};
use super::receiver::{Received, Receiver};

/// Longest any row polls for one observable.
pub const DEADLINE: Duration = Duration::from_secs(20);

/// Fast retry timings so retry rows run on a real clock in seconds.
pub fn fast_retry() -> Value {
    json!({"retry_base": "200ms", "retry_max_attempts": 5, "retry_window": "15m"})
}

/// `events` merged with the loopback allowlist, over the fixture config.
pub fn delivery_config(root: &Path, events: &Value) -> Value {
    let mut events = events.clone();
    if events.get("callback_allow_private").is_none() {
        events["callback_allow_private"] = json!(["127.0.0.0/8"]);
    }
    config(root, &events)
}

/// A gateway on `cfg` that trusts `receiver`, with the event catalogued.
pub async fn start_cfg(root: &Path, receiver: &Receiver, cfg: Value) -> Gateway {
    start_cfg_env(root, receiver, cfg, &[]).await
}

/// As [`start_cfg`], with `extra` added to the gateway's environment.
pub async fn start_cfg_env(
    root: &Path,
    receiver: &Receiver,
    cfg: Value,
    extra: &[(&str, &str)],
) -> Gateway {
    let trust = receiver.trust_env();
    let mut env: Vec<(&str, &str)> = trust.iter().map(|(k, v)| (*k, v.as_str())).collect();
    env.extend_from_slice(extra);
    let gw = Gateway::start_with_env(root, cfg, &env).await;
    gw.event_names(Some(ALICE), Some(EVENT)).await;
    gw
}

/// Environment variable the signed inbound route reads its HMAC key from.
pub const INBOUND_SECRET_ENV: &str = "EVENTS_INBOUND_HMAC";

/// The fixture config with the `push` route requiring a GitHub-style
/// `X-Hub-Signature-256` HMAC keyed by `{env.EVENTS_INBOUND_HMAC}`.
pub fn signed_inbound_config(root: &Path, events: &Value) -> Value {
    let mut cfg = delivery_config(root, events);
    let signed = GITHUB_CAPABILITY.replacen(
        "    method: POST\n",
        "    method: POST\n    secret: \"{env.EVENTS_INBOUND_HMAC}\"\n    signature_header: X-Hub-Signature-256\n",
        1,
    );
    assert_ne!(signed, GITHUB_CAPABILITY, "the route gained a secret");
    std::fs::write(root.join("caps").join("github.yaml"), signed).expect("capability file");
    cfg["webhooks"]["require_signature"] = json!(true);
    cfg
}

/// POST `body` under `delivery_id` with `X-Hub-Signature-256` computed over
/// the exact body bytes under `key`; the HTTP status.
pub async fn fire_signed(gw: &Gateway, delivery_id: &str, body: &Value, key: &str) -> u16 {
    use hmac::{Hmac, KeyInit, Mac};
    let body = body.to_string();
    let mut mac = Hmac::<sha2::Sha256>::new_from_slice(key.as_bytes()).expect("any key length");
    mac.update(body.as_bytes());
    let signature = format!("sha256={}", hex::encode(mac.finalize().into_bytes()));
    gw.client
        .post(format!("{}/webhooks/github/push", gw.url))
        .header("content-type", "application/json")
        .header("X-GitHub-Delivery", delivery_id)
        .header("X-Hub-Signature-256", signature)
        .body(body)
        .send()
        .await
        .unwrap_or_else(|e| panic!("signed POST: {e}; logs={}", gw.logs()))
        .status()
        .as_u16()
}

/// As [`start_cfg`] over the fixture config with `events` merged in.
#[allow(
    clippy::needless_pass_by_value,
    reason = "every call site builds the section inline with json!"
)]
pub async fn start(root: &Path, receiver: &Receiver, events: Value) -> Gateway {
    start_cfg(root, receiver, delivery_config(root, &events)).await
}

pub fn params(url: &str, secret: &str, arguments: Value) -> Value {
    let mut params = json!({
        "name": EVENT,
        "delivery": {"mode": "webhook", "url": url, "secret": secret},
    });
    params["arguments"] = arguments;
    params
}

/// Subscribe and return the subscription id (panics on an error answer).
pub async fn subscribe(
    gw: &Gateway,
    key: &str,
    url: &str,
    secret: &str,
    arguments: Value,
) -> String {
    let answer = gw
        .rpc(
            Some(key),
            "events/subscribe",
            params(url, secret, arguments),
        )
        .await;
    answer["result"]["id"]
        .as_str()
        .unwrap_or_else(|| panic!("subscribe answers an id: {answer}"))
        .to_owned()
}

/// Unsubscribe by key; the bare result.
pub async fn unsubscribe(gw: &Gateway, key: &str, url: &str, arguments: Value) -> Value {
    let answer = gw
        .rpc(
            Some(key),
            "events/unsubscribe",
            json!({"name": EVENT, "arguments": arguments, "delivery": {"url": url}}),
        )
        .await;
    bare(&answer)
}

/// The method's own result, without the transport's `resultType` and `_meta`.
pub fn bare(answer: &Value) -> Value {
    let mut result = answer["result"].clone();
    if let Some(map) = result.as_object_mut() {
        map.remove("resultType");
        map.remove("_meta");
    }
    result
}

/// A GitHub-style push body for `repo`.
pub fn push(repo: &str) -> Value {
    push_ref(repo, "main")
}

/// A GitHub-style push body for `repo` on `git_ref`.
pub fn push_ref(repo: &str, git_ref: &str) -> Value {
    json!({"action": "opened", "repository": {"full_name": repo}, "ref": git_ref})
}

/// POST one push for `repo` under `delivery_id`; the route must accept it.
pub async fn fire(gw: &Gateway, delivery_id: &str, repo: &str) {
    let status = gw.webhook(delivery_id, &push(repo)).await;
    assert!(
        (200..300).contains(&status),
        "inbound webhook answered {status}"
    );
}

/// Poll `check` every 50 ms until it holds or `within` passes.
pub async fn wait_until(within: Duration, mut check: impl FnMut() -> bool) -> bool {
    let deadline = tokio::time::Instant::now() + within;
    loop {
        if check() {
            return true;
        }
        if tokio::time::Instant::now() >= deadline {
            return false;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

/// The receiver's event deliveries once at least `n` arrived, or a panic
/// naming how many did within [`DEADLINE`].
pub async fn events_at_least(receiver: &Receiver, n: usize) -> Vec<Received> {
    let arrived = wait_until(DEADLINE, || receiver.events().len() >= n).await;
    let got = receiver.events();
    assert!(arrived, "expected {n} event deliveries, got {}", got.len());
    got
}

/// Every JSON record in `<store>/<dir>/`.
pub fn records(root: &Path, dir: &str) -> Vec<Value> {
    let Ok(entries) = std::fs::read_dir(root.join("events").join(dir)) else {
        return Vec::new();
    };
    entries
        .flatten()
        .filter(|e| e.path().extension().is_some_and(|x| x == "json"))
        .filter_map(|e| std::fs::read(e.path()).ok())
        .filter_map(|bytes| serde_json::from_slice(&bytes).ok())
        .collect()
}

/// Dead letters on disk.
pub fn dead_letters(root: &Path) -> Vec<Value> {
    records(root, "dead")
}

/// Dead letters with `reason`, once at least one exists, or a panic.
pub async fn dead_with_reason(root: &Path, reason: &str) -> Vec<Value> {
    let found = wait_until(DEADLINE, || {
        dead_letters(root).iter().any(|d| d["reason"] == reason)
    })
    .await;
    let all = dead_letters(root);
    assert!(
        found,
        "expected a dead letter with reason {reason:?}, store has {all:?}"
    );
    all.into_iter().filter(|d| d["reason"] == reason).collect()
}

/// Every record in the transparency log files beside the gateway
/// (`audit.jsonl` and any rotated segment).
pub fn audit_records(root: &Path) -> Vec<Value> {
    let Ok(entries) = std::fs::read_dir(root) else {
        return Vec::new();
    };
    entries
        .flatten()
        .filter(|e| e.file_name().to_string_lossy().starts_with("audit"))
        .filter_map(|e| std::fs::read_to_string(e.path()).ok())
        .flat_map(|text| {
            text.lines()
                .filter_map(|l| serde_json::from_str::<Value>(l).ok())
                .collect::<Vec<_>>()
        })
        .collect()
}

/// Audit records that mention `needle` anywhere.
pub fn audit_mentioning(root: &Path, needle: &str) -> Vec<Value> {
    audit_records(root)
        .into_iter()
        .filter(|r| r.to_string().contains(needle))
        .collect()
}

/// Lowercase hex SHA-256 of `bytes`.
pub fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(sha2::Sha256::digest(bytes))
}

/// The `deliveryStatus` a refresh (same key) answers with.
pub async fn delivery_status(
    gw: &Gateway,
    key: &str,
    url: &str,
    secret: &str,
    arguments: Value,
) -> Value {
    let answer = gw
        .rpc(
            Some(key),
            "events/subscribe",
            params(url, secret, arguments),
        )
        .await;
    answer["result"]["deliveryStatus"].clone()
}

// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Subscribe, unsubscribe and delivery helpers for the upstream-event rows:
//! backend `x` on the I2 delivery config, subscriptions by webhook.

use std::path::Path;

use serde_json::{Value, json};

use super::delivery::{DEADLINE, delivery_config, wait_until};
use super::gateway::{ALICE, BOB, CAROL, Gateway};
use super::receiver::{Received, Receiver, whsec};

pub fn api_key(name: &str, key: &str, backends: &[&str]) -> Value {
    json!({
        "name": name,
        "key_sha256": mcp_gateway::config::api_key_digest_spec(key.as_bytes()),
        "backends": backends,
    })
}

/// The I2 delivery config with backend `x` = `backend` added; alice and bob
/// may reach `x`, carol may not.
#[allow(
    clippy::needless_pass_by_value,
    reason = "call sites build the value inline with json!"
)]
pub fn upstream_config(root: &Path, backend: Value, extra: &[(&str, Value)]) -> Value {
    let allow = json!({"callback_allow_private": ["127.0.0.0/8", "::1/128"]}); // localhost may be ::1
    let mut cfg = delivery_config(root, &allow);
    cfg["backends"] = json!({ "x": backend });
    for (name, value) in extra {
        cfg["backends"][*name] = value.clone();
    }
    cfg["auth"]["api_keys"] = json!([
        api_key("alice", ALICE, &["x", "hooks"]),
        api_key("bob", BOB, &["x"]),
        api_key("carol", CAROL, &["hooks"]),
    ]);
    cfg
}

#[allow(
    clippy::needless_pass_by_value,
    reason = "call sites build the value inline with json!"
)]
pub fn sub_params(name: &str, url: &str, secret: &str, arguments: Value) -> Value {
    json!({
        "name": name,
        "arguments": arguments,
        "delivery": {"mode": "webhook", "url": url, "secret": secret},
    })
}

/// Subscribe `key` to `name`; the subscription id (panics on an error).
pub async fn sub(
    gw: &Gateway,
    key: &str,
    name: &str,
    receiver: &Receiver,
    arguments: Value,
) -> String {
    let answer = gw
        .rpc(
            Some(key),
            "events/subscribe",
            sub_params(name, &receiver.localhost_url(), &whsec(32), arguments),
        )
        .await;
    answer["result"]["id"]
        .as_str()
        .unwrap_or_else(|| panic!("subscribe to {name} answers an id: {answer}"))
        .to_owned()
}

pub async fn unsub(gw: &Gateway, key: &str, name: &str, receiver: &Receiver, arguments: Value) {
    let answer = gw
        .rpc(
            Some(key),
            "events/unsubscribe",
            json!({"name": name, "arguments": arguments,
                   "delivery": {"url": receiver.localhost_url()}}),
        )
        .await;
    assert!(
        answer.get("error").is_none(),
        "unsubscribe answers: {answer}"
    );
}

/// Deliveries carrying event `name` for subscription `id`.
pub fn delivered(receiver: &Receiver, id: &str, name: &str) -> Vec<Value> {
    receiver
        .events()
        .iter()
        .filter(|r: &&Received| r.header("x-mcp-subscription-id").as_deref() == Some(id))
        .map(Received::json)
        .filter(|body| body["name"] == name)
        .collect()
}

/// Wait until subscription `id` has `n` deliveries of `name`; return them.
pub async fn expect_events(receiver: &Receiver, id: &str, name: &str, n: usize) -> Vec<Value> {
    let ok = wait_until(DEADLINE, || delivered(receiver, id, name).len() >= n).await;
    let got = delivered(receiver, id, name);
    assert!(
        ok,
        "expected {n} {name} deliveries for {id}, got {}",
        got.len()
    );
    got
}

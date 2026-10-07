// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-7630 I5, design §11 D2/D3 (lead ruling): a backend that cannot offer
//! upstream-notification events answers a subscription to one of them with a
//! typed refusal naming why, never a silent no-op. The three names are
//! `backend.<x>.resource_updated|resources_changed|prompts_changed`.
//!
//! Refused: the SSE-handshake HTTP transport (an explicit
//! `streamable_http: false` never connected, or the transport a connect
//! detected; MIK-7969), A2A, and identity propagation. An unset key is
//! judged at connect, so an unreachable one answers the backend error. The refusal is
//! `-32014` with `data.feature = "backendEvents"` and `data.reason`; it is
//! answered only to a caller who may reach the backend, so it cannot be used
//! to probe the config, and before any callback traffic.

#[path = "mik_7630_events/gateway.rs"]
#[allow(dead_code, reason = "shared harness; each binary uses a subset")]
mod gateway;

use std::path::Path;

use gateway::{ALICE, CAROL, Gateway, config, error};
use serde_json::{Value, json};

/// Nothing listens here: a callback POST would fail with `-32015`, so a row
/// that reaches the callback cannot pass by accident.
const CALLBACK: &str = "https://127.0.0.1:9/hook";
const SECRET: &str = "whsec_MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=";
/// A port with no listener: the backends are never reached by a refusal.
const DEAD: &str = "http://127.0.0.1:9";

fn key(name: &str, key: &str, backends: &[&str]) -> Value {
    json!({
        "name": name,
        "key_sha256": mcp_gateway::config::api_key_digest_spec(key.as_bytes()),
        "backends": backends,
    })
}

/// The fixture config plus one backend per refusal reason and one
/// streamable HTTP backend; alice may reach all of them, carol only `hooks`.
fn refusal_config(root: &Path) -> Value {
    let mut cfg = config(root, &json!({}));
    cfg["backends"] = json!({
        "sse": {"http_url": format!("{DEAD}/sse"), "streamable_http": false},
        "plain": {"http_url": format!("{DEAD}/mcp")},
        "agent": {"a2a_url": DEAD},
        "idp": {
            "http_url": format!("{DEAD}/mcp"),
            "streamable_http": true,
            "identity_propagation": {"strategy": "passthrough",
                "audience": "https://idp.example", "session_mode": "per_user"},
        },
        "fine": {"http_url": format!("{DEAD}/mcp"), "streamable_http": true},
        "off": {"http_url": format!("{DEAD}/sse"), "enabled": false},
    });
    cfg["auth"]["api_keys"] = json!([
        key(
            "alice",
            ALICE,
            &["hooks", "sse", "plain", "agent", "idp", "fine", "off"]
        ),
        key("carol", CAROL, &["hooks"]),
    ]);
    cfg
}

async fn subscribe(gw: &Gateway, key: &str, name: &str) -> Value {
    gw.rpc(
        Some(key),
        "events/subscribe",
        json!({
            "name": name,
            "arguments": {},
            "delivery": {"mode": "webhook", "url": CALLBACK, "secret": SECRET},
        }),
    )
    .await
}

#[tokio::test]
async fn ineligible_backends_refuse_upstream_events_with_the_reason() {
    let dir = tempfile::tempdir().expect("tempdir");
    let gw = Gateway::start(dir.path(), refusal_config(dir.path())).await;
    let cases = [
        ("sse", "sse_handshake_transport"),
        ("agent", "a2a_transport"),
        ("idp", "identity_propagation"),
    ];
    for (backend, reason) in cases {
        for kind in ["resource_updated", "resources_changed", "prompts_changed"] {
            let name = format!("backend.{backend}.{kind}");
            let answer = subscribe(&gw, ALICE, &name).await;
            let err = error(&answer);
            assert_eq!(err["code"], -32014, "{name}: typed refusal, got {answer}");
            assert_eq!(
                err["data"],
                json!({"feature": "backendEvents", "value": name, "reason": reason}),
                "{name}: the refusal names the reason"
            );
        }
    }
    // MIK-7969: an unset key that cannot connect was never learned to be
    // SSE; it answers the backend error, as `tools/call` would.
    for kind in ["resource_updated", "resources_changed", "prompts_changed"] {
        let name = format!("backend.plain.{kind}");
        let answer = subscribe(&gw, ALICE, &name).await;
        assert_eq!(
            error(&answer)["code"],
            -32000,
            "{name}: backend error, got {answer}"
        );
    }
}

#[tokio::test]
async fn the_refusal_is_not_a_probe() {
    let dir = tempfile::tempdir().expect("tempdir");
    let gw = Gateway::start(dir.path(), refusal_config(dir.path())).await;
    // carol may not reach `sse`: the same answer as an unknown name.
    let answer = subscribe(&gw, CAROL, "backend.sse.resources_changed").await;
    assert_eq!(error(&answer)["code"], -32011, "invisible: {answer}");
    let unknown = subscribe(&gw, ALICE, "backend.nosuch.resources_changed").await;
    assert_eq!(error(&unknown)["code"], -32011, "unknown: {unknown}");
    // An eligible backend is never refused for a reason it does not have.
    let fine = subscribe(&gw, ALICE, "backend.fine.resources_changed").await;
    assert_ne!(error(&fine)["code"], -32014, "eligible: {fine}");
    // A disabled backend is absent, whatever it would be refused for.
    let off = subscribe(&gw, ALICE, "backend.off.resources_changed").await;
    assert_eq!(error(&off)["code"], -32011, "disabled: {off}");
    // Some other suffix on an ineligible backend is not one of the three.
    let other = subscribe(&gw, ALICE, "backend.sse.something_else").await;
    assert_eq!(error(&other)["code"], -32011, "other suffix: {other}");
}

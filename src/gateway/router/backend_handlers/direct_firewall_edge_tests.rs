// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The direct route's request firewall verdicts the guard cells do not reach:
//! a warning that still serves the call, and a sequence-anomaly block that
//! carries its own code (`-32002`) rather than the generic firewall refusal.
#![cfg(feature = "firewall")]

use std::sync::atomic::Ordering;

use axum::http::StatusCode;
use serde_json::json;

use crate::gateway::router::direct_guards_fixture::{
    Answer, fixture_firewalled_anomaly, fixture_firewalled_with, post_direct,
};
use crate::security::firewall::FirewallAction;

#[tokio::test]
async fn a_warn_verdict_serves_the_call() {
    let fx = fixture_firewalled_with(Answer::Ok, Some(FirewallAction::Warn), false).await;
    // Shell injection is a High finding (block) until the `read` rule warns.
    let args = json!({"cmd": "; rm -rf / "});
    let (status, body) = post_direct(&fx, "alpha", "k-std", "read", args, None, None).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(body.get("error").is_none(), "{body}");
    assert_eq!(fx.calls.load(Ordering::SeqCst), 1, "{body}");
}

#[tokio::test]
async fn an_anomaly_block_carries_its_own_code() {
    let fx = fixture_firewalled_anomaly(Answer::Ok).await;
    let call = || post_direct(&fx, "alpha", "k-std", "read", json!({}), None, None);
    let (status, body) = call().await;
    assert_eq!(status, StatusCode::OK, "first call only primes: {body}");
    let (status, body) = call().await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert_eq!(body["error"]["code"], -32002, "{body}");
    let message = body["error"]["message"].as_str().unwrap_or_default();
    assert!(message.starts_with("Anomaly detection blocked"), "{body}");
    assert_eq!(
        fx.calls.load(Ordering::SeqCst),
        1,
        "the block never dispatches"
    );
}

// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Test-only drivers for the route x check matrix (MIK-8137 family, b3).
//!
//! Each driver builds an existing router fixture and sends one backend
//! `tools/call` through that route's real entry point, nothing more. The
//! matrix (`gateway::route_check_matrix_tests`) owns every assertion.

use std::path::Path;
use std::sync::atomic::Ordering;

use serde_json::Value;

use super::direct_guards_fixture::{Answer, post_direct, post_meta_invoke};

/// What one call through a route produced.
pub(crate) struct Sent {
    /// The JSON-RPC body the client got.
    pub(crate) body: Value,
    /// How many `tools/call` sends reached the backend.
    pub(crate) backend_calls: usize,
    /// The params each of those sends carried.
    pub(crate) seen: Vec<Value>,
}

fn sent(fx: &super::direct_guards_fixture::Fx, body: Value) -> Sent {
    Sent {
        body,
        backend_calls: fx.calls.load(Ordering::SeqCst),
        seen: fx.seen.lock().expect("seen lock").clone(),
    }
}

/// R1 `/mcp` `gateway_invoke alpha read`, with the production firewall on both
/// layers writing audit rows to `audit`.
pub(crate) async fn invoke_firewalled(audit: &Path, args: Value) -> Sent {
    let fx = super::direct_guards_fixture::fixture_firewalled_audited(
        Answer::Ok,
        audit.to_path_buf(),
    )
    .await;
    let (_, body) = post_meta_invoke(&fx, "k-std", "alpha", "read", args, None, None).await;
    sent(&fx, body)
}

/// R3 `/mcp/alpha` `tools/call read`, on the same firewalled fixture.
pub(crate) async fn direct_firewalled(audit: &Path, args: Value) -> Sent {
    let fx = super::direct_guards_fixture::fixture_firewalled_audited(
        Answer::Ok,
        audit.to_path_buf(),
    )
    .await;
    let (_, body) = post_direct(&fx, "alpha", "k-std", "read", args, None, None).await;
    sent(&fx, body)
}

/// R1 `/mcp` `gateway_invoke alpha read` with `security.sanitize_input` = `on`.
pub(crate) async fn invoke_sanitizing(on: bool, args: Value) -> Sent {
    let fx = super::direct_guards_fixture::fixture_sanitizing(Answer::Ok, on).await;
    let (_, body) = post_meta_invoke(&fx, "k-std", "alpha", "read", args, None, None).await;
    sent(&fx, body)
}

/// R3 `/mcp/alpha` `tools/call read` with `security.sanitize_input` = `on`.
pub(crate) async fn direct_sanitizing(on: bool, args: Value) -> Sent {
    let fx = super::direct_guards_fixture::fixture_sanitizing(Answer::Ok, on).await;
    let (_, body) = post_direct(&fx, "alpha", "k-std", "read", args, None, None).await;
    sent(&fx, body)
}

/// R1 `/mcp` `gateway_invoke alpha read` on the firewalled fixture, whose
/// backend answers `text`.
pub(crate) async fn invoke_answering(text: &'static str) -> Sent {
    let fx = super::direct_guards_fixture::fixture_firewalled_with(Answer::Text(text), None, false)
        .await;
    let (_, body) = post_meta_invoke(&fx, "k-std", "alpha", "read", serde_json::json!({}), None, None)
        .await;
    sent(&fx, body)
}

/// R3 `/mcp/alpha` `tools/call read` on the firewalled fixture, whose backend
/// answers `text`.
pub(crate) async fn direct_answering(text: &'static str) -> Sent {
    let fx = super::direct_guards_fixture::fixture_firewalled_with(Answer::Text(text), None, false)
        .await;
    let (_, body) = post_direct(&fx, "alpha", "k-std", "read", serde_json::json!({}), None, None)
        .await;
    sent(&fx, body)
}

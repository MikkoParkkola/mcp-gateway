// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Tests for the dispatch authorization chokepoint (MIK-7252).
//!
//! Plan: `docs/design/authorize-at-dispatch-test-plan.md`. Test names follow
//! its convention, `authz_<row>_<slug>`, so a row and its test are findable
//! from each other.
//!
//! One rule the plan states and these fixtures keep: no double reimplements
//! production. The only doubles here are a transport at the network boundary
//! and the authorizers `AllowAll` / `DenyAll` / `CountingAuthorizer`, none of
//! which contains policy logic. The thing under test is the real dispatch path.

#[path = "authz_tests/dispatch_shapes.rs"]
mod dispatch_shapes;
#[path = "authz_tests/playbooks.rs"]
mod playbooks;
#[path = "authz_tests/before_the_check.rs"]
mod before_the_check;
#[path = "authz_tests/cache_epoch.rs"]
mod cache_epoch;
#[path = "authz_tests/verified_callers.rs"]
mod verified_callers;

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::time::Duration;

use serde_json::{Value, json};

use crate::backend::{Backend, BackendRegistry};
use crate::config::FailsafeConfig;
use crate::gateway::authz::{AllowAll, CountingAuthorizer, DenyAll, DenyOne};
use crate::gateway::meta_mcp::{MetaMcp, MetaMcpCallerContext};
use crate::protocol::RequestId;
use crate::transport::Transport;

#[path = "authz_fixture.rs"]
mod fixture;
pub(in crate::gateway::meta_mcp) use fixture::{counted_backend, ctx, invoke_args};

/// Outer envelope a client sends: `tools/call` / `gateway_invoke` with the
/// nonce on `params.arguments`, the same shape `handlers.rs` captures.
fn captured_external_gateway_invoke(
    nonce: &str,
) -> (super::signing::SigningInvocationContext, Value) {
    let mut request = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {
            "name": "gateway_invoke",
            "arguments": {
                "server": "alpha",
                "tool": "read",
                "arguments": {},
                "nonce": nonce,
            }
        }
    });
    let context = super::signing::SigningInvocationContext::capture(&mut request);
    let arguments = request
        .pointer("/params/arguments")
        .expect("arguments survive capture")
        .clone();
    (context, arguments)
}

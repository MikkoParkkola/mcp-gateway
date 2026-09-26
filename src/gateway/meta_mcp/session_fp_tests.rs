// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! F9-T7c: the meta layer names sessions in its logs by fingerprint only.

use std::sync::Arc;

use serde_json::json;

use super::{InvokeScope, MetaMcp};
use crate::backend::BackendRegistry;
use crate::gateway::router::CallerStanding;
use crate::gateway::session_id::log_capture::{assert_fingerprinted, capture_debug};
use crate::protocol::RequestId;

fn meta_with_profile(name: &str) -> MetaMcp {
    let mut configs = std::collections::HashMap::new();
    configs.insert(
        name.to_string(),
        crate::routing_profile::RoutingProfileConfig::default(),
    );
    MetaMcp::new(Arc::new(BackendRegistry::new())).with_profile_registry(
        crate::routing_profile::ProfileRegistry::from_config(&configs, name),
    )
}

fn initialize(meta: &MetaMcp, session: &str, profile: &str) {
    let params = json!({"protocolVersion": "2024-11-05", "profile": profile});
    meta.handle_initialize(
        RequestId::Number(1),
        Some(&params),
        Some(session),
        None,
        crate::protocol::meta::Era::Legacy,
        InvokeScope::allow_all(CallerStanding::Admin),
    );
}

// meta_mcp/mod.rs: the profile binding at initialize, found and not found
#[test]
fn initialize_logs_the_session_by_fingerprint() {
    let meta = meta_with_profile("probe");
    let bound = "gw-b0a4d000-bound-session";
    let unbound = "gw-4b0a4d00-unbound-session";
    let (captured, guard) = capture_debug();
    initialize(&meta, bound, "probe");
    initialize(&meta, unbound, "no-such-profile");
    drop(guard);
    let text = captured.text();
    assert_fingerprinted(&text, "Session bound to routing profile", bound);
    assert_fingerprinted(&text, "Requested profile not found at initialize", unbound);
}

// spec_preview.rs promote and meta_mcp/mod.rs clear
#[cfg(feature = "spec-preview")]
#[test]
fn spec_preview_promotion_logs_the_session_by_fingerprint() {
    let meta = MetaMcp::new(Arc::new(BackendRegistry::new()));
    let id = "gw-5bec0000-promoted-session";
    let (captured, guard) = capture_debug();
    meta.promote_tool_for_session(Some(id), "srv:tool");
    meta.clear_session_promoted(id);
    drop(guard);
    let text = captured.text();
    assert_fingerprinted(&text, "Promoted tool to session surfaced set", id);
    assert_fingerprinted(&text, "Cleared spec-preview promoted tools", id);
}

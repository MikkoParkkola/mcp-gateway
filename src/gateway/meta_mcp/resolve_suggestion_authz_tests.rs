// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-7517 — `tools/resolve` suggestions answer to the caller's authorization.
//!
//! A `tools/resolve` miss returns Levenshtein "did you mean?" hints in the
//! JSON-RPC error body. The candidate pool used to be every cached tool name on
//! the gateway, so a caller could submit near-miss spellings and read back a
//! catalogue it is not allowed to list — an enumeration oracle rather than an
//! incidental leak.
//!
//! The pool is assembled from two independent branches (`collect_all_cached_
//! tool_names`): the capability backend, and the MCP backend loop. Each carries
//! its own filter and a refactor can drop either alone, so each gets its own
//! case below — the first fixture has an empty backend registry and the second
//! primes a real cache, so neither case can stand in for the other.
//!
//! Both directions are asserted in each case. Absence alone is satisfied by a
//! gateway that answers every miss with no suggestions at all, which would pass
//! the security criterion by deleting the feature.

use super::MetaMcp;
use crate::backend::{Backend, BackendRegistry};
use crate::capability::CapabilityBackend;
use crate::config::{BackendConfig, FailsafeConfig};
use crate::protocol::{JsonRpcResponse, RequestId, ToolsListResult};
use crate::routing_profile::{ProfileRegistry, RoutingProfileConfig};
use serde_json::json;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tempfile::TempDir;

/// The tool the `narrow` profile denies, and the one it leaves alone.
const DENIED: &str = "invariance_denied";
const ALLOWED: &str = "invariance_always";

/// One-character mutations of the two names above.
///
/// Each sits at Levenshtein distance 1 from its own tool and 6 from the other —
/// past the threshold of 3 that `build_tool_not_found_message` calls
/// `did_you_mean` with — so a probe is decided by exactly one name and neither
/// direction of the assertion can be carried by the other tool.
const NEAR_DENIED: &str = "invariance_deni3d";
const NEAR_ALLOWED: &str = "invariance_alway5";

const NARROW: &str = "narrow";

/// A registry whose `narrow` profile denies exactly one of the two tools.
///
/// The default profile denies nothing: without a profile that actually decides,
/// both cases would pass whether or not the pool is filtered at all.
fn narrowing_registry() -> ProfileRegistry {
    let mut configs = HashMap::new();
    configs.insert(
        "open".to_string(),
        RoutingProfileConfig {
            description: "denies nothing".to_string(),
            ..Default::default()
        },
    );
    configs.insert(
        NARROW.to_string(),
        RoutingProfileConfig {
            description: "denies one tool".to_string(),
            deny_tools: Some(vec![DENIED.to_string()]),
            ..Default::default()
        },
    );
    ProfileRegistry::from_config(&configs, "open")
}

/// The error message `tools/resolve` answers `name` with, for a given session.
async fn resolve_miss(meta: &MetaMcp, session: Option<&str>, name: &str) -> String {
    meta.handle_tools_resolve(
        RequestId::Number(9),
        Some(&json!({ "name": name })),
        session,
        crate::gateway::meta_mcp::InvokeScope::allow_all(
            crate::gateway::router::CallerStanding::Admin,
        ),
    )
    .await
    .error
    .expect("an unresolvable name must answer with an error")
    .message
}

/// Bind `session` to the narrowing profile.
///
/// A real session id, never the empty one: `active_profile` reads through
/// `session_key`, which maps an empty id to no session at all and would hand
/// the caller the permissive default instead of `narrow`.
fn bind_narrow_profile(meta: &MetaMcp, session: Option<&str>) {
    meta.handle_initialize(
        RequestId::Number(1),
        None,
        session,
        Some(NARROW),
        crate::protocol::meta::Era::Legacy,
        crate::gateway::meta_mcp::InvokeScope::allow_all(
            crate::gateway::router::CallerStanding::Admin,
        ),
    );
}

/// A transport that answers `tools/list` with a fixed response.
struct ListingTransport {
    response: JsonRpcResponse,
}

#[async_trait::async_trait]
impl crate::transport::Transport for ListingTransport {
    async fn request(
        &self,
        method: &str,
        _params: Option<serde_json::Value>,
    ) -> crate::Result<JsonRpcResponse> {
        assert_eq!(method, "tools/list");
        Ok(self.response.clone())
    }

    async fn notify(&self, _method: &str, _params: Option<serde_json::Value>) -> crate::Result<()> {
        Ok(())
    }

    fn is_connected(&self) -> bool {
        true
    }

    async fn close(&self) -> crate::Result<()> {
        Ok(())
    }
}

fn named_tool(name: &str) -> crate::protocol::Tool {
    crate::protocol::Tool {
        name: name.to_string(),
        title: None,
        description: Some(format!("{name} test tool")),
        input_schema: json!({"type": "object"}),
        output_schema: None,
        annotations: None,
        role: None,
        projection: None,
    }
}

/// A gateway whose two tools live on the capability backend.
///
/// The backend registry stays empty on purpose, so only the
/// `get_capabilities()` branch of the pool can satisfy this case.
async fn meta_with_capability_tools() -> (MetaMcp, TempDir) {
    let dir = TempDir::new().unwrap();
    for (name, path) in [(ALLOWED, "always"), (DENIED, "denied")] {
        std::fs::write(
            dir.path().join(format!("{name}.yaml")),
            format!(
                r"
name: {name}
description: resolve suggestion authz fixture
providers:
  primary:
    service: rest
    config:
      base_url: https://example.invalid
      path: /{path}
"
            ),
        )
        .unwrap();
    }

    let cap = Arc::new(CapabilityBackend::new(
        "caps",
        Arc::new(crate::capability::CapabilityExecutor::new()),
    ));
    cap.load_from_directory(dir.path().to_str().unwrap())
        .await
        .unwrap();

    let meta =
        MetaMcp::new(Arc::new(BackendRegistry::new())).with_profile_registry(narrowing_registry());
    meta.set_capabilities(cap);
    (meta, dir)
}

/// A gateway whose two tools live in a primed MCP backend cache.
async fn meta_with_cached_backend_tools() -> MetaMcp {
    let backend = Arc::new(Backend::new(
        "probe",
        BackendConfig::default(),
        &FailsafeConfig::default(),
        Duration::from_secs(300),
    ));
    let response = JsonRpcResponse::success_serialized(
        RequestId::Number(1),
        ToolsListResult {
            tools: vec![named_tool(ALLOWED), named_tool(DENIED)],
            next_cursor: None,
        },
    );
    backend.set_transport_for_test(Arc::new(ListingTransport { response }));
    backend.get_tools().await.expect("prime backend cache");
    assert!(
        backend.has_cached_tools(),
        "premise: an unprimed cache contributes no names, which would satisfy \
         the absence assertion without any filtering happening"
    );

    let registry = Arc::new(BackendRegistry::new());
    let _ = registry.register(backend);
    MetaMcp::new(registry).with_profile_registry(narrowing_registry())
}

#[tokio::test]
async fn capability_tool_names_are_filtered_out_of_resolve_suggestions() {
    let (meta, _dir) = meta_with_capability_tools().await;
    let session = Some("mik7517-caps");
    bind_narrow_profile(&meta, session);

    let allowed_msg = resolve_miss(&meta, session, NEAR_ALLOWED).await;
    let denied_msg = resolve_miss(&meta, session, NEAR_DENIED).await;

    assert!(
        allowed_msg.contains(ALLOWED),
        "premise: a capability this profile allows must still be suggested, or \
         the assertion below passes for a gateway that suggests nothing at \
         all: {allowed_msg}"
    );
    assert!(
        !denied_msg.contains(DENIED),
        "MIK-7517: a denied capability was named in a 'did you mean?' \
         suggestion: {denied_msg}"
    );
}

#[tokio::test]
async fn cached_backend_tool_names_are_filtered_out_of_resolve_suggestions() {
    let meta = meta_with_cached_backend_tools().await;
    let session = Some("mik7517-backend");
    bind_narrow_profile(&meta, session);

    let allowed_msg = resolve_miss(&meta, session, NEAR_ALLOWED).await;
    let denied_msg = resolve_miss(&meta, session, NEAR_DENIED).await;

    assert!(
        allowed_msg.contains(ALLOWED),
        "premise: a cached tool this profile allows must still be suggested: {allowed_msg}"
    );
    assert!(
        !denied_msg.contains(DENIED),
        "MIK-7517: a denied tool's name leaked out of a backend cache via a \
         'did you mean?' suggestion: {denied_msg}"
    );
}

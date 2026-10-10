// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
use std::sync::Arc;
use std::time::Duration;

use serde_json::json;

use crate::backend::BackendRegistry;
use crate::config::Config;
use crate::config::SurfacedToolConfig;
use crate::config_reload::{LiveConfig, ReloadContext};
use crate::gateway::destructive_confirmation::ConfirmationChannel;
use crate::protocol::RequestId;
use std::sync::atomic::{AtomicUsize, Ordering};

use super::*;
use crate::gateway::trace;

#[path = "order2_fsm_tests.rs"]
mod order2_fsm;

#[path = "empty_session_gate_tests.rs"]
mod empty_session_gate;

#[path = "context_integrity_evidence_tests.rs"]
mod context_integrity_evidence;
#[path = "session_fp_tests.rs"]
mod session_fp;

#[path = "tests/admin_exposure.rs"]
mod admin_exposure;
#[path = "tests/backend_lists.rs"]
mod backend_lists;
#[path = "tests/code_mode.rs"]
mod code_mode;
#[path = "tests/enforced_transform.rs"]
mod enforced_transform;
#[path = "tests/input_requests.rs"]
mod input_requests;
#[path = "tests/invoke_bridge.rs"]
mod invoke_bridge;
#[path = "tests/modern_connections.rs"]
mod modern_connections;
#[path = "tests/narrowed_tool_lists.rs"]
mod narrowed_tool_lists;
#[path = "tests/profiles.rs"]
mod profiles;
#[path = "tests/response_cache.rs"]
mod response_cache;
#[path = "tests/search_dispatch.rs"]
mod search_dispatch;
#[path = "tests/slot_quota_confirmation.rs"]
mod slot_quota_confirmation;
#[path = "tests/surfaced_tools.rs"]
mod surfaced_tools;

/// The permissive authorizer the helpers below hand out.
static ALLOW_ALL: crate::gateway::authz::AllowAll = crate::gateway::authz::AllowAll;

/// As [`allow_all_ctx`], but carrying a caller identity.
///
/// Kept separate so a test that depends on the identity reaching dispatch says
/// so, and a test that does not stays on the plain form.
fn allow_all_ctx_named<'a>(
    api_key_name: Option<&'a str>,
    agent_id: Option<crate::security::ProvenAgentId<'a>>,
) -> crate::gateway::meta_mcp::MetaMcpCallerContext<'a> {
    crate::gateway::meta_mcp::MetaMcpCallerContext {
        signing: None,
        execution: None,
        credential_principal: None,
        authentication: crate::gateway::meta_mcp::Authentication::Anonymous,
        credential_kind: crate::security::audit::CredentialKind::None,
        is_modern: false,
        protocol_revision: Some(crate::protocol::PROTOCOL_VERSION),
        authorizer: &ALLOW_ALL,
        api_key_name,
        agent_id,
        agent_declared: None,
        grant_subject: None,
        stdio_nonce: None,
        caller_key: None,
        verified_identity: None,
        is_admin: false,
        surface_request: crate::gateway::recovery::SurfaceRequest::Configured,
        input_capabilities: crate::protocol::meta::Declared::NONE,
        retry: &crate::protocol::mrtr::NO_RETRY,
        confirmation: ConfirmationChannel::Unavailable,
        task: None,
        // Fail-closed: a helper that declared nothing is a 2025 client, the
        // same reasoning that puts `Declared::NONE` on the line above.
        era: crate::protocol::meta::Era::Legacy,
        channel: &crate::gateway::input_bridge::NoClientChannel,
    }
}

/// A caller context that permits everything, for tests whose subject is not
/// authorization.
///
/// Named at every call site rather than reached through a `Default`, so a test
/// that is not exercising the authorizer says so out loud. `AllowAll` is
/// `#[cfg(test)]`, so no release build can reach this path.
fn allow_all_ctx() -> crate::gateway::meta_mcp::MetaMcpCallerContext<'static> {
    crate::gateway::meta_mcp::MetaMcpCallerContext {
        signing: None,
        execution: None,
        credential_principal: None,
        authentication: crate::gateway::meta_mcp::Authentication::Anonymous,
        credential_kind: crate::security::audit::CredentialKind::None,
        is_modern: false,
        protocol_revision: Some(crate::protocol::PROTOCOL_VERSION),
        authorizer: &ALLOW_ALL,
        api_key_name: None,
        agent_id: None,
        agent_declared: None,
        grant_subject: None,
        stdio_nonce: None,
        caller_key: None,
        verified_identity: None,
        is_admin: false,
        surface_request: crate::gateway::recovery::SurfaceRequest::Configured,
        input_capabilities: crate::protocol::meta::Declared::NONE,
        retry: &crate::protocol::mrtr::NO_RETRY,
        confirmation: ConfirmationChannel::Unavailable,
        task: None,
        // Fail-closed: a helper that declared nothing is a 2025 client, the
        // same reasoning that puts `Declared::NONE` on the line above.
        era: crate::protocol::meta::Era::Legacy,
        channel: &crate::gateway::input_bridge::NoClientChannel,
    }
}

fn make_meta_mcp() -> MetaMcp {
    MetaMcp::new(Arc::new(BackendRegistry::new()))
}

struct ToolCallTestTransport {
    result: serde_json::Value,
}

#[async_trait::async_trait]
impl crate::transport::Transport for ToolCallTestTransport {
    async fn request(
        &self,
        method: &str,
        _params: Option<serde_json::Value>,
    ) -> crate::Result<crate::protocol::JsonRpcResponse> {
        assert_eq!(method, "tools/call");
        Ok(crate::protocol::JsonRpcResponse::success_serialized(
            RequestId::Number(1),
            self.result.clone(),
        ))
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

fn make_meta_mcp_with_profiles() -> MetaMcp {
    use crate::routing_profile::{ProfileRegistry, RoutingProfileConfig};
    use std::collections::HashMap;

    let backends = Arc::new(BackendRegistry::new());
    let mut configs: HashMap<String, RoutingProfileConfig> = HashMap::new();
    configs.insert(
        "research".to_string(),
        RoutingProfileConfig {
            description: "Web research tools".to_string(),
            allow_tools: Some(vec!["brave_*".to_string()]),
            ..Default::default()
        },
    );
    configs.insert(
        "coding".to_string(),
        RoutingProfileConfig {
            description: "Software dev — no social".to_string(),
            deny_tools: Some(vec!["slack_*".to_string()]),
            ..Default::default()
        },
    );
    let registry = ProfileRegistry::from_config(&configs, "research");

    MetaMcp::new(backends).with_profile_registry(registry)
}

// ── Per-action attestation wiring (MIK-5223, B1-IDENT) ────────────────────
//
// These exercise the `gateway_invoke` attestation seam directly via the
// `check_attestation` gate, isolating the wiring decision (no validator =>
// no-op, observe => audit-but-pass, enforce => fail-closed) from the heavy
// backend-dispatch machinery.

#[cfg(test)]
#[path = "attestation_wiring_tests.rs"]
mod attestation_wiring;

#[cfg(test)]
#[path = "attestation_plan_tests.rs"]
mod attestation_plan;
#[cfg(test)]
#[path = "chain_strip_tests.rs"]
mod chain_strip;
/// MIK-8202 P2: the meta route's clock reads on a clock before 1970.
#[cfg(test)]
#[path = "clock_p2_tests.rs"]
mod clock_p2;
/// `MIK-7993` r5: a playbook's step notes are carried onto its answer.
#[cfg(test)]
#[path = "playbook_writes_tests.rs"]
mod playbook_writes;

/// A caller the gateway can name, and so can bind a continuation to.
///
/// Carried by the declaring fixture rather than left `None`, because an
/// unnameable caller is refused before an interim result reaches it (MRTR.2):
/// a fixture without one would test the refusal it does not mention instead of
/// the capability gate it does.
static NAMED_CALLER: std::sync::LazyLock<crate::key_server::oidc::VerifiedIdentity> =
    std::sync::LazyLock::new(|| crate::key_server::oidc::VerifiedIdentity {
        subject: "traveller-1".to_string(),
        email: "traveller@example.test".to_string(),
        name: None,
        groups: vec![],
        issuer: "https://idp.example.test".to_string(),
    });

/// What a client declared, read through the production parser.
///
/// The `capabilities` argument is the `clientCapabilities` object exactly as a
/// client would send it, so a test states a wire shape and never a parsed
/// value — a fixture that built the flags directly would agree with itself
/// about normalization the gate is supposed to own.
fn declaring(capabilities: &serde_json::Value) -> crate::protocol::meta::Declared {
    let params = json!({
        "_meta": {
            "io.modelcontextprotocol/protocolVersion": "2026-07-28",
            "io.modelcontextprotocol/clientCapabilities": capabilities
        }
    });
    crate::protocol::meta::classify_request(Some(&params), Some("2026-07-28"))
        .declared_capabilities()
}

/// Build a `MetaMcp` whose only backend is a mock at `url`, with a short
/// aggregation timeout so tests run fast.
fn meta_with_backend(url: &str, timeout: Duration) -> MetaMcp {
    meta_with_backend_timeout(url, timeout, Duration::from_secs(5))
}

/// [`meta_with_backend`] whose backend gives up on a call after `backend`.
fn meta_with_backend_timeout(url: &str, timeout: Duration, backend: Duration) -> MetaMcp {
    use crate::backend::Backend;
    use crate::config::{BackendConfig, TransportConfig};

    let config = BackendConfig {
        description: String::new(),
        enabled: true,
        transport: TransportConfig::Http {
            http_url: url.to_string(),
            streamable_http: Some(true),
            protocol_version: None,
        },
        stop_when_idle_for: None,
        max_frame_bytes: None,
        timeout: backend,
        ..BackendConfig::default()
    };
    let backend = Arc::new(Backend::new(
        "mock",
        config,
        &crate::config::FailsafeConfig::default(),
        Duration::from_secs(60),
    ));
    let registry = Arc::new(BackendRegistry::new());
    let _ = registry.register(backend);

    MetaMcp::new(registry).with_prompts_resources_fetch_timeout(timeout)
}

/// An exact grant binding for the mTLS-proven agent `id`.
fn mtls_agent(id: &str) -> crate::identity_grants::GrantAgent {
    crate::identity_grants::GrantAgent::Exact(crate::identity_grants::GrantAgentKey {
        source: crate::security::ProofSource::MutualTls,
        id: id.to_string(),
    })
}

/// The session id a connection declaring MCP 2026-07-28 arrives with.
///
/// The revision removed protocol-level sessions and the router spells that
/// absence as an empty id rather than `None` (`session_key`, `mod.rs`). Tests
/// that pass a named session do not reach the defect at all, so the empty id
/// is the condition under test, not an incidental fixture detail.
const MODERN_SESSIONLESS: Option<&str> = Some("");

/// A capability backend whose visible tool set genuinely depends on the FSM
/// state.
///
/// Every capability fixture in the tree declares `visible_in_states: vec![]`
/// — always visible, in every state — so against those fixtures the discovery
/// set is invariant under the FSM state and B-08/B-09 would run green whether
/// or not the leak they exist to catch is present. One capability here is
/// pinned to `default`, which is what makes a leaked state observable.
async fn meta_with_state_staged_capabilities() -> MetaMcp {
    use tempfile::TempDir;

    let dir = TempDir::new().unwrap();
    crate::gateway::test_helpers::write_owner_only(
        dir.path().join("always.yaml"),
        r"
name: staged_always
description: visible in every state
providers:
  primary:
    service: rest
    config:
      base_url: https://example.invalid
      path: /always
",
    )
    .unwrap();
    crate::gateway::test_helpers::write_owner_only(
        dir.path().join("default_only.yaml"),
        r"
name: staged_default_only
description: visible only in the default state
visible_in_states:
  - default
providers:
  primary:
    service: rest
    config:
      base_url: https://example.invalid
      path: /default-only
",
    )
    .unwrap();

    let cap_backend = Arc::new(CapabilityBackend::new(
        "staged",
        Arc::new(crate::capability::CapabilityExecutor::new()),
    ));
    cap_backend
        .load_from_directory(dir.path().to_str().unwrap())
        .await
        .unwrap();

    let meta = MetaMcp::new(Arc::new(BackendRegistry::new()));
    meta.set_capabilities(cap_backend);
    meta
}

/// Tool names in a discovery result, sorted.
///
/// Sorted because membership, not ordering, is what ORDER.2 constrains, and an
/// unsorted pin would flake on directory-read order rather than on the defect.
fn discovery_names(v: &Value) -> Vec<String> {
    let arr = v
        .get("tools")
        .or_else(|| v.get("matches"))
        .and_then(Value::as_array)
        .unwrap_or_else(|| panic!("no tools/matches array in discovery result: {v}"));
    let mut names: Vec<String> = arr
        .iter()
        .map(|t| {
            let raw = t
                .get("name")
                .or_else(|| t.get("tool"))
                .and_then(Value::as_str)
                .unwrap_or_else(|| panic!("discovery entry names no tool: {t}"));
            // `gateway_search` names a tool `server:tool_name`; the other three
            // readers name it bare. Compare on the bare name so one pinned
            // literal covers all four entry points.
            raw.rsplit_once(':')
                .map_or(raw, |(_, name)| name)
                .to_string()
        })
        .collect();
    names.sort();
    names
}

/// The staged set as seen in the default FSM state, pinned.
const STAGED_DEFAULT_TOOLS: &[&str] = &["staged_always", "staged_default_only"];

/// The staged set as seen in any other state — the OTHER set.
const STAGED_OTHER_STATE_TOOLS: &[&str] = &["staged_always"];

/// The state B-08 and B-09 transition to. Not `default`, and not in
/// `staged_default_only`'s `visible_in_states`.
const TARGET_STATE: &str = "triage";

#[path = "bridge_fallthrough_tests.rs"]
mod bridge_fallthrough;
#[cfg(feature = "firewall")]
#[path = "collusion_bridge_tests.rs"]
mod collusion_bridge;
#[path = "list_servers_tools_known_tests.rs"]
mod list_servers_tools_known;

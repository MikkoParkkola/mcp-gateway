// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! F13 text A keeps the MIK-7518 guarantee: the "did you mean?" hint that R2's
//! cold-slot refusal appends on the Meta-MCP route is drawn only from names the
//! caller's routing profile lets it invoke (`miss_hint_pool`'s `may_invoke`
//! filter). F13 moved the pool into that helper, so this pins the filter on
//! the text A site. Both directions are asserted: absence alone is satisfied
//! by a gateway that suggests nothing.

use std::sync::Arc;

use serde_json::{Value, json};

use super::MetaMcp;
use crate::backend::{Backend, BackendRegistry};
use crate::config::{BackendConfig, FailsafeConfig, InputSchemaEnforcement};
use crate::gateway::authz::AllowAll;
use crate::gateway::meta_mcp::{InvokeScope, MetaMcpCallerContext};
use crate::gateway::router::CallerStanding;
use crate::protocol::{JsonRpcResponse, RequestId};
use crate::routing_profile::{ProfileRegistry, RoutingProfileConfig};

/// The tool the `narrow` profile denies, and the one it leaves alone.
const DENIED: &str = "invariance_denied";
const ALLOWED: &str = "invariance_always";
/// Distance 1 from their own tool and 6 from the other (hint threshold 3),
/// so each probe is decided by exactly one name.
const NEAR_DENIED: &str = "invariance_deni3d";
const NEAR_ALLOWED: &str = "invariance_alway5";
const SERVER: &str = "probe";
const NARROW: &str = "narrow";

/// Lists both tools; a `tools/call` reaching it is a test failure (R2 must
/// refuse first).
struct ListOnly;

#[async_trait::async_trait]
impl crate::transport::Transport for ListOnly {
    async fn request(
        &self,
        method: &str,
        _params: Option<Value>,
    ) -> crate::Result<JsonRpcResponse> {
        assert_eq!(method, "tools/list", "R2 must refuse before dispatch");
        let tools: Vec<Value> = [ALLOWED, DENIED]
            .iter()
            .map(|name| json!({"name": name, "inputSchema": {"type": "object"}}))
            .collect();
        Ok(JsonRpcResponse::success(
            RequestId::Number(1),
            json!({ "tools": tools }),
        ))
    }

    async fn notify(&self, _method: &str, _params: Option<Value>) -> crate::Result<()> {
        Ok(())
    }

    fn is_connected(&self) -> bool {
        true
    }

    async fn close(&self) -> crate::Result<()> {
        Ok(())
    }
}

/// A gateway whose `probe` slot is COLD (never listed), in closed mode, with
/// `session` bound to a profile denying exactly `DENIED`.
fn cold_meta(session: &str) -> MetaMcp {
    let config = BackendConfig {
        input_schema_enforcement: InputSchemaEnforcement::Closed,
        ..BackendConfig::default()
    };
    let ttl = std::time::Duration::from_secs(300);
    let backend = Arc::new(Backend::new(
        SERVER,
        config,
        &FailsafeConfig::default(),
        ttl,
    ));
    backend.set_transport_for_test(Arc::new(ListOnly));
    assert!(!backend.has_cached_tools(), "premise: the slot starts cold");
    let registry = Arc::new(BackendRegistry::new());
    assert!(registry.register(backend));

    let mut configs = std::collections::HashMap::new();
    configs.insert("open".to_string(), RoutingProfileConfig::default());
    configs.insert(
        NARROW.to_string(),
        RoutingProfileConfig {
            deny_tools: Some(vec![DENIED.to_string()]),
            ..Default::default()
        },
    );
    let meta = MetaMcp::new(registry)
        .with_profile_registry(ProfileRegistry::from_config(&configs, "open"));
    meta.handle_initialize(
        RequestId::Number(1),
        None,
        Some(session),
        Some(NARROW),
        crate::protocol::meta::Era::Legacy,
        InvokeScope::allow_all(CallerStanding::Admin),
    );
    meta
}

fn ctx() -> MetaMcpCallerContext<'static> {
    MetaMcpCallerContext {
        signing: None,
        execution: None,
        credential_principal: None,
        authentication: crate::gateway::meta_mcp::Authentication::Anonymous,
        credential_kind: crate::security::audit::CredentialKind::None,
        is_modern: false,
        protocol_revision: None,
        authorizer: &AllowAll,
        api_key_name: Some("test-caller"),
        agent_id: None,
        agent_declared: None,
        grant_subject: None,
        stdio_nonce: None,
        verified_identity: None,
        is_admin: false,
        input_capabilities: crate::protocol::meta::Declared::NONE,
        retry: &crate::protocol::mrtr::NO_RETRY,
        confirmation: crate::gateway::destructive_confirmation::ConfirmationChannel::Unavailable,
        task: None,
        era: crate::protocol::meta::Era::Legacy,
        channel: &crate::gateway::input_bridge::NoClientChannel,
    }
}

/// The whole body `gateway_invoke` answers `tool` with on a fresh cold slot;
/// asserts it is R2's text A (not the dispatch miss), so the hint under test
/// is the one F13 appends.
async fn text_a_body(tool: &str) -> String {
    let session = format!("f13-hint-{tool}");
    let meta = cold_meta(&session);
    let args = json!({ "server": SERVER, "tool": tool, "arguments": {} });
    let body = match meta.invoke_tool(&args, Some(&session), &ctx()).await {
        Ok(value) => value.to_string(),
        Err(err) => err.to_string(),
    };
    let text_a = crate::backend::text_absent(tool);
    assert!(body.contains(&text_a), "premise: not R2's text A: {body}");
    body
}

/// F13 x MIK-7518: text A's hint answers to the caller's profile.
/// New-API row: text A does not exist on base (the call is forwarded). The
/// filter is proven on this site by mutant M14 (drop the `may_invoke` retain
/// in `miss_hint_pool`).
#[tokio::test]
async fn f13_text_a_hint_is_scoped_to_the_callers_profile() {
    let allowed = text_a_body(NEAR_ALLOWED).await;
    assert!(
        allowed.contains(ALLOWED),
        "premise: an allowed tool must still be suggested: {allowed}"
    );
    let denied = text_a_body(NEAR_DENIED).await;
    assert!(
        !denied.contains(DENIED),
        "text A's hint named a tool the caller's profile denies: {denied}"
    );
}

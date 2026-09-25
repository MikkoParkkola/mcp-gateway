// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-7518 — invocation-failure suggestions answer to the caller's profile.
//!
//! A `gateway_invoke` miss returns Levenshtein "did you mean?" hints built from
//! the target backend's cached tool list. The pool was that list raw, so a
//! caller could submit near-miss spellings against a named server and harvest
//! its catalogue out of the error bodies — including tools its routing profile
//! forbids. Second instance of the class MIK-7517 closed in `spec_preview`.
//!
//! The pool carries two independent filters and a refactor can drop either
//! alone, so each gets its own case.
//!
//! * `tool_allowed` is exercised end to end through `invoke_tool`, because that
//!   is the caller-reachable route the ticket reports.
//! * `backend_allowed` is exercised against `suggestible_tool_names` directly.
//!   It cannot be reached through `invoke_tool`: `validate_invocation` calls
//!   `RoutingProfile::check`, which refuses on the backend filter first
//!   (`routing_profile/mod.rs:133`), so a denied backend never dispatches. The
//!   guard still belongs here — it keeps the pool correct for any future caller
//!   of this helper that is not behind that refusal — and a direct case is the
//!   only thing that can hold it.
//!
//! Both directions are asserted in each case. Absence alone is satisfied by a
//! gateway that suggests nothing at all, which would pass the security
//! criterion by deleting the feature.

use std::sync::Arc;

use serde_json::{Value, json};

use crate::backend::{Backend, BackendRegistry};
use crate::config::{BackendConfig, FailsafeConfig};
use crate::gateway::authz::AllowAll;
use crate::gateway::meta_mcp::{MetaMcp, MetaMcpCallerContext};
use crate::protocol::{JsonRpcResponse, RequestId, ToolsListResult};
use crate::routing_profile::{ProfileRegistry, RoutingProfileConfig};
use crate::transport::Transport;

/// The tool the `narrow` profile denies, and the one it leaves alone.
const DENIED: &str = "invariance_denied";
const ALLOWED: &str = "invariance_always";

/// One-character mutations of the two names above.
///
/// Each sits at Levenshtein distance 1 from its own tool and 6 from the other —
/// past the threshold of 3 that `invocation_miss_message` calls `did_you_mean`
/// with — so a probe is decided by exactly one name and neither direction of
/// the assertion can be carried by the other tool.
const NEAR_DENIED: &str = "invariance_deni3d";
const NEAR_ALLOWED: &str = "invariance_alway5";

const SERVER: &str = "probe";
const NARROW: &str = "narrow";

/// What the backend answers a `tools/call` with.
///
/// Names neither tool: were the refusal text to carry one, the absence
/// assertion could fail for a reason that has nothing to do with the pool.
const UPSTREAM_REFUSAL: &str = "upstream declined this call";

/// A transport that lists the two tools and refuses every `tools/call`.
///
/// The invoke path primes the cache with `tools/list` and then dispatches
/// anyway ("in case the cache is stale"), so both methods have to answer.
struct ListThenRefuse;

#[async_trait::async_trait]
impl Transport for ListThenRefuse {
    async fn request(
        &self,
        method: &str,
        _params: Option<Value>,
    ) -> crate::Result<JsonRpcResponse> {
        if method == "tools/list" {
            return Ok(JsonRpcResponse::success_serialized(
                RequestId::Number(1),
                ToolsListResult {
                    tools: vec![named_tool(ALLOWED), named_tool(DENIED)],
                    next_cursor: None,
                },
            ));
        }
        Ok(JsonRpcResponse::error(
            Some(RequestId::Number(1)),
            -32601,
            UPSTREAM_REFUSAL,
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

/// A registry whose `narrow` profile denies exactly one of the two tools.
///
/// The default profile denies nothing: without a profile that actually decides,
/// both cases would pass whether or not the pool is filtered at all.
fn narrowing_registry() -> ProfileRegistry {
    let mut configs = std::collections::HashMap::new();
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

/// A backend whose tool cache is primed with both names.
async fn primed_backend() -> Arc<Backend> {
    let backend = Arc::new(Backend::new(
        SERVER,
        BackendConfig::default(),
        &FailsafeConfig::default(),
        std::time::Duration::from_secs(300),
    ));
    backend.set_transport_for_test(Arc::new(ListThenRefuse));
    backend.get_tools().await.expect("prime backend cache");
    assert!(
        backend.has_cached_tools(),
        "premise: an unprimed cache contributes no names, which would satisfy \
         the absence assertion without any filtering happening"
    );
    backend
}

async fn meta_with_primed_backend() -> MetaMcp {
    let registry = Arc::new(BackendRegistry::new());
    let _ = registry.register(primed_backend().await);
    MetaMcp::new(registry).with_profile_registry(narrowing_registry())
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
    );
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
        grant_subject: None,
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

/// The whole user-visible body `gateway_invoke` answers a miss on `tool` with.
///
/// The whole body, not just the message: the invoke path renders a dispatch
/// error into a `{content, isError, recovery}` envelope that repeats the text
/// in more than one field, and a name is leaked wherever it appears.
async fn invoke_miss(meta: &MetaMcp, session: Option<&str>, tool: &str) -> String {
    let args = json!({ "server": SERVER, "tool": tool, "arguments": {} });
    let body = match meta.invoke_tool(&args, session, &ctx()).await {
        Ok(value) => value.to_string(),
        Err(err) => err.to_string(),
    };
    assert!(
        body.contains(UPSTREAM_REFUSAL) || body.contains("not found on server"),
        "premise: this probe must actually reach the suggestion path, or the \
         absence assertion is about a response that was never built: {body}"
    );
    body
}

/// The `tool_allowed` branch, end to end through the reported route.
#[tokio::test]
async fn denied_tool_names_are_filtered_out_of_invocation_suggestions() {
    let meta = meta_with_primed_backend().await;
    let session = Some("mik7518-tool");
    bind_narrow_profile(&meta, session);

    let allowed_msg = invoke_miss(&meta, session, NEAR_ALLOWED).await;
    let denied_msg = invoke_miss(&meta, session, NEAR_DENIED).await;

    assert!(
        allowed_msg.contains(ALLOWED),
        "premise: a tool this profile allows must still be suggested, or the \
         assertion below passes for a gateway that suggests nothing at all: \
         {allowed_msg}"
    );
    assert!(
        !denied_msg.contains(DENIED),
        "MIK-7518: a tool the caller's profile denies was named in a 'did you \
         mean?' suggestion on an invocation failure: {denied_msg}"
    );
}

/// The `backend_allowed` branch, against the pool builder directly.
///
/// Unreachable through `invoke_tool` — see the module docs — so the helper is
/// the only seam that can hold this guard.
#[tokio::test]
async fn a_denied_backend_contributes_no_invocation_suggestions() {
    let backend = primed_backend().await;
    let registry = Arc::new(BackendRegistry::new());
    let _ = registry.register(Arc::clone(&backend));

    let mut configs = std::collections::HashMap::new();
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
            description: "denies the whole server".to_string(),
            deny_backends: Some(vec![SERVER.to_string()]),
            ..Default::default()
        },
    );
    let meta = MetaMcp::new(registry)
        .with_profile_registry(ProfileRegistry::from_config(&configs, "open"));

    let session = Some("mik7518-backend");
    bind_narrow_profile(&meta, session);

    assert!(
        meta.suggestible_tool_names(&backend, Some("mik7518-open"))
            .contains(&ALLOWED.to_string()),
        "premise: an unbound session gets the permissive default, so the pool \
         must be non-empty there — otherwise the assertion below is satisfied \
         by a helper that always returns nothing"
    );
    assert!(
        meta.suggestible_tool_names(&backend, session).is_empty(),
        "MIK-7518: a server the caller's profile denies must contribute no \
         suggestion candidates at all"
    );
}

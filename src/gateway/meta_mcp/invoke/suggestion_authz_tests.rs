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
//! The pool is filtered by `may_invoke` (#555), which applies the routing
//! profile's `check` -- backend filter, then tool filter -- and the authorizer.
//! A refactor can drop the filter, or narrow it to the authorizer alone, and
//! both leave every other test green, so the profile rows get their own cases.
//!
//! * A profile-denied tool: end to end through `invoke_tool`, the
//!   caller-reachable route the ticket reports.
//! * A profile-denied backend: `invoke_tool` refuses before dispatch, so no
//!   pool is ever built. The case pins that the refusal itself names no tool.
//!
//! These cases once lived beside a `suggestible_tool_names` helper in
//! `invoke/suggestion.rs`. A later docs commit (3fc7c0576) dropped the
//! `mod suggestion;` line, the helper and its `#[path]`-declared tests went
//! out of the build together, and the orphan guard still counted the
//! declaration inside the uncompiled file. #555 then rebuilt the filter on
//! `may_invoke`, so these rows now pin that filter instead.
//!
//! Both directions are asserted. Absence alone is satisfied by a gateway that
//! suggests nothing at all, which would pass the security criterion by
//! deleting the feature.

use std::sync::Arc;

use serde_json::{Value, json};

use crate::backend::{Backend, BackendRegistry};
use crate::config::{BackendConfig, FailsafeConfig};
use crate::gateway::meta_mcp::test_callers::anonymous_caller;
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
    let caller = ctx();
    meta.handle_initialize(
        RequestId::Number(1),
        None,
        session,
        Some(NARROW),
        crate::protocol::meta::Era::Legacy,
        caller.scope(),
    );
}

/// The anonymous test caller, on the legacy era the profile was bound under.
fn ctx() -> MetaMcpCallerContext<'static> {
    MetaMcpCallerContext {
        is_modern: false,
        era: crate::protocol::meta::Era::Legacy,
        ..anonymous_caller()
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
        // F13: under `closed` a name the primed list lacks is refused before
        // dispatch with text A, which carries the same scoped hint.
        body.contains(UPSTREAM_REFUSAL)
            || body.contains("not found on server")
            || body.contains(&crate::backend::text_absent(tool)),
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

/// A profile-denied backend: refused before dispatch, and the refusal names
/// no tool.
#[tokio::test]
async fn a_denied_backend_refusal_names_none_of_its_tools() {
    let backend = primed_backend().await;
    let registry = Arc::new(BackendRegistry::new());
    let _ = registry.register(backend);

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

    // Premise: with the permissive default the same probe does get a hint,
    // so the absence below is the profile's doing, not a silent pool.
    let open = invoke_miss(&meta, Some("mik7518-open"), NEAR_ALLOWED).await;
    assert!(open.contains(ALLOWED), "premise: {open}");

    let session = Some("mik7518-backend");
    bind_narrow_profile(&meta, session);
    let args = json!({ "server": SERVER, "tool": NEAR_ALLOWED, "arguments": {} });
    let body = match meta.invoke_tool(&args, session, &ctx()).await {
        Ok(value) => value.to_string(),
        Err(err) => err.to_string(),
    };
    assert!(
        body.contains("routing profile"),
        "premise: the backend filter must be what answered: {body}"
    );
    assert!(
        !body.contains(ALLOWED) && !body.contains(DENIED),
        "MIK-7518: a server the caller's profile denies must not leak its tool \
         names in the refusal: {body}"
    );
}

// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-7334.CATALOGUE.1 — a per-user backend's catalogue must reach its owner.
//!
//! The criterion (`RELEASE-4.0.0-scope-update.md:32`) reads: *"Supported
//! identity-dependent backend catalogues, cached metadata and results are
//! isolated by verified caller and authorization context."* Isolation quantifies
//! over a set, and today that set is empty: on a multi-user gateway
//! `meta_route_isolation_refused` omits every identity-bound backend from
//! discovery, so nothing is isolated because nothing is served.
//!
//! The release owner declined the rescope that would have graded that MET
//! (PR #604) and ruled BUILD. These cases are the acceptance edge of that
//! ruling.
//!
//! EVERY CASE ASSERTS BOTH DIRECTIONS. A gateway that answers discovery with
//! nothing at all satisfies "B must not see A's tools" perfectly, so the
//! forbidden half alone grades an empty response as a pass. Each case therefore
//! names a backend that MUST appear beside the one that MUST NOT, and the two
//! are distinguishable by name.
//!
//! What is red here, and why: the OMITTED half passes today — that is the
//! shipped leak-stop doing its job, and it must keep passing. The SERVED half
//! fails, because a `per_user` backend is omitted from the very caller it
//! belongs to. Reading the red output, the failing assertion is always the
//! positive one.

use super::MetaMcp;
use crate::backend::{Backend, BackendRegistry};
use crate::config::{BackendConfig, FailsafeConfig, OAuthConfig};
use crate::identity_propagation::{
    IdentityPropagationConfig, PropagationStrategyKind, SessionMode,
};
use crate::protocol::{JsonRpcResponse, RequestId, ToolsListResult};
use crate::routing_profile::{ProfileRegistry, RoutingProfileConfig};
use serde_json::{Value, json};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

/// The backend whose catalogue is identity-dependent: `session_mode = per_user`
/// with propagation required. This is the set C0 quantifies over, and the one
/// the criterion says must be isolated rather than withheld.
pub(super) const PER_USER_BACKEND: &str = "per_user_hub";
pub(super) const PER_USER_TOOL: &str = "per_user_ledger_read";

/// A genuinely shared service backend. Its tools must stay visible on a
/// multi-user gateway, so a change that achieves "isolation" by blanking
/// discovery fails here instead of passing quietly.
pub(super) const SHARED_BACKEND: &str = "shared_hub";
pub(super) const SHARED_TOOL: &str = "shared_status_read";

/// A backend behind ONE gateway-held OAuth login with no per-user binding.
/// `oauth.enabled && !shared_account` is the first arm of
/// `enforce_oauth_isolation_for` (`src/backend/ops.rs:106`). Nothing in this row
/// makes that login per-caller, so it must STAY omitted on a multi-user gateway
/// whatever the catalogue work does — it is the control that fails if the B1
/// fix loosens the guard for every authenticated caller rather than only where
/// the following fetch runs on that caller's own slot.
pub(super) const GATEWAY_OAUTH_BACKEND: &str = "gateway_oauth_hub";
pub(super) const GATEWAY_OAUTH_TOOL: &str = "gateway_oauth_secret_read";

/// A transport answering one canned `tools/list`.
struct CannedTools {
    tools: Vec<String>,
}

#[async_trait::async_trait]
impl crate::transport::Transport for CannedTools {
    async fn request(
        &self,
        method: &str,
        _params: Option<Value>,
    ) -> crate::Result<JsonRpcResponse> {
        assert_eq!(method, "tools/list", "fixture serves only tools/list");
        Ok(JsonRpcResponse::success_serialized(
            RequestId::Number(1),
            ToolsListResult {
                tools: self.tools.iter().map(|n| named_tool(n)).collect(),
                next_cursor: None,
            },
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

/// A transport that answers `tools/list` and RECORDS every other method that
/// reaches it, so a test can assert a backend was never forwarded to.
struct RecordingTools {
    tools: Vec<String>,
    seen: parking_lot::Mutex<Vec<String>>,
}

impl RecordingTools {
    fn new(tools: &[&str]) -> Self {
        Self {
            tools: tools.iter().map(|t| (*t).to_string()).collect(),
            seen: parking_lot::Mutex::new(Vec::new()),
        }
    }

    fn forwarded(&self, method: &str) -> bool {
        self.seen.lock().iter().any(|m| m == method)
    }
}

#[async_trait::async_trait]
impl crate::transport::Transport for RecordingTools {
    async fn request(
        &self,
        method: &str,
        _params: Option<Value>,
    ) -> crate::Result<JsonRpcResponse> {
        self.seen.lock().push(method.to_string());
        Ok(JsonRpcResponse::success_serialized(
            RequestId::Number(1),
            ToolsListResult {
                tools: self.tools.iter().map(|n| named_tool(n)).collect(),
                next_cursor: None,
            },
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

pub(super) fn named_tool(name: &str) -> crate::protocol::Tool {
    crate::protocol::Tool {
        name: name.to_string(),
        title: None,
        description: Some(format!("{name} catalogue isolation fixture")),
        input_schema: json!({ "type": "object" }),
        output_schema: None,
        annotations: None,
        role: None,
        projection: None,
    }
}

/// A registered backend with a warm tool cache.
///
/// The cache is primed through `get_tools_shared` on purpose: it is the ONLY
/// metadata fetch that exists at HEAD, and priming it is what makes the
/// discovery paths reach a populated cache. A cold cache would contribute no
/// names and would satisfy the absence half of every assertion below without
/// any isolation having happened.
pub(super) async fn warm_backend(name: &str, tool: &str, config: BackendConfig) -> Arc<Backend> {
    let backend = Arc::new(Backend::new(
        name,
        config,
        &FailsafeConfig::default(),
        Duration::from_secs(300),
    ));
    backend.set_transport_for_test(Arc::new(CannedTools {
        tools: vec![tool.to_string()],
    }));
    backend
        .get_tools_shared()
        .await
        .expect("fixture must prime its tool cache");
    assert!(
        backend.has_cached_tools(),
        "premise: an unprimed cache contributes no names, which passes the \
         omission assertions for the wrong reason"
    );
    backend
}

/// `session_mode = per_user`, propagation required — the identity-dependent
/// catalogue. `pool_key_for` (`src/backend/pool.rs:173`) mints a `PerUser` slot
/// only for this shape, so it is exactly C0's set.
async fn per_user_backend() -> Arc<Backend> {
    warm_backend(
        PER_USER_BACKEND,
        PER_USER_TOOL,
        BackendConfig {
            identity_propagation: Some(IdentityPropagationConfig {
                strategy: PropagationStrategyKind::SignedAssertion,
                audience: "ledger".to_string(),
                required: true,
                session_mode: SessionMode::PerUser,
                token_exchange_endpoint: None,
                token_exchange_scope: None,
            }),
            ..Default::default()
        },
    )
    .await
}

/// One gateway-held OAuth login, not blessed as a shared account.
pub(super) async fn gateway_oauth_backend() -> Arc<Backend> {
    warm_backend(
        GATEWAY_OAUTH_BACKEND,
        GATEWAY_OAUTH_TOOL,
        BackendConfig {
            oauth: Some(OAuthConfig {
                enabled: true,
                shared_account: false,
                scopes: vec![],
                client_id: None,
                client_secret: None,
                callback_host: None,
                callback_port: None,
                callback_path: None,
                token_refresh_buffer_secs: 300,
            }),
            ..Default::default()
        },
    )
    .await
}

/// A gateway holding all three backends, warm.
///
/// `multi_user` is the axis under test: the same registry is asked the same
/// question in both postures, so a difference in the answer is the guard and
/// nothing else.
pub(super) async fn gateway(multi_user: bool) -> MetaMcp {
    let registry = Arc::new(BackendRegistry::new());
    for backend in [
        per_user_backend().await,
        warm_backend(SHARED_BACKEND, SHARED_TOOL, BackendConfig::default()).await,
        gateway_oauth_backend().await,
    ] {
        assert!(
            registry.register(backend),
            "fixture backend failed to register"
        );
    }

    let mut configs: HashMap<String, RoutingProfileConfig> = HashMap::new();
    configs.insert(
        "open".to_string(),
        RoutingProfileConfig {
            description: "denies nothing, so authorization cannot decide these cases".to_string(),
            ..Default::default()
        },
    );

    let meta = MetaMcp::new(registry)
        .with_profile_registry(ProfileRegistry::from_config(&configs, "open"));
    meta.set_multi_user(multi_user);
    meta
}

/// GIVEN the same three backends on a SINGLE-user gateway
/// WHEN discovery lists tools
/// THEN all three catalogues are served.
///
/// GREEN TODAY, and it is the control that keeps the case above honest in both
/// directions. It fails if per-caller catalogues are delivered by degrading the
/// single-tenant path — the IDP.5 guarantee `pool_key_for` already makes for
/// transports (`src/backend/pool.rs:169-171`) — and it proves the fixture's
/// tools are discoverable at all, so the multi-user failure above is the guard
/// and not an empty cache.
#[tokio::test]
async fn single_user_gateway_still_serves_every_catalogue() {
    let names = super::catalogue_per_caller_tests::listed_for(
        &gateway(false).await,
        &super::anonymous_caller(),
    )
    .await;

    for expected in [PER_USER_TOOL, SHARED_TOOL, GATEWAY_OAUTH_TOOL] {
        assert!(
            names.contains(&expected.to_string()),
            "single-tenant discovery lost `{expected}`: {names:?} — isolation \
             must not be bought by breaking the shared path"
        );
    }
}

/// T9 — the isolation guard stays fail-closed where the fetch after it is shared.
///
/// GREEN TODAY BY CONSTRUCTION, and that is its whole job. Design §9.2 says the
/// `meta_route_isolation_refused` call sites "become credential-aware". Read as
/// a mechanical sweep, that loosens the guard at sites whose NEXT operation
/// still runs on the gateway's shared credential — `handle_logging_set_level`
/// (`src/gateway/meta_mcp/protocol.rs:306`) guards, then forwards with
/// `backend.request(...)`; `handle_prompts_list` (`protocol.rs:158`) and
/// `handle_resources_list` (`resources.rs:293`) guard, then call the
/// `*_shared` fetch.
///
/// `has_per_user_credential = true` does not narrow the guard, it
/// short-circuits it: `enforce_oauth_isolation_for` returns `Ok(())` at
/// `mod.rs:1116` before any arm is evaluated. So this case goes RED the day
/// somebody implements B1 as the sweep rather than as a per-site opt-in, which
/// is the only moment anyone would want to hear about it.
///
/// Two-directional: the genuinely shared backend must NOT be refused, so a
/// change that fails the gateway closed for everything also fails here.
#[tokio::test]
async fn identity_bound_backends_stay_refused_on_the_shared_credential_paths() {
    let meta = gateway(true).await;
    let refused = |name: &str| {
        let backend = meta
            .backends
            .get(name)
            .unwrap_or_else(|| panic!("fixture backend `{name}` is registered"));
        meta.meta_route_isolation_refused(&backend)
    };

    assert!(
        refused(GATEWAY_OAUTH_BACKEND),
        "a backend behind ONE gateway-held OAuth login stopped being refused on \
         a multi-user gateway — the shared token is now reachable by any caller \
         through the paths that forward it directly (ADR-008 INV-2)"
    );
    assert!(
        refused(PER_USER_BACKEND),
        "a `required` per-user backend stopped being refused on the routes that \
         carry no identity. Credential-awareness belongs only where the fetch \
         after the guard runs on the caller's OWN pool slot; the logging, \
         prompts and resources paths forward on the SHARED credential"
    );
    assert!(
        !refused(SHARED_BACKEND),
        "a genuinely shared backend became refused — the guard is now failing \
         closed on everything, which would make the assertions above pass for \
         the wrong reason"
    );
}

/// T5-R — the MCP result cache KEY separates callers, replacing design §5's T5.
///
/// T5 as drafted asserted that no `tools/call` result cache exists and "passes
/// today by absence". §4.3 and §9.1 of the same design establish the opposite
/// and cite it: `invoke.rs:1842-1855` (`cache.get`), `:2440` (`cache.set`),
/// `:1794` (idempotency replay). The row was never updated after that
/// correction landed, so as written it fails for the wrong reason — or gets
/// "fixed" by deleting a cache that must stay.
///
/// Inverted to assert the property C3 actually rests on. It exercises
/// `response_cache_key_for` (`support.rs:168`) itself rather than only the
/// principal helper feeding it: a future cache that derives a correct principal
/// and then DROPS it while assembling the key is exactly the regression this row
/// exists to catch, and a principal-only assertion would pass straight through it.
///
/// Two-directional. The inequality alone is satisfied by a key function that
/// mixes in something random per call — which would also mean the cache never
/// hits — so the same-caller-same-key half runs beside it.
#[test]
fn result_cache_keys_separate_callers_and_keep_one_caller_stable() {
    use super::support::{
        Authentication, CachePrincipal, caller_cache_principal, response_cache_key_for,
    };

    let retry = crate::protocol::mrtr::RetryFields::default();
    let context = crate::cache::KeyContext {
        routing_profile: "open",
        protocol_revision: None,
        policy_epoch: 1,
    };
    let key_for = |principal: &CachePrincipal| {
        response_cache_key_for(
            "hub",
            "ledger_read",
            &json!({ "account": "shared-argument" }),
            "",
            principal,
            &retry,
            context,
        )
        .expect("a resolved principal has a key")
    };

    let anon = Authentication::Anonymous;
    let alpha = caller_cache_principal(Some("alpha"), None, None, None, anon);
    let beta = caller_cache_principal(Some("beta"), None, None, None, anon);
    assert_ne!(
        alpha, beta,
        "two identities collapsed to one cache principal before the key was even built"
    );

    // Same server, same tool, same arguments, same authorization context — the
    // ONLY difference is who is asking.
    assert_ne!(
        key_for(&alpha),
        key_for(&beta),
        "two callers share one result-cache key, so one caller's cached tool \
         result is served to the other (C3)"
    );
    assert_eq!(
        key_for(&alpha),
        key_for(&alpha),
        "one caller's key is not stable across requests: the cache could never \
         hit, and the inequality above would hold for every pair regardless of \
         whether the principal reaches the key at all"
    );
    assert_ne!(
        key_for(&alpha),
        key_for(&CachePrincipal::Anonymous),
        "an identified caller and an anonymous one share a key"
    );

    // Length-prefixed, so two identities cannot collide by concatenation.
    //
    // The single-field `idp:` arm cannot express that collision — two bindings
    // that differ at all produce different strings whatever the format is, so
    // asserting on it would be vacuous. The two-field `grant:` arm is where a
    // naive `format!("grant:{authority}:{subject}")` WOULD collide, and it is
    // the arm the length prefixes exist for. Caught by review of this test:
    // the first draft asserted the vacuous version.
    let grant = |authority: &str, subject: &str| {
        caller_cache_principal(
            None,
            None,
            Some(&crate::identity_grants::GrantSubject {
                authority: authority.to_string(),
                subject: subject.to_string(),
                label: None,
            }),
            None,
            Authentication::Anonymous,
        )
    };
    assert_ne!(
        grant("ab", "c"),
        grant("a", "bc"),
        "two distinct identities collide into one principal under naive \
         concatenation, so one caller's cached results are served to the other"
    );
}

/// T9b — the behavioural half of T9: no request actually REACHES an
/// identity-bound backend on a shared-credential route.
///
/// T9 asserts the guard helper still refuses. That is necessary and not
/// sufficient: it stays green if someone removes the
/// `meta_route_isolation_refused` call from `handle_logging_set_level`
/// altogether rather than loosening the helper. Raised by review of this suite,
/// and correct — a control that tests the helper cannot catch a regression in
/// the caller.
///
/// So this drives the real handler and watches the wire. `logging/setLevel` is
/// the sharpest of the three shared-credential routes (`protocol.rs:306`)
/// because it forwards with `backend.request(...)` — the gateway's own
/// credential — on behalf of whoever asked.
///
/// Two-directional: the genuinely shared backend MUST receive the forward, so a
/// change that simply stops forwarding to everyone fails here instead of
/// passing as though it had achieved isolation.
#[tokio::test]
async fn shared_credential_routes_never_reach_an_identity_bound_backend() {
    let registry = Arc::new(BackendRegistry::new());
    let mut wires = Vec::new();

    for (name, tool, config) in [
        (SHARED_BACKEND, SHARED_TOOL, BackendConfig::default()),
        (
            PER_USER_BACKEND,
            PER_USER_TOOL,
            BackendConfig {
                identity_propagation: Some(IdentityPropagationConfig {
                    strategy: PropagationStrategyKind::SignedAssertion,
                    audience: "ledger".to_string(),
                    required: true,
                    session_mode: SessionMode::PerUser,
                    token_exchange_endpoint: None,
                    token_exchange_scope: None,
                }),
                ..Default::default()
            },
        ),
    ] {
        let backend = Arc::new(Backend::new(
            name,
            config,
            &FailsafeConfig::default(),
            Duration::from_secs(300),
        ));
        let wire = Arc::new(RecordingTools::new(&[tool]));
        backend.set_transport_for_test(Arc::clone(&wire) as Arc<dyn crate::transport::Transport>);
        backend.get_tools_shared().await.expect("prime the cache");
        assert!(registry.register(backend), "fixture registration");
        wires.push((name, wire));
    }

    let meta = MetaMcp::new(registry);
    meta.set_multi_user(true);
    meta.handle_logging_set_level(RequestId::Number(7), Some(&json!({ "level": "debug" })))
        .await;

    for (name, wire) in wires {
        let forwarded = wire.forwarded("logging/setLevel");
        if name == SHARED_BACKEND {
            assert!(
                forwarded,
                "a genuinely shared backend never received the forward, so the \
                 assertion below would hold for a gateway that forwards to \
                 nobody rather than for one that isolates"
            );
        } else {
            assert!(
                !forwarded,
                "`logging/setLevel` reached an identity-bound backend over the \
                 gateway's OWN credential on a multi-user gateway — an \
                 arbitrary caller is now operating another account's backend \
                 session (ADR-008 INV-2, `protocol.rs:306`)"
            );
        }
    }
}

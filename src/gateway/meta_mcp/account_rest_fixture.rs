// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Fixture for the REST managed-account consumer tests.
//!
//! REUSES THE PROVEN CUSTODY, ADDS ONLY A NETWORK. Every account primitive here
//! comes from `account_resolver_fixture`: the REAL sealed store in a `TempDir`,
//! the REAL `CustodyHandle` with its two exclusive locks, the REAL five-field
//! account key, and the one faked seam (`ScriptedProvider`) that stands in for a
//! network issuer. This module adds exactly two things the REST path needs and
//! the MCP path did not: an isolated loopback HTTP capture endpoint, and the
//! capability backend that dispatches to it.
//!
//! THE PRODUCTION INSTALLER, NOT AN INVENTED ONE. Strategies are installed by
//! `gateway::server::account_bindings::install_account_strategies` — the same
//! call `Gateway::start` makes — against a real `Config` whose `accounts` block
//! declares the descriptors. Nothing here constructs a `VaultStrategy`, and
//! nothing here compiles a propagation config of its own.
//!
//! THE ONE EXPLICIT SEAM. `CapabilityExecutionContext::verified_identity` is
//! handed the fixture principal directly in the executor-level cases. That is
//! the verification-context seam the increment adds; the MetaMcp control in the
//! sibling test file is what proves the gateway actually fills it from
//! `MetaMcpCallerContext` rather than from a `GrantSubject`, an API key or a
//! display name.
//!
//! WHAT IS REAL ON THE WIRE. The capture endpoint is a real `axum` server bound
//! to an ephemeral `127.0.0.1` port, reached by the production
//! `CapabilityExecutor` HTTP client. An IP literal needs no DNS, so the client's
//! `PinningResolver` is not in the way; the SSRF guard is opened for it by the
//! EXISTING `allow_loopback_egress` flag, which is exactly the isolated-runtime
//! escape hatch it was added for. A refusal is proved by ZERO recorded requests
//! — an observed absence, not an unread buffer.
//!
//! NO SLEEPS, NO ENV READS, NO REAL PROVIDER. Every token, key and host here is
//! synthetic and every `.invalid` host is unroutable by construction.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

use parking_lot::Mutex;
use serde_json::{Value, json};

use crate::backend::BackendRegistry;
use crate::capability::{
    CapabilityBackend, CapabilityDefinition, CapabilityExecutionContext, CapabilityExecutor,
    parse_capability,
};
use crate::config::Config;
use crate::gateway::meta_mcp::{MetaMcp, MetaMcpCallerContext};
use crate::gateway::oauth::GatewayKeyPair;
use crate::gateway::server::account_bindings::{
    declare_account_descriptors, install_account_strategies,
};
use crate::identity_propagation::AccountStrategyRegistry;
use crate::key_server::oidc::VerifiedIdentity;
use crate::personal_accounts::config::{AccountsConfig, AccountsLimits, DescriptorMode};

use super::account_resolver_fixture::{descriptor, identity};

/// The capability backend name. The MetaMcp control addresses it as the server
/// half of a `server:tool` reference, exactly as a client would.
pub(super) const CAPABILITIES: &str = "capabilities";
/// The one capability every case invokes. ONE tool and ONE argument set for
/// every principal: identical requests are what make a crossed credential
/// observable rather than inferred.
pub(super) const TOOL: &str = "drive_read";

// ── Capture endpoint ─────────────────────────────────────────────────────────

/// Every request the capture endpoint saw, in order.
///
/// Records the `Authorization` header VALUE because that is the assertion: a
/// crossed credential is only visible if the value is compared. Nothing else is
/// kept, and the record never leaves the test process.
#[derive(Default)]
pub(super) struct Captured {
    seen: Mutex<Vec<Option<String>>>,
}

impl Captured {
    pub(super) fn count(&self) -> usize {
        self.seen.lock().len()
    }

    pub(super) fn authorizations(&self) -> Vec<Option<String>> {
        self.seen.lock().clone()
    }

    /// The single request a positive case expects; panics loudly on any other
    /// count so "reached the endpoint" is never assumed.
    pub(super) fn only(&self) -> String {
        let seen = self.authorizations();
        assert_eq!(seen.len(), 1, "expected exactly one captured request");
        seen.into_iter()
            .next()
            .expect("checked above")
            .expect("the captured request must carry an Authorization header")
    }
}

async fn capture_handler(
    axum::extract::State(state): axum::extract::State<Arc<Captured>>,
    headers: axum::http::HeaderMap,
) -> axum::Json<Value> {
    let authorization = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .map(str::to_string);
    let mut seen = state.seen.lock();
    seen.push(authorization.clone());
    // The body ECHOES the credential and a per-request sequence number, so a
    // cache assertion can be made on the RESPONSE and not only on a counter: two
    // dispatches can never produce the same body, and a body carrying another
    // principal's credential is a crossed entry stated outright rather than
    // inferred from a count.
    axum::Json(json!({
        "ok": true,
        "seq": seen.len(),
        "authorization": authorization,
    }))
}

/// Bind a real HTTP endpoint on an ephemeral loopback port and start serving.
///
/// Returns the port so the capability's `base_url` names the endpoint that was
/// actually bound — no fixed port, so parallel tests cannot collide.
pub(super) async fn capture_endpoint() -> (u16, Arc<Captured>) {
    let captured = Arc::new(Captured::default());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("the capture endpoint must bind a loopback port");
    let port = listener
        .local_addr()
        .expect("the bound endpoint must report its address")
        .port();
    let router = axum::Router::new()
        .route("/read", axum::routing::get(capture_handler))
        .with_state(Arc::clone(&captured));
    tokio::spawn(async move {
        let _ = axum::serve(listener, router).await;
    });
    (port, captured)
}

// ── Configuration and installation ───────────────────────────────────────────

/// A durable audit sink. A managed descriptor compiles to `required: true`, and
/// the mint path refuses to hand out a credential with no durable audit record,
/// so every managed fixture needs one. Leaked for the process, as the existing
/// propagation fixtures do.
fn leaked_transparency_logger() -> Arc<crate::security::TransparencyLogger> {
    use crate::security::TransparencyLogger;
    use crate::security::transparency_log::TransparencyLogConfig;

    let file = tempfile::NamedTempFile::new().expect("tempfile");
    let path = file.path().to_string_lossy().to_string();
    std::mem::forget(file);
    Arc::new(
        TransparencyLogger::open(Arc::new(TransparencyLogConfig {
            enabled: true,
            path,
            key_id: "test".to_string(),
            shared_secret: String::new(),
        }))
        .expect("logger opens"),
    )
}

/// The `accounts` block. Store settings are SYNTHETIC and nothing here opens
/// them: declaration and installation read the `descriptors` map, and the
/// custody handed in is the separately started real fixture custody.
///
/// `overrides` lets a case replace a descriptor wholesale — the external and
/// shared cases do exactly that, so mixed modes come from one code path.
pub(super) fn rest_config(
    descriptors: &[(&str, crate::personal_accounts::config::AccountDescriptor)],
) -> Config {
    Config {
        backends: HashMap::new(),
        accounts: Some(AccountsConfig {
            schema_version: "accounts.v1".to_string(),
            enabled: true,
            deployment: "single_process".to_string(),
            instance_id: "gateway-rest-consumer-tests".to_string(),
            store_dir: PathBuf::from("/synthetic/fixture/accounts/records"),
            authority_dir: PathBuf::from("/synthetic/fixture/accounts/authority"),
            current_key_id: "current".to_string(),
            keys: [(
                "current".to_string(),
                "env:FIXTURE_ACCOUNT_STORE_KEY".to_string(),
            )]
            .into_iter()
            .collect(),
            descriptors: Some(
                descriptors
                    .iter()
                    .map(|(id, descriptor)| ((*id).to_string(), descriptor.clone()))
                    .collect(),
            ),
            limits: AccountsLimits::default(),
        }),
        ..Config::default()
    }
}

/// A `personal_managed` descriptor under `id`, straight from the proven fixture.
pub(super) fn managed(id: &str) -> crate::personal_accounts::config::AccountDescriptor {
    descriptor(id)
}

/// An `external` descriptor reusing the EXISTING `IdentityPropagationConfig`
/// shape with `required: true`, as the contract restricts external mode to.
pub(super) fn external(id: &str) -> crate::personal_accounts::config::AccountDescriptor {
    let mut descriptor = descriptor(id);
    descriptor.mode = DescriptorMode::External;
    descriptor.external_strategy = Some(crate::identity_propagation::IdentityPropagationConfig {
        strategy: crate::identity_propagation::PropagationStrategyKind::SignedAssertion,
        audience: "https://partner.invalid/".to_string(),
        required: true,
        session_mode: crate::identity_propagation::SessionMode::Stateless,
        token_exchange_endpoint: None,
        token_exchange_scope: None,
    });
    descriptor
}

/// A `shared` descriptor: the deployment already serves this account
/// statically, so nothing is installed and the legacy path must be preserved
/// byte for byte.
pub(super) fn shared(id: &str) -> crate::personal_accounts::config::AccountDescriptor {
    let mut descriptor = descriptor(id);
    descriptor.mode = DescriptorMode::Shared;
    descriptor
}

/// A gateway whose account strategies were installed by the PRODUCTION
/// installer, with the transparency log the mint path requires.
///
/// Returns the `MetaMcp` (the MetaMcp control needs it) and the registry both
/// consumers share. The registry is the SAME object the installer wrote to and
/// the same one the executor reads, so an MCP backend and a REST capability
/// naming one descriptor hold one strategy instance, not two.
pub(super) fn installed_gateway(
    descriptors: &[(&str, crate::personal_accounts::config::AccountDescriptor)],
    custody: &Arc<dyn crate::personal_accounts::AccountCustody>,
) -> (Arc<MetaMcp>, Arc<AccountStrategyRegistry>) {
    let mut meta = MetaMcp::new(Arc::new(BackendRegistry::new()));
    meta.enable_transparency_log(leaked_transparency_logger());
    let gateway_key = Arc::new(GatewayKeyPair::generate().expect("keygen"));
    let config = rest_config(descriptors);
    install_account_strategies(&config, Some(custody), &gateway_key, &meta)
        .expect("the shared installer must accept the fixture configuration");
    let registry = meta.account_strategies();
    (Arc::new(meta), registry)
}

/// A registry that has DECLARED the descriptors but installed no strategy for
/// them — the state a reload leaves behind when a binding is dropped between
/// compilation and installation. Registration must still admit a capability
/// naming a declared descriptor; DISPATCH is what must refuse.
pub(super) fn declared_only(
    descriptors: &[(&str, crate::personal_accounts::config::AccountDescriptor)],
) -> Arc<AccountStrategyRegistry> {
    let registry = Arc::new(AccountStrategyRegistry::default());
    declare_account_descriptors(&rest_config(descriptors), &registry);
    registry
}

// ── The capability under test ────────────────────────────────────────────────

/// One REST capability. `account` names an `accounts.descriptors` map key and
/// `key` is `oauth:<provider>`; both are parameters so a mismatch case states
/// its mismatch instead of hiding it in a helper.
pub(super) fn capability(base_url: &str, key: &str, account: Option<&str>) -> CapabilityDefinition {
    let account_line = account.map_or_else(String::new, |id| format!("  account: {id}\n"));
    parse_capability(&format!(
        "name: {TOOL}\n\
         description: Read one folder through a personal account\n\
         auth:\n\
         \x20 required: true\n\
         \x20 type: bearer\n\
         \x20 key: {key}\n\
         {account_line}\
         providers:\n\
         \x20 primary:\n\
         \x20   service: rest\n\
         \x20   config:\n\
         \x20     base_url: {base_url}\n\
         \x20     path: /read\n\
         \x20     method: GET\n"
    ))
    .expect("fixture capability must parse")
}

/// The capability backend a dispatch actually goes through, with the shared
/// registry wired into its executor exactly as gateway startup wires it.
///
/// Registration goes through the production `register_capability`, so an
/// unresolved account reference or a provider mismatch is refused HERE — at the
/// real registration boundary — and the returned `Result` is the oracle.
pub(super) fn backend_with(
    registry: &Arc<AccountStrategyRegistry>,
    capability: CapabilityDefinition,
) -> crate::Result<Arc<CapabilityBackend>> {
    let executor =
        Arc::new(CapabilityExecutor::new().with_account_strategies(Arc::clone(registry)));
    let backend = Arc::new(CapabilityBackend::new(CAPABILITIES, executor));
    backend.register_capability(capability)?;
    Ok(backend)
}

/// The SAME capability, made cacheable with an EXPLICIT positive TTL.
///
/// Without a `cache` block `is_cacheable()` is false and every "second call did
/// not re-dispatch" assertion would be vacuous. Sixty seconds is far longer than
/// any case here takes, so no test depends on wall-clock timing and none sleeps.
pub(super) fn cacheable_capability(
    base_url: &str,
    key: &str,
    account: Option<&str>,
) -> CapabilityDefinition {
    let account_line = account.map_or_else(String::new, |id| format!("  account: {id}\n"));
    parse_capability(&format!(
        "name: {TOOL}\n\
         description: Read one folder through a personal account\n\
         cache:\n\
         \x20 ttl: 60\n\
         \x20 strategy: memory\n\
         auth:\n\
         \x20 required: true\n\
         \x20 type: bearer\n\
         \x20 key: {key}\n\
         {account_line}\
         providers:\n\
         \x20 primary:\n\
         \x20   service: rest\n\
         \x20   config:\n\
         \x20     base_url: {base_url}\n\
         \x20     path: /read\n\
         \x20     method: GET\n"
    ))
    .expect("fixture cacheable capability must parse")
}

/// The base URL a CACHING case must use.
///
/// `allow_loopback_egress` is what lets the other cases reach an IP literal —
/// and it also disables the response cache by design, so a warm-cache test
/// cannot use it. `localhost` is a NAME, so it clears the SSRF guard on its own
/// and the enforcing (uncached-flag-free) context applies. Only DNS pinning is
/// then in the way, which is why these cases swap the client below.
pub(super) fn cacheable_base_url(port: u16) -> String {
    format!("http://localhost:{port}")
}

/// Finite-timeout client for the swapped-client caching fixtures, mirroring
/// `capability::executor_tests::finite_http_client`: a bare client has no
/// request timeout and a hung listener would stall the suite.
fn finite_http_client() -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()
        .expect("the fixture HTTP client must build")
}

/// An executor whose response cache is LIVE for these dispatches.
///
/// `legacy_token` seeds the gateway-held `oauth:google` login — the TRAP. It is
/// the credential a fallback would reach for, so a refusal that leaves it
/// unused and unrecorded at the endpoint is what proves nothing fell back.
pub(super) fn caching_executor(
    registry: &Arc<AccountStrategyRegistry>,
    legacy_token: Option<(&str, &tempfile::TempDir)>,
) -> CapabilityExecutor {
    let executor = match legacy_token {
        Some((token, dir)) => {
            let storage = Arc::new(
                crate::oauth::TokenStorage::new(dir.path().to_path_buf())
                    .expect("token storage opens"),
            );
            let executor = CapabilityExecutor::with_token_storage(storage);
            executor.set_oauth_token(
                "google",
                crate::oauth::TokenInfo {
                    expires_at: Some(u64::MAX),
                    ..crate::oauth::TokenInfo::from_response(
                        token.to_string(),
                        None,
                        None,
                        None,
                        None,
                    )
                },
            );
            executor
        }
        None => CapabilityExecutor::new(),
    };
    executor
        .with_account_strategies(Arc::clone(registry))
        .with_test_http_client(finite_http_client())
}

/// The context a CACHING dispatch carries: verified identity, no loopback
/// relaxation (so the cache is live), no invoke snapshot (a standalone executor
/// keys without one).
pub(super) fn caching_context(subject: &str) -> CapabilityExecutionContext {
    CapabilityExecutionContext::default().with_verified_identity(Arc::new(identity(subject)))
}

/// Resolve the account NOW and carry the result, exactly as the invoke path
/// does before the executor is entered. Returns the context the executor will
/// then RECHECK — which is the only way to place a revocation strictly between
/// the resolve and the cache lookup.
pub(super) async fn prepared_caching_context(
    registry: &Arc<AccountStrategyRegistry>,
    subject: &str,
    account: &str,
    key: &str,
) -> CapabilityExecutionContext {
    let verified = Arc::new(identity(subject));
    match registry
        .resolve(account, key, Some(verified.as_ref()))
        .await
        .expect("the account must resolve while the grant is still current")
    {
        crate::identity_propagation::AccountCredential::Prepared(prepared) => {
            CapabilityExecutionContext::default()
                .with_verified_identity(verified)
                .with_account_credential(prepared)
        }
        crate::identity_propagation::AccountCredential::Legacy => {
            panic!("the fixture descriptor is managed, not shared")
        }
    }
}

// ── Already-expired external strategy ────────────────────────────────────────

/// An external strategy whose issuer publishes an expiry ALREADY IN THE PAST.
///
/// This is the shape of a real external credential that came back stale: the
/// mint succeeds, the headers are usable, and only `expires_at` says it must not
/// be used. Nothing else about it is unusual, which is precisely why it has to
/// be refused on the expiry alone.
struct AlreadyExpiredStrategy {
    audience: String,
}

#[async_trait::async_trait]
impl crate::identity_propagation::IdentityPropagation for AlreadyExpiredStrategy {
    async fn propagate(
        &self,
        identity: &VerifiedIdentity,
        _backend: &crate::identity_propagation::BackendDescriptor,
    ) -> std::result::Result<
        crate::identity_propagation::PropagatedCredential,
        crate::identity_propagation::PropagationError,
    > {
        let subject_key = identity.stable_actor_id();
        Ok(crate::identity_propagation::PropagatedCredential {
            headers: vec![(
                "Authorization".to_string(),
                format!("Bearer {EXPIRED_EXTERNAL_TOKEN}"),
            )],
            // One hour in the past. Not zero, not "unset": a concrete, published
            // expiry that has demonstrably passed.
            expires_at: chrono::Utc::now().timestamp() - 3600,
            cache_binding: format!("expired-external|{subject_key}"),
            subject_key,
            audience: self.audience.clone(),
            scopes: Vec::new(),
        })
    }
}

/// The token the expired external strategy would have put on the wire. A
/// refusal must never carry it and the endpoint must never see it.
pub(super) const EXPIRED_EXTERNAL_TOKEN: &str = "synthetic-expired-external-token-4b7e";

/// Declare and install an `external` descriptor backed by the already-expired
/// strategy above.
///
/// Installed through the SAME `AccountStrategyRegistry::install` the production
/// installer calls, with `managed: None` — which is what an external descriptor
/// compiles to and what makes this the real external code path rather than a
/// managed one with a flag flipped. `required` is false only so the case needs
/// no transparency log; the expiry is the subject.
pub(super) fn installed_expired_external(id: &str) -> Arc<AccountStrategyRegistry> {
    let registry = Arc::new(AccountStrategyRegistry::default());
    let audience = "https://partner.invalid/".to_string();
    let strategy: Arc<dyn crate::identity_propagation::IdentityPropagation> =
        Arc::new(AlreadyExpiredStrategy {
            audience: audience.clone(),
        });
    registry.install(
        crate::identity_propagation::InstalledAccount {
            descriptor_id: id.to_string(),
            provider: "google".to_string(),
            audience,
            required: false,
            token_exchange_endpoint: None,
            token_exchange_scope: None,
            strategy,
            managed: None,
        },
        DescriptorMode::External,
    );
    registry
}

/// The request-scoped context a dispatch carries.
///
/// `allow_loopback_egress` is the EXISTING isolated-runtime flag and is what
/// lets the production client reach the capture endpoint's IP literal; it is
/// never set by general capability execution. `verified_identity` is the seam
/// under test.
pub(super) fn context(subject: Option<&str>) -> CapabilityExecutionContext {
    let context = CapabilityExecutionContext::default().with_isolated_loopback_egress();
    match subject {
        Some(subject) => context.with_verified_identity(Arc::new(identity(subject))),
        None => context,
    }
}

/// Invoke the capability through the backend, with no arguments.
pub(super) async fn call(
    backend: &CapabilityBackend,
    subject: Option<&str>,
) -> crate::Result<crate::protocol::ToolsCallResult> {
    backend
        .call_tool_with_context(TOOL, json!({}), context(subject))
        .await
}

// ── MetaMcp threading control ────────────────────────────────────────────────

static ALLOW_ALL: crate::gateway::authz::AllowAll = crate::gateway::authz::AllowAll;

fn caller(verified_identity: Option<&VerifiedIdentity>) -> MetaMcpCallerContext<'_> {
    MetaMcpCallerContext {
        task: None,
        signing: None,
        execution: None,
        credential_principal: None,
        is_modern: false,
        // The legacy fixture negotiates the current published revision so the
        // revision-keyed caches behave as they do for a real session.
        protocol_revision: Some(crate::protocol::PROTOCOL_VERSION),
        authorizer: &ALLOW_ALL,
        verified_identity,
        api_key_name: None,
        agent_id: None,
        grant_subject: None,
        is_admin: false,
        input_capabilities: crate::protocol::meta::Declared::NONE,
        retry: &crate::protocol::mrtr::NO_RETRY,
        confirmation: crate::gateway::destructive_confirmation::ConfirmationChannel::Unavailable,
    }
}

/// THE MetaMcp action: the real Code Mode dispatch entry, which routes through
/// `invoke_tool` and reaches the capability backend exactly as production
/// traffic does. The identity handed in is a fixture principal; what the control
/// proves is that the gateway carries THAT value to the executor rather than
/// inventing one from a grant subject or an API key name.
pub(super) async fn meta_execute(meta: &MetaMcp, subject: Option<&str>) -> crate::Result<Value> {
    let verified = subject.map(identity);
    let context = caller(verified.as_ref());
    let args = json!({
        "tool": format!("{CAPABILITIES}:{TOOL}"),
        "arguments": {},
    });
    meta.code_mode_execute(&args, Some("rest-fixture-session"), &context)
        .await
}

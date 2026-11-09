// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Shared fixture (test plan `2026-09-27-direct-route-guards-test-plan.md`
//! "Shared fixture") for the direct-route guard cells (MIK-7597).
#![allow(dead_code)]

use std::sync::Arc;
use std::sync::atomic::AtomicUsize;
use std::time::Duration;

use serde_json::Value;

use super::create_router;
use super::tests::{test_router_app_state_with_auth, test_router_app_state_with_auth_and_config};
use crate::backend::Backend;
use crate::config::{ApiKeyConfig, AuthConfig, BackendConfig};
use crate::gateway::meta_mcp::MetaMcp;
use crate::transport::Transport;

/// What a cell wants the shared `alpha` / `alpha-pt` backend to answer with,
/// covering the adapter table's classification rows (design doc §2.1a).
#[derive(Clone, Copy)]
pub(crate) enum Answer {
    /// Ordinary success, `isError: false`.
    Ok,
    /// Like `Ok`, its `tools/list` also naming a second tool, `note`, and an
    /// open-schema backend tool named `gateway_invoke` (MIK-8154 S9f).
    WithNote,
    /// Like `Ok`, its `tools/list` giving `read` a structurally invalid input
    /// schema, so a surfaced `read` is withheld for it (MIK-8353 3d-2, K5).
    InvalidRead,
    /// Success envelope, `isError: true` (a tool refusing a request).
    IsError,
    /// JSON-RPC `error`, an arbitrary non-rate-limit code.
    RpcError(i32),
    /// A rate-limit refusal, carried as `isError: true` (test plan T5/T3b
    /// need the JSON-RPC-error flavour too; build one with `RpcError` and a
    /// "rate limit" message, since `is_rate_limited` matches on text, not
    /// shape).
    RateLimited,
    /// A transport-level failure: the backend was never reachable.
    Transport,
    /// Success, `isError: false`, whose text is the given payload (response
    /// inspection and context-integrity cells).
    Text(&'static str),
    /// Success whose whole result the function builds (MIK-8689: a result
    /// carrying backend members the gateway overwrites).
    Built(fn() -> Value),
    /// The first `tools/call` asks the client a question (`input_required`);
    /// every later call succeeds. Drives a bridged input round (T3c).
    AskOnce,
    /// Like `AskOnce`, the question carrying no `requestState` (MIK-8078).
    AskNoState,
    /// Asks on every call that carries no `requestState`, and answers every
    /// retry that does: each fresh call takes one continuation slot, and a
    /// redeem gives it back without taking another (MIK-8293).
    AskAlways,
    /// A completed answer that still carries a `requestState` (MIK-8078).
    DoneWithState,
    /// Like `AskOnce`, a question `InputRequired::from_result` declines (an
    /// `inputRequests` that is not an object) beside a string state (MIK-8078).
    AskMalformed,
    /// Like `AskOnce`, its state longer than a continuation can seal.
    AskBig,
    /// Like `AskOnce`, the question and a `content` text carrying this text.
    AskWith(&'static str),
    /// Like `AskOnce`, the question carrying a `_meta` that is not an object.
    AskBadMeta,
    /// A response carrying both the question and a JSON-RPC `error`.
    AskAndError,
    /// The first `tools/call` succeeds, the second asks, every later one
    /// succeeds: a chain whose second step asks (MIK-8137 P1 G4).
    AskSecond,
    /// The backend cannot be reached: nothing was sent (`TransportConnect`).
    Unreachable,
    /// Every `tools/call` fails with the error the function builds, as the
    /// dispatch would raise it (MIK-8379 D4: one row per failure class).
    FailsWith(fn() -> crate::Error),
    /// Like `AskOnce`, the question then edited by the function (MIK-8089).
    AskEdited(fn(&mut Value)),
    /// Like `Ok`, from a 2026-07-28 backend: its `tools/list` carries
    /// `resultType`, `ttlMs` (5000) and `cacheScope` itself, and every other
    /// answer a `ttlMs` of 3000 (MIK-8022).
    ModernList,
    /// A two-page `tools/list` whose pages carry these `ttlMs` hints.
    Paged(Option<u64>, Option<u64>),
    /// A two-page `tools/list` whose first page carries this `ttlMs` hint and
    /// whose last page is unreadable (its `tools` is not an array).
    Unreadable(Option<u64>),
    /// A two-page `tools/list` whose first page carries this `ttlMs` hint and
    /// whose last page a non-numeric one (MIK-8049).
    NonNumeric(u64),
    /// Like `Ok`, claiming `cacheScope: "public"` for the call's answer.
    PublicScope,
    /// JSON-RPC `error` whose message is the given text (MIK-8139).
    RpcErrorText(&'static str),
    /// JSON-RPC `error` with a plain message and the given text in `data`.
    RpcErrorData(&'static str),
    /// A failed dispatch: the backend's refusal as `Error::JsonRpc` with the
    /// given message, as a non-2xx JSON-RPC answer arrives (MIK-8139).
    FailedWith(&'static str),
    /// A failed dispatch dressed as an `accounts.v1` account refusal, with
    /// the given message (MIK-8139: a backend can forge the marker).
    ForgedAccount(&'static str),
    /// State-only interim rounds (`requestState`, no questions; MIK-8177):
    /// calls before the given index answer a harmless round, the call at it a
    /// round whose `content` carries the given text, every later call
    /// succeeds. Index 0 refuses the initial round, 1 a resumed one.
    StateOnlyRounds(usize, &'static str),
    /// The first `tools/call` asks (as [`Answer::AskOnce`]); every later one
    /// completes with its own arguments echoed as text (MIK-8176: a playbook
    /// step can carry an earlier step's envelope into a completed answer).
    AskThenEcho,
    /// The first `tools/call` asks; later ones are a tiny store: `cmd`
    /// `"store <text>"` keeps `<text>`, and `"get"` returns what was kept
    /// (MIK-8323: a backend handed an envelope can return it to a later,
    /// fresh call).
    AskThenStore,
    /// Success whose text is the given payload when the call's `cmd` is
    /// `"leak"`, and `ok` otherwise: two calls in flight get different answers.
    LeakOnCmd(&'static str),
}

/// A router wired for the direct-route guard cells: non-admin keys
/// (`k-std`, `k-budget`, `k-rl` with a rate limit of 1, `k-deny` denied `read`;
/// all `backends: ["*"]`), and `alpha` / `alpha-pt`
/// (`passthrough: true`) sharing one call counter and one `Answer`.
pub(crate) struct Fx {
    pub state: Arc<super::AppState>,
    pub router: axum::Router,
    pub calls: Arc<AtomicUsize>,
    /// The params every `tools/call` reached the backend with.
    pub seen: Arc<std::sync::Mutex<Vec<Value>>>,
    _store: crate::gateway::router::tests::FixtureDir,
    /// The meta layer's audit log, when a builder gives it one; last, so it
    /// drops after the router and state that hold the logger.
    _audit: Option<crate::security::transparency_log::temp::TempLog>,
    /// The route's audit log, on a propagating fixture.
    _route_audit: Option<crate::security::transparency_log::temp::TempLog>,
}

fn key(name: &str) -> ApiKeyConfig {
    // `hardened` refuses a request with no per-caller identity, so its keys
    // are personal ones.
    let kind = if HARDENED.with(std::cell::Cell::get) {
        crate::config::ApiKeyKind::Personal
    } else {
        crate::config::ApiKeyKind::Shared
    };
    ApiKeyConfig {
        key: None,
        key_sha256: Some(crate::config::api_key_digest_spec(name.as_bytes())),
        expires_at: None,
        name: name.to_string(),
        rate_limit: 0,
        backends: vec!["*".to_string()],
        allowed_tools: None,
        denied_tools: None,
        admin: false,
        kind,
        ..Default::default()
    }
}

/// Replace backend `name` with a fresh instance under the same name, as a
/// live reload does (MIK-8168): same config, its own call counter, answering
/// `Ok`. Returns the new backend's counter.
pub(crate) fn replace_backend(fx: &Fx, name: &str) -> Arc<AtomicUsize> {
    let config = BackendConfig {
        passthrough: name.ends_with("-pt"),
        ..BackendConfig::default()
    };
    replace_backend_configured(fx, name, config)
}

/// [`replace_backend`] with `config` as the replacement's declared config
/// (its transport URL, say), still answered by the counting transport.
pub(crate) fn replace_backend_configured(
    fx: &Fx,
    name: &str,
    config: BackendConfig,
) -> Arc<AtomicUsize> {
    let calls = Arc::new(AtomicUsize::new(0));
    let backend = Arc::new(Backend::new(
        name,
        config,
        &fixture_failsafe(),
        Duration::from_secs(60),
    ));
    backend.set_transport_for_test(Arc::new(CountingBackend {
        calls: Arc::clone(&calls),
        seen: Arc::default(),
        answer: Answer::Ok,
        kept: Arc::default(),
    }));
    assert!(
        fx.state.backends.register(backend),
        "replacement registration"
    );
    calls
}

/// Build the fixture, arming the replaced `MetaMcp` with `arm` before it is
/// installed (idempotency is enabled first, so `arm` can layer more on top).
pub(crate) async fn fixture(answer: Answer, arm: impl FnOnce(&mut MetaMcp)) -> Fx {
    fixture_built(answer, |mut meta| {
        arm(&mut meta);
        meta
    })
    .await
}

/// [`fixture`], for arming that needs the owned builder methods
/// (`with_profile_registry`, `with_cost_governance`).
pub(crate) async fn fixture_built(answer: Answer, build: impl FnOnce(MetaMcp) -> MetaMcp) -> Fx {
    fixture_inner(answer, false, build).await
}

/// [`fixture_built`] with `transport` answering for both backends in place of
/// the scripted one (the route x check matrix's annotated tool, MIK-8137 b3).
pub(crate) async fn fixture_built_on(
    transport: Arc<dyn Transport>,
    build: impl FnOnce(MetaMcp) -> MetaMcp,
) -> Fx {
    with_transport(transport, Box::pin(fixture_inner(Answer::Ok, false, build))).await
}

thread_local! {
    /// The mTLS policy a fixture's router state enforces, when set.
    static STATE_MTLS: std::cell::RefCell<Option<Arc<crate::mtls::MtlsPolicy>>> =
        const { std::cell::RefCell::new(None) };
}

/// Builds `fixture` (any of this module's fixtures) with `policy` as the
/// router state's mTLS policy.
pub(crate) async fn with_mtls_policy(
    policy: Arc<crate::mtls::MtlsPolicy>,
    fixture: std::pin::Pin<Box<impl std::future::Future<Output = Fx>>>,
) -> Fx {
    STATE_MTLS.with(|p| *p.borrow_mut() = Some(policy));
    let fx = fixture.await;
    STATE_MTLS.with(|p| *p.borrow_mut() = None);
    fx
}

/// Builds `fixture` (any of this module's fixtures) over `transport`. Boxed,
/// so the caller's future holds a pointer, not the fixture's whole state.
pub(crate) async fn with_transport(
    transport: Arc<dyn Transport>,
    fixture: std::pin::Pin<Box<impl std::future::Future<Output = Fx>>>,
) -> Fx {
    TRANSPORT.with(|t| *t.borrow_mut() = Some(transport));
    let fx = fixture.await;
    TRANSPORT.with(|t| *t.borrow_mut() = None);
    fx
}

#[path = "direct_guards_fixture_answers.rs"]
mod answers;
#[cfg(feature = "firewall")]
#[path = "direct_guards_fixture_firewalled.rs"]
mod firewalled;
#[cfg(feature = "firewall")]
pub(crate) use firewalled::*;
#[path = "direct_guards_fixture_signed.rs"]
mod signed;
pub(crate) use signed::*;
#[path = "direct_guards_fixture_variants.rs"]
mod variants;
pub(crate) use variants::*;
#[path = "direct_guards_fixture_egress.rs"]
mod egress;
pub(crate) use answers::envelope_in;
#[path = "direct_guards_fixture_quota.rs"]
mod quota;
#[path = "direct_guards_fixture_requests.rs"]
mod requests;
use egress::{CountingBackend, backend_transport};
#[cfg(feature = "firewall")]
pub(crate) use egress::{
    fixture_audited_built_on, fixture_audited_on, fixture_firewalled_keyed, fixture_firewalled_on,
    fixture_hardened_signed_firewalled, fixture_inspecting_on, fixture_inspection_off_on,
    fixture_observing_on, meta_firewall,
};
#[cfg(feature = "firewall")]
pub(crate) use egress::{fixture_hardened_signed_built_on, fixture_logged};
#[cfg(feature = "firewall")]
pub(crate) use quota::Minting;
#[cfg(feature = "cost-governance")]
pub(crate) use quota::{MINT_MODES, fixture_optional_failing_mint};
use quota::{fixture_backend_config, fixture_failsafe, propagating_route_log};
#[cfg(feature = "firewall")]
pub(crate) use quota::{fixture_firewalled_budget_built, fixture_propagating_budgeted};
pub(crate) use quota::{
    fixture_propagating, fixture_propagating_logged, fixture_propagating_signed,
};
pub(crate) use quota::{fixture_signed_with_secrets, fixture_with_secrets};
// Its only caller, the stored-echo rows, needs the firewall feature.
#[cfg(feature = "firewall")]
pub(crate) use quota::fixture_with_secrets_over_http;
pub(crate) use requests::{
    initialize, post_direct, post_meta_invoke, post_meta_invoke_nonce, send, send_with_headers,
};

/// `meta` with message signing armed under [`SIGNING_KEY`].
fn signing(mut meta: MetaMcp, require_nonce: bool) -> MetaMcp {
    meta.enable_message_signing(
        crate::security::message_signing::MessageSigner::new(
            SIGNING_KEY.as_bytes().to_vec(),
            None,
            "hardened".into(),
        ),
        Duration::from_secs(300),
        require_nonce,
    );
    meta
}

pub(crate) const SIGNING_KEY: &str = "direct-guards-signing-key-0123456789abcdef";

/// A key whose name the response redactor reads as a GitHub token (a fake,
/// split so no scanner reads the source as one), so text naming it (a
/// per-key cost warning) is redacted on the way out.
#[cfg(feature = "firewall")]
pub(crate) const CREDENTIAL_KEY: &str = concat!("ghp_", "abcdefghijklmnopqrstuvwxyz1234567890");

/// The static bearer the [`fixture_with_bearer`] fixture serves.
pub(crate) const BEARER_SECRET: &str = "the-static-bearer";

// Per-thread knobs `fixture_firewalled_with` sets around one `fixture_inner`
// call, so the plain fixtures keep their signatures.
thread_local! {
    static HARDENED: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    static WITH_BEARER: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    pub(crate) static WITH_ADMIN: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    static MODERN_OFF: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    static KEY_SERVER: std::cell::RefCell<Option<Arc<crate::key_server::KeyServer>>> =
        const { std::cell::RefCell::new(None) };
    /// `security.sanitize_input` for the state (the route x check matrix).
    static SANITIZE: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    /// Authentication off for the state (ADR-023: the pin holds without it).
    static AUTH_OFF: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    /// Both backends require identity propagation, each to its own audience
    /// (`aud-<name>`), so one caller reaches them under two bindings
    /// (MIK-8293 S3c).
    static PROPAGATING: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    /// With `PROPAGATING`, propagation is optional (`required: false`).
    static OPTIONAL: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    /// A transport that replaces the scripted backend (the egress matrix).
    static TRANSPORT: std::cell::RefCell<Option<Arc<dyn Transport>>> =
        const { std::cell::RefCell::new(None) };
    /// Both backends run `input_schema_enforcement = "off"` (MIK-8353 3a).
    static SCHEMA_OFF: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    /// The state's transparency log, so the direct route records deliveries
    /// (MIK-8689: a row reads them back).
    static STATE_LOG: std::cell::RefCell<Option<Arc<crate::security::TransparencyLogger>>> =
        const { std::cell::RefCell::new(None) };
}

#[cfg(feature = "firewall")]
thread_local! {
    static FIREWALL_RULE: std::cell::Cell<Option<crate::security::firewall::FirewallAction>> =
        const { std::cell::Cell::new(None) };
    static CLIENT_BREAKER: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    static ANOMALY: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    /// Calls per window the call budget allows; 0 leaves the budget off (MIK-8362).
    static BUDGET: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    static RELAY: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    /// Relay detection keeps every k-gram in the next fixture built here.
    static EVERY_KGRAM: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    static META_FIREWALL: std::cell::RefCell<Option<Arc<crate::security::firewall::Firewall>>> =
        const { std::cell::RefCell::new(None) };
    static AUDIT_LOG: std::cell::RefCell<Option<std::path::PathBuf>> =
        const { std::cell::RefCell::new(None) };
}

/// The auth the fixture serves: four keys, plus a client breaker when asked.
fn fixture_auth() -> AuthConfig {
    let mut auth = AuthConfig {
        enabled: !AUTH_OFF.with(std::cell::Cell::get),
        api_keys: vec![
            key("k-std"),
            key("k-other"),
            key("k-budget"),
            ApiKeyConfig {
                rate_limit: 1,
                ..key("k-rl")
            },
            ApiKeyConfig {
                // `gateway_invok` is MIK-8340's near-meta-tool name: one edit
                // from `gateway_invoke`, withheld from this key by policy.
                denied_tools: Some(vec!["read".to_string(), "gateway_invok".to_string()]),
                ..key("k-deny")
            },
            ApiKeyConfig {
                // MIK-8361's absent twin: a policy like `k-deny`'s that does
                // not name `read`, so only the catalogue decides.
                denied_tools: Some(vec!["other".to_string()]),
                ..key("k-deny-x")
            },
            ApiKeyConfig {
                // MIK-8361 capability scope twin: this key's own scope denies
                // the capability rows' `hook_or_day` by name.
                denied_tools: Some(vec!["hook_or_day".to_string()]),
                ..key("k-deny-cap")
            },
            ApiKeyConfig {
                // MIK-8387 C2 and FW1: a key scoped to `alpha` and the
                // never-registered `ghost`, so `alpha-pt` and the capability
                // backend sit outside its scope.
                backends: vec!["alpha".to_string(), "ghost".to_string()],
                ..key("k-alpha-ghost")
            },
        ],
        ..Default::default()
    };
    requests::admin_key(&mut auth);
    if WITH_BEARER.with(std::cell::Cell::get) {
        auth.bearer_token = Some(BEARER_SECRET.to_string());
        auth.api_keys.push(key("bearer"));
    }
    #[cfg(feature = "firewall")]
    if CLIENT_BREAKER.with(std::cell::Cell::get) {
        auth.client_circuit_breaker = Some(crate::config::CircuitBreakerConfig {
            failure_threshold: 1,
            ..crate::config::CircuitBreakerConfig::default()
        });
    }
    auth
}

/// The router state the per-thread knobs ask for.
async fn fixture_state() -> (
    Arc<super::AppState>,
    crate::gateway::router::tests::FixtureDir,
) {
    let auth = fixture_auth();
    let hardened = HARDENED.with(std::cell::Cell::get);
    let modern_off = MODERN_OFF.with(std::cell::Cell::get);
    if hardened || modern_off {
        let mut config = crate::config::Config::default();
        if hardened {
            config.security.posture = crate::security::SecurityPosture::Hardened;
        }
        if modern_off {
            config.server.modern_protocol = false;
        }
        test_router_app_state_with_auth_and_config(&auth, config).await
    } else if let Some(key_server) = KEY_SERVER.with(|k| k.borrow().clone()) {
        super::tests::test_router_app_state_with_auth_and_key_server(&auth, Some(key_server)).await
    } else {
        test_router_app_state_with_auth(&auth).await
    }
}

/// The rebuilt Meta-MCP keeps the state's admission store: sync calls and
/// tasks share one, as `server/task_runtime.rs` wires it.
// One literal per fixture switch, as the cells read it: splitting would hide
// which knob a cell turns.
#[allow(clippy::too_many_lines)]
async fn fixture_inner(
    answer: Answer,
    #[cfg_attr(not(feature = "firewall"), allow(unused_variables))] firewalled: bool,
    build: impl FnOnce(MetaMcp) -> MetaMcp,
) -> Fx {
    // Taken before the first await, so no other fixture on this thread can
    // take a flag set for this one (`keep_every_kgram_next`).
    #[cfg(feature = "firewall")]
    let every = EVERY_KGRAM.with(|e| e.replace(false));
    let (mut state, store) = fixture_state().await;
    let (calls, seen) = (Arc::new(AtomicUsize::new(0)), Arc::default());
    let state_mut = Arc::get_mut(&mut state).expect("state is unique");
    // The flag applies from the published config (ADR-023).
    let mut config = (*state_mut.live_config.get()).clone();
    config.security.sanitize_input = SANITIZE.with(std::cell::Cell::get);
    state_mut.live_config.set(config);
    let route_log = propagating_route_log(state_mut);
    if let Some(log) = STATE_LOG.with(|l| l.borrow().clone()) {
        state_mut.transparency_log = Some(log);
    }
    if let Some(policy) = STATE_MTLS.with(|p| p.borrow().clone()) {
        state_mut.mtls_policy = policy;
    }
    for (name, passthrough) in [("alpha", false), ("alpha-pt", true)] {
        let backend = Arc::new(Backend::new(
            name,
            fixture_backend_config(name, passthrough),
            &fixture_failsafe(),
            Duration::from_secs(60),
        ));
        if let quota::Backends::Scripted = quota::backends() {
            backend.set_transport_for_test(backend_transport((&calls, &seen), answer));
        }
        assert!(state_mut.backends.register(backend), "fixture registration");
    }
    let mut meta = MetaMcp::new(Arc::clone(&state_mut.backends)).admitting_as(&state_mut.meta_mcp);
    meta.enable_idempotency(
        Arc::new(crate::idempotency::IdempotencyCache::new()),
        Duration::from_secs(300),
    );
    #[cfg(feature = "firewall")]
    if firewalled {
        use crate::security::firewall::{Firewall, FirewallConfig};
        let rules = FIREWALL_RULE
            .with(std::cell::Cell::get)
            .map_or_else(Vec::new, egress::firewall_rules);
        let anomaly = ANOMALY.with(std::cell::Cell::get);
        let tracker = anomaly.then(|| {
            let tracker = Arc::new(crate::transition::TransitionTracker::new());
            for _ in 0..10 {
                tracker.record_transition("train", "alpha:read");
                tracker.record_transition("train", "alpha:other");
            }
            tracker
        });
        let config = FirewallConfig {
            enabled: true,
            scan_requests: true,
            scan_responses: true,
            credential_redaction: true,
            rules,
            audit_log: AUDIT_LOG.with(|a| a.borrow().clone()),
            budget: crate::security::firewall::budget_guard::BudgetGuardConfig {
                enabled: BUDGET.with(std::cell::Cell::get) > 0,
                max_calls_per_window: BUDGET.with(std::cell::Cell::get),
                window_secs: 3_600,
            },
            anomaly_detection: anomaly,
            anomaly_threshold: 0.7,
            anomaly_block_threshold: anomaly.then_some(0.9),
            anomaly_min_observations: 1,
            collusion: if RELAY.with(std::cell::Cell::get) {
                crate::security::firewall::CollusionConfig {
                    action: crate::security::firewall::CollusionAction::Block,
                    sources: vec!["alpha:read".into(), "alpha:resources/read".into()],
                    ..crate::security::firewall::CollusionConfig::default()
                }
            } else {
                crate::security::firewall::CollusionConfig::default()
            },
            ..FirewallConfig::default()
        };
        // A row whose verdict must not depend on the per-process hash key keeps
        // every k-gram instead of the keyed sample (`keep_every_kgram_next`).
        let keyed = |fw: Firewall| if every { fw.keeping_every_kgram() } else { fw };
        let firewall = Arc::new(keyed(
            Firewall::from_config(config.clone(), tracker.clone())
                .with_continuations(meta.continuation()),
        ));
        super::firewall_publish_fixture::publish_firewall(state_mut, &firewall);
        state_mut.firewall = Some(firewall);
        let meta_firewall = Arc::new(keyed(
            Firewall::from_config(config, tracker).with_continuations(meta.continuation()),
        ));
        META_FIREWALL.with(|f| *f.borrow_mut() = Some(Arc::clone(&meta_firewall)));
        meta.set_firewall(Some(meta_firewall));
    }
    meta.set_live_config(Arc::clone(&state_mut.live_config)); // as startup wires it
    state_mut.meta_mcp = Arc::new(build(meta));
    let router = create_router(Arc::clone(&state));
    Fx {
        state,
        router,
        calls,
        seen,
        _store: store,
        _audit: None,
        _route_audit: route_log,
    }
}

/// MIK-8154 F2 rows: a reload of `name` as config reload does it, the old
/// instance removed and a new one registered with `passthrough`, sending
/// through the fixture's counting transport. Returned as a hook to run at a
/// seam.
pub(crate) fn reload_for_test(
    fx: &Fx,
    name: &'static str,
    passthrough: bool,
) -> impl FnOnce() + use<> {
    let (state, calls, seen) = (
        Arc::clone(&fx.state),
        Arc::clone(&fx.calls),
        Arc::clone(&fx.seen),
    );
    move || {
        let backend = Arc::new(Backend::new(
            name,
            fixture_backend_config(name, passthrough),
            &fixture_failsafe(),
            Duration::from_secs(60),
        ));
        backend.set_transport_for_test(backend_transport((&calls, &seen), Answer::Ok));
        state.backends.remove(name);
        assert!(state.backends.register(backend), "reload registration");
    }
}

/// The next fixture built on this thread (a thread-local flag, like `RELAY`,
/// taken at the fixture's first line) keeps every k-gram for relay
/// detection, so a relay row's verdict does not depend on the per-process hash
/// key: with the keyed 1-in-4 sample, a short text is missed for a small,
/// documented share of keys.
#[cfg(feature = "firewall")]
pub(crate) fn keep_every_kgram_next() {
    EVERY_KGRAM.with(|e| e.set(true));
}

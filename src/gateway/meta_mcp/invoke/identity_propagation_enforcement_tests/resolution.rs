// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
use super::*;

// IDP.1 end-to-end via Code Mode (gateway_execute): an identified caller reaches an
// identity-required backend WITH its per-user Bearer credential on the wire.
// Regression guard for the review finding that Code Mode dropped verified_identity.
#[tokio::test]
async fn code_mode_execute_propagates_identity_to_backend() {
    let (m, captured) = meta_with_capturing_backend();
    let id = identity();
    m.seed_caller_slot_for_test("mem", &id).await;
    let caller = crate::gateway::meta_mcp::MetaMcpCallerContext {
        task: None,
        signing: None,
        execution: None,
        credential_principal: None,
        authentication: crate::gateway::meta_mcp::Authentication::Anonymous,
        credential_kind: crate::security::audit::CredentialKind::None,
        is_modern: false,
        protocol_revision: None,
        authorizer: &ALLOW_ALL_INVOKE,
        stdio_nonce: None,
        caller_key: None,
        verified_identity: Some(&id),
        api_key_name: None,
        agent_id: None,
        agent_declared: None,
        grant_subject: None,
        is_admin: false,
        surface_request: crate::gateway::recovery::SurfaceRequest::Configured,
        input_capabilities: crate::protocol::meta::Declared::NONE,
        retry: &crate::protocol::mrtr::NO_RETRY,
        confirmation: crate::gateway::destructive_confirmation::ConfirmationChannel::Unavailable,
        era: crate::protocol::meta::Era::Legacy,
        channel: &crate::gateway::input_bridge::NoClientChannel,
    };
    let args = json!({ "tool": "mem:read", "arguments": {} });
    m.code_mode_execute(&args, Some("s1"), &caller)
        .await
        .expect("code-mode execute ok");

    let headers = captured.lock().clone();
    let auth = headers.iter().find(|(k, _)| k == "Authorization");
    assert!(
        auth.is_some_and(|(_, v)| v.starts_with("Bearer ")),
        "Code Mode must propagate the per-user Bearer credential; got {headers:?}"
    );
}

// Fail-closed still holds through Code Mode: a required backend with NO
// verified identity refuses at resolve, before dispatch.
#[tokio::test]
async fn code_mode_execute_fails_closed_without_identity() {
    let (m, _captured) = meta_with_capturing_backend();
    let caller = crate::gateway::meta_mcp::MetaMcpCallerContext {
        task: None,
        signing: None,
        execution: None,
        credential_principal: None,
        authentication: crate::gateway::meta_mcp::Authentication::Anonymous,
        credential_kind: crate::security::audit::CredentialKind::None,
        is_modern: false,
        protocol_revision: None,
        authorizer: &ALLOW_ALL_INVOKE,
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
        confirmation: crate::gateway::destructive_confirmation::ConfirmationChannel::Unavailable,
        era: crate::protocol::meta::Era::Legacy,
        channel: &crate::gateway::input_bridge::NoClientChannel,
    };
    let args = json!({ "tool": "mem:read", "arguments": {} });
    let err = m
        .code_mode_execute(&args, Some("s1"), &caller)
        .await
        .expect_err("must refuse without identity");
    assert!(
        err.to_string().contains("required"),
        "fail-closed error: {err}"
    );
}

// MIK-6740 operator-misconfig fail-OPEN guard (caller-level, end-to-end
// through Code Mode): a `required` backend whose credential mints
// successfully but whose transparency log is UNCONFIGURED must fail closed —
// the mint aborts with an error AND no per-user header reaches the backend
// transport. Without the guard, the audit helper's `None -> Ok(())` no-op
// would let the credential go on the wire with zero audit record.
#[tokio::test]
async fn required_mint_without_transparency_log_fails_closed() {
    // The propagation-succeeds fixture with NO transparency log wired.
    let (m, captured) = meta_with_capturing_backend_no_log();
    let id = identity();
    m.seed_caller_slot_for_test("mem", &id).await;
    let caller = crate::gateway::meta_mcp::MetaMcpCallerContext {
        task: None,
        signing: None,
        execution: None,
        credential_principal: None,
        authentication: crate::gateway::meta_mcp::Authentication::Anonymous,
        credential_kind: crate::security::audit::CredentialKind::None,
        is_modern: false,
        protocol_revision: None,
        authorizer: &ALLOW_ALL_INVOKE,
        stdio_nonce: None,
        caller_key: None,
        verified_identity: Some(&id),
        api_key_name: None,
        agent_id: None,
        agent_declared: None,
        grant_subject: None,
        is_admin: false,
        surface_request: crate::gateway::recovery::SurfaceRequest::Configured,
        input_capabilities: crate::protocol::meta::Declared::NONE,
        retry: &crate::protocol::mrtr::NO_RETRY,
        confirmation: crate::gateway::destructive_confirmation::ConfirmationChannel::Unavailable,
        era: crate::protocol::meta::Era::Legacy,
        channel: &crate::gateway::input_bridge::NoClientChannel,
    };
    let args = json!({ "tool": "mem:read", "arguments": {} });
    let err = m
        .code_mode_execute(&args, Some("s1"), &caller)
        .await
        .expect_err("required mint with no audit sink must fail closed");
    let msg = err.to_string();
    assert!(
        msg.contains("transparency log") || msg.contains("audit"),
        "fail-closed error must cite the missing audit sink: {msg}"
    );
    // The security property: no per-user credential reached the wire.
    assert!(
        captured.lock().is_empty(),
        "no per-user header must reach the backend when the mint fails closed; \
         got {:?}",
        captured.lock()
    );
}

// CWE-209 (PR #355 codex re-review): when a required mint SUCCEEDS but the
// mint audit-write FAILS, the branch must fail closed AND return a GENERIC
// client-facing error — never interpolate the underlying transparency-log
// error (`PropagationError::AuditFailed`, which wraps the append IO error /
// filesystem detail) into the caller-visible string. This drives a genuine
// audit-write failure through `resolve_caller_credential` and asserts the
// returned `Error::Internal` carries only the generic message.
//
// Failure-injection mirrors
// `identity_propagation::tests::audit_fail_closed::mint_write_failure_is_fail_closed`:
// POSIX checks file permissions only at `open(2)`, so a real write failure
// is forced with process-wide `RLIMIT_FSIZE=0` (every write -> `EFBIG`) in a
// re-exec'd CHILD process. `open()` writes nothing so it still succeeds;
// in-memory minting still succeeds; only the audit append fails. Unix-only.
#[cfg(unix)]
#[test]
fn mint_audit_write_failure_returns_generic_error_no_leak() {
    const ENV_VAR: &str = "IDP_INVOKE_AUDIT_FSIZE_CHILD_PATH";
    const MARK_OK: &str = "MINT_AUDIT_ERROR_WAS_GENERIC";
    const TEST_PATH: &str = "gateway::meta_mcp::invoke::identity_propagation_enforcement_tests::resolution::mint_audit_write_failure_returns_generic_error_no_leak";

    if std::env::var(ENV_VAR).is_ok() {
        // Child: RLIMIT_FSIZE=0 is already active (parent shell wrapper), so
        // the transparency-log append write fails while the in-memory mint
        // succeeds — exercising exactly the fixed mint-audit-failure branch.
        use crate::security::TransparencyLogger;
        use crate::security::transparency_log::TransparencyLogConfig;

        let path = std::env::var(ENV_VAR).expect("child path env var");
        let cfg = Arc::new(TransparencyLogConfig {
            enabled: true,
            path,
            key_id: "test".to_string(),
            ..TransparencyLogConfig::default()
        });
        let logger =
            Arc::new(TransparencyLogger::open(cfg).expect("open() writes nothing, must succeed"));
        let mut m = meta_with_strategy();
        m.enable_transparency_log(logger);

        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("current-thread runtime");
        let err = rt.block_on(async {
            m.resolve_caller_credential("memory", &idp_cfg(true), Some(&identity()))
                .await
                .expect_err("required mint whose audit write fails must fail closed")
        });
        let msg = err.to_string();

        // Fail-closed preserved: still an Internal error (mint aborted).
        assert!(
            matches!(err, crate::Error::Internal(_)),
            "mint-audit failure must fail closed as Internal: {err}"
        );
        // Generic client-facing message (backend name is a non-sensitive id).
        assert!(
            msg.contains("audit unavailable") && msg.contains("memory"),
            "must return the generic audit-unavailable message: {msg}"
        );
        // The pre-fix leak: none of the underlying transparency-log /
        // AuditFailed detail may reach the caller-visible string.
        for leaked in [
            "transparency-log write failed",
            "audit write failed",
            "action 'idp_mint'",
            "File too large",
            "os error",
        ] {
            assert!(
                !msg.contains(leaked),
                "client-facing mint-audit error must not leak {leaked:?}: {msg}"
            );
        }
        println!("{MARK_OK}");
        return;
    }

    // Parent: re-exec this exact test under RLIMIT_FSIZE=0 and assert on
    // what the child observed. `trap '' XFSZ` ignores SIGXFSZ (whose default
    // disposition would kill the child) so the write returns `Err` instead.
    let exe = std::env::current_exe().expect("current test binary path");
    // A new log's open() writes its genesis record (#2275); create it here,
    // outside the size limit, so the child's open() only reads.
    let path = leaked_test_transparency_logger()
        .path()
        .to_string_lossy()
        .to_string();
    let script =
        format!("ulimit -f 0; trap '' XFSZ; exec \"$0\" '{TEST_PATH}' --exact --nocapture");
    let profile_dir = tempfile::tempdir().expect("private profile dir");
    let output = std::process::Command::new("sh")
        .arg("-c")
        .arg(script)
        .arg(&exe)
        .env(ENV_VAR, &path)
        // Under a zero file-size limit the child's coverage profile is written
        // empty and corrupts the measured set (#2573); give it a private file.
        .env(
            "LLVM_PROFILE_FILE",
            profile_dir.path().join("child-%p.profraw"),
        )
        .output()
        .expect("spawn fsize-limited child process");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains(MARK_OK),
        "child did not confirm a generic (non-leaking) mint-audit error \
         (status={:?}, stdout={stdout}, stderr={})",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
    // The child must also EXIT cleanly: a child that prints the marker and
    // then aborts (panic/abort after the observation) must not read as a
    // pass. Mirrors the two sibling fail-closed subprocess tests.
    assert!(
        output.status.success(),
        "child printed the marker but did not exit successfully \
         (status={:?}, stderr={})",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
}

#[tokio::test]
async fn mints_bearer_credential_for_identity() {
    let mut m = meta_with_strategy();
    // A `required` mint needs a durable audit sink (MIK-6740 fail-closed).
    m.enable_transparency_log(leaked_test_transparency_logger());
    let cred = m
        .resolve_caller_credential("memory", &idp_cfg(true), Some(&identity()))
        .await
        .expect("mint ok");
    assert_eq!(cred.headers.len(), 1);
    assert_eq!(cred.headers[0].0, "Authorization");
    assert!(cred.headers[0].1.starts_with("Bearer "));
    // IDP.8 — a cache binding is produced so per-user results cache isolated.
    assert!(cred.cache_binding.is_some());
}

// IDP.8 — distinct identities produce distinct cache bindings, so two users
// calling the same tool with the same arguments cannot collide in the cache.
#[tokio::test]
async fn distinct_identities_get_distinct_cache_bindings() {
    let mut m = meta_with_strategy();
    // A `required` mint needs a durable audit sink (MIK-6740 fail-closed).
    m.enable_transparency_log(leaked_test_transparency_logger());
    let alice = m
        .resolve_caller_credential("memory", &idp_cfg(true), Some(&identity()))
        .await
        .expect("alice")
        .cache_binding;
    let bob_identity = VerifiedIdentity {
        subject: "bob".to_string(),
        email: "bob@corp".to_string(),
        name: None,
        groups: vec![],
        issuer: "https://idp".to_string(),
    };
    let bob = m
        .resolve_caller_credential("memory", &idp_cfg(true), Some(&bob_identity))
        .await
        .expect("bob")
        .cache_binding;
    assert!(alice.is_some() && bob.is_some());
    assert_ne!(alice, bob, "per-user cache bindings must differ");
}

// IDP.2 — fail-closed: a REQUIRED backend with no verified identity refuses
// (never falls back to the static credential).
#[tokio::test]
async fn required_backend_without_identity_fails_closed() {
    let m = meta_with_strategy();
    let err = m
        .resolve_caller_credential("memory", &idp_cfg(true), None)
        .await
        .expect_err("must refuse");
    assert!(
        err.to_string().contains("required"),
        "fail-closed error: {err}"
    );
}

// IDP.2 — fail-closed: a REQUIRED backend with no strategy wired refuses.
#[tokio::test]
async fn required_backend_without_strategy_fails_closed() {
    let m = MetaMcp::new(Arc::new(BackendRegistry::new())); // no strategy set
    let err = m
        .resolve_caller_credential("memory", &idp_cfg(true), Some(&identity()))
        .await
        .expect_err("must refuse");
    assert!(
        err.to_string().contains("required"),
        "fail-closed error: {err}"
    );
}

// MIK-6710 — fail-closed: a REQUIRED backend registered on a stdio
// transport (which cannot carry `extra_headers` on the wire) refuses
// BEFORE minting, even with a verified identity and a working strategy —
// never mints a credential that `request_with_headers` would silently
// drop, leaving the backend to run unauthenticated.
#[tokio::test]
async fn required_backend_on_stdio_transport_fails_closed_before_mint() {
    use crate::backend::Backend;
    use crate::config::{BackendConfig, TransportConfig};

    let registry = Arc::new(BackendRegistry::new());
    let config = BackendConfig {
        transport: TransportConfig::Stdio {
            command: "true".to_string(),
            cwd: None,
            protocol_version: None,
        },
        identity_propagation: Some(idp_cfg(true)),
        ..BackendConfig::default()
    };
    let backend = Arc::new(Backend::new(
        "stdio-mem",
        config,
        &crate::config::FailsafeConfig::default(),
        std::time::Duration::from_secs(60),
    ));
    let _ = registry.register(backend);

    let m = MetaMcp::new(registry);
    let key = Arc::new(GatewayKeyPair::generate().expect("keygen"));
    m.set_identity_propagation(Arc::new(SignedAssertionStrategy::new(key, 300)));

    let err = m
        .resolve_caller_credential("stdio-mem", &idp_cfg(true), Some(&identity()))
        .await
        .expect_err("stdio transport cannot carry identity headers; must refuse");
    assert!(err.to_string().contains("MIK-6710"), "error: {err}");
}

// A non-required backend on a stdio transport is unaffected by MIK-6710 —
// best-effort, matching the existing non-required fallback. (A
// non-required backend WITH a verified identity and a working strategy
// still mints normally regardless of transport capability — the
// transport gate only ever refuses a `required` backend; this test
// exercises the identity-absent fallback, which is the case where a
// non-required backend legitimately produces no headers.)
#[tokio::test]
async fn optional_backend_on_stdio_transport_yields_no_headers() {
    use crate::backend::Backend;
    use crate::config::{BackendConfig, TransportConfig};

    let registry = Arc::new(BackendRegistry::new());
    let config = BackendConfig {
        transport: TransportConfig::Stdio {
            command: "true".to_string(),
            cwd: None,
            protocol_version: None,
        },
        identity_propagation: Some(idp_cfg(false)),
        ..BackendConfig::default()
    };
    let backend = Arc::new(Backend::new(
        "stdio-mem-optional",
        config,
        &crate::config::FailsafeConfig::default(),
        std::time::Duration::from_secs(60),
    ));
    let _ = registry.register(backend);

    let m = MetaMcp::new(registry);
    let key = Arc::new(GatewayKeyPair::generate().expect("keygen"));
    m.set_identity_propagation(Arc::new(SignedAssertionStrategy::new(key, 300)));

    let cred = m
        .resolve_caller_credential("stdio-mem-optional", &idp_cfg(false), None)
        .await
        .expect("optional backend proceeds despite incapable transport");
    assert!(cred.headers.is_empty());
}

// A NON-required backend without identity degrades to the empty credential
// (best-effort; no headers, no binding → shared cache key, IDP.5).
#[tokio::test]
async fn optional_backend_without_identity_yields_no_headers() {
    let m = meta_with_strategy();
    let cred = m
        .resolve_caller_credential("memory", &idp_cfg(false), None)
        .await
        .expect("optional ok");
    assert!(cred.headers.is_empty());
    assert!(cred.cache_binding.is_none());
}

// Direct backend route (/mcp/{name}) — resolve_propagation_headers mints the
// per-user credential for a propagation-configured backend so the direct
// passthrough carries it too (MIK-6734 review finding 4).
#[tokio::test]
async fn direct_route_resolves_bearer_for_identity() {
    let (m, _captured) = meta_with_capturing_backend();
    let headers = m
        .resolve_propagation_headers("mem", Some(&identity()))
        .await
        .expect("resolve ok");
    assert!(
        headers
            .iter()
            .any(|(k, v)| k == "Authorization" && v.starts_with("Bearer ")),
        "direct route must resolve the per-user Bearer credential: {headers:?}"
    );
}

// Direct route fails closed for a required backend with no identity — never
// forwards with only the static credential.
#[tokio::test]
async fn direct_route_fails_closed_without_identity() {
    let (m, _captured) = meta_with_capturing_backend();
    let err = m
        .resolve_propagation_headers("mem", None)
        .await
        .expect_err("must refuse");
    assert!(
        err.to_string().contains("required"),
        "fail-closed error: {err}"
    );
}

// Direct route to a backend with no identity_propagation config is unchanged
// (empty headers → static path).
#[tokio::test]
async fn direct_route_unconfigured_backend_yields_no_headers() {
    let (m, _captured) = meta_with_capturing_backend();
    let headers = m
        .resolve_propagation_headers("no-such-backend", Some(&identity()))
        .await
        .expect("resolve ok");
    assert!(headers.is_empty());
}

// MIK-6729 review M2 — the wired path: `resolve_caller_credential` MUST
// copy `idp_cfg.token_exchange_endpoint`/`token_exchange_scope` into the
// `BackendDescriptor` it hands to the installed strategy. Installs the
// TokenExchangeStrategy the exact same way the production Gateway startup
// match arm does (`gateway::server::mod` — `TokenExchangeStrategy::new` +
// `meta_mcp.set_identity_propagation`), so this test exercises the real
// wired path, not a hand-rolled stand-in.
//
// No live STS is available in-test, so this asserts the FAILURE MODE
// instead of a minted token: an unreachable endpoint must fail with a
// network/exchange error ("token-exchange request failed"), never with
// `Misconfigured("... no token_exchange_endpoint configured ...")`. The
// `Misconfigured` message is `TokenExchangeStrategy::propagate`'s first
// check, reached ONLY when the descriptor's `token_exchange_endpoint` is
// `None` — i.e. exactly what happens if invoke.rs's two wiring lines
// (`token_exchange_endpoint`/`token_exchange_scope` copy into
// `BackendDescriptor`) are deleted. Verified live (MIK-6729 review): with
// those two lines removed, this test fails because the error message
// becomes "... no token_exchange_endpoint configured (MIK-6729)" instead
// of "token-exchange request failed"; every OLD test in this module still
// passes, because none of them exercise a `TokenExchange` strategy.
fn meta_with_token_exchange_strategy() -> MetaMcp {
    // Mirrors gateway::server::mod's
    // `Some(PropagationStrategyKind::TokenExchange) => { ... }` install
    // arm verbatim (same constructor, same `set_identity_propagation`
    // call) without needing a full `Config`/`Gateway::start`.
    let m = MetaMcp::new(Arc::new(BackendRegistry::new()));
    let key = Arc::new(GatewayKeyPair::generate().expect("keygen"));
    m.set_identity_propagation(Arc::new(TokenExchangeStrategy::new(key, 300)));
    m
}

fn token_exchange_idp_cfg() -> IdentityPropagationConfig {
    IdentityPropagationConfig {
        strategy: PropagationStrategyKind::TokenExchange,
        audience: "https://mail.internal".to_string(),
        required: true,
        session_mode: SessionMode::PerUser,
        // Port 0 is never reachable / instantly refused by the OS —
        // deterministic network failure, same technique as
        // `token_exchange::tests::unreachable_endpoint_is_refused`.
        token_exchange_endpoint: Some("https://127.0.0.1:0/token".to_string()),
        token_exchange_scope: Some("mail.read".to_string()),
    }
}

#[tokio::test]
async fn resolve_caller_credential_wires_token_exchange_endpoint_and_scope() {
    let m = meta_with_token_exchange_strategy();
    let err = m
        .resolve_caller_credential("mail", &token_exchange_idp_cfg(), Some(&identity()))
        .await
        .expect_err("unreachable token-exchange endpoint must fail closed");
    let msg = err.to_string();
    assert!(
        !msg.contains("no identity-propagation strategy"),
        "strategy must be installed: {msg}"
    );
    assert!(
        !msg.contains("token_exchange_endpoint configured"),
        "if this fires, invoke.rs stopped wiring \
         token_exchange_endpoint/token_exchange_scope into BackendDescriptor \
         (MIK-6729 review M2): {msg}"
    );
    assert!(
        msg.contains("token-exchange request failed"),
        "must fail as a network/exchange error (proving the endpoint WAS \
         wired into the descriptor), not a Misconfigured short-circuit: {msg}"
    );
}

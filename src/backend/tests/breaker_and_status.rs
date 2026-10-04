// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Circuit breaker, health probe recovery, OAuth isolation and runtime-profile status.

use super::*;

#[tokio::test]
async fn is_circuit_tripped_reflects_breaker_state() {
    let backend = Backend::new(
        "test",
        BackendConfig::default(),
        &crate::config::FailsafeConfig::default(),
        Duration::from_secs(60),
    );
    assert!(!backend.is_circuit_tripped());
    backend.trip_circuit_breaker_for_test();
    assert!(backend.is_circuit_tripped());
    backend.reset_circuit_breaker();
    assert!(!backend.is_circuit_tripped());
}

// Headline regression: a successful health probe must auto-reset a tripped
// breaker. This is the recovery the old health check could never perform,
// because it pinged through the breaker (which short-circuits when Open).
#[tokio::test]
async fn health_probe_resets_tripped_breaker_on_success() {
    let backend = Arc::new(Backend::new(
        "test",
        BackendConfig::default(),
        &crate::config::FailsafeConfig::default(),
        Duration::from_secs(60),
    ));
    let mock = Arc::new(RecoveryMock::connected());
    backend.set_transport_for_test(mock.clone() as Arc<dyn Transport>);

    backend.trip_circuit_breaker_for_test();
    assert!(backend.is_circuit_tripped(), "precondition: breaker open");

    backend
        .health_probe(Duration::from_secs(5))
        .await
        .expect("probe should succeed");

    assert!(
        !backend.is_circuit_tripped(),
        "a successful probe must reset the tripped breaker"
    );
    assert_eq!(mock.pings.load(Ordering::SeqCst), 1);
}

// A failing probe must NOT reset the breaker — recovery is success-gated.
#[tokio::test]
async fn health_probe_failure_leaves_breaker_tripped() {
    let backend = Arc::new(Backend::new(
        "test",
        BackendConfig::default(),
        &crate::config::FailsafeConfig::default(),
        Duration::from_secs(60),
    ));
    let mock = Arc::new(RecoveryMock::connected());
    mock.fail.store(true, Ordering::Relaxed);
    backend.set_transport_for_test(mock.clone() as Arc<dyn Transport>);

    backend.trip_circuit_breaker_for_test();
    let result = backend.health_probe(Duration::from_secs(5)).await;

    assert!(result.is_err(), "failed probe returns Err");
    assert!(
        backend.is_circuit_tripped(),
        "a failed probe must leave the breaker tripped"
    );
}

#[test]
fn oauth_requires_per_user_isolation_reflects_config() {
    let mk = |oauth: Option<crate::config::OAuthConfig>| {
        Backend::new(
            "b",
            BackendConfig {
                oauth,
                ..BackendConfig::default()
            },
            &crate::config::FailsafeConfig::default(),
            Duration::from_secs(60),
        )
    };
    let oauth = |enabled: bool, shared: bool| crate::config::OAuthConfig {
        enabled,
        scopes: vec![],
        client_id: None,
        client_secret: None,
        callback_host: None,
        callback_port: None,
        callback_path: None,
        token_refresh_buffer_secs: 300,
        shared_account: shared,
    };
    // Enabled, gateway-held, not blessed shared → guard MUST fire.
    assert!(
        mk(Some(oauth(true, false))).oauth_requires_per_user_isolation(),
        "enabled non-shared gateway-held OAuth must require per-user isolation"
    );
    // Operator blessed the account as shared → no isolation required.
    assert!(
        !mk(Some(oauth(true, true))).oauth_requires_per_user_isolation(),
        "shared_account=true opts out of the isolation guard"
    );
    // OAuth disabled → nothing to isolate.
    assert!(!mk(Some(oauth(false, false))).oauth_requires_per_user_isolation());
    // No OAuth config → nothing to isolate.
    assert!(!mk(None).oauth_requires_per_user_isolation());
}

// F3 sink-side guard (MIK-6746): even when Config::validate() is bypassed
// by programmatic construction, create_oauth_client() must refuse to build a
// backend OAuth client for a backend that also declares identity_propagation.
// The backend OAuth would persist a gateway-held token during initialize(),
// authenticating the transport session as the gateway before any per-request
// per-user override — silently defeating per-user propagation. Fail closed at
// the last chokepoint. Contradiction holds for BOTH implemented strategies.
#[test]
fn create_oauth_client_refuses_identity_propagation_backends() {
    let oauth_enabled = crate::config::OAuthConfig {
        enabled: true,
        scopes: vec![],
        client_id: None,
        client_secret: None,
        callback_host: None,
        callback_port: None,
        callback_path: None,
        token_refresh_buffer_secs: 300,
        shared_account: false,
    };
    let idp = |strategy: crate::identity_propagation::PropagationStrategyKind| {
        crate::identity_propagation::IdentityPropagationConfig {
            strategy,
            audience: "https://backend.example".to_string(),
            required: true,
            session_mode: crate::identity_propagation::SessionMode::Stateless,
            token_exchange_endpoint: None,
            token_exchange_scope: None,
        }
    };
    let mk = |strategy| {
        Backend::new(
            "b",
            BackendConfig {
                oauth: Some(oauth_enabled.clone()),
                identity_propagation: Some(idp(strategy)),
                ..BackendConfig::default()
            },
            &crate::config::FailsafeConfig::default(),
            Duration::from_secs(60),
        )
    };
    for strategy in [
        crate::identity_propagation::PropagationStrategyKind::SignedAssertion,
        crate::identity_propagation::PropagationStrategyKind::Passthrough,
    ] {
        let backend = mk(strategy);
        match backend.create_oauth_client(
            "https://backend.example",
            crate::security::ssrf::DestinationPolicy::Configured,
        ) {
            Err(Error::ConfigValidation(_)) => {}
            Err(other) => {
                panic!("expected ConfigValidation, got {other:?} for {strategy:?}")
            }
            Ok(_) => panic!(
                "enabled backend oauth + identity_propagation must fail closed for {strategy:?}"
            ),
        }
    }

    // shared_account=true does NOT exempt: sharing one gateway-held token
    // still contradicts per-user propagation.
    let shared = Backend::new(
        "b",
        BackendConfig {
            oauth: Some(crate::config::OAuthConfig {
                shared_account: true,
                ..oauth_enabled.clone()
            }),
            identity_propagation: Some(idp(
                crate::identity_propagation::PropagationStrategyKind::SignedAssertion,
            )),
            ..BackendConfig::default()
        },
        &crate::config::FailsafeConfig::default(),
        Duration::from_secs(60),
    );
    assert!(
        shared
            .create_oauth_client(
                "https://backend.example",
                crate::security::ssrf::DestinationPolicy::Configured
            )
            .is_err(),
        "shared_account=true must not exempt the F3 guard"
    );

    // No identity_propagation → enabled backend oauth proceeds (returns a
    // client), proving the guard does not over-reach.
    let plain = Backend::new(
        "b",
        BackendConfig {
            oauth: Some(oauth_enabled.clone()),
            ..BackendConfig::default()
        },
        &crate::config::FailsafeConfig::default(),
        Duration::from_secs(60),
    );
    assert!(
        plain
            .create_oauth_client(
                "https://backend.example",
                crate::security::ssrf::DestinationPolicy::Configured
            )
            .is_ok(),
        "backend oauth without identity_propagation must still be allowed"
    );
}

#[test]
fn backend_status_surfaces_ready_runtime_profile_lifecycle() {
    let cfg = BackendConfig {
        transport: TransportConfig::Stdio {
            command: "mcp-docs-server --stdio".to_string(),
            cwd: None,
            protocol_version: None,
        },
        runtime_profile: Some("containerized".to_string()),
        ..BackendConfig::default()
    };

    let mut runtime = crate::config::RuntimeConfig::default();
    runtime.availability.docker = true;
    runtime.profiles.insert(
        "containerized".to_string(),
        crate::config::RuntimeProfileConfig {
            provider: Some(crate::runtime::RuntimeProviderKind::Docker),
            image: Some("ghcr.io/example/docs-mcp:1".to_string()),
            restart: crate::runtime::RuntimeRestartPolicy {
                max_restarts: 4,
                backoff_secs: 11,
            },
            ..crate::config::RuntimeProfileConfig::default()
        },
    );
    let plan = runtime_plan_for_backend("docs", &cfg, &runtime).expect("runtime plan");
    let backend = Backend::new_with_runtime_plan(
        "docs",
        cfg,
        &crate::config::FailsafeConfig::default(),
        Duration::from_secs(60),
        Some(plan),
    );

    let status = backend.status();
    let runtime = status.runtime.expect("runtime status");
    assert_eq!(runtime.profile, "containerized");
    assert_eq!(
        runtime.provider,
        crate::runtime::RuntimeProviderKind::Docker
    );
    assert_eq!(
        runtime.license_tier,
        crate::runtime::RuntimeLicenseTier::FreeCore
    );
    assert_eq!(runtime.state, BackendRuntimeState::Ready);
    assert!(runtime.denied_reasons.is_empty());
    assert!(runtime.confirmation_ids.is_empty());
    assert_eq!(runtime.restart_max_attempts, 4);
    assert_eq!(runtime.restart_backoff_secs, 11);
    assert!(runtime.health_check.contains("docker inspect"));
    assert_eq!(
        runtime.restart_command_hint.as_deref(),
        Some("docker restart mcp-gateway-docs")
    );
    assert!(runtime.rollback_step.contains("docker rm --force"));
}

#[test]
fn backend_status_surfaces_confirmation_required_runtime_profile() {
    let cfg = BackendConfig {
        transport: TransportConfig::Stdio {
            command: "mcp-docs-server --stdio".to_string(),
            cwd: None,
            protocol_version: None,
        },
        runtime_profile: Some("local_privileged".to_string()),
        ..BackendConfig::default()
    };

    let mut runtime = crate::config::RuntimeConfig::default();
    runtime.profiles.insert(
        "local_privileged".to_string(),
        crate::config::RuntimeProfileConfig {
            provider: Some(crate::runtime::RuntimeProviderKind::LocalProcess),
            privileged: true,
            ..crate::config::RuntimeProfileConfig::default()
        },
    );
    let plan = runtime_plan_for_backend("docs", &cfg, &runtime).expect("runtime plan");
    let backend = Backend::new_with_runtime_plan(
        "docs",
        cfg,
        &crate::config::FailsafeConfig::default(),
        Duration::from_secs(60),
        Some(plan),
    );

    let status = backend.status();
    let runtime = status.runtime.expect("runtime status");
    assert_eq!(runtime.profile, "local_privileged");
    assert_eq!(
        runtime.provider,
        crate::runtime::RuntimeProviderKind::LocalProcess
    );
    assert_eq!(runtime.state, BackendRuntimeState::ConfirmationRequired);
    assert!(runtime.denied_reasons.is_empty());
    assert_eq!(runtime.confirmation_ids, vec!["runtime.privileged"]);
    assert!(runtime.health_check.contains("stdio"));
    assert_eq!(
        runtime.restart_command_hint.as_deref(),
        Some("restart the gateway-managed child process")
    );
    assert!(runtime.rollback_step.contains("direct-launch"));
}

#[test]
fn stdio_backend_uses_container_runtime_bridge_command() {
    let cfg = BackendConfig {
        transport: TransportConfig::Stdio {
            command: "definitely-not-a-real-mcp-server".to_string(),
            cwd: None,
            protocol_version: None,
        },
        env: HashMap::from([
            ("SAFE_HANDLE".to_string(), "safe-value".to_string()),
            ("UNDECLARED_ENV".to_string(), "must-not-pass".to_string()),
        ]),
        runtime_profile: Some("containerized".to_string()),
        ..BackendConfig::default()
    };

    let mut runtime = crate::config::RuntimeConfig::default();
    runtime.availability.docker = true;
    runtime.profiles.insert(
        "containerized".to_string(),
        crate::config::RuntimeProfileConfig {
            provider: Some(crate::runtime::RuntimeProviderKind::Docker),
            image: Some("ghcr.io/example/server:latest".to_string()),
            env_keys: vec!["SAFE_HANDLE".to_string()],
            ..crate::config::RuntimeProfileConfig::default()
        },
    );
    let plan = runtime_plan_for_backend("docs", &cfg, &runtime).expect("runtime plan");
    let backend = Backend::new_with_runtime_plan(
        "docs",
        cfg,
        &crate::config::FailsafeConfig::default(),
        Duration::from_secs(60),
        Some(plan),
    );

    let launch = backend
        .resolve_stdio_runtime_launch("definitely-not-a-real-mcp-server")
        .expect("container stdio bridge launch");
    let parts = crate::transport::split_command(&launch.command)
        .expect("bridge command is shell-splitable");

    assert_eq!(parts.first().map(String::as_str), Some("docker"));
    assert_eq!(parts.get(1).map(String::as_str), Some("run"));
    assert_eq!(
        parts.get(2..6),
        Some(
            &[
                "--interactive".to_string(),
                "--rm".to_string(),
                "--name".to_string(),
                "mcp-gateway-docs".to_string()
            ][..]
        ),
        "bridge flags must not split paired docker options: {parts:?}"
    );
    assert!(parts.contains(&"--interactive".to_string()));
    assert!(parts.contains(&"--rm".to_string()));
    assert!(!parts.contains(&"--detach".to_string()));
    assert!(
        !parts.iter().any(|arg| arg.starts_with("--restart=")),
        "stdio bridge must drop detached restart policy flags: {parts:?}"
    );
    assert!(parts.contains(&"--network=none".to_string()));
    assert!(parts.contains(&"--read-only".to_string()));
    assert!(parts.contains(&"--cap-drop=ALL".to_string()));
    assert!(parts.contains(&"SAFE_HANDLE".to_string()));
    assert!(!parts.contains(&"UNDECLARED_ENV".to_string()));
    assert!(parts.contains(&"ghcr.io/example/server:latest".to_string()));
    assert_eq!(
        launch.env,
        HashMap::from([("SAFE_HANDLE".to_string(), "safe-value".to_string())])
    );
}

#[tokio::test]
async fn stdio_backend_requires_runtime_confirmations_before_spawn() {
    let cfg = BackendConfig {
        transport: TransportConfig::Stdio {
            command: "definitely-not-a-real-mcp-server".to_string(),
            cwd: None,
            protocol_version: None,
        },
        runtime_profile: Some("local_privileged".to_string()),
        ..BackendConfig::default()
    };

    let mut runtime = crate::config::RuntimeConfig::default();
    runtime.profiles.insert(
        "local_privileged".to_string(),
        crate::config::RuntimeProfileConfig {
            provider: Some(crate::runtime::RuntimeProviderKind::LocalProcess),
            privileged: true,
            ..crate::config::RuntimeProfileConfig::default()
        },
    );
    let plan = runtime_plan_for_backend("docs", &cfg, &runtime).expect("runtime plan");
    assert_eq!(
        plan.launch_command
            .as_ref()
            .map(|command| command.program.as_str()),
        Some("definitely-not-a-real-mcp-server")
    );
    let backend = Backend::new_with_runtime_plan(
        "docs",
        cfg,
        &crate::config::FailsafeConfig::default(),
        Duration::from_secs(60),
        Some(plan),
    );

    let err = backend
        .start()
        .await
        .expect_err("missing runtime confirmation rejected");
    assert!(
        err.to_string().contains("requires confirmations"),
        "confirmation-required runtime plan should fail closed before spawn: {err}"
    );
}

/// Transport whose every request fails with a caller-supplied error, so a test
/// can drive the real dispatch path and watch what it records.
struct ErroringTransport {
    error_text: String,
}

#[async_trait]
impl Transport for ErroringTransport {
    async fn request(&self, _method: &str, _params: Option<Value>) -> Result<JsonRpcResponse> {
        Err(Error::Transport(self.error_text.clone()))
    }

    async fn notify(&self, _method: &str, _params: Option<Value>) -> Result<()> {
        Err(Error::Transport(self.error_text.clone()))
    }

    fn is_connected(&self) -> bool {
        true
    }

    async fn close(&self) -> Result<()> {
        Ok(())
    }
}

async fn dispatch_failing_request(error_text: &str) -> Arc<Backend> {
    let backend = Arc::new(Backend::new(
        "test",
        BackendConfig::default(),
        &crate::config::FailsafeConfig::default(),
        Duration::from_secs(60),
    ));
    backend.set_transport_for_test(Arc::new(ErroringTransport {
        error_text: error_text.to_string(),
    }) as Arc<dyn Transport>);
    let result = backend.request("tools/list", None).await;
    assert!(result.is_err(), "the mock transport always fails");
    backend
}

/// GH475.RL.3 — a rate-limited dispatch is not a circuit-breaker failure.
#[tokio::test]
async fn rate_limited_dispatch_is_not_a_breaker_failure() {
    let backend = dispatch_failing_request("API returned 429 Too Many Requests").await;

    let stats = backend.circuit_breaker_stats();
    assert_eq!(
        stats.current_failures, 0,
        "a throttled backend is not a failing backend"
    );
    assert_eq!(stats.state, crate::failsafe::CircuitState::Closed);
    assert_eq!(backend.health_metrics().failure_count, 0);
}

/// GH475.RL.13 — a `429` still proves the backend is reachable.
#[tokio::test]
async fn rate_limited_dispatch_records_transport_health() {
    let backend = dispatch_failing_request("rate limit exceeded, slow down").await;

    let metrics = backend.health_metrics();
    assert_eq!(
        metrics.success_count, 1,
        "a 429 is a reachable backend, so health records a success"
    );
    assert_eq!(metrics.consecutive_failures, 0);
}

/// GH475.RL.7 — an ordinary failure is still a failure at the circuit breaker
/// and in transport health. The error-budget windows carry the same tag and are
/// asserted separately, in `error_budget_tests` in `src/gateway/meta_mcp/invoke.rs`.
#[tokio::test]
async fn ordinary_dispatch_failure_still_counts() {
    let backend = dispatch_failing_request("HTTP 500: internal error, request id 4291a").await;

    assert_eq!(backend.circuit_breaker_stats().current_failures, 1);
    assert_eq!(backend.health_metrics().failure_count, 1);
    assert_eq!(backend.health_metrics().success_count, 0);
}

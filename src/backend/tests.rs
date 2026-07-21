// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Unit tests for [`super::Backend`] construction, start/health-probe
//! lifecycle, request/notify dispatch, cached-metadata single-flight
//! behavior, and tool-annotation inference.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use async_trait::async_trait;
use serde_json::{Value, json};
use tokio::sync::Barrier;
use tokio::time::sleep;

use super::*;
use crate::config::TransportConfig;
use crate::protocol::{JsonRpcResponse, RequestId, ToolAnnotations, ToolsListResult};
use crate::transport::Transport;
use crate::{Error, Result};

struct MockTransport {
    response: JsonRpcResponse,
    delay: Duration,
    connected: AtomicBool,
    requests: AtomicUsize,
}

impl MockTransport {
    fn new(response: JsonRpcResponse, delay: Duration) -> Self {
        Self {
            response,
            delay,
            connected: AtomicBool::new(true),
            requests: AtomicUsize::new(0),
        }
    }
}

#[async_trait]
impl Transport for MockTransport {
    async fn request(&self, method: &str, _params: Option<Value>) -> Result<JsonRpcResponse> {
        assert_eq!(method, "tools/list");
        self.requests.fetch_add(1, Ordering::SeqCst);
        sleep(self.delay).await;
        Ok(self.response.clone())
    }

    async fn notify(&self, _method: &str, _params: Option<Value>) -> Result<()> {
        Ok(())
    }

    fn is_connected(&self) -> bool {
        self.connected.load(Ordering::Relaxed)
    }

    async fn close(&self) -> Result<()> {
        self.connected.store(false, Ordering::Relaxed);
        Ok(())
    }
}

// Method-agnostic transport for health-probe / recovery tests: answers any
// request with success unless `fail` is set, with a settable `connected`
// flag. Distinct from MockTransport, which hard-asserts "tools/list".
struct RecoveryMock {
    connected: AtomicBool,
    fail: AtomicBool,
    eof: AtomicBool,
    pings: AtomicUsize,
    closes: AtomicUsize,
    response: JsonRpcResponse,
    delay: Duration,
}

impl RecoveryMock {
    fn connected() -> Self {
        Self::responding(JsonRpcResponse::success_serialized(
            RequestId::Number(1),
            json!({}),
        ))
    }

    fn responding(response: JsonRpcResponse) -> Self {
        Self {
            connected: AtomicBool::new(true),
            fail: AtomicBool::new(false),
            eof: AtomicBool::new(false),
            pings: AtomicUsize::new(0),
            closes: AtomicUsize::new(0),
            response,
            delay: Duration::ZERO,
        }
    }

    fn delayed(delay: Duration) -> Self {
        Self {
            delay,
            ..Self::connected()
        }
    }
}

#[async_trait]
impl Transport for RecoveryMock {
    async fn request(&self, method: &str, _params: Option<Value>) -> Result<JsonRpcResponse> {
        assert_eq!(method, "ping");
        self.pings.fetch_add(1, Ordering::SeqCst);
        sleep(self.delay).await;
        if self.fail.load(Ordering::Relaxed) {
            return Err(Error::BackendUnavailable("probe failed".to_string()));
        }
        if self.eof.load(Ordering::Relaxed) {
            return Err(Error::Transport("Response channel closed".to_string()));
        }
        Ok(self.response.clone())
    }

    async fn notify(&self, _method: &str, _params: Option<Value>) -> Result<()> {
        Ok(())
    }

    fn is_connected(&self) -> bool {
        self.connected.load(Ordering::Relaxed)
    }

    async fn close(&self) -> Result<()> {
        self.closes.fetch_add(1, Ordering::SeqCst);
        self.connected.store(false, Ordering::Relaxed);
        Ok(())
    }
}

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
    assert_eq!(
        mock.closes.load(Ordering::SeqCst),
        1,
        "a dead transport must be closed before restart"
    );
}

#[tokio::test]
async fn health_probe_accepts_method_not_found_without_restart() {
    let backend = Arc::new(Backend::new(
        "test",
        BackendConfig::default(),
        &crate::config::FailsafeConfig::default(),
        Duration::from_secs(60),
    ));
    let mock = Arc::new(RecoveryMock::responding(JsonRpcResponse::error(
        Some(RequestId::Number(1)),
        -32601,
        "Method not found",
    )));
    backend.set_transport_for_test(mock.clone() as Arc<dyn Transport>);

    backend
        .health_probe(Duration::from_secs(5))
        .await
        .expect("an exact -32601 response proves the transport is alive");

    assert_eq!(mock.pings.load(Ordering::SeqCst), 1);
    assert_eq!(
        mock.closes.load(Ordering::SeqCst),
        0,
        "unsupported ping must not restart a live MCP server"
    );
}

#[tokio::test]
async fn health_probe_restarts_on_other_json_rpc_error() {
    let backend = Arc::new(Backend::new(
        "test",
        BackendConfig::default(),
        &crate::config::FailsafeConfig::default(),
        Duration::from_secs(60),
    ));
    let mock = Arc::new(RecoveryMock::responding(JsonRpcResponse::error(
        Some(RequestId::Number(1)),
        -32603,
        "Internal error",
    )));
    backend.set_transport_for_test(mock.clone() as Arc<dyn Transport>);

    let result = backend.health_probe(Duration::from_secs(5)).await;

    assert!(
        result.is_err(),
        "a real JSON-RPC failure is not a healthy probe"
    );
    assert_eq!(mock.pings.load(Ordering::SeqCst), 1);
    assert_eq!(
        mock.closes.load(Ordering::SeqCst),
        1,
        "a failed probe must close the old transport before restart"
    );
}

#[tokio::test]
async fn health_probe_restarts_on_malformed_json_rpc_response() {
    let backend = Arc::new(Backend::new(
        "test",
        BackendConfig::default(),
        &crate::config::FailsafeConfig::default(),
        Duration::from_secs(60),
    ));
    let mock = Arc::new(RecoveryMock::responding(JsonRpcResponse {
        jsonrpc: "1.0".to_string(),
        id: Some(RequestId::Number(1)),
        result: Some(json!({})),
        error: None,
    }));
    backend.set_transport_for_test(mock.clone() as Arc<dyn Transport>);

    let result = backend.health_probe(Duration::from_secs(5)).await;

    assert!(
        result.is_err(),
        "a malformed response cannot prove liveness"
    );
    assert_eq!(mock.closes.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn health_probe_restarts_a_wedged_transport_after_timeout() {
    let backend = Arc::new(Backend::new(
        "test",
        BackendConfig::default(),
        &crate::config::FailsafeConfig::default(),
        Duration::from_secs(60),
    ));
    let mock = Arc::new(RecoveryMock::delayed(Duration::from_secs(5)));
    backend.set_transport_for_test(mock.clone() as Arc<dyn Transport>);

    let result = backend.health_probe(Duration::from_millis(10)).await;

    assert!(result.is_err(), "a wedged transport must time out");
    assert_eq!(mock.pings.load(Ordering::SeqCst), 1);
    assert_eq!(
        mock.closes.load(Ordering::SeqCst),
        1,
        "a timed-out transport must be closed before restart"
    );
}

#[tokio::test]
async fn health_probe_restarts_when_backend_closes_response_channel() {
    let backend = Arc::new(Backend::new(
        "test",
        BackendConfig::default(),
        &crate::config::FailsafeConfig::default(),
        Duration::from_secs(60),
    ));
    let mock = Arc::new(RecoveryMock::connected());
    mock.eof.store(true, Ordering::Relaxed);
    backend.set_transport_for_test(mock.clone() as Arc<dyn Transport>);

    let result = backend.health_probe(Duration::from_secs(5)).await;

    assert!(result.is_err(), "EOF must not be mistaken for liveness");
    assert_eq!(mock.pings.load(Ordering::SeqCst), 1);
    assert_eq!(
        mock.closes.load(Ordering::SeqCst),
        1,
        "EOF must close the old transport before restart"
    );
}

#[cfg(unix)]
async fn run_health_probe_process(ping_error_code: i32) -> (Result<()>, Vec<String>) {
    let workspace = tempfile::tempdir().expect("create health-probe child workspace");
    let server = workspace.path().join("server.sh");
    std::fs::write(
        &server,
        r#"while IFS= read -r request; do
    id=$(printf '%s\n' "$request" | sed -n 's/.*"id":\([0-9][0-9]*\).*/\1/p')
    case "$request" in
        *'"method":"initialize"'*)
            printf '%s\n' initialize >> events.log
            printf '{"jsonrpc":"2.0","id":%s,"result":{"protocolVersion":"2025-11-25"}}\n' "$id"
            ;;
        *'"method":"notifications/initialized"'*)
            printf '%s\n' initialized >> events.log
            ;;
        *'"method":"ping"'*)
            printf '%s\n' ping >> events.log
            printf '{"jsonrpc":"2.0","id":%s,"error":{"code":%s,"message":"probe response"}}\n' "$id" "$PROBE_ERROR_CODE"
            ;;
    esac
done
"#,
    )
    .expect("write health-probe child server");

    let backend = Backend::new(
        "process-probe",
        BackendConfig {
            transport: TransportConfig::Stdio {
                command: "sh server.sh".to_string(),
                cwd: Some(workspace.path().to_string_lossy().into_owned()),
                protocol_version: None,
            },
            timeout: Duration::from_secs(2),
            env: HashMap::from([("PROBE_ERROR_CODE".to_string(), ping_error_code.to_string())]),
            ..BackendConfig::default()
        },
        &crate::config::FailsafeConfig::default(),
        Duration::from_secs(60),
    );

    let result = backend.health_probe(Duration::from_secs(2)).await;
    backend.stop().await.expect("stop health-probe child");

    let events = std::fs::read_to_string(workspace.path().join("events.log"))
        .expect("read health-probe child events");
    (result, events.lines().map(str::to_string).collect())
}

#[tokio::test]
#[cfg(unix)]
async fn health_probe_initializes_process_before_unsupported_ping_without_restart() {
    let (result, events) = run_health_probe_process(-32601).await;

    result.expect("a correlated method-not-found response proves process liveness");
    assert_eq!(
        events,
        ["initialize", "initialized", "ping"],
        "unsupported ping must not restart the initialized child process"
    );
}

#[tokio::test]
#[cfg(unix)]
async fn health_probe_initializes_process_before_ping_and_restarts_real_errors() {
    let (result, events) = run_health_probe_process(-32603).await;

    assert!(
        result.is_err(),
        "a non--32601 ping error must fail the probe"
    );
    assert_eq!(
        events,
        [
            "initialize",
            "initialized",
            "ping",
            "initialize",
            "initialized"
        ],
        "probe must initialize before ping and restart exactly once after a real error"
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
        match backend.create_oauth_client("https://backend.example") {
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
            .create_oauth_client("https://backend.example")
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
        plain.create_oauth_client("https://backend.example").is_ok(),
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
fn status_serialization_omits_backend_config_secrets() {
    let env_secret = "SENTINEL_STATUS_ENV_7e19";
    let header_secret = "SENTINEL_STATUS_HEADER_2c51";
    let url_secret = "SENTINEL_STATUS_URL_90d3";
    let backend = Backend::new(
        "status-secret",
        BackendConfig {
            transport: TransportConfig::Http {
                http_url: format!("https://svc.example.com/mcp?token={url_secret}"),
                streamable_http: true,
                protocol_version: None,
            },
            env: HashMap::from([("STATUS_ENV".to_string(), env_secret.to_string())]),
            headers: HashMap::from([("Authorization".to_string(), header_secret.to_string())]),
            ..BackendConfig::default()
        },
        &crate::config::FailsafeConfig::default(),
        Duration::from_secs(60),
    );

    let json = serde_json::to_string(&backend.status()).expect("serialize backend status");
    assert!(json.contains("status-secret"));
    for sentinel in [env_secret, header_secret, url_secret] {
        assert!(
            !json.contains(sentinel),
            "secret escaped BackendStatus: {json}"
        );
    }
    assert!(!json.contains("\"env\""));
    assert!(!json.contains("\"headers\""));
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
    let parts = shlex::split(&launch.command).expect("bridge command is shell-splitable");

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

fn sample_tool(name: &str) -> Tool {
    Tool {
        name: name.to_string(),
        title: None,
        description: Some(format!("{name} tool")),
        input_schema: json!({"type": "object"}),
        output_schema: None,
        annotations: None,
        role: None,
        projection: None,
    }
}

#[test]
fn normalize_tool_annotations_fills_missing_hints() {
    let mut tools = vec![sample_tool("search_messages"), sample_tool("send_message")];

    normalize_tool_annotations("beeper", &mut tools);

    let search = tools[0].annotations.as_ref().unwrap();
    assert_eq!(search.read_only_hint, Some(true));
    assert_eq!(search.destructive_hint, Some(false));
    assert_eq!(search.idempotent_hint, Some(true));
    assert_eq!(search.open_world_hint, Some(true));

    let send = tools[1].annotations.as_ref().unwrap();
    assert_eq!(send.read_only_hint, Some(false));
    assert_eq!(send.destructive_hint, Some(true));
    assert_eq!(send.idempotent_hint, Some(false));
    assert_eq!(send.open_world_hint, Some(true));
}

#[test]
fn normalize_tool_annotations_preserves_existing_true_hints_and_adds_false_hints() {
    let mut tool = sample_tool("recall");
    tool.annotations = Some(ToolAnnotations {
        read_only_hint: Some(true),
        destructive_hint: None,
        idempotent_hint: None,
        open_world_hint: None,
        title: None,
    });
    let mut tools = vec![tool];

    normalize_tool_annotations("hebb", &mut tools);

    let annotations = tools[0].annotations.as_ref().unwrap();
    assert_eq!(annotations.read_only_hint, Some(true));
    assert_eq!(annotations.destructive_hint, Some(false));
    assert_eq!(annotations.idempotent_hint, Some(true));
    assert_eq!(annotations.open_world_hint, Some(false));
}

#[test]
fn normalize_tool_annotations_preserves_downstream_annotation_title_and_hints() {
    let mut tool = sample_tool("remote_write");
    tool.annotations = Some(ToolAnnotations {
        title: Some("Remote Write".to_string()),
        read_only_hint: Some(false),
        destructive_hint: Some(false),
        idempotent_hint: Some(false),
        open_world_hint: Some(false),
    });
    let mut tools = vec![tool];

    normalize_tool_annotations("remote-api", &mut tools);

    let annotations = tools[0].annotations.as_ref().unwrap();
    assert_eq!(annotations.title.as_deref(), Some("Remote Write"));
    assert_eq!(annotations.read_only_hint, Some(false));
    assert_eq!(annotations.destructive_hint, Some(false));
    assert_eq!(annotations.idempotent_hint, Some(false));
    assert_eq!(annotations.open_world_hint, Some(false));
}

#[test]
fn cached_metadata_tracks_freshness() {
    let cache = CachedMetadata::new();
    assert!(!cache.is_fresh(Duration::from_secs(60)));

    cache.store_shared(Arc::new(vec![1, 2, 3]));

    assert!(cache.is_fresh(Duration::from_secs(60)));
    let snapshot = cache.snapshot_shared().unwrap();
    assert_eq!(snapshot.as_ref(), &vec![1, 2, 3]);
    assert_eq!(snapshot.len(), 3);
}

#[tokio::test]
async fn cached_metadata_shared_reads_reuse_arc() {
    let cache = CachedMetadata::new();

    let first = cache
        .get_or_fetch_shared(Duration::from_secs(60), || async { Ok(vec![1, 2, 3]) })
        .await
        .unwrap();
    let second = cache
        .get_or_fetch_shared(Duration::from_secs(60), || async {
            panic!("fresh cache hit should not refetch")
        })
        .await
        .unwrap();

    assert!(Arc::ptr_eq(&first, &second));
}

#[tokio::test]
async fn cached_metadata_retries_after_fetch_error() {
    let cache = CachedMetadata::new();
    let attempts = AtomicUsize::new(0);

    let first = cache
        .get_or_fetch_shared(Duration::from_secs(60), || async {
            let attempt = attempts.fetch_add(1, Ordering::SeqCst);
            if attempt == 0 {
                Err(Error::BackendUnavailable("boom".to_string()))
            } else {
                Ok(vec![7])
            }
        })
        .await;
    assert!(first.is_err());

    let second = cache
        .get_or_fetch_shared(Duration::from_secs(60), || async {
            let attempt = attempts.fetch_add(1, Ordering::SeqCst);
            if attempt == 0 {
                Err(Error::BackendUnavailable("boom".to_string()))
            } else {
                Ok(vec![7])
            }
        })
        .await;

    assert_eq!(second.unwrap().as_ref(), &vec![7]);
    assert_eq!(attempts.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn get_tools_singleflight_coalesces_concurrent_requests() {
    let backend = Arc::new(Backend::new(
        "test",
        BackendConfig::default(),
        &crate::config::FailsafeConfig::default(),
        Duration::from_secs(60),
    ));
    let response = JsonRpcResponse::success_serialized(
        RequestId::Number(1),
        ToolsListResult {
            tools: vec![sample_tool("echo")],
            next_cursor: None,
        },
    );
    let transport = Arc::new(MockTransport::new(response, Duration::from_millis(25)));
    let transport_dyn: Arc<dyn Transport> = transport.clone();
    backend.set_transport_for_test(transport_dyn);

    let barrier = Arc::new(Barrier::new(6));
    let mut tasks = Vec::new();
    for _ in 0..5 {
        let backend = Arc::clone(&backend);
        let barrier = Arc::clone(&barrier);
        tasks.push(tokio::spawn(async move {
            barrier.wait().await;
            backend.get_tools().await.unwrap()
        }));
    }

    barrier.wait().await;

    for task in tasks {
        let tools = task.await.unwrap();
        assert_eq!(tools.len(), 1);
        assert_eq!(tools[0].name, "echo");
    }

    assert_eq!(transport.requests.load(Ordering::SeqCst), 1);
    assert!(backend.has_cached_tools());
    assert_eq!(backend.cached_tools_count(), 1);
    assert_eq!(
        backend.get_cached_tool("echo").map(|tool| tool.name),
        Some("echo".to_string())
    );
}

#[tokio::test]
async fn get_tools_does_not_cache_json_rpc_error_response() {
    let backend = Arc::new(Backend::new(
        "test",
        BackendConfig::default(),
        &crate::config::FailsafeConfig::default(),
        Duration::from_secs(60),
    ));
    let response = JsonRpcResponse::error(Some(RequestId::Number(1)), -32000, "backend down");
    let transport = Arc::new(MockTransport::new(response, Duration::from_millis(0)));
    let transport_dyn: Arc<dyn Transport> = transport.clone();
    backend.set_transport_for_test(transport_dyn);

    let result = backend.get_tools().await;

    assert!(result.is_err());
    assert!(!backend.has_cached_tools());
    assert_eq!(transport.requests.load(Ordering::SeqCst), 1);
}

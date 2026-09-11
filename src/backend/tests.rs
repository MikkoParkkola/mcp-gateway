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
    pings: AtomicUsize,
}

impl RecoveryMock {
    fn connected() -> Self {
        Self {
            connected: AtomicBool::new(true),
            fail: AtomicBool::new(false),
            pings: AtomicUsize::new(0),
        }
    }
}

#[async_trait]
impl Transport for RecoveryMock {
    async fn request(&self, _method: &str, _params: Option<Value>) -> Result<JsonRpcResponse> {
        self.pings.fetch_add(1, Ordering::SeqCst);
        if self.fail.load(Ordering::Relaxed) {
            return Err(Error::BackendUnavailable("probe failed".to_string()));
        }
        Ok(JsonRpcResponse::success_serialized(
            RequestId::Number(1),
            json!({}),
        ))
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

    prepare_tool_metadata("beeper", &mut tools);

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

    prepare_tool_metadata("hebb", &mut tools);

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

    prepare_tool_metadata("remote-api", &mut tools);

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

// --- MIK-7214.HEADER.8 — tools violating an `x-mcp-header` constraint are
// excluded from `tools/list`, on the same tool-metadata path as the
// destructive-annotation gate.

fn tool_with_schema(name: &str, input_schema: serde_json::Value) -> Tool {
    let mut tool = sample_tool(name);
    tool.input_schema = input_schema;
    tool
}

#[test]
fn prepare_tool_metadata_keeps_a_well_formed_annotation() {
    // GIVEN one tool whose `x-mcp-header` meets every constraint
    let mut tools = vec![tool_with_schema(
        "search",
        json!({"type": "object", "properties": {
            "tenant": {"type": "string", "x-mcp-header": "Tenant"}
        }}),
    )];

    // WHEN the tool-metadata path filters the list
    prepare_tool_metadata("beeper", &mut tools);

    // THEN it survives
    assert_eq!(tools.len(), 1);
    assert_eq!(tools[0].name, "search");
}

#[test]
fn prepare_tool_metadata_drops_only_the_violating_tool() {
    // GIVEN a valid tool beside one annotating a `number` property
    let mut tools = vec![
        tool_with_schema("keep", json!({"type": "object", "properties": {}})),
        tool_with_schema(
            "drop",
            json!({"type": "object", "properties": {
                "ratio": {"type": "number", "x-mcp-header": "Ratio"}
            }}),
        ),
    ];

    prepare_tool_metadata("beeper", &mut tools);

    // THEN exclusion is per-tool, never per-backend
    assert_eq!(tools.len(), 1);
    assert_eq!(tools[0].name, "keep");
}

#[test]
fn prepare_tool_metadata_drops_a_crlf_injection_attempt() {
    let mut tools = vec![tool_with_schema(
        "inject",
        json!({"type": "object", "properties": {
            "tenant": {"type": "string", "x-mcp-header": "T\r\nX-Injected: 1"}
        }}),
    )];

    prepare_tool_metadata("beeper", &mut tools);

    assert!(
        tools.is_empty(),
        "a control character must exclude the tool"
    );
}

#[test]
fn prepare_tool_metadata_leaves_unannotated_tools_untouched() {
    let mut tools = vec![sample_tool("plain"), sample_tool("also_plain")];

    prepare_tool_metadata("beeper", &mut tools);

    assert_eq!(tools.len(), 2);
}

#[test]
fn prepare_tool_metadata_excludes_and_annotates_in_one_pass() {
    // GIVEN a violating tool beside one that needs its hints inferred
    let mut tools = vec![
        tool_with_schema(
            "bad",
            json!({"type": "object", "properties": {
                "tenant": {"type": "string", "x-mcp-header": "Tenant Id"}
            }}),
        ),
        tool_with_schema("get_thing", json!({"type": "object"})),
    ];

    // WHEN the single tool-metadata entry point runs
    prepare_tool_metadata("beeper", &mut tools);

    // THEN both steps happened: neither caller can get one without the other
    assert_eq!(tools.len(), 1);
    assert_eq!(tools[0].name, "get_thing");
    assert_eq!(
        tools[0].annotations.as_ref().and_then(|a| a.read_only_hint),
        Some(true)
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

// ── MIK-7217 OUTBOUND.1/.2 — era-gated health probe ─────────────────────
//
// Rows from section 6 of
// `docs/design/2026-09-11-outbound-era-gated-health-probe.md`. Each test names
// the row it pins. Rows marked fail-first there must fail against HEAD; a row
// that passes today is pinning something other than the defect it names.

/// One scripted answer from the peer, in the shape the probe actually receives
/// it. The two error shapes are not interchangeable: an in-band JSON-RPC error
/// is `Ok(JsonRpcResponse)` with `error` set (stdio, WebSocket), a
/// status-carried one is `Err(Error::JsonRpc)` (HTTP). An implementation that
/// covers only the first restarts every HTTP peer that declines a probe.
#[derive(Clone)]
enum ProbeAnswer {
    Result(Value),
    InBandError(i32),
    StatusError(i32),
    Fault,
}

/// Records the method of every request and answers from a script, so a row can
/// pin *which* method reached the wire rather than only how many did.
struct ProbeMock {
    methods: std::sync::Mutex<Vec<String>>,
    answers: std::sync::Mutex<std::collections::VecDeque<ProbeAnswer>>,
    /// Answer given once the script runs out. It exists because an
    /// invalidation spawns a **detached** classification probe: that probe
    /// draws from the same mock at a time no test controls, so a row scripting
    /// one answer per tick would be racing it for queue slots. A standing
    /// answer makes every row that outlives its script deterministic.
    default_answer: std::sync::Mutex<ProbeAnswer>,
    connected: AtomicBool,
}

impl ProbeMock {
    fn scripted(answers: Vec<ProbeAnswer>) -> Self {
        Self {
            methods: std::sync::Mutex::new(Vec::new()),
            answers: std::sync::Mutex::new(answers.into()),
            default_answer: std::sync::Mutex::new(ProbeAnswer::Result(json!({}))),
            connected: AtomicBool::new(true),
        }
    }

    /// The era classification probe answers `server/discover` with a code only
    /// a modern peer knows, which is what leaves the cache `Probed`/`Modern`.
    /// `-32601` would do the opposite: `classify` reads it as legacy evidence.
    fn modern_then(mut rest: Vec<ProbeAnswer>) -> Self {
        let mut answers = vec![ProbeAnswer::InBandError(
            crate::protocol::era::UNSUPPORTED_PROTOCOL_VERSION,
        )];
        answers.append(&mut rest);
        Self::scripted(answers)
    }

    /// The mirror of `modern_then`: `-32601` to `server/discover` is the
    /// honest legacy answer, so this leaves the cache `Probed`/`Legacy`.
    fn legacy_then(mut rest: Vec<ProbeAnswer>) -> Self {
        let mut answers = vec![ProbeAnswer::InBandError(
            crate::protocol::era::METHOD_NOT_FOUND_CODE,
        )];
        answers.append(&mut rest);
        Self::scripted(answers)
    }

    /// Set the standing answer. Rows that need the peer's behaviour to change
    /// mid-test use this rather than lengthening the script, so a detached
    /// probe arriving late gets the same answer a tick would.
    fn set_default(&self, answer: ProbeAnswer) {
        *self.default_answer.lock().expect("default lock") = answer;
    }

    /// Refuse everything after the scripted prefix, the way a peer that knows
    /// neither `server/discover` nor `ping` does.
    fn refusing(self, code: i32) -> Self {
        self.set_default(ProbeAnswer::InBandError(code));
        self
    }

    fn methods(&self) -> Vec<String> {
        self.methods.lock().expect("methods lock").clone()
    }

    /// Methods seen after the era classification probe consumed the first one.
    fn probed_methods(&self) -> Vec<String> {
        self.methods().into_iter().skip(1).collect()
    }
}

#[async_trait]
impl Transport for ProbeMock {
    async fn request(&self, method: &str, _params: Option<Value>) -> Result<JsonRpcResponse> {
        self.methods
            .lock()
            .expect("methods lock")
            .push(method.to_string());
        let answer = self
            .answers
            .lock()
            .expect("answers lock")
            .pop_front()
            .unwrap_or_else(|| self.default_answer.lock().expect("default lock").clone());
        match answer {
            ProbeAnswer::Result(value) => Ok(JsonRpcResponse::success_serialized(
                RequestId::Number(1),
                value,
            )),
            ProbeAnswer::InBandError(code) => Ok(JsonRpcResponse::error(
                Some(RequestId::Number(1)),
                code,
                "declined",
            )),
            ProbeAnswer::StatusError(code) => Err(Error::JsonRpc {
                code,
                message: "declined".to_string(),
                data: None,
            }),
            ProbeAnswer::Fault => Err(Error::BackendUnavailable("socket closed".to_string())),
        }
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

/// Whether the shared pool slot still holds `mock`.
///
/// `force_restart` takes the transport out of that slot before it does anything
/// else, so losing the slot is the probe's restart observable. Counting
/// `close()` calls is not: the probe holds an internal-activity lease for its
/// whole duration, so `force_restart` always takes its busy branch and defers
/// the close to a task that waits for every other owner of the `Arc` to let
/// go, and a test that keeps `mock` to assert on is one of those owners, so
/// the count cannot move in any row here. Row 7 is the control that proves
/// this observable does.
fn still_wired(backend: &Backend, mock: &Arc<ProbeMock>) -> bool {
    backend
        .pooled_transport_for_test(&crate::backend::pool::PoolKey::Shared)
        .is_some_and(|t| std::ptr::addr_eq(Arc::as_ptr(&t), Arc::as_ptr(mock)))
}

/// A backend wired to `mock`, with its era resolved from the mock's first
/// scripted answer when `classify` is asked to run.
async fn probe_backend(mock: Arc<ProbeMock>, resolve_era: bool) -> Arc<Backend> {
    let backend = Arc::new(Backend::new(
        "test",
        BackendConfig::default(),
        &crate::config::FailsafeConfig::default(),
        Duration::from_secs(60),
    ));
    let transport = mock as Arc<dyn Transport>;
    backend.set_transport_for_test(Arc::clone(&transport));
    if resolve_era {
        backend.resolve_era(&transport).await;
    }
    backend
}

/// Row 1 — a modern peer is asked the modern liveness method. `ping` was
/// removed in the 2026-07-28 revision, so putting it on a modern wire is the
/// outbound defect OUTBOUND.1 names.
#[tokio::test]
async fn row_1_modern_backend_is_probed_with_server_discover() {
    let mock = Arc::new(ProbeMock::modern_then(vec![ProbeAnswer::Result(json!({}))]));
    let backend = probe_backend(Arc::clone(&mock), true).await;
    assert_eq!(
        backend.cached_era().await,
        Some(crate::protocol::era::Era::Modern),
        "precondition: the fixture must construct a modern peer"
    );

    let _ = backend.health_probe(Duration::from_secs(5)).await;

    assert_eq!(
        mock.probed_methods(),
        vec!["server/discover".to_string()],
        "a modern peer is probed with server/discover"
    );
    assert!(
        !mock.methods().contains(&"ping".to_string()),
        "ping must never reach a modern peer"
    );
}

/// Row 2 — regression guard. It passes at HEAD, which sends `ping` to
/// everything; it exists to catch the mirror-image defect once row 1 lands.
#[tokio::test]
async fn row_2_legacy_backend_is_probed_with_ping() {
    let mock = Arc::new(ProbeMock::scripted(vec![
        ProbeAnswer::InBandError(crate::protocol::era::METHOD_NOT_FOUND_CODE),
        ProbeAnswer::Result(json!({})),
    ]));
    let backend = probe_backend(Arc::clone(&mock), true).await;
    assert_eq!(
        backend.cached_era().await,
        Some(crate::protocol::era::Era::Legacy),
        "precondition: -32601 to server/discover classifies the peer legacy"
    );

    let _ = backend.health_probe(Duration::from_secs(5)).await;

    assert_eq!(mock.probed_methods(), vec!["ping".to_string()]);
}

/// Row 3 — regression guard. An era that was never resolved is not modern:
/// `classify`'s rule is that silence is never evidence of modernity, and this
/// pins that rule at the probe's call site rather than at `classify`'s.
#[tokio::test]
async fn row_3_unclassified_backend_takes_the_legacy_arm() {
    let mock = Arc::new(ProbeMock::scripted(vec![ProbeAnswer::Result(json!({}))]));
    let backend = probe_backend(Arc::clone(&mock), false).await;
    assert_eq!(
        backend.cached_era().await,
        None,
        "precondition: the era was never resolved"
    );

    let _ = backend.health_probe(Duration::from_secs(5)).await;

    assert_eq!(mock.methods(), vec!["ping".to_string()]);
}

/// Row 4 — an in-band `-32601` is an *unserved* answer, not a healthy one: the
/// peer answered, so nothing is broken, but it did not serve the probe. HEAD
/// reads any `Ok(Ok(_))` as success and resets the breaker.
///
/// The row's third assertion in section 6, "counter increments", is not made
/// here: the consecutive-unserved count does not exist at HEAD, and a test that
/// fails to compile records no fail-first evidence. Rows 10 to 11b pin the
/// counter once it exists.
#[tokio::test]
async fn row_4_in_band_method_not_found_is_unserved_not_healthy() {
    let mock = Arc::new(ProbeMock::legacy_then(vec![ProbeAnswer::InBandError(
        crate::protocol::era::METHOD_NOT_FOUND_CODE,
    )]));
    let backend = probe_backend(Arc::clone(&mock), true).await;
    backend.trip_circuit_breaker_for_test();

    let _ = backend.health_probe(Duration::from_secs(5)).await;

    assert!(
        backend.is_circuit_tripped(),
        "an unserved answer is not evidence of health and must not reset the breaker"
    );
    assert!(
        still_wired(&backend, &mock),
        "an unserved answer is not a fault and must not restart the backend"
    );
}

/// Row 5 — the same `-32601`, carried as an HTTP 404 with a JSON-RPC error
/// body. HEAD sees `Ok(Err(_))` and calls `force_restart()`, so a peer that
/// merely declines the probe is torn down. Same counter caveat as row 4.
#[tokio::test]
async fn row_5_status_carried_method_not_found_is_unserved_not_a_fault() {
    let mock = Arc::new(ProbeMock::legacy_then(vec![ProbeAnswer::StatusError(
        crate::protocol::era::METHOD_NOT_FOUND_CODE,
    )]));
    let backend = probe_backend(Arc::clone(&mock), true).await;
    backend.trip_circuit_breaker_for_test();

    let _ = backend.health_probe(Duration::from_secs(5)).await;

    assert!(
        still_wired(&backend, &mock),
        "a status-carried decline is still a decline, not a fault"
    );
    assert!(backend.is_circuit_tripped());
}

/// Row 6 — the widened middle arm. `-32603` is not method-not-found, and the
/// era assertion is what stops an implementation from widening *invalidation*
/// along with the unserved arm: only method-not-found is evidence about era.
///
/// That era assertion is a second-stage pin, not part of this row's fail-first
/// evidence: at HEAD the row stops on the breaker assertion, which is row 4's
/// defect, and HEAD has no invalidation path that could move the era at all.
/// It begins to discriminate once the widened arm lands. Row 6b is the same
/// shape, stopping on the restart instead.
#[tokio::test]
async fn row_6_in_band_internal_error_is_unserved_and_leaves_the_era_alone() {
    let mock = Arc::new(ProbeMock::modern_then(vec![ProbeAnswer::InBandError(
        crate::error::rpc_codes::INTERNAL_ERROR,
    )]));
    let backend = probe_backend(Arc::clone(&mock), true).await;
    backend.trip_circuit_breaker_for_test();

    let _ = backend.health_probe(Duration::from_secs(5)).await;

    assert!(backend.is_circuit_tripped());
    assert!(still_wired(&backend, &mock));
    assert_eq!(
        backend.cached_era().await,
        Some(crate::protocol::era::Era::Modern),
        "only method-not-found is evidence about era; -32603 says nothing"
    );
}

/// Row 6b — where the two halves of section 3 meet: the widened arm *and* the
/// status carriage. An implementation that faults on any parsed code except
/// `-32601` passes every other row while restarting backends it must not.
#[tokio::test]
async fn row_6b_status_carried_internal_error_is_unserved_and_leaves_the_era_alone() {
    let mock = Arc::new(ProbeMock::modern_then(vec![ProbeAnswer::StatusError(
        crate::error::rpc_codes::INTERNAL_ERROR,
    )]));
    let backend = probe_backend(Arc::clone(&mock), true).await;
    backend.trip_circuit_breaker_for_test();

    let _ = backend.health_probe(Duration::from_secs(5)).await;

    assert!(
        still_wired(&backend, &mock),
        "a status-carried -32603 is still a decline, not a fault"
    );
    assert!(backend.is_circuit_tripped());
    assert_eq!(
        backend.cached_era().await,
        Some(crate::protocol::era::Era::Modern),
        "a status-carried -32603 is not evidence about era either"
    );
}

/// Row 7 — regression guard, and the control for every `still_wired` assertion
/// above: a transport fault still restarts the backend. If this row ever passes
/// while reporting the mock still wired, rows 5 and 6b are green because the
/// observable is dead, not because the probe stopped restarting.
#[tokio::test]
async fn row_7_a_transport_fault_still_restarts() {
    let mock = Arc::new(ProbeMock::legacy_then(vec![ProbeAnswer::Fault]));
    let backend = probe_backend(Arc::clone(&mock), true).await;

    let _ = backend.health_probe(Duration::from_secs(5)).await;

    assert!(
        !still_wired(&backend, &mock),
        "a closed socket is a fault and must still rebuild the transport"
    );
}

/// Row 8 — regression guard: a served `ping` on the legacy arm still resets a
/// tripped breaker. It guards against fixing rows 4 to 6 by making nothing
/// healthy.
#[tokio::test]
async fn row_8_a_ping_result_on_the_legacy_arm_resets_the_breaker() {
    let mock = Arc::new(ProbeMock::legacy_then(vec![ProbeAnswer::Result(json!({}))]));
    let backend = probe_backend(Arc::clone(&mock), true).await;
    backend.trip_circuit_breaker_for_test();

    let _ = backend.health_probe(Duration::from_secs(5)).await;

    assert_eq!(mock.probed_methods(), vec!["ping".to_string()]);
    assert!(
        !backend.is_circuit_tripped(),
        "a served answer is evidence of health and must reset the breaker"
    );
}

/// Row 8b — the mirror half, and fail-first: the reset must be wired to the
/// *result*, not to the legacy branch that happens to carry it today. HEAD
/// never sends `server/discover` from the probe, so the method assertion is
/// what fails here.
#[tokio::test]
async fn row_8b_a_discover_result_on_the_modern_arm_resets_the_breaker() {
    let mock = Arc::new(ProbeMock::modern_then(vec![ProbeAnswer::Result(json!({}))]));
    let backend = probe_backend(Arc::clone(&mock), true).await;
    backend.trip_circuit_breaker_for_test();

    let _ = backend.health_probe(Duration::from_secs(5)).await;

    assert_eq!(
        mock.probed_methods(),
        vec!["server/discover".to_string()],
        "a modern peer is probed with server/discover"
    );
    assert!(
        !backend.is_circuit_tripped(),
        "the reset belongs to the result, not to the arm that carries it"
    );
}

/// Row 9 — `-32601` *to `server/discover`* is the one answer that is evidence
/// about era, and the cached verdict must not survive it.
///
/// Only the accessor is asserted. "The next tick sends `ping`" is a property of
/// rows 1 and 2 composed with this one: those rows pin method selection as a
/// function of the era, so re-asserting it here would add a second observation
/// of the same rule - and it cannot be observed cleanly anyway, because the
/// invalidation spawns a detached classification probe whose `server/discover`
/// lands on the same wire at a time no test controls.
#[tokio::test]
async fn row_9_method_not_found_to_discover_invalidates_the_cached_era() {
    let mock = Arc::new(ProbeMock::modern_then(vec![ProbeAnswer::InBandError(
        crate::protocol::era::METHOD_NOT_FOUND_CODE,
    )]));
    let backend = probe_backend(Arc::clone(&mock), true).await;
    assert_eq!(
        backend.cached_era().await,
        Some(crate::protocol::era::Era::Modern)
    );

    let _ = backend.health_probe(Duration::from_secs(5)).await;

    assert_ne!(
        backend.cached_era().await,
        Some(crate::protocol::era::Era::Modern),
        "a peer that does not know server/discover is not modern, whatever the probe said"
    );
}

/// Row 9e — the status-carried twin of row 9, and the one row that pins the
/// only new plumbing section 3 adds: a `-32601` arriving as `Err(Error::JsonRpc)`
/// is the same evidence about era as the in-band one. Row 9 is in-band only and
/// row 5 starts from a legacy cache, so without this row an HTTP peer that
/// refuses `server/discover` with a 404 keeps a `Modern` cache and is probed
/// forever with the method it just refused.
#[tokio::test]
async fn row_9e_a_status_carried_method_not_found_also_invalidates_the_era() {
    let mock = Arc::new(ProbeMock::modern_then(vec![ProbeAnswer::StatusError(
        crate::protocol::era::METHOD_NOT_FOUND_CODE,
    )]));
    let backend = probe_backend(Arc::clone(&mock), true).await;
    assert_eq!(
        backend.cached_era().await,
        Some(crate::protocol::era::Era::Modern)
    );

    let _ = backend.health_probe(Duration::from_secs(5)).await;

    assert_ne!(
        backend.cached_era().await,
        Some(crate::protocol::era::Era::Modern),
        "a refusal carried by the status line is the same evidence as an in-band one"
    );
}

/// Row 9c — re-classification comes only from positive evidence, never from an
/// absence. A served `ping` says nothing about the era, and an implementation
/// reading any successful probe as "the peer is fine, restore what we thought"
/// sends the modern liveness method to a peer just reclassified as legacy.
#[tokio::test]
async fn row_9c_a_served_ping_is_not_evidence_of_modernity() {
    let mock = Arc::new(ProbeMock::modern_then(vec![ProbeAnswer::InBandError(
        crate::protocol::era::METHOD_NOT_FOUND_CODE,
    )]));
    let backend = probe_backend(Arc::clone(&mock), true).await;

    let _ = backend.health_probe(Duration::from_secs(5)).await;
    let _ = backend.health_probe(Duration::from_secs(5)).await;

    assert_ne!(
        backend.cached_era().await,
        Some(crate::protocol::era::Era::Modern),
        "an answered ping is an absence of evidence about the era, not positive evidence"
    );
}

/// Row 9b — re-classification works in both directions, and the evidence
/// arrives **off the probe path**. The start path's `resolve_era` is what
/// returns a peer to `Era::Modern`, and the tick that follows must select the
/// modern method again. Restoring the verdict without restoring the method
/// selection is the mirror-image OUTBOUND.1 defect, so the row asserts the
/// method of one controlled tick rather than the accessor alone.
#[tokio::test]
async fn row_9b_positive_evidence_off_the_probe_path_reclassifies_the_peer() {
    let mock = Arc::new(
        ProbeMock::modern_then(vec![]).refusing(crate::protocol::era::METHOD_NOT_FOUND_CODE),
    );
    let backend = probe_backend(Arc::clone(&mock), true).await;

    let _ = backend.health_probe(Duration::from_secs(5)).await;
    assert_ne!(
        backend.cached_era().await,
        Some(crate::protocol::era::Era::Modern),
        "the -32601 to server/discover must drop the cached verdict"
    );

    // The peer is replaced by one that answers discovery properly - an upgrade,
    // as far as the gateway can tell - and the start path probes it again.
    mock.set_default(ProbeAnswer::Result(json!({
        "capabilities": {},
        "supportedVersions": [crate::protocol::meta::MODERN_VERSIONS[0]],
    })));
    let transport = Arc::clone(&mock) as Arc<dyn Transport>;
    backend.resolve_era(&transport).await;

    assert_eq!(
        backend.cached_era().await,
        Some(crate::protocol::era::Era::Modern),
        "positive evidence must be able to restore the modern verdict"
    );

    // One controlled tick after the restoration. Snapshotting first is what
    // makes it controlled: `resolve_era` and any detached probe have already
    // written their methods, so the tail below belongs to this tick alone.
    let before = mock.methods().len();
    let _ = backend.health_probe(Duration::from_secs(5)).await;
    assert_eq!(
        mock.methods()[before..],
        ["server/discover".to_string()],
        "a peer restored to Modern is probed with the modern method again"
    );
}

/// Row 9d — the escalation sequence section 3 uses to justify the bound, end to
/// end, and the one that crosses an era invalidation: `server/discover` refused
/// (invalidate, 1), `ping` refused (2), `ping` refused (3, trip and restart).
/// An implementation that resets the unserved count when it invalidates the era
/// leaves a refuse-everything backend permanently wedged and green.
#[tokio::test]
async fn row_9d_three_unserved_answers_across_an_invalidation_still_escalate() {
    let mock = Arc::new(
        ProbeMock::modern_then(vec![]).refusing(crate::protocol::era::METHOD_NOT_FOUND_CODE),
    );
    let backend = probe_backend(Arc::clone(&mock), true).await;

    for _ in 0..3 {
        let _ = backend.health_probe(Duration::from_secs(5)).await;
    }

    assert!(
        backend.is_circuit_tripped(),
        "three consecutive unserved answers must trip the breaker"
    );
    assert!(
        !still_wired(&backend, &mock),
        "the third unserved answer escalates to a restart"
    );
}

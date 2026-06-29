use super::{
    ContainerProvider, LocalProcessProvider, RuntimeApplyAction, RuntimeApplyError,
    RuntimeApplyRequest, RuntimeApplyStatus, RuntimeAvailability, RuntimeCommandOutcome,
    RuntimeCommandRunner, RuntimeDataClass, RuntimeDenyReason, RuntimeIntent, RuntimeLaunchCommand,
    RuntimeMount, RuntimeMountMode, RuntimeNetworkEgress, RuntimePlanner, RuntimeProvider,
    RuntimeProviderKind, RuntimeProviderSelection, StdRuntimeCommandRunner,
};

#[derive(Default)]
struct RecordingRunner {
    calls: Vec<(RuntimeLaunchCommand, Vec<String>)>,
}

impl RuntimeCommandRunner for RecordingRunner {
    fn run(
        &mut self,
        command: &RuntimeLaunchCommand,
        env_keys: &[String],
    ) -> Result<RuntimeCommandOutcome, RuntimeApplyError> {
        self.calls.push((command.clone(), env_keys.to_vec()));
        Ok(RuntimeCommandOutcome {
            external_id: Some("fixture-runtime-id".to_string()),
            exit_code: Some(0),
            stdout: "fixture-runtime-id\n".to_string(),
            stderr: String::new(),
        })
    }
}

#[test]
fn planner_prefers_docker_for_sensitive_server_when_available() {
    let planner = RuntimePlanner::new(RuntimeAvailability::with_docker());
    let mut intent = RuntimeIntent::named("gmail");
    intent.image = Some("ghcr.io/example/gmail-mcp:1".to_string());
    intent.data_class = RuntimeDataClass::Sensitive;

    let plan = planner.plan(&intent);

    assert_eq!(plan.provider, RuntimeProviderKind::Docker);
    assert_eq!(plan.audit.license_tier, super::RuntimeLicenseTier::FreeCore);
    assert_eq!(
        plan.recommendation.selected_by,
        RuntimeProviderSelection::IsolationPreferred
    );
    assert!(plan.recommendation.reason.contains("isolate"));
    assert!(!plan.is_denied());
}

#[test]
fn planner_falls_back_to_local_process_when_container_is_unavailable() {
    let planner = RuntimePlanner::new(RuntimeAvailability::local_only());
    let mut intent = RuntimeIntent::named("filesystem");
    intent.data_class = RuntimeDataClass::HighPrivilege;

    let plan = planner.plan(&intent);

    assert_eq!(plan.provider, RuntimeProviderKind::LocalProcess);
    assert_eq!(
        plan.recommendation.selected_by,
        RuntimeProviderSelection::CompatibilityFallback
    );
    assert!(plan.recommendation.reason.contains("compatibility"));
    assert!(!plan.is_denied());
    assert_eq!(
        plan.preflight_checks[0].check,
        "verify executable is available on PATH"
    );
}

#[test]
fn planner_emits_executable_docker_lifecycle_command() {
    let planner = RuntimePlanner::new(RuntimeAvailability::with_docker());
    let mut intent = RuntimeIntent::named("gmail");
    intent.image = Some("ghcr.io/example/gmail-mcp:1".to_string());
    intent.data_class = RuntimeDataClass::Sensitive;
    intent.env_keys = vec!["GMAIL_HANDLE".to_string()];

    let plan = planner.plan(&intent);
    let start = plan.lifecycle.start_command_hint.as_deref().unwrap();

    assert_eq!(plan.provider, RuntimeProviderKind::Docker);
    assert!(start.contains("docker run"));
    assert!(start.contains("--detach"));
    assert!(start.contains("--network=none"));
    assert!(start.contains("--restart=on-failure:2"));
    assert!(!start.contains("--rm"));
    assert!(start.contains("--read-only"));
    assert!(start.contains("--cap-drop=ALL"));
    assert!(start.contains("--security-opt=no-new-privileges"));
    assert!(start.contains("--env GMAIL_HANDLE"));
    assert!(plan.lifecycle.health_check.contains("docker inspect"));
    assert_eq!(
        plan.lifecycle.logs_hint.as_deref(),
        Some("docker logs mcp-gateway-gmail")
    );
    assert_eq!(
        plan.lifecycle.restart_command_hint.as_deref(),
        Some("docker restart mcp-gateway-gmail")
    );
    assert_eq!(plan.apply_command.as_deref(), Some(start));
    assert_eq!(
        plan.launch_command
            .as_ref()
            .map(|command| command.program.as_str()),
        Some("docker")
    );
    assert_eq!(
        plan.health_command.as_ref().map(|command| &command.args),
        Some(&vec![
            "inspect".to_string(),
            "--format".to_string(),
            "{{.State.Running}}".to_string(),
            "mcp-gateway-gmail".to_string(),
        ])
    );
    assert_eq!(
        plan.logs_command.as_ref().map(|command| &command.args),
        Some(&vec![
            "logs".to_string(),
            "--tail".to_string(),
            "200".to_string(),
            "mcp-gateway-gmail".to_string(),
        ])
    );
    assert_eq!(
        plan.stop_command.as_ref().map(|command| &command.args),
        Some(&vec![
            "rm".to_string(),
            "--force".to_string(),
            "mcp-gateway-gmail".to_string(),
        ])
    );
    assert_eq!(
        plan.restart_command.as_ref().map(|command| &command.args),
        Some(&vec![
            "restart".to_string(),
            "mcp-gateway-gmail".to_string(),
        ])
    );
}

#[test]
fn docker_launch_uses_rm_only_when_restart_policy_disabled() {
    let planner = RuntimePlanner::new(RuntimeAvailability::with_docker());
    let mut intent = RuntimeIntent::named("one-shot");
    intent.image = Some("ghcr.io/example/one-shot:1".to_string());
    let mut policy = planner.compile_default_policy(&intent);
    policy.restart.max_restarts = 0;

    let plan = planner.plan_with_policy(&intent, RuntimeProviderKind::Docker, policy);
    let start = plan.lifecycle.start_command_hint.as_deref().unwrap();

    assert!(start.contains("--rm"));
    assert!(!start.contains("--restart=on-failure"));
}

#[test]
fn local_lifecycle_preserves_existing_executable_hint() {
    let planner = RuntimePlanner::new(RuntimeAvailability::local_only());
    let mut intent = RuntimeIntent::named("local-docs");
    intent.executable = Some("mcp-docs-server".to_string());

    let plan = planner.plan(&intent);

    assert_eq!(plan.provider, RuntimeProviderKind::LocalProcess);
    assert_eq!(
        plan.lifecycle.start_command_hint.as_deref(),
        Some("mcp-docs-server")
    );
    assert!(plan.lifecycle.health_check.contains("stdio"));
    assert!(plan.lifecycle.rollback_step.contains("direct-launch"));
    assert_eq!(plan.apply_command.as_deref(), Some("mcp-docs-server"));
}

#[test]
fn policy_compiler_records_guarded_names_without_values() {
    let planner = RuntimePlanner::new(RuntimeAvailability::local_only());
    let mut intent = RuntimeIntent::named("service-api");
    intent.env_keys = vec!["SERVICE_HANDLE".to_string(), "SAFE_MODE".to_string()];
    intent.guarded_env_keys = vec!["SERVICE_HANDLE".to_string()];

    let plan = planner.plan(&intent);
    let serialized = serde_json::to_string(&plan).unwrap();

    assert!(
        plan.policy
            .env
            .allowed_keys
            .contains(&"SERVICE_HANDLE".to_string())
    );
    assert!(
        plan.policy
            .env
            .guarded_keys
            .contains(&"SERVICE_HANDLE".to_string())
    );
    assert!(plan.requires_confirmation());
    assert!(!serialized.contains("handle-value"));
}

#[test]
fn broad_egress_requires_human_confirmation() {
    let planner = RuntimePlanner::new(RuntimeAvailability::local_only());
    let mut intent = RuntimeIntent::named("remote-search");
    intent.requested_egress = RuntimeNetworkEgress::Full;

    let plan = planner.plan(&intent);

    assert!(
        plan.confirmations
            .iter()
            .any(|confirmation| confirmation.id == "network.full_egress")
    );
    assert!(!plan.is_denied());
}

#[test]
fn host_root_mount_fails_closed() {
    let planner = RuntimePlanner::new(RuntimeAvailability::with_docker());
    let mut intent = RuntimeIntent::named("dangerous-filesystem");
    intent.image = Some("ghcr.io/example/filesystem:1".to_string());
    intent.requested_mounts = vec![RuntimeMount {
        source: "/".to_string(),
        target: "/host".to_string(),
        mode: RuntimeMountMode::ReadOnly,
    }];

    let plan = planner.plan(&intent);

    assert!(plan.is_denied());
    assert!(
        plan.audit
            .denied_reasons
            .contains(&RuntimeDenyReason::ForbiddenMount)
    );
}

#[test]
fn container_provider_requires_image() {
    let planner = RuntimePlanner::new(RuntimeAvailability::with_docker());
    let intent = RuntimeIntent::named("missing-image");

    let plan = planner.plan_with_policy(
        &intent,
        RuntimeProviderKind::Docker,
        planner.compile_default_policy(&intent),
    );

    assert!(plan.is_denied());
    assert!(
        plan.audit
            .denied_reasons
            .contains(&RuntimeDenyReason::MissingContainerImage)
    );
}

#[test]
fn docker_apply_invokes_runner_with_restricted_defaults_and_value_free_audit() {
    let planner = RuntimePlanner::new(RuntimeAvailability::with_docker());
    let mut intent = RuntimeIntent::named("gmail");
    intent.image = Some("ghcr.io/example/gmail-mcp:1".to_string());
    intent.data_class = RuntimeDataClass::Sensitive;
    intent.env_keys = vec!["GMAIL_HANDLE".to_string()];

    let plan = planner.plan(&intent);
    let mut runner = RecordingRunner::default();
    let result = plan
        .apply_with(&mut runner, &RuntimeApplyRequest::empty())
        .expect("docker apply");

    assert_eq!(runner.calls.len(), 1);
    let (command, env_keys) = &runner.calls[0];
    assert_eq!(command.program, "docker");
    assert!(command.args.contains(&"run".to_string()));
    assert!(command.args.contains(&"--detach".to_string()));
    assert!(command.args.contains(&"--network=none".to_string()));
    assert!(command.args.contains(&"--restart=on-failure:2".to_string()));
    assert!(!command.args.contains(&"--rm".to_string()));
    assert!(command.args.contains(&"--read-only".to_string()));
    assert!(command.args.contains(&"--cap-drop=ALL".to_string()));
    assert!(
        command
            .args
            .contains(&"--security-opt=no-new-privileges".to_string())
    );
    assert!(command.args.contains(&"GMAIL_HANDLE".to_string()));
    assert_eq!(env_keys, &vec!["GMAIL_HANDLE".to_string()]);
    assert_eq!(result.audit.provider, RuntimeProviderKind::Docker);
    assert_eq!(result.audit.env_keys, vec!["GMAIL_HANDLE".to_string()]);

    let serialized = serde_json::to_string(&result).unwrap();
    assert!(!serialized.contains("fixture-handle-value"));
}

#[test]
fn docker_lifecycle_controls_use_same_runner_without_env_names() {
    let planner = RuntimePlanner::new(RuntimeAvailability::with_docker());
    let mut intent = RuntimeIntent::named("gmail");
    intent.image = Some("ghcr.io/example/gmail-mcp:1".to_string());
    intent.data_class = RuntimeDataClass::Sensitive;
    intent.env_keys = vec!["GMAIL_HANDLE".to_string()];

    let plan = planner.plan(&intent);
    let mut runner = RecordingRunner::default();
    let request = RuntimeApplyRequest::empty();
    let health = plan.health_with(&mut runner, &request).expect("health");
    let logs = plan.logs_with(&mut runner, &request).expect("logs");
    let restart = plan.restart_with(&mut runner, &request).expect("restart");
    let stop = plan.stop_with(&mut runner, &request).expect("stop");

    assert_eq!(runner.calls.len(), 4);
    assert_eq!(runner.calls[0].0.program, "docker");
    assert_eq!(runner.calls[0].0.args[0], "inspect");
    assert_eq!(runner.calls[0].1, Vec::<String>::new());
    assert_eq!(runner.calls[1].0.args[0], "logs");
    assert_eq!(runner.calls[1].1, Vec::<String>::new());
    assert_eq!(runner.calls[2].0.args[0], "restart");
    assert_eq!(runner.calls[2].1, Vec::<String>::new());
    assert_eq!(runner.calls[3].0.args[0], "rm");
    assert_eq!(runner.calls[3].0.args[1], "--force");
    assert_eq!(runner.calls[3].1, Vec::<String>::new());
    assert_eq!(health.audit.action, RuntimeApplyAction::Health);
    assert_eq!(health.audit.status, RuntimeApplyStatus::Healthy);
    assert_eq!(logs.audit.action, RuntimeApplyAction::Logs);
    assert_eq!(logs.audit.status, RuntimeApplyStatus::LogsCollected);
    assert_eq!(restart.audit.action, RuntimeApplyAction::Restart);
    assert_eq!(restart.audit.status, RuntimeApplyStatus::Restarted);
    assert_eq!(stop.audit.action, RuntimeApplyAction::Stop);
    assert_eq!(stop.audit.status, RuntimeApplyStatus::Stopped);
}

#[test]
fn runtime_apply_fails_closed_for_denied_mount_before_runner() {
    let planner = RuntimePlanner::new(RuntimeAvailability::with_docker());
    let mut intent = RuntimeIntent::named("dangerous-filesystem");
    intent.image = Some("ghcr.io/example/filesystem:1".to_string());
    intent.requested_mounts = vec![RuntimeMount {
        source: "/".to_string(),
        target: "/host".to_string(),
        mode: RuntimeMountMode::ReadOnly,
    }];

    let plan = planner.plan(&intent);
    let mut runner = RecordingRunner::default();
    let error = plan
        .apply_with(&mut runner, &RuntimeApplyRequest::empty())
        .expect_err("denied apply");

    assert!(
        matches!(error, RuntimeApplyError::Denied(reasons) if reasons.contains(&RuntimeDenyReason::ForbiddenMount))
    );
    assert!(runner.calls.is_empty());
}

#[test]
fn runtime_lifecycle_controls_fail_closed_for_denied_mount_before_runner() {
    let planner = RuntimePlanner::new(RuntimeAvailability::with_docker());
    let mut intent = RuntimeIntent::named("dangerous-filesystem");
    intent.image = Some("ghcr.io/example/filesystem:1".to_string());
    intent.requested_mounts = vec![RuntimeMount {
        source: "/".to_string(),
        target: "/host".to_string(),
        mode: RuntimeMountMode::ReadOnly,
    }];

    let plan = planner.plan(&intent);
    let mut runner = RecordingRunner::default();
    for result in [
        plan.health_with(&mut runner, &RuntimeApplyRequest::empty()),
        plan.logs_with(&mut runner, &RuntimeApplyRequest::empty()),
        plan.restart_with(&mut runner, &RuntimeApplyRequest::empty()),
        plan.stop_with(&mut runner, &RuntimeApplyRequest::empty()),
    ] {
        assert!(
            matches!(result, Err(RuntimeApplyError::Denied(reasons)) if reasons.contains(&RuntimeDenyReason::ForbiddenMount))
        );
    }
    assert!(runner.calls.is_empty());
}

#[test]
fn runtime_apply_requires_confirmation_for_full_network_before_runner() {
    let planner = RuntimePlanner::new(RuntimeAvailability::with_docker());
    let mut intent = RuntimeIntent::named("remote-search");
    intent.image = Some("ghcr.io/example/search:1".to_string());
    intent.data_class = RuntimeDataClass::Sensitive;
    intent.requested_egress = RuntimeNetworkEgress::Full;

    let plan = planner.plan(&intent);
    let mut runner = RecordingRunner::default();
    let error = plan
        .apply_with(&mut runner, &RuntimeApplyRequest::empty())
        .expect_err("confirmation required");

    assert!(
        matches!(error, RuntimeApplyError::ConfirmationRequired(ids) if ids.contains(&"network.full_egress".to_string()))
    );
    assert!(runner.calls.is_empty());
}

#[test]
fn local_and_docker_providers_use_same_contract() {
    let availability = RuntimeAvailability::with_docker();
    let mut intent = RuntimeIntent::named("contract");
    intent.image = Some("ghcr.io/example/contract:1".to_string());
    let policy = RuntimePlanner::new(availability.clone()).compile_default_policy(&intent);

    let providers: Vec<Box<dyn RuntimeProvider>> = vec![
        Box::<LocalProcessProvider>::default(),
        Box::new(ContainerProvider::docker()),
    ];

    let plans = providers
        .iter()
        .map(|provider| provider.compile_plan(&intent, policy.clone(), &availability))
        .collect::<Vec<_>>();

    assert_eq!(plans.len(), 2);
    assert_eq!(plans[0].provider, RuntimeProviderKind::LocalProcess);
    assert_eq!(plans[1].provider, RuntimeProviderKind::Docker);
    assert_eq!(plans[0].policy.id, plans[1].policy.id);
}

#[test]
#[ignore = "requires a reachable Docker daemon; run scripts/dev/runtime-provider-docker-smoke.sh"]
fn runtime_provider_real_docker_smoke_exercises_lifecycle() {
    assert_eq!(
        std::env::var("MCP_GATEWAY_RUNTIME_DOCKER_SMOKE").as_deref(),
        Ok("1"),
        "set MCP_GATEWAY_RUNTIME_DOCKER_SMOKE=1 or run scripts/dev/runtime-provider-docker-smoke.sh"
    );

    let image = std::env::var("MCP_GATEWAY_RUNTIME_DOCKER_IMAGE")
        .unwrap_or_else(|_| "docker.io/library/hello-world:latest".to_string());
    let server_name = format!(
        "docker-smoke-{}-{}",
        std::process::id(),
        unix_timestamp_secs()
    );
    let planner = RuntimePlanner::new(RuntimeAvailability::with_docker());
    let mut intent = RuntimeIntent::named(server_name);
    intent.image = Some(image);
    intent.data_class = RuntimeDataClass::Sensitive;

    let plan = planner.plan(&intent);
    let container_name = docker_container_name(&plan);
    let _cleanup = DockerCleanup::new(&container_name);
    let mut runner = StdRuntimeCommandRunner;
    let request = RuntimeApplyRequest::empty();

    let started = plan
        .apply_with(&mut runner, &request)
        .expect("docker start");
    assert_eq!(started.audit.provider, RuntimeProviderKind::Docker);
    assert_eq!(started.audit.action, RuntimeApplyAction::Start);
    assert_eq!(started.audit.status, RuntimeApplyStatus::Started);
    assert_eq!(started.audit.env_keys, Vec::<String>::new());
    assert!(
        started
            .outcome
            .external_id
            .as_deref()
            .is_some_and(|id| !id.is_empty())
    );

    let health = plan
        .health_with(&mut runner, &request)
        .expect("docker inspect");
    assert_eq!(health.audit.action, RuntimeApplyAction::Health);
    assert!(
        matches!(health.outcome.stdout.trim(), "true" | "false"),
        "unexpected docker inspect running state: {:?}",
        health.outcome.stdout
    );

    let logs = plan.logs_with(&mut runner, &request).expect("docker logs");
    assert_eq!(logs.audit.action, RuntimeApplyAction::Logs);
    assert!(logs.outcome.stdout.contains("Hello from Docker"));

    let restarted = plan
        .restart_with(&mut runner, &request)
        .expect("docker restart");
    assert_eq!(restarted.audit.action, RuntimeApplyAction::Restart);

    let stopped = plan.stop_with(&mut runner, &request).expect("docker rm");
    assert_eq!(stopped.audit.action, RuntimeApplyAction::Stop);
}

fn unix_timestamp_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system time after unix epoch")
        .as_secs()
}

fn docker_container_name(plan: &super::RuntimePlan) -> String {
    let args = &plan
        .launch_command
        .as_ref()
        .expect("docker launch command")
        .args;
    let name_index = args
        .iter()
        .position(|arg| arg == "--name")
        .expect("docker --name argument");
    args.get(name_index + 1)
        .expect("docker container name value")
        .clone()
}

struct DockerCleanup {
    name: String,
}

impl DockerCleanup {
    fn new(name: &str) -> Self {
        remove_docker_container(name);
        Self {
            name: name.to_string(),
        }
    }
}

impl Drop for DockerCleanup {
    fn drop(&mut self) {
        remove_docker_container(&self.name);
    }
}

fn remove_docker_container(name: &str) {
    let _ = std::process::Command::new("docker")
        .args(["rm", "--force", name])
        .output();
}

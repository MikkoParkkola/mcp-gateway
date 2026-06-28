use super::{
    ContainerProvider, LocalProcessProvider, RuntimeAvailability, RuntimeDataClass,
    RuntimeDenyReason, RuntimeIntent, RuntimeMount, RuntimeMountMode, RuntimeNetworkEgress,
    RuntimePlanner, RuntimeProvider, RuntimeProviderKind, RuntimeProviderSelection,
};

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
fn planner_emits_observe_only_docker_lifecycle_hints() {
    let planner = RuntimePlanner::new(RuntimeAvailability::with_docker());
    let mut intent = RuntimeIntent::named("gmail");
    intent.image = Some("ghcr.io/example/gmail-mcp:1".to_string());
    intent.data_class = RuntimeDataClass::Sensitive;
    intent.env_keys = vec!["GMAIL_HANDLE".to_string()];

    let plan = planner.plan(&intent);
    let start = plan.lifecycle.start_command_hint.as_deref().unwrap();

    assert_eq!(plan.provider, RuntimeProviderKind::Docker);
    assert!(start.contains("docker run"));
    assert!(start.contains("--network=none"));
    assert!(start.contains("--env GMAIL_HANDLE"));
    assert!(plan.lifecycle.health_check.contains("docker inspect"));
    assert_eq!(
        plan.lifecycle.logs_hint.as_deref(),
        Some("docker logs mcp-gateway-gmail")
    );
    assert!(plan.apply_command.is_none());
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
    assert!(plan.apply_command.is_none());
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

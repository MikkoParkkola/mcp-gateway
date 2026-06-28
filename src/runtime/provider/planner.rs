use std::collections::BTreeSet;

use super::{
    RuntimeAuditEvent, RuntimeAvailability, RuntimeConfirmation, RuntimeConfirmationRisk,
    RuntimeDataClass, RuntimeDenial, RuntimeDenyReason, RuntimeEnvironmentPolicy, RuntimeIntent,
    RuntimeLifecyclePlan, RuntimeMount, RuntimeMountMode, RuntimeNetworkEgress, RuntimePlan,
    RuntimePolicy, RuntimePreflightCheck, RuntimeProviderKind, RuntimeProviderSelection,
    RuntimeRecommendation, RuntimeResourcePolicy, RuntimeRestartPolicy,
};

/// Runtime planner for provider recommendation and policy compilation.
#[derive(Debug, Clone)]
pub struct RuntimePlanner {
    availability: RuntimeAvailability,
}

impl RuntimePlanner {
    /// Create a planner with detected or fixture availability.
    #[must_use]
    pub fn new(availability: RuntimeAvailability) -> Self {
        Self { availability }
    }

    /// Recommend the safest available provider for an intent.
    #[must_use]
    pub fn recommend_provider(&self, intent: &RuntimeIntent) -> RuntimeProviderKind {
        if let Some(provider) = intent.preferred_provider
            && self.availability.supports(provider)
        {
            return provider;
        }

        if should_isolate(intent) && self.availability.docker {
            RuntimeProviderKind::Docker
        } else if should_isolate(intent) && self.availability.podman {
            RuntimeProviderKind::Podman
        } else {
            RuntimeProviderKind::LocalProcess
        }
    }

    /// Compile least-privilege defaults for an intent.
    #[must_use]
    pub fn compile_default_policy(&self, intent: &RuntimeIntent) -> RuntimePolicy {
        let mut allowed_keys: BTreeSet<String> = intent.env_keys.iter().cloned().collect();
        let guarded_keys: BTreeSet<String> = intent.guarded_env_keys.iter().cloned().collect();
        allowed_keys.extend(guarded_keys.iter().cloned());

        RuntimePolicy {
            id: format!("runtime-policy:{}", sanitize_policy_id(&intent.server_name)),
            mounts: intent.requested_mounts.clone(),
            network_egress: intent.requested_egress.clone(),
            resources: RuntimeResourcePolicy::default(),
            env: RuntimeEnvironmentPolicy {
                allowed_keys: allowed_keys.into_iter().collect(),
                guarded_keys: guarded_keys.into_iter().collect(),
            },
            restart: RuntimeRestartPolicy::default(),
            privileged: intent.privileged,
        }
    }

    /// Plan an intent with compiled defaults.
    #[must_use]
    pub fn plan(&self, intent: &RuntimeIntent) -> RuntimePlan {
        let provider = self.recommend_provider(intent);
        let policy = self.compile_default_policy(intent);
        self.plan_with_policy(intent, provider, policy)
    }

    /// Plan an intent with an explicit provider and policy.
    #[must_use]
    pub fn plan_with_policy(
        &self,
        intent: &RuntimeIntent,
        provider: RuntimeProviderKind,
        policy: RuntimePolicy,
    ) -> RuntimePlan {
        compile_provider_plan(provider, intent, policy, &self.availability)
    }
}

pub(super) fn compile_provider_plan(
    provider: RuntimeProviderKind,
    intent: &RuntimeIntent,
    policy: RuntimePolicy,
    availability: &RuntimeAvailability,
) -> RuntimePlan {
    let mut confirmations = Vec::new();
    let mut denied = Vec::new();

    if !availability.supports(provider) {
        denied.push(RuntimeDenial {
            reason: RuntimeDenyReason::RuntimeUnavailable,
            detail: format!("{provider:?} runtime is not available"),
        });
    }

    if provider.is_containerized() && intent.image.as_deref().unwrap_or_default().is_empty() {
        denied.push(RuntimeDenial {
            reason: RuntimeDenyReason::MissingContainerImage,
            detail: "containerized runtime requires an image reference".to_string(),
        });
    }

    if policy.resources.cpu_cores == 0
        || policy.resources.memory_mb == 0
        || policy.resources.timeout_secs == 0
    {
        denied.push(RuntimeDenial {
            reason: RuntimeDenyReason::InvalidResourcePolicy,
            detail: "cpu, memory, and timeout must all be positive".to_string(),
        });
    }

    for mount in &policy.mounts {
        if is_forbidden_mount(&mount.source) {
            denied.push(RuntimeDenial {
                reason: RuntimeDenyReason::ForbiddenMount,
                detail: format!("mount source '{}' is forbidden", mount.source),
            });
        } else {
            confirmations.push(RuntimeConfirmation {
                id: "filesystem.host_mount".to_string(),
                reason: format!(
                    "host mount '{}' to '{}' requires human approval",
                    mount.source, mount.target
                ),
                risk: RuntimeConfirmationRisk::High,
            });
        }
    }

    if policy.network_egress == RuntimeNetworkEgress::Full {
        confirmations.push(RuntimeConfirmation {
            id: "network.full_egress".to_string(),
            reason: "unrestricted outbound network access requires human approval".to_string(),
            risk: RuntimeConfirmationRisk::High,
        });
    }

    if policy.privileged {
        confirmations.push(RuntimeConfirmation {
            id: "runtime.privileged".to_string(),
            reason: "privileged runtime execution requires human approval".to_string(),
            risk: RuntimeConfirmationRisk::High,
        });
    }

    if !policy.env.guarded_keys.is_empty() {
        confirmations.push(RuntimeConfirmation {
            id: "environment.guarded_names".to_string(),
            reason: "guarded environment names require owner approval".to_string(),
            risk: RuntimeConfirmationRisk::Medium,
        });
    }

    dedupe_confirmations(&mut confirmations);
    let confirmation_ids = confirmations
        .iter()
        .map(|confirmation| confirmation.id.clone())
        .collect::<Vec<_>>();
    let denied_reasons = denied
        .iter()
        .map(|denial| denial.reason)
        .collect::<Vec<_>>();
    let guarded_env_keys = policy.env.guarded_keys.clone();

    let lifecycle = lifecycle_plan(provider, intent, &policy);

    RuntimePlan {
        server_name: intent.server_name.clone(),
        provider,
        preflight_checks: preflight_checks(provider),
        rollback_step: lifecycle.rollback_step.clone(),
        apply_command: None,
        recommendation: recommendation_for(provider, intent, availability),
        lifecycle,
        audit: RuntimeAuditEvent {
            server_name: intent.server_name.clone(),
            provider,
            policy_id: policy.id.clone(),
            license_tier: provider.license_tier(),
            confirmation_ids,
            denied_reasons,
            guarded_env_keys,
        },
        policy,
        confirmations,
        denied,
    }
}

fn should_isolate(intent: &RuntimeIntent) -> bool {
    matches!(
        intent.data_class,
        RuntimeDataClass::Sensitive | RuntimeDataClass::HighPrivilege
    ) || intent.privileged
        || !intent.requested_mounts.is_empty()
        || !intent.guarded_env_keys.is_empty()
}

fn recommendation_for(
    provider: RuntimeProviderKind,
    intent: &RuntimeIntent,
    availability: &RuntimeAvailability,
) -> RuntimeRecommendation {
    if intent
        .preferred_provider
        .is_some_and(|preferred| preferred == provider && availability.supports(preferred))
    {
        return RuntimeRecommendation {
            reason: format!("{provider:?} was selected because the operator requested it"),
            security_tradeoff: provider_tradeoff(provider).to_string(),
            selected_by: RuntimeProviderSelection::OperatorPreference,
        };
    }

    if provider.is_containerized() && should_isolate(intent) {
        RuntimeRecommendation {
            reason: format!(
                "{provider:?} was selected to isolate sensitive, privileged, mounted, or guarded environment execution"
            ),
            security_tradeoff: provider_tradeoff(provider).to_string(),
            selected_by: RuntimeProviderSelection::IsolationPreferred,
        }
    } else {
        RuntimeRecommendation {
            reason: "LocalProcess was selected to preserve existing direct-launch compatibility"
                .to_string(),
            security_tradeoff: provider_tradeoff(provider).to_string(),
            selected_by: RuntimeProviderSelection::CompatibilityFallback,
        }
    }
}

fn provider_tradeoff(provider: RuntimeProviderKind) -> &'static str {
    match provider {
        RuntimeProviderKind::LocalProcess => {
            "lowest install friction, but inherits more ambient host privileges"
        }
        RuntimeProviderKind::Docker => {
            "better filesystem and process isolation, but requires Docker daemon trust"
        }
        RuntimeProviderKind::Podman => {
            "better rootless container isolation when available, with host integration limits"
        }
        RuntimeProviderKind::Systemd => {
            "durable service lifecycle, but policy depends on unit hardening"
        }
        RuntimeProviderKind::Launchd => {
            "native macOS service lifecycle, but weaker container isolation"
        }
        RuntimeProviderKind::Kubernetes => {
            "fleet scheduling and policy control, but requires cluster governance"
        }
    }
}

fn lifecycle_plan(
    provider: RuntimeProviderKind,
    intent: &RuntimeIntent,
    policy: &RuntimePolicy,
) -> RuntimeLifecyclePlan {
    let runtime_name = format!(
        "mcp-gateway-{}",
        sanitize_policy_id(&intent.server_name).trim_matches('-')
    );
    match provider {
        RuntimeProviderKind::LocalProcess => RuntimeLifecyclePlan {
            start_command_hint: intent.executable.clone(),
            health_check: "perform MCP initialize over the managed stdio session".to_string(),
            logs_hint: Some("inspect gateway-managed process stdout and stderr".to_string()),
            stop_command_hint: Some("terminate the gateway-managed child process".to_string()),
            rollback_step:
                "Keep runtime.provider unset or restore the previous direct-launch config."
                    .to_string(),
        },
        RuntimeProviderKind::Docker => RuntimeLifecyclePlan {
            start_command_hint: container_start_command("docker", &runtime_name, intent, policy),
            health_check: format!(
                "docker inspect {runtime_name} and perform MCP initialize through the configured endpoint"
            ),
            logs_hint: Some(format!("docker logs {runtime_name}")),
            stop_command_hint: Some(format!("docker stop {runtime_name}")),
            rollback_step: format!(
                "docker stop {runtime_name}, then restore the previous gateway config"
            ),
        },
        RuntimeProviderKind::Podman => RuntimeLifecyclePlan {
            start_command_hint: container_start_command("podman", &runtime_name, intent, policy),
            health_check: format!(
                "podman inspect {runtime_name} and perform MCP initialize through the configured endpoint"
            ),
            logs_hint: Some(format!("podman logs {runtime_name}")),
            stop_command_hint: Some(format!("podman stop {runtime_name}")),
            rollback_step: format!(
                "podman stop {runtime_name}, then restore the previous gateway config"
            ),
        },
        RuntimeProviderKind::Systemd => RuntimeLifecyclePlan {
            start_command_hint: Some(format!("systemctl --user start {runtime_name}.service")),
            health_check: format!("systemctl --user is-active {runtime_name}.service"),
            logs_hint: Some(format!("journalctl --user -u {runtime_name}.service")),
            stop_command_hint: Some(format!("systemctl --user stop {runtime_name}.service")),
            rollback_step: format!(
                "systemctl --user stop {runtime_name}.service, then restore the previous gateway config"
            ),
        },
        RuntimeProviderKind::Launchd => RuntimeLifecyclePlan {
            start_command_hint: Some(format!("launchctl bootstrap gui/$UID {runtime_name}.plist")),
            health_check: format!("launchctl print gui/$UID/{runtime_name}"),
            logs_hint: Some("inspect the configured launchd stdout and stderr paths".to_string()),
            stop_command_hint: Some(format!("launchctl bootout gui/$UID/{runtime_name}")),
            rollback_step: format!(
                "launchctl bootout gui/$UID/{runtime_name}, then restore the previous gateway config"
            ),
        },
        RuntimeProviderKind::Kubernetes => RuntimeLifecyclePlan {
            start_command_hint: Some(format!("kubectl apply -f {runtime_name}.runtime.yaml")),
            health_check: format!("kubectl rollout status deployment/{runtime_name}"),
            logs_hint: Some(format!("kubectl logs deployment/{runtime_name}")),
            stop_command_hint: Some(format!("kubectl delete -f {runtime_name}.runtime.yaml")),
            rollback_step: format!(
                "kubectl delete -f {runtime_name}.runtime.yaml, then restore the previous gateway config"
            ),
        },
    }
}

fn container_start_command(
    binary: &str,
    runtime_name: &str,
    intent: &RuntimeIntent,
    policy: &RuntimePolicy,
) -> Option<String> {
    let image = intent.image.as_deref()?;
    let mut parts = vec![
        binary.to_string(),
        "run".to_string(),
        "--rm".to_string(),
        "--name".to_string(),
        runtime_name.to_string(),
        format!("--cpus={}", policy.resources.cpu_cores),
        format!("--memory={}m", policy.resources.memory_mb),
        container_network_flag(&policy.network_egress),
    ];

    for key in &policy.env.allowed_keys {
        parts.push("--env".to_string());
        parts.push(key.clone());
    }

    for mount in &policy.mounts {
        parts.push("--mount".to_string());
        parts.push(container_mount_arg(mount));
    }

    if policy.privileged {
        parts.push("--privileged".to_string());
    }

    parts.push(image.to_string());
    Some(parts.join(" "))
}

fn container_network_flag(network: &RuntimeNetworkEgress) -> String {
    match network {
        RuntimeNetworkEgress::None | RuntimeNetworkEgress::Loopback => "--network=none".to_string(),
        RuntimeNetworkEgress::Allowlist(_) => "--network=mcp-gateway-allowlist".to_string(),
        RuntimeNetworkEgress::Full => "--network=bridge".to_string(),
    }
}

fn container_mount_arg(mount: &RuntimeMount) -> String {
    let mut arg = format!("type=bind,source={},target={}", mount.source, mount.target);
    if mount.mode == RuntimeMountMode::ReadOnly {
        arg.push_str(",readonly");
    }
    arg
}

fn preflight_checks(provider: RuntimeProviderKind) -> Vec<RuntimePreflightCheck> {
    let check = match provider {
        RuntimeProviderKind::LocalProcess => "verify executable is available on PATH",
        RuntimeProviderKind::Docker => "docker info",
        RuntimeProviderKind::Podman => "podman info",
        RuntimeProviderKind::Systemd => "systemctl --user status",
        RuntimeProviderKind::Launchd => "launchctl print gui/$UID",
        RuntimeProviderKind::Kubernetes => "kubectl get namespace",
    };
    vec![RuntimePreflightCheck {
        name: format!("runtime.{provider:?}.available").to_ascii_lowercase(),
        required: true,
        check: check.to_string(),
    }]
}

fn dedupe_confirmations(confirmations: &mut Vec<RuntimeConfirmation>) {
    let mut seen = BTreeSet::new();
    confirmations.retain(|confirmation| seen.insert(confirmation.id.clone()));
}

fn is_forbidden_mount(source: &str) -> bool {
    matches!(source, "/" | "/etc" | "/System" | "/var/run/docker.sock")
}

fn sanitize_policy_id(server_name: &str) -> String {
    server_name
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' {
                ch.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .collect()
}

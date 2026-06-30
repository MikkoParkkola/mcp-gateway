use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::{
    Error, Result,
    runtime::{
        RuntimeAvailability, RuntimeDataClass, RuntimeIntent, RuntimeMount, RuntimeNetworkEgress,
        RuntimePlan, RuntimePlanner, RuntimePolicy, RuntimeProviderKind, RuntimeResourcePolicy,
        RuntimeRestartPolicy,
    },
};

/// `RuntimeProvider` configuration for MCP server execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct RuntimeConfig {
    /// Provider used when a profile does not select one explicitly.
    pub default_provider: RuntimeProviderKind,
    /// Operator-declared local runtime availability.
    pub availability: RuntimeAvailabilityConfig,
    /// Named runtime profiles referenced by servers, `TrustCards`, or operators.
    pub profiles: HashMap<String, RuntimeProfileConfig>,
}

impl Default for RuntimeConfig {
    fn default() -> Self {
        Self {
            default_provider: RuntimeProviderKind::LocalProcess,
            availability: RuntimeAvailabilityConfig::default(),
            profiles: HashMap::new(),
        }
    }
}

impl RuntimeConfig {
    /// Convert configured availability into the planner's runtime availability bitmap.
    #[must_use]
    pub fn runtime_availability(&self) -> RuntimeAvailability {
        self.availability.runtime_availability()
    }

    /// Compile a named profile into a runtime intent.
    #[must_use]
    pub fn intent_for_profile(
        &self,
        profile_name: &str,
        server_name: &str,
    ) -> Option<RuntimeIntent> {
        self.profiles
            .get(profile_name)
            .map(|profile| profile.intent(server_name, self.provider_for(profile)))
    }

    /// Compile a named profile into a canonical runtime policy.
    #[must_use]
    pub fn policy_for_profile(
        &self,
        profile_name: &str,
        server_name: &str,
    ) -> Option<RuntimePolicy> {
        let intent = self.intent_for_profile(profile_name, server_name)?;
        let profile = self.profiles.get(profile_name)?;
        Some(profile.policy(&intent, self.runtime_availability()))
    }

    /// Plan a named profile without launching the runtime.
    #[must_use]
    pub fn plan_profile(&self, profile_name: &str, server_name: &str) -> Option<RuntimePlan> {
        self.plan_backend_profile(profile_name, server_name, None)
    }

    /// Plan a named profile for a backend, using the backend executable when
    /// the reusable profile does not declare one itself.
    #[must_use]
    pub fn plan_backend_profile(
        &self,
        profile_name: &str,
        server_name: &str,
        executable_hint: Option<&str>,
    ) -> Option<RuntimePlan> {
        let profile = self.profiles.get(profile_name)?;
        let provider = self.provider_for(profile);
        let mut intent = profile.intent(server_name, provider);
        if intent.executable.is_none() {
            intent.executable = executable_hint.map(ToString::to_string);
        }
        let policy = profile.policy(&intent, self.runtime_availability());
        Some(
            RuntimePlanner::new(self.runtime_availability())
                .plan_with_policy(&intent, provider, policy),
        )
    }

    /// Validate runtime profiles without probing local daemons.
    pub(crate) fn validate(&self) -> Result<()> {
        for (name, profile) in &self.profiles {
            validate_profile_name(name)?;
            profile.validate(name, self.provider_for(profile))?;
        }
        Ok(())
    }

    fn provider_for(&self, profile: &RuntimeProfileConfig) -> RuntimeProviderKind {
        profile.provider.unwrap_or(self.default_provider)
    }
}

/// Operator-declared runtime availability.
#[allow(clippy::struct_excessive_bools)] // Mirrors RuntimeAvailability for config ergonomics.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct RuntimeAvailabilityConfig {
    /// Local direct process execution is available.
    #[serde(default = "default_true")]
    pub local_process: bool,
    /// Docker CLI/daemon is available.
    pub docker: bool,
    /// Podman CLI/service is available.
    pub podman: bool,
    /// systemd user service manager is available.
    pub systemd: bool,
    /// macOS launchd is available.
    pub launchd: bool,
    /// Kubernetes target is configured.
    pub kubernetes: bool,
}

impl Default for RuntimeAvailabilityConfig {
    fn default() -> Self {
        Self {
            local_process: true,
            docker: false,
            podman: false,
            systemd: false,
            launchd: false,
            kubernetes: false,
        }
    }
}

impl RuntimeAvailabilityConfig {
    /// Convert to planner availability.
    #[must_use]
    pub fn runtime_availability(&self) -> RuntimeAvailability {
        RuntimeAvailability {
            local_process: self.local_process,
            docker: self.docker,
            podman: self.podman,
            systemd: self.systemd,
            launchd: self.launchd,
            kubernetes: self.kubernetes,
        }
    }
}

/// A named runtime policy profile.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct RuntimeProfileConfig {
    /// Explicit provider for this profile.
    pub provider: Option<RuntimeProviderKind>,
    /// Executable basename for local direct process compatibility.
    pub executable: Option<String>,
    /// Container image reference for containerized providers.
    pub image: Option<String>,
    /// Data sensitivity used for provider recommendations and audit.
    pub data_class: RuntimeDataClass,
    /// Environment variable names allowed into the runtime.
    pub env_keys: Vec<String>,
    /// Environment variable names that require owner approval.
    pub guarded_env_keys: Vec<String>,
    /// Requested network egress policy.
    pub network_egress: RuntimeNetworkEgress,
    /// Requested filesystem mounts.
    pub mounts: Vec<RuntimeMount>,
    /// Resource limits.
    pub resources: RuntimeResourcePolicy,
    /// Restart behavior.
    pub restart: RuntimeRestartPolicy,
    /// Whether privileged runtime execution is requested.
    pub privileged: bool,
}

impl Default for RuntimeProfileConfig {
    fn default() -> Self {
        Self {
            provider: None,
            executable: None,
            image: None,
            data_class: RuntimeDataClass::Internal,
            env_keys: Vec::new(),
            guarded_env_keys: Vec::new(),
            network_egress: RuntimeNetworkEgress::None,
            mounts: Vec::new(),
            resources: RuntimeResourcePolicy::default(),
            restart: RuntimeRestartPolicy::default(),
            privileged: false,
        }
    }
}

impl RuntimeProfileConfig {
    fn intent(&self, server_name: &str, provider: RuntimeProviderKind) -> RuntimeIntent {
        RuntimeIntent {
            server_name: server_name.to_string(),
            executable: self.executable.clone(),
            image: self.image.clone(),
            data_class: self.data_class,
            preferred_provider: Some(provider),
            requested_egress: self.network_egress.clone(),
            requested_mounts: self.mounts.clone(),
            env_keys: self.env_keys.clone(),
            guarded_env_keys: self.guarded_env_keys.clone(),
            privileged: self.privileged,
        }
    }

    fn policy(&self, intent: &RuntimeIntent, availability: RuntimeAvailability) -> RuntimePolicy {
        let mut policy = RuntimePlanner::new(availability).compile_default_policy(intent);
        policy.resources = self.resources.clone();
        policy.restart = self.restart.clone();
        policy.privileged = self.privileged;
        policy
    }

    fn validate(&self, name: &str, provider: RuntimeProviderKind) -> Result<()> {
        if provider.is_containerized() && self.image.as_deref().is_none_or(str::is_empty) {
            return Err(config_error(format!(
                "runtime.profiles.{name}.image is required for {provider:?}"
            )));
        }
        validate_resources(name, &self.resources)?;
        validate_env_keys(name, "env_keys", &self.env_keys)?;
        validate_env_keys(name, "guarded_env_keys", &self.guarded_env_keys)?;
        validate_network(name, &self.network_egress)?;
        validate_mounts(name, &self.mounts)?;
        Ok(())
    }
}

fn validate_profile_name(name: &str) -> Result<()> {
    if name.is_empty() {
        return Err(config_error("runtime profile name must not be empty"));
    }
    if name.contains('/') || name.contains('\\') || name.contains(':') {
        return Err(config_error(format!(
            "runtime profile name '{name}' contains an invalid path separator"
        )));
    }
    Ok(())
}

fn validate_resources(name: &str, resources: &RuntimeResourcePolicy) -> Result<()> {
    if resources.cpu_cores == 0 || resources.memory_mb == 0 || resources.timeout_secs == 0 {
        return Err(config_error(format!(
            "runtime.profiles.{name}.resources cpu_cores, memory_mb, and timeout_secs must be positive"
        )));
    }
    Ok(())
}

fn validate_env_keys(name: &str, field: &str, keys: &[String]) -> Result<()> {
    for key in keys {
        if !is_env_key(key) {
            return Err(config_error(format!(
                "runtime.profiles.{name}.{field} contains invalid environment key '{key}'"
            )));
        }
    }
    Ok(())
}

fn validate_network(name: &str, network: &RuntimeNetworkEgress) -> Result<()> {
    if let RuntimeNetworkEgress::Allowlist(entries) = network
        && (entries.is_empty() || entries.iter().any(|entry| entry.trim().is_empty()))
    {
        return Err(config_error(format!(
            "runtime.profiles.{name}.network_egress allowlist entries must be non-empty"
        )));
    }
    Ok(())
}

fn validate_mounts(name: &str, mounts: &[RuntimeMount]) -> Result<()> {
    for mount in mounts {
        if mount.source.trim().is_empty() || mount.target.trim().is_empty() {
            return Err(config_error(format!(
                "runtime.profiles.{name}.mounts source and target must be non-empty"
            )));
        }
        if !mount.target.starts_with('/') {
            return Err(config_error(format!(
                "runtime.profiles.{name}.mounts target '{}' must be absolute",
                mount.target
            )));
        }
    }
    Ok(())
}

fn is_env_key(key: &str) -> bool {
    let mut chars = key.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    (first == '_' || first.is_ascii_alphabetic())
        && chars.all(|ch| ch == '_' || ch.is_ascii_alphanumeric())
}

fn config_error(message: impl Into<String>) -> Error {
    Error::ConfigValidation(message.into())
}

fn default_true() -> bool {
    true
}

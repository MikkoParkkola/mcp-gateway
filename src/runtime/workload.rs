//! Agent workload definitions for cross-substrate test matrix.
//!
//! Provides a standard 10-task agent workload that must produce identical
//! attestation, memory-bridge, and audit-trail outputs on every substrate.

use serde::{Deserialize, Serialize};

use crate::runtime::descriptor::{
    AttestationConfig, Capability, CheckpointPolicy, HebbBridgeConfig, MountSpec, NetworkEgress,
    ResourceSpec, SandboxDescriptor,
};

/// A set of agent tasks paired with a sandbox descriptor.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Workload {
    /// Workload identifier.
    pub id: String,

    /// Agent tasks to execute inside the sandbox.
    pub tasks: Vec<AgentTask>,

    /// Sandbox descriptor for the workload's runtime.
    pub descriptor: SandboxDescriptor,
}

impl Workload {
    /// Standard 10-task agent workload for cross-substrate testing.
    pub fn standard_test() -> Self {
        let tasks = (1..=10)
            .map(|i| AgentTask {
                id: format!("task-{i:02}"),
                name: format!("agent_task_{i:02}"),
                tool: format!("tool_{i:02}"),
                expected_output_hash: format!("sha256:{i:064x}"),
            })
            .collect();

        let descriptor = SandboxDescriptor {
            name: "standard-agent-workload".into(),
            image: "symphony/agent-runtime:latest".into(),
            resources: ResourceSpec {
                cpu_millis: 2000,
                memory_bytes: 4_294_967_296,
                disk_bytes: 10_737_418_240,
            },
            capabilities: vec![
                Capability {
                    name: "CAP_NET_RAW".into(),
                },
                Capability {
                    name: "CAP_SYS_PTRACE".into(),
                },
            ],
            network_egress: NetworkEgress {
                mode: "allowlist".into(),
                allowed_destinations: vec![
                    "10.0.0.0/8".into(),
                    "api.anthropic.com".into(),
                ],
            },
            env: {
                let mut m = std::collections::HashMap::new();
                m.insert("AGENT_MODE".into(), "production".into());
                m.insert("LOG_LEVEL".into(), "info".into());
                m.insert("HEBB_ENDPOINT".into(), "http://127.0.0.1:7331".into());
                m
            },
            mounts: vec![
                MountSpec {
                    source: "/opt/agent".into(),
                    destination: "/app".into(),
                    mount_type: "bind".into(),
                    read_only: true,
                },
                MountSpec {
                    source: "tmpfs".into(),
                    destination: "/tmp".into(),
                    mount_type: "tmpfs".into(),
                    read_only: false,
                },
            ],
            attestation: AttestationConfig {
                required: true,
                measurements: vec!["sha256".into()],
                allowed_runtimes: vec!["gvisor".into(), "apple-vz".into()],
            },
            hebb_bridge: HebbBridgeConfig {
                enabled: true,
                endpoint: "http://127.0.0.1:7331".into(),
                max_context_tokens: 32_768,
            },
            checkpoint_policy: CheckpointPolicy {
                enabled: true,
                interval_secs: 300,
                storage_path: "/var/lib/symphony/checkpoints".into(),
            },
        };

        Workload {
            id: "standard-10-task".into(),
            tasks,
            descriptor,
        }
    }
}

/// A single agent task.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentTask {
    /// Task identifier.
    pub id: String,

    /// Human-readable task name.
    pub name: String,

    /// Tool name the task invokes.
    pub tool: String,

    /// Expected output hash for verification.
    pub expected_output_hash: String,
}

//! Symphony+ Sandbox descriptor schema.
//!
//! The [`SandboxDescriptor`] is the single, substrate-agnostic specification
//! for an agent sandbox.  An operator writes one descriptor; the
//! [`compiler`](super::compiler) picks the substrate.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

/// Top-level symphony+ Sandbox descriptor.
///
/// Encodes everything needed to compile the sandbox to any supported
/// substrate: OCI bundle fields, attestation, memory-bridge config, and
/// checkpoint policy.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SandboxDescriptor {
    /// Human-readable sandbox name.
    pub name: String,

    /// Container image reference (e.g. `docker.io/library/ubuntu:22.04`).
    pub image: String,

    /// CPU, memory, and disk limits.
    pub resources: ResourceSpec,

    /// Linux capabilities required inside the sandbox.
    pub capabilities: Vec<Capability>,

    /// Network egress policy.
    pub network_egress: NetworkEgress,

    /// Environment variables passed into the sandbox.
    pub env: HashMap<String, String>,

    /// Filesystem mounts (read-only and writable overlay).
    pub mounts: Vec<MountSpec>,

    /// Attestation requirements enforced by the substrate (B1-IDENT).
    #[serde(default)]
    pub attestation: AttestationConfig,

    /// Hebb memory-bridge configuration (B2-MEM).
    #[serde(default)]
    pub hebb_bridge: HebbBridgeConfig,

    /// Checkpoint / durability policy (B3-DURABLE).
    #[serde(default)]
    pub checkpoint_policy: CheckpointPolicy,
}

/// CPU, memory, and disk resource limits.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ResourceSpec {
    /// CPU cores (milli-cores, e.g. 1000 = 1 core).
    pub cpu_millis: u32,

    /// Memory limit in bytes.
    pub memory_bytes: u64,

    /// Ephemeral storage limit in bytes.  `0` = unlimited.
    pub disk_bytes: u64,
}

/// A Linux capability (e.g. `CAP_NET_RAW`).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Capability {
    /// Capability name (e.g. `CAP_NET_RAW`).
    pub name: String,
}

/// Network egress policy.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NetworkEgress {
    /// Egress mode: `deny`, `allowlist`, or `unrestricted`.
    pub mode: String,

    /// Allowed destination CIDRs or hostnames (used when `mode == "allowlist"`).
    pub allowed_destinations: Vec<String>,
}

/// Filesystem mount specification.
///
/// Supports read-only bind mounts (`read_only = true`) and writable
/// overlay mounts (`read_only = false`).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MountSpec {
    /// Host path (source).
    pub source: String,

    /// Container path (destination).
    pub destination: String,

    /// Mount type: `bind`, `overlay`, `tmpfs`.
    pub mount_type: String,

    /// When `true`, the mount is read-only.
    pub read_only: bool,
}

/// Attestation configuration — substrate enforces these requirements (B1-IDENT).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct AttestationConfig {
    /// Whether attestation is required before the sandbox starts.
    pub required: bool,

    /// Attestation measurement types (e.g. `sha256`, `tpm2`).
    pub measurements: Vec<String>,

    /// Allowed runtime identities that may execute the sandbox.
    pub allowed_runtimes: Vec<String>,
}

/// Hebb memory-bridge configuration (B2-MEM).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct HebbBridgeConfig {
    /// Whether the hebb memory bridge is enabled.
    pub enabled: bool,

    /// Hebb daemon endpoint (e.g. `http://127.0.0.1:7331`).
    pub endpoint: String,

    /// Maximum context window in tokens.
    pub max_context_tokens: u64,
}

/// Checkpoint / durability policy (B3-DURABLE).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct CheckpointPolicy {
    /// Whether checkpointing is enabled.
    pub enabled: bool,

    /// Checkpoint interval in seconds.
    pub interval_secs: u64,

    /// Checkpoint storage path on the host.
    pub storage_path: String,
}

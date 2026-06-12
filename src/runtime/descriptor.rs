//! symphony+ Sandbox descriptor schema.
//!
//! **AC.1 (MIK-NEW.RUNTIME-D.1)**: schema published with fields:
//! `name`, `image`, `resources`, `capabilities`, `network_egress`, `env`,
//! `mounts` (read-only + writable overlay).
//!
//! **AC.7 (B1-IDENT)**: descriptor carries attestation requirements via
//! [`AttestationConfig`]; substrate enforces.
//!
//! **AC.8 (B2-MEM)**: descriptor carries hebb-bridge config via
//! [`HebbBridgeConfig`]; substrate enforces.
//!
//! **AC.9 (B3-DURABLE)**: descriptor carries checkpoint policy via
//! [`CheckpointPolicy`]; substrate enforces.
//!
//! **AC.5 (MIK-NEW.RUNTIME-D.5)**: override hook via
//! [`SandboxDescriptor::substrate_override`].

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use super::substrate::Substrate;

// ── SandboxDescriptor ────────────────────────────────────────────────────

/// Top-level Sandbox descriptor — the single operator-authored spec that
/// compiles to either a gVisor OCI bundle or an Apple VM-spec depending on
/// the host substrate.
///
/// # Fields (AC.1 verbatim)
///
/// * `name` — human-readable identifier for this sandbox instance.
/// * `image` — OCI image reference (e.g. `"docker.io/library/ubuntu:22.04"`).
/// * `resources` — CPU/memory/disk limits.
/// * `capabilities` — Linux capabilities to grant (e.g. `"CAP_NET_BIND_SERVICE"`).
/// * `network_egress` — egress policy for the sandbox.
/// * `env` — environment variables injected into the sandbox.
/// * `mounts` — filesystem mounts (read-only and writable overlay).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SandboxDescriptor {
    /// Human-readable sandbox instance name.
    pub name: String,

    /// OCI image reference.
    ///
    /// Examples: `"docker.io/library/ubuntu:22.04"`,
    /// `"ghcr.io/symphony/agent-runtime:v2"`.
    pub image: String,

    /// CPU, memory, and disk resource limits.
    pub resources: ResourceSpec,

    /// Linux capabilities to grant inside the sandbox.
    ///
    /// Empty list means no additional capabilities beyond the default set.
    /// Example: `["CAP_NET_BIND_SERVICE", "CAP_SYS_PTRACE"]`.
    #[serde(default)]
    pub capabilities: Vec<String>,

    /// Network egress policy.
    #[serde(default)]
    pub network_egress: NetworkEgressPolicy,

    /// Environment variables injected into the sandbox process.
    #[serde(default)]
    pub env: HashMap<String, String>,

    /// Filesystem mounts.
    ///
    /// Order matters: later mounts can overlay earlier ones.  Read-only
    /// mounts are applied first, then writable overlay mounts on top.
    #[serde(default)]
    pub mounts: Vec<MountSpec>,

    // ── Bet fields (B1–B3) ─────────────────────────────────────────────

    /// Attestation requirements (B1-IDENT).
    ///
    /// When `Some`, the substrate MUST verify the sandbox image against
    /// these attestation rules before starting.
    #[serde(default)]
    pub attestation: Option<AttestationConfig>,

    /// Hebb memory-bridge configuration (B2-MEM).
    ///
    /// When `Some`, the substrate MUST wire the sandbox into the hebb
    /// memory bridge so agent session memory is persisted and retrievable.
    #[serde(default)]
    pub hebb_bridge: Option<HebbBridgeConfig>,

    /// Checkpoint policy (B3-DURABLE).
    ///
    /// When `Some`, the substrate MUST periodically snapshot the sandbox
    /// state according to this policy and resume from the latest snapshot
    /// on restart.
    #[serde(default)]
    pub checkpoint_policy: Option<CheckpointPolicy>,

    // ── Override hook (AC.5) ───────────────────────────────────────────

    /// Substrate override — operator can pin this sandbox to a specific
    /// substrate when uniform abstraction is wrong for the task.
    ///
    /// `None` (default) means auto-detect.
    #[serde(default)]
    pub substrate_override: Option<Substrate>,
}

// ── ResourceSpec ─────────────────────────────────────────────────────────

/// CPU, memory, and disk resource limits for a sandbox.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ResourceSpec {
    /// CPU cores (can be fractional, e.g. `0.5` for half a core).
    #[serde(default = "default_cpu_cores")]
    pub cpu_cores: f64,

    /// Memory limit in megabytes.
    #[serde(default = "default_memory_mb")]
    pub memory_mb: u64,

    /// Disk limit in megabytes.
    ///
    /// `0` means no explicit limit (inherits image size).
    #[serde(default)]
    pub disk_mb: u64,
}

fn default_cpu_cores() -> f64 {
    1.0
}

fn default_memory_mb() -> u64 {
    512
}

impl Default for ResourceSpec {
    fn default() -> Self {
        Self {
            cpu_cores: default_cpu_cores(),
            memory_mb: default_memory_mb(),
            disk_mb: 0,
        }
    }
}

// ── NetworkEgressPolicy ──────────────────────────────────────────────────

/// Network egress policy for a sandbox.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum NetworkEgressPolicy {
    /// No network access permitted.
    None,

    /// Only loopback (localhost) access.
    #[default]
    Loopback,

    /// Full internet access.
    Full,

    /// Allow egress only to the specified CIDR ranges.
    #[serde(untagged)]
    Allowlist(Vec<String>),
}

// ── MountSpec ────────────────────────────────────────────────────────────

/// A filesystem mount specification.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MountSpec {
    /// Mount type: read-only or writable overlay.
    #[serde(rename = "type")]
    pub mount_type: MountType,

    /// Host path to mount into the sandbox.
    pub source: String,

    /// Target path inside the sandbox.
    pub target: String,
}

/// Mount type — read-only or writable overlay.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum MountType {
    /// Read-only bind mount.  The sandbox cannot modify these files.
    ReadOnly,

    /// Writable overlay.  Writes go to a copy-on-write layer; the host
    /// source is never modified.
    WritableOverlay,
}

// ── AttestationConfig (B1-IDENT) ─────────────────────────────────────────

/// Attestation requirements for sandbox image verification.
///
/// The substrate MUST verify the sandbox image against these rules before
/// starting the sandbox.  If verification fails, the sandbox is refused.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AttestationConfig {
    /// Required attestation method (e.g. `"cosign"`, `"notary"`).
    pub method: String,

    /// Expected signer identity (e.g. key fingerprint, x509 subject).
    pub signer: String,

    /// Optional transparency log URL.
    #[serde(default)]
    pub rekor_url: Option<String>,
}

// ── HebbBridgeConfig (B2-MEM) ────────────────────────────────────────────

/// Hebb memory-bridge configuration.
///
/// When present, the substrate wires the sandbox into the hebb memory
/// bridge so agent session memory is persisted and retrievable across
/// sandbox restarts.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HebbBridgeConfig {
    /// Hebb database endpoint URL.
    pub endpoint: String,

    /// Namespace for this sandbox's memory.
    pub namespace: String,

    /// Maximum memory entries to retain.
    #[serde(default = "default_hebb_max_entries")]
    pub max_entries: usize,
}

fn default_hebb_max_entries() -> usize {
    10_000
}

// ── CheckpointPolicy (B3-DURABLE) ────────────────────────────────────────

/// Checkpoint policy for durable sandbox state.
///
/// The substrate periodically snapshots the sandbox according to this
/// policy and resumes from the latest snapshot on restart.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CheckpointPolicy {
    /// Interval between snapshots, in seconds.
    pub interval_secs: u64,

    /// Maximum number of snapshots to retain.
    #[serde(default = "default_max_snapshots")]
    pub max_snapshots: usize,

    /// Path where snapshots are stored on the host.
    pub snapshot_dir: String,
}

fn default_max_snapshots() -> usize {
    5
}

// ── SandboxDescriptor helpers ────────────────────────────────────────────

impl SandboxDescriptor {
    /// Resolve the effective substrate for this descriptor.
    ///
    /// If `substrate_override` is `Some`, that substrate is used (AC.5).
    /// Otherwise, the host substrate is auto-detected (AC.2).
    #[must_use]
    pub fn effective_substrate(&self) -> Substrate {
        self.substrate_override.unwrap_or_else(Substrate::detect)
    }

    /// Returns an iterator over read-only mounts (convenience).
    #[must_use]
    pub fn read_only_mounts(&self) -> impl Iterator<Item = &MountSpec> {
        self.mounts
            .iter()
            .filter(|m| m.mount_type == MountType::ReadOnly)
    }

    /// Returns an iterator over writable overlay mounts (convenience).
    #[must_use]
    pub fn writable_mounts(&self) -> impl Iterator<Item = &MountSpec> {
        self.mounts
            .iter()
            .filter(|m| m.mount_type == MountType::WritableOverlay)
    }
}

// ── Validation ───────────────────────────────────────────────────────────

impl SandboxDescriptor {
    /// Validate the descriptor.
    ///
    /// Returns `Ok(())` if the descriptor is valid, or an `Err` with a
    /// human-readable message describing the first validation failure.
    ///
    /// # Errors
    ///
    /// * `name` must be non-empty.
    /// * `image` must be non-empty.
    /// * Mount sources and targets must be non-empty.
    #[must_use]
    pub fn validate(&self) -> Result<(), String> {
        if self.name.is_empty() {
            return Err("SandboxDescriptor.name must not be empty".to_string());
        }
        if self.image.is_empty() {
            return Err("SandboxDescriptor.image must not be empty".to_string());
        }
        if self.resources.cpu_cores <= 0.0 {
            return Err(format!(
                "cpu_cores must be positive, got {}",
                self.resources.cpu_cores
            ));
        }
        if self.resources.memory_mb == 0 {
            return Err("memory_mb must be positive".to_string());
        }
        for (i, mount) in self.mounts.iter().enumerate() {
            if mount.source.is_empty() {
                return Err(format!("mounts[{i}].source must not be empty"));
            }
            if mount.target.is_empty() {
                return Err(format!("mounts[{i}].target must not be empty"));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
#[path = "descriptor_tests.rs"]
mod tests;

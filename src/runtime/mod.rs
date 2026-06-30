//! RUNTIME-D: dual-substrate OCI abstraction layer.
//!
//! Provides a unified [`SandboxDescriptor`] that compiles to either a gVisor
//! `runsc` OCI bundle (Linux) or an Apple containerization VM-spec (macOS),
//! with automatic substrate detection, divergence tracking, and operator
//! override hooks.
//!
//! # Architecture
//!
//! ```text
//! SandboxDescriptor  (operator-authored, YAML/JSON)
//!   └── Compiler     (substrate-aware)
//!         ├── gVisor OCI bundle   (Linux / runsc)
//!         └── Apple VM-spec       (macOS / Hypervisor.framework)
//! ```
//!
//! # Acceptance Criteria (MIK-5226)
//!
//! | AC  | Label            | Module                  |
//! |-----|------------------|-------------------------|
//! | D.1 | Descriptor schema | [`descriptor`]          |
//! | D.2 | Compiler          | [`compiler`]            |
//! | D.3 | Test matrix       | [`compiler`] (tests)    |
//! | D.4 | Divergence        | [`divergence`]          |
//! | D.5 | Override hook     | [`descriptor`]          |
//! | D.6 | Documentation     | `docs/runtime/`         |
//! | D.7 | Attestation (B1)  | [`descriptor`]          |
//! | D.8 | Hebb bridge (B2)  | [`descriptor`]          |
//! | D.9 | Checkpoint (B3)   | [`descriptor`]          |
//! |D.10 | OCI std (B4)      | [`compiler`]            |
//!
//! # Boundary: runtime-substrate vs backend runtime providers
//!
//! This crate contains two distinct runtime layers — do not confuse them:
//!
//! | Layer                    | Feature flag?       | What it does |
//! |--------------------------|---------------------|--------------|
//! | **runtime-substrate**    | `runtime-substrate` | Compiles a [`SandboxDescriptor`] into an OCI bundle or Apple VM-spec. Answers "what should the sandbox look like?" — NEVER launches processes. |
//! | **Backend runtime providers** | Always on     | The [`RuntimeProvider`] trait lives in [`provider`]. Implementations ([`local_compat`], [`docker`]) actually spawn, monitor, and stop MCP server processes/containers. Answers "run this MCP server now." |
//!
//! The `runtime-substrate` descriptor compiler is an off-by-default design
//! tool for advanced operators crafting custom sandboxes.  The backend
//! runtime provider layer is the production execution path for every
//! backend start/stop cycle.  They share the `src/runtime/` directory for
//! discoverability but operate at completely different lifecycle phases.

pub mod compiler;
pub mod descriptor;
pub mod divergence;
pub mod r#override;

/// Hardened provisioning call path (wired entry point, off-by-default feature).
#[cfg(feature = "runtime-substrate")]
pub mod provision;

mod substrate;

// ── Backend runtime provider modules ────────────────────────────────────────

pub mod audit;
pub mod docker;
pub mod local_compat;
pub mod policy;
pub mod provider;

// ── Re-exports: descriptor/substrate layer (MIK-5226) ───────────────────────

pub use compiler::{
    AppleVmNetwork, AppleVmSpec, CompiledBundle, Compiler, OciBundle, VirtioFsMount,
};
pub use descriptor::{
    AttestationConfig, CheckpointPolicy, HebbBridgeConfig, MountSpec, MountType,
    NetworkEgressPolicy, ResourceSpec, SandboxDescriptor,
};
pub use divergence::{DivergenceRecord, DivergenceRegistry, SubstrateTag};
pub use r#override::OverrideHook;
pub use substrate::Substrate;

// ── Re-exports: backend runtime provider layer (MIK-6555) ───────────────────

pub use audit::{redact_secret_value, AuditAction, AuditEvent};
pub use local_compat::LocalCompatProvider;
pub use docker::DockerProvider;
pub use policy::{
    EnvPolicy, EgressPolicy, IdentityPolicy, LogPolicy, MountEntry, MountPolicy,
    ResourcePolicy, RuntimeConfig, SecretPolicy, TimeoutPolicy,
    FORBIDDEN_DOCKER_SOCKET_PATHS, FORBIDDEN_MOUNT_PATHS,
};
pub use provider::{
    create_provider, validate_egress, validate_mount, PolicyVerdict, RuntimeHandle,
    RuntimeProvider,
};

#[cfg(test)]
mod tests;

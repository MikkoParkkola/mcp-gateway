// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
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

pub mod compiler;
pub mod descriptor;
pub mod divergence;
pub mod r#override;
pub mod provider;

/// Hardened provisioning call path (wired entry point, off-by-default feature).
#[cfg(feature = "runtime-substrate")]
pub mod provision;

mod substrate;

pub use compiler::{
    AppleVmNetwork, AppleVmSpec, CompiledBundle, Compiler, OciBundle, VirtioFsMount,
};
pub use descriptor::{
    AttestationConfig, CheckpointPolicy, HebbBridgeConfig, MountSpec, MountType,
    NetworkEgressPolicy, ResourceSpec, SandboxDescriptor,
};
pub use divergence::{DivergenceRecord, DivergenceRegistry, SubstrateTag};
pub use r#override::OverrideHook;
pub use provider::{
    ContainerProvider, LocalProcessProvider, RuntimeApplyAction, RuntimeApplyAuditEvent,
    RuntimeApplyError, RuntimeApplyRequest, RuntimeApplyResult, RuntimeApplyStatus,
    RuntimeAuditEvent, RuntimeAvailability, RuntimeCommandOutcome, RuntimeCommandRunner,
    RuntimeConfirmation, RuntimeConfirmationRisk, RuntimeDataClass, RuntimeDenial,
    RuntimeDenyReason, RuntimeEnvironmentPolicy, RuntimeIntent, RuntimeLaunchCommand,
    RuntimeLaunchMode, RuntimeLicenseTier, RuntimeLifecyclePlan, RuntimeMount, RuntimeMountMode,
    RuntimeNetworkEgress, RuntimePlan, RuntimePlanner, RuntimePolicy, RuntimePreflightCheck,
    RuntimeProvider, RuntimeProviderKind, RuntimeProviderSelection, RuntimeRecommendation,
    RuntimeResourcePolicy, RuntimeRestartPolicy, StdRuntimeCommandRunner,
};
pub use substrate::Substrate;

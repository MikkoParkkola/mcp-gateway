//! Dual-substrate OCI abstraction layer (RUNTIME-D / B4-PLATFORM).
//!
//! Compiles a single [`SandboxDescriptor`](descriptor::SandboxDescriptor)
//! to gVisor `runsc` OCI bundles on Linux and Apple Virtualization.framework
//! VM-specs on macOS.  Substrate is auto-detected; operators can override
//! via [`OverrideHook`](override_hook::OverrideHook).
//!
//! # Modules
//!
//! - [`descriptor`] — Sandbox descriptor schema (AC.1)
//! - [`substrate`] — Substrate kinds and auto-detection (AC.2)
//! - [`compiler`] — Descriptor → OCI / VM-spec compilers (AC.2)
//! - [`divergence`] — Substrate-divergence detection (AC.4)
//! - [`override_hook`] — Substrate override / pinning (AC.5)
//! - [`audit`] — Audit trail with substrate-id tags (AC.3, AC.4)
//! - [`workload`] — Agent workload definitions for test matrix (AC.3)

pub mod audit;
pub mod compiler;
pub mod descriptor;
pub mod divergence;
pub mod override_hook;
pub mod substrate;
pub mod workload;

pub use audit::{AuditRecord, AuditTrail, SubstrateId};
pub use compiler::{AppleVmSpec, GvisorBundle};
pub use descriptor::SandboxDescriptor;
pub use divergence::{DivergenceRegistry, SubstrateDivergence};
pub use override_hook::OverrideHook;
pub use substrate::{CompiledSpec, SubstrateKind};
pub use workload::Workload;

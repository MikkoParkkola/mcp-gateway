//! Substrate types and auto-detection.
//!
//! A *substrate* is a concrete container runtime: gVisor `runsc` on Linux
//! or Apple Virtualization.framework on macOS.  [`SubstrateKind::auto_detect`]
//! selects the appropriate substrate at runtime.

use serde::{Deserialize, Serialize};

use super::compiler::{AppleVmSpec, GvisorBundle};
use crate::error::Result;
use crate::runtime::descriptor::SandboxDescriptor;

/// Container-runtime substrate kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SubstrateKind {
    /// gVisor `runsc` OCI bundle (Linux / Ubuntu).
    Gvisor,
    /// Apple Virtualization.framework VM-spec (macOS).
    Apple,
}

impl SubstrateKind {
    /// Auto-detect the substrate for the current platform.
    ///
    /// Returns `Gvisor` on Linux, `Apple` on macOS.  Falls back to `Gvisor`
    /// on other platforms.
    pub fn auto_detect() -> Self {
        if cfg!(target_os = "linux") {
            Self::Gvisor
        } else if cfg!(target_os = "macos") {
            Self::Apple
        } else {
            Self::Gvisor
        }
    }

    /// Compile a descriptor to this substrate's native format.
    pub fn compile(self, descriptor: &SandboxDescriptor) -> Result<CompiledSpec> {
        match self {
            Self::Gvisor => {
                let bundle = super::compiler::gvisor_compile(descriptor)?;
                Ok(CompiledSpec::Gvisor(bundle))
            }
            Self::Apple => {
                let spec = super::compiler::apple_compile(descriptor)?;
                Ok(CompiledSpec::Apple(spec))
            }
        }
    }
}

/// Substrate-specific compiled output.
#[derive(Debug, Clone, PartialEq)]
pub enum CompiledSpec {
    /// gVisor OCI bundle.
    Gvisor(GvisorBundle),
    /// Apple Virtualization.framework VM-spec.
    Apple(AppleVmSpec),
}

impl CompiledSpec {
    /// Return the substrate kind that produced this spec.
    pub fn substrate(&self) -> SubstrateKind {
        match self {
            Self::Gvisor(_) => SubstrateKind::Gvisor,
            Self::Apple(_) => SubstrateKind::Apple,
        }
    }
}

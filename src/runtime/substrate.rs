// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Substrate detection and enumeration.
//!
//! The [`Substrate`] enum represents the two supported containerization
//! backends — gVisor `runsc` on Linux and Apple containerization
//! (Hypervisor.framework) on macOS.  Auto-detection uses `target_os`.

use serde::{Deserialize, Serialize};

/// The containerization substrate.
///
/// # Auto-detection
///
/// [`Substrate::detect`] returns `GVisor` on Linux and `AppleVm` on macOS.
/// This is the default when a [`SandboxDescriptor`](super::SandboxDescriptor) has no
/// `substrate_override` (AC.2, AC.5).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Hash)]
#[serde(rename_all = "snake_case")]
pub enum Substrate {
    /// gVisor `runsc` OCI runtime (Linux).
    #[serde(rename = "gvisor")]
    GVisor,

    /// Apple containerization via Hypervisor.framework VM-spec (macOS).
    AppleVm,
}

impl Substrate {
    /// Auto-detect the host substrate based on `target_os`.
    ///
    /// Returns `GVisor` on Linux, `AppleVm` on macOS.
    #[must_use]
    pub fn detect() -> Self {
        #[cfg(target_os = "linux")]
        {
            Self::GVisor
        }
        #[cfg(target_os = "macos")]
        {
            Self::AppleVm
        }
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        {
            // On unsupported platforms, default to GVisor OCI spec as
            // it is the most portable format.
            Self::GVisor
        }
    }

    /// Human-readable substrate name for logging/audit.
    #[must_use]
    pub fn name(&self) -> &'static str {
        match self {
            Self::GVisor => "gvisor",
            Self::AppleVm => "apple_vm",
        }
    }

    /// OCI runtime label for diagnostics; not part of the token flow.
    #[must_use]
    pub fn runtime_label(self) -> &'static str {
        match self {
            Self::GVisor => "runsc",
            Self::AppleVm => "apple-containerization",
        }
    }

    /// OCI hook at which the token is injected — the same lifecycle point on
    /// both substrates, keeping the flow identical.
    #[must_use]
    pub fn token_injection_hook(self) -> &'static str {
        "createRuntime"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detect_matches_target_os() {
        let s = Substrate::detect();
        #[cfg(target_os = "linux")]
        assert_eq!(s, Substrate::GVisor);
        // Any other platform takes the unsupported-platform fallback.
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        assert_eq!(s, Substrate::GVisor);
        #[cfg(target_os = "macos")]
        assert_eq!(s, Substrate::AppleVm);
    }

    #[test]
    fn substrate_name_is_stable() {
        assert_eq!(Substrate::GVisor.name(), "gvisor");
        assert_eq!(Substrate::AppleVm.name(), "apple_vm");
    }

    #[test]
    fn substrate_serde_round_trip() {
        let json = serde_json::to_string(&Substrate::GVisor).unwrap();
        assert_eq!(json, r#""gvisor""#);
        let restored: Substrate = serde_json::from_str(&json).unwrap();
        assert_eq!(restored, Substrate::GVisor);

        let json = serde_json::to_string(&Substrate::AppleVm).unwrap();
        assert_eq!(json, r#""apple_vm""#);
        let restored: Substrate = serde_json::from_str(&json).unwrap();
        assert_eq!(restored, Substrate::AppleVm);
    }

    #[test]
    fn runtime_labels_and_token_hook_are_the_launcher_values() {
        assert_eq!(Substrate::GVisor.runtime_label(), "runsc");
        assert_eq!(Substrate::AppleVm.runtime_label(), "apple-containerization");
        assert_eq!(Substrate::GVisor.token_injection_hook(), "createRuntime");
        assert_eq!(Substrate::AppleVm.token_injection_hook(), "createRuntime");
    }

    #[test]
    fn substrates_are_distinct() {
        assert_ne!(Substrate::GVisor, Substrate::AppleVm);
    }
}

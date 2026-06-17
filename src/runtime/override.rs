//! Substrate override hook.
//!
//! **AC.5 (MIK-NEW.RUNTIME-D.5)**: the [`OverrideHook`] lets an operator pin
//! a Sandbox to a specific substrate when uniform abstraction is wrong
//! for the task.
//!
//! The override is stored in [`SandboxDescriptor::substrate_override`] and
//! enforced by [`SandboxDescriptor::effective_substrate`].  This module
//! provides the validation wrapper that logs and audits override decisions.

use serde::{Deserialize, Serialize};

use super::substrate::Substrate;

/// Operator-controlled substrate override.
///
/// Wraps an optional [`Substrate`] value.  When `Some`, forces all
/// compilation to use the pinned substrate regardless of the host OS.
/// When `None`, the compiler auto-detects.
///
/// This is the programmatic representation of the override hook (AC.5).
/// The hook is implemented directly in
/// [`super::descriptor::SandboxDescriptor::effective_substrate`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct OverrideHook {
    /// The pinned substrate, or `None` for auto-detect.
    pub pinned: Option<Substrate>,
}

impl OverrideHook {
    /// Create a hook with no override (auto-detect).
    #[must_use]
    pub fn auto() -> Self {
        Self { pinned: None }
    }

    /// Create a hook that pins to gVisor.
    #[must_use]
    pub fn pin_gvisor() -> Self {
        Self {
            pinned: Some(Substrate::GVisor),
        }
    }

    /// Create a hook that pins to Apple VM.
    #[must_use]
    pub fn pin_apple_vm() -> Self {
        Self {
            pinned: Some(Substrate::AppleVm),
        }
    }

    /// Returns `true` if the operator has pinned a specific substrate.
    #[must_use]
    pub fn is_pinned(&self) -> bool {
        self.pinned.is_some()
    }

    /// Resolve the effective substrate: pinned if set, otherwise auto-detect.
    #[must_use]
    pub fn resolve(&self) -> Substrate {
        self.pinned.unwrap_or_else(Substrate::detect)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auto_hook_detects_substrate() {
        let hook = OverrideHook::auto();
        assert!(!hook.is_pinned());
        let s = hook.resolve();
        #[cfg(target_os = "linux")]
        assert_eq!(s, Substrate::GVisor);
        #[cfg(target_os = "macos")]
        assert_eq!(s, Substrate::AppleVm);
    }

    #[test]
    fn pin_gvisor_overrides_detection() {
        let hook = OverrideHook::pin_gvisor();
        assert!(hook.is_pinned());
        assert_eq!(hook.resolve(), Substrate::GVisor);
    }

    #[test]
    fn pin_apple_vm_overrides_detection() {
        let hook = OverrideHook::pin_apple_vm();
        assert!(hook.is_pinned());
        assert_eq!(hook.resolve(), Substrate::AppleVm);
    }

    #[test]
    fn override_hook_default_is_auto() {
        let hook = OverrideHook::default();
        assert!(!hook.is_pinned());
    }

    #[test]
    fn override_hook_serde_round_trip() {
        let hook = OverrideHook::pin_gvisor();
        let json = serde_json::to_string(&hook).unwrap();
        let restored: OverrideHook = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.pinned, Some(Substrate::GVisor));
    }
}

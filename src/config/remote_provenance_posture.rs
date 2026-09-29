// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Which remote backends run without signed provenance (#1943).
//!
//! Config load verifies a remote backend's signed metadata when
//! `require_for_remote_backends` is set or when metadata for it exists
//! (`Config::validate_remote_backend_provenance`). A remote backend with no
//! metadata therefore runs unverified while the flag is off; this names them,
//! so startup and `doctor` can say so.

use super::Config;

impl Config {
    /// Enabled remote backends that run without signed provenance checks,
    /// sorted by name. Empty while `require_for_remote_backends` is set.
    #[must_use]
    fn unverified_remote_backends(&self) -> Vec<&str> {
        let policy = &self.security.remote_server_signing;
        if policy.require_for_remote_backends {
            return Vec::new();
        }
        // Same scope as the load-time check: enabled backends whose transport
        // `remote_transport_identity` calls remote.
        let mut names: Vec<&str> = self
            .backends
            .iter()
            .filter(|(name, backend)| {
                backend.enabled
                    && super::remote_transport_identity(&backend.transport).is_some()
                    && !policy.backends.contains_key(name.as_str())
            })
            .map(|(name, _)| name.as_str())
            .collect();
        names.sort_unstable();
        names
    }

    /// The operator-facing warning naming every enabled remote backend that
    /// runs without signed provenance, or `None` when there is none.
    #[must_use]
    pub fn remote_provenance_warning(&self) -> Option<String> {
        let names = self.unverified_remote_backends();
        if names.is_empty() {
            return None;
        }
        Some(format!(
            "remote backends run without signed provenance checks: {}. Set \
             security.remote_server_signing.require_for_remote_backends and add signed \
             metadata to verify them.",
            names.join(", ")
        ))
    }
}

#[cfg(test)]
#[path = "remote_provenance_posture_tests.rs"]
mod tests;

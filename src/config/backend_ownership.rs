// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Backend settings that are valid only where the gateway owns the process
//! (split from `config/mod.rs`).

use super::{Config, TransportConfig};
use crate::{Error, Result};

impl Config {
    /// `max_frame_bytes` applies to a stdio backend only, within the allowed range.
    ///
    /// # Errors
    ///
    /// A validation error naming the backend.
    pub(super) fn validate_max_frame_bytes(&self) -> Result<()> {
        use crate::transport::{CEILING_MAX_FRAME_BYTES, MIN_MAX_FRAME_BYTES};
        for (name, backend) in &self.backends {
            let Some(bytes) = backend.max_frame_bytes else {
                continue;
            };
            if !matches!(backend.transport, TransportConfig::Stdio { .. }) {
                return Err(Error::ConfigValidation(format!(
                    "backends.{name}.max_frame_bytes is only valid for a stdio backend (one \
                     declared with a `command`)"
                )));
            }
            if !(MIN_MAX_FRAME_BYTES..=CEILING_MAX_FRAME_BYTES).contains(&bytes) {
                return Err(Error::ConfigValidation(format!(
                    "backends.{name}.max_frame_bytes must be between {MIN_MAX_FRAME_BYTES} and \
                     {CEILING_MAX_FRAME_BYTES} bytes"
                )));
            }
        }
        Ok(())
    }

    /// `stop_when_idle_for` is meaningful only where the gateway OWNS the backend
    /// process - a backend declared with a `command`, which the gateway spawned
    /// and can therefore stop and restart.
    ///
    /// For an externally managed endpoint the gateway can close its client
    /// connection, but that does not stop the server on the other end, so the
    /// setting would promise a reclaim it cannot perform. Locality does not grant
    /// ownership: a local HTTP MCP server on 127.0.0.1 is still not ours to stop.
    ///
    /// This rejects rather than ignores, deliberately. The predecessor key
    /// `idle_timeout` was accepted everywhere and enforced nowhere; one operator
    /// had it set on 24 backends believing it worked. Silently accepting a
    /// setting the gateway cannot honour is the exact failure being corrected.
    ///
    /// # Errors
    ///
    /// Returns a validation error naming the backend when the setting is present
    /// on a backend the gateway does not start.
    pub(super) fn validate_stop_when_idle_ownership(&self) -> Result<()> {
        for (name, backend) in &self.backends {
            if backend.stop_when_idle_for.is_none() {
                continue;
            }
            if !matches!(backend.transport, TransportConfig::Stdio { .. }) {
                return Err(Error::ConfigValidation(format!(
                    "backends.{name}.stop_when_idle_for is only valid for a backend the gateway \
                     starts itself (one declared with a `command`). This backend is reached over \
                     a URL the gateway did not start, so closing the connection would not stop \
                     it. Remove the setting, or run that server under the gateway as a stdio \
                     backend."
                )));
            }
        }
        Ok(())
    }
}

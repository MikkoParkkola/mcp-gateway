//! Gateway-level session sandboxing for per-session resource limits.
//!
//! Enforces resource quotas and access control rules on every tool invocation
//! before it reaches the backend.  Limits are configured per-profile and
//! applied by the [`SandboxEnforcer`].
//!
//! # Design
//!
//! ```text
//! SandboxConfig   (loaded from gateway YAML, serde::Deserialize)
//!   └── profiles  Map<profile_name, SessionSandbox>
//!
//! SandboxEnforcer (one per active MCP session, wraps a SessionSandbox)
//!   ├── call_count   AtomicU64
//!   └── started_at   Instant
//! ```
//!
//! `SandboxEnforcer::check()` is the single enforcement point; it must be
//! called before every tool invocation.
//!
//! # Example
//!
//! ```rust
//! use std::time::Duration;
//! use mcp_gateway::session_sandbox::{SessionSandbox, SandboxEnforcer};
//!
//! let sandbox = SessionSandbox {
//!     max_calls: 100,
//!     max_duration: Duration::from_secs(3600),
//!     allowed_backends: Some(vec!["search".to_string()]),
//!     denied_tools: vec!["exec".to_string()],
//!     max_payload_bytes: 65_536,
//! };
//! let enforcer = SandboxEnforcer::new(sandbox);
//! // Before each tool call:
//! enforcer.check("search", "web_search", 1024).unwrap();
//! ```

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use crate::{Error, Result};

// ── SessionSandbox ────────────────────────────────────────────────────────────

/// Per-session resource limits and access-control rules.
///
/// A `SessionSandbox` is a static policy description; it does not hold any
/// mutable runtime state.  Use [`SandboxEnforcer`] to track live usage against
/// these limits.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SessionSandbox {
    /// Maximum number of tool calls permitted in the session.
    /// `0` means unlimited.
    #[serde(default = "default_max_calls")]
    pub max_calls: u64,

    /// Session wall-clock timeout.  The session is rejected once this
    /// `Duration` has elapsed since the enforcer was created.
    /// `Duration::ZERO` means no timeout.
    #[serde(
        default = "default_max_duration",
        serialize_with = "serialize_duration_secs",
        deserialize_with = "deserialize_duration_secs"
    )]
    pub max_duration: Duration,

    /// Allowlist of backend names.  `None` permits all backends.
    /// When `Some`, only the listed backends may be called.
    #[serde(default)]
    pub allowed_backends: Option<Vec<String>>,

    /// Denylist of tool names (exact match).  A tool whose name appears here
    /// is rejected regardless of which backend serves it.
    #[serde(default)]
    pub denied_tools: Vec<String>,

    /// Maximum size of the tool argument payload in bytes.
    /// `0` means unlimited.
    #[serde(default = "default_max_payload_bytes")]
    pub max_payload_bytes: usize,
}

fn default_max_calls() -> u64 {
    0
}

fn default_max_duration() -> Duration {
    Duration::ZERO
}

fn default_max_payload_bytes() -> usize {
    0
}

impl Default for SessionSandbox {
    /// An unrestricted sandbox — no limits applied.
    fn default() -> Self {
        Self {
            max_calls: 0,
            max_duration: Duration::ZERO,
            allowed_backends: None,
            denied_tools: Vec::new(),
            max_payload_bytes: 0,
        }
    }
}

// Serde helpers for Duration as integer seconds in YAML/JSON config.

fn serialize_duration_secs<S>(d: &Duration, s: S) -> std::result::Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    s.serialize_u64(d.as_secs())
}

fn deserialize_duration_secs<'de, D>(d: D) -> std::result::Result<Duration, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let secs = u64::deserialize(d)?;
    Ok(Duration::from_secs(secs))
}

// ── SandboxConfig ─────────────────────────────────────────────────────────────

/// Gateway-level sandbox configuration, loaded from the top-level config file.
///
/// ```yaml
/// sandbox:
///   default_profile: strict
///   profiles:
///     permissive:
///       max_calls: 0       # unlimited
///       max_duration: 0    # no timeout
///     strict:
///       max_calls: 50
///       max_duration: 1800
///       denied_tools:
///         - exec
///         - shell
///       max_payload_bytes: 65536
/// ```
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SandboxConfig {
    /// Name of the profile applied when no session-specific profile is
    /// requested.  Defaults to `"default"`.
    #[serde(default = "default_profile_name")]
    pub default_profile: String,

    /// Named sandbox profiles.
    #[serde(default)]
    pub profiles: HashMap<String, SessionSandbox>,
}

fn default_profile_name() -> String {
    "default".to_string()
}

impl SandboxConfig {
    /// Resolve a sandbox for the given profile name.
    ///
    /// Falls back to the `default_profile` if `name` is `None`, and to an
    /// unrestricted [`SessionSandbox::default()`] if neither is found.
    #[must_use]
    pub fn resolve(&self, name: Option<&str>) -> SessionSandbox {
        let key = name.unwrap_or(&self.default_profile);
        self.profiles.get(key).cloned().unwrap_or_default()
    }
}

// ── SandboxViolation ──────────────────────────────────────────────────────────

/// Reason a sandbox check was rejected.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SandboxViolation {
    /// The session has exceeded its call quota.
    CallLimitExceeded {
        /// Number of calls that have been attempted.
        attempted: u64,
        /// Configured limit.
        limit: u64,
    },
    /// The session has been running longer than `max_duration`.
    SessionExpired {
        /// Elapsed time in seconds.
        elapsed_secs: u64,
        /// Configured limit in seconds.
        limit_secs: u64,
    },
    /// The requested backend is not on the session's allowlist.
    BackendNotAllowed {
        /// The backend that was requested.
        backend: String,
    },
    /// The requested tool is on the session's denylist.
    ToolDenied {
        /// The tool that was requested.
        tool: String,
    },
    /// The argument payload exceeds the configured byte limit.
    PayloadTooLarge {
        /// Actual payload size in bytes.
        actual_bytes: usize,
        /// Configured limit in bytes.
        limit_bytes: usize,
    },
}

impl std::fmt::Display for SandboxViolation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::CallLimitExceeded { attempted, limit } => write!(
                f,
                "session call limit exceeded: attempted {attempted}, limit {limit}"
            ),
            Self::SessionExpired {
                elapsed_secs,
                limit_secs,
            } => write!(
                f,
                "session expired: elapsed {elapsed_secs}s, limit {limit_secs}s"
            ),
            Self::BackendNotAllowed { backend } => {
                write!(f, "backend not allowed in this session: {backend}")
            }
            Self::ToolDenied { tool } => write!(f, "tool denied in this session: {tool}"),
            Self::PayloadTooLarge {
                actual_bytes,
                limit_bytes,
            } => write!(
                f,
                "payload too large: {actual_bytes} bytes exceeds limit of {limit_bytes}"
            ),
        }
    }
}

// ── SandboxEnforcer ───────────────────────────────────────────────────────────

/// Live sandbox enforcer for a single MCP session.
///
/// Wraps a [`SessionSandbox`] policy and tracks mutable runtime state
/// (call count, session start time).  Create one per session and call
/// [`SandboxEnforcer::check`] before every tool invocation.
///
/// Thread-safe: `call_count` is an `AtomicU64` and `started_at` is
/// immutable after construction.  Multiple threads may share a reference.
#[derive(Debug)]
pub struct SandboxEnforcer {
    sandbox: SessionSandbox,
    call_count: AtomicU64,
    started_at: Instant,
}

impl SandboxEnforcer {
    /// Create an enforcer starting now.
    #[must_use]
    pub fn new(sandbox: SessionSandbox) -> Self {
        Self {
            sandbox,
            call_count: AtomicU64::new(0),
            started_at: Instant::now(),
        }
    }

    /// Create an enforcer with an explicit start time (useful for testing).
    #[must_use]
    pub fn new_at(sandbox: SessionSandbox, started_at: Instant) -> Self {
        Self {
            sandbox,
            call_count: AtomicU64::new(0),
            started_at,
        }
    }

    /// Check whether a tool invocation is permitted and, if so, atomically
    /// record it.
    ///
    /// Checks are applied in order:
    /// 1. Session duration (cheapest — no state mutation)
    /// 2. Backend allowlist
    /// 3. Tool denylist
    /// 4. Payload size
    /// 5. Call quota (increments counter on success)
    ///
    /// # Arguments
    ///
    /// * `backend` — name of the backend serving the tool (e.g. `"search"`).
    /// * `tool` — name of the tool being invoked (e.g. `"web_search"`).
    /// * `payload_bytes` — byte length of the argument payload.
    ///
    /// # Errors
    ///
    /// Returns `Error::Protocol` with a [`SandboxViolation`] description when
    /// any limit is exceeded.
    pub fn check(&self, backend: &str, tool: &str, payload_bytes: usize) -> Result<()> {
        // 1. Session timeout
        if self.sandbox.max_duration != Duration::ZERO {
            let elapsed = self.started_at.elapsed();
            if elapsed > self.sandbox.max_duration {
                return Err(Error::Protocol(
                    SandboxViolation::SessionExpired {
                        elapsed_secs: elapsed.as_secs(),
                        limit_secs: self.sandbox.max_duration.as_secs(),
                    }
                    .to_string(),
                ));
            }
        }

        // 2. Backend allowlist
        if let Some(ref allowed) = self.sandbox.allowed_backends
            && !allowed.iter().any(|b| b == backend)
        {
            return Err(Error::Protocol(
                SandboxViolation::BackendNotAllowed {
                    backend: backend.to_string(),
                }
                .to_string(),
            ));
        }

        // 3. Tool denylist
        if self.sandbox.denied_tools.iter().any(|t| t == tool) {
            return Err(Error::Protocol(
                SandboxViolation::ToolDenied {
                    tool: tool.to_string(),
                }
                .to_string(),
            ));
        }

        // 4. Payload size
        if self.sandbox.max_payload_bytes != 0 && payload_bytes > self.sandbox.max_payload_bytes {
            return Err(Error::Protocol(
                SandboxViolation::PayloadTooLarge {
                    actual_bytes: payload_bytes,
                    limit_bytes: self.sandbox.max_payload_bytes,
                }
                .to_string(),
            ));
        }

        // 5. Call quota — increment then check.
        // Using fetch_add so the count reflects the current (about-to-happen) call.
        if self.sandbox.max_calls != 0 {
            let prev = self.call_count.fetch_add(1, Ordering::Relaxed);
            let attempted = prev + 1;
            if attempted > self.sandbox.max_calls {
                // Roll back the increment so the count stays accurate.
                self.call_count.fetch_sub(1, Ordering::Relaxed);
                return Err(Error::Protocol(
                    SandboxViolation::CallLimitExceeded {
                        attempted,
                        limit: self.sandbox.max_calls,
                    }
                    .to_string(),
                ));
            }
        } else {
            // Unlimited — still track count for observability.
            self.call_count.fetch_add(1, Ordering::Relaxed);
        }

        Ok(())
    }

    /// Current call count (calls that passed the sandbox check).
    #[must_use]
    pub fn call_count(&self) -> u64 {
        self.call_count.load(Ordering::Relaxed)
    }

    /// Elapsed time since the enforcer was created.
    #[must_use]
    pub fn elapsed(&self) -> Duration {
        self.started_at.elapsed()
    }

    /// The sandbox policy this enforcer applies.
    #[must_use]
    pub fn sandbox(&self) -> &SessionSandbox {
        &self.sandbox
    }
}

#[cfg(test)]
#[path = "session_sandbox_tests.rs"]
mod tests;

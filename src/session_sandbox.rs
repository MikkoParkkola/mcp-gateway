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
        if let Some(ref allowed) = self.sandbox.allowed_backends {
            if !allowed.iter().any(|b| b == backend) {
                return Err(Error::Protocol(
                    SandboxViolation::BackendNotAllowed {
                        backend: backend.to_string(),
                    }
                    .to_string(),
                ));
            }
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

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── helpers ───────────────────────────────────────────────────────────────

    fn unlimited() -> SessionSandbox {
        SessionSandbox::default()
    }

    fn enforcer(s: SessionSandbox) -> SandboxEnforcer {
        SandboxEnforcer::new(s)
    }

    // ── default / unlimited ───────────────────────────────────────────────────

    #[test]
    fn default_sandbox_allows_everything() {
        let e = enforcer(unlimited());
        assert!(e.check("any_backend", "any_tool", usize::MAX).is_ok());
        assert!(e.check("other", "other_tool", 0).is_ok());
    }

    #[test]
    fn call_count_increments_on_success() {
        let e = enforcer(unlimited());
        e.check("b", "t", 0).unwrap();
        e.check("b", "t", 0).unwrap();
        e.check("b", "t", 0).unwrap();
        assert_eq!(e.call_count(), 3);
    }

    // ── max_calls ─────────────────────────────────────────────────────────────

    #[test]
    fn call_limit_allows_up_to_max() {
        let e = enforcer(SessionSandbox {
            max_calls: 3,
            ..Default::default()
        });
        assert!(e.check("b", "t", 0).is_ok());
        assert!(e.check("b", "t", 0).is_ok());
        assert!(e.check("b", "t", 0).is_ok());
    }

    #[test]
    fn call_limit_rejects_on_exceeded() {
        let e = enforcer(SessionSandbox {
            max_calls: 2,
            ..Default::default()
        });
        e.check("b", "t", 0).unwrap();
        e.check("b", "t", 0).unwrap();
        let err = e.check("b", "t", 0).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("call limit exceeded"), "unexpected msg: {msg}");
        assert!(msg.contains("limit 2"), "unexpected msg: {msg}");
    }

    #[test]
    fn call_limit_count_does_not_increment_after_rejection() {
        let e = enforcer(SessionSandbox {
            max_calls: 1,
            ..Default::default()
        });
        e.check("b", "t", 0).unwrap();
        assert_eq!(e.call_count(), 1);
        let _ = e.check("b", "t", 0); // rejected
        assert_eq!(e.call_count(), 1); // still 1
    }

    #[test]
    fn zero_max_calls_means_unlimited() {
        let e = enforcer(SessionSandbox {
            max_calls: 0, // unlimited
            ..Default::default()
        });
        for _ in 0..1000 {
            e.check("b", "t", 0).unwrap();
        }
        assert_eq!(e.call_count(), 1000);
    }

    // ── max_duration ──────────────────────────────────────────────────────────

    #[test]
    fn session_allows_calls_within_duration() {
        let e = enforcer(SessionSandbox {
            max_duration: Duration::from_secs(3600),
            ..Default::default()
        });
        assert!(e.check("b", "t", 0).is_ok());
    }

    #[test]
    fn session_rejects_after_duration_elapsed() {
        // Start the enforcer 2 seconds in the past so it appears expired.
        let past = Instant::now() - Duration::from_secs(2);
        let sandbox = SessionSandbox {
            max_duration: Duration::from_secs(1),
            ..Default::default()
        };
        let e = SandboxEnforcer::new_at(sandbox, past);
        let err = e.check("b", "t", 0).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("expired"), "unexpected msg: {msg}");
        assert!(msg.contains("limit 1s"), "unexpected msg: {msg}");
    }

    #[test]
    fn zero_max_duration_means_no_timeout() {
        // Zero duration should never expire regardless of elapsed time.
        let past = Instant::now() - Duration::from_secs(999_999);
        let e = SandboxEnforcer::new_at(
            SessionSandbox {
                max_duration: Duration::ZERO,
                ..Default::default()
            },
            past,
        );
        assert!(e.check("b", "t", 0).is_ok());
    }

    // ── allowed_backends ─────────────────────────────────────────────────────

    #[test]
    fn backend_allowlist_permits_listed_backend() {
        let e = enforcer(SessionSandbox {
            allowed_backends: Some(vec!["search".to_string(), "db".to_string()]),
            ..Default::default()
        });
        assert!(e.check("search", "t", 0).is_ok());
        assert!(e.check("db", "t", 0).is_ok());
    }

    #[test]
    fn backend_allowlist_rejects_unlisted_backend() {
        let e = enforcer(SessionSandbox {
            allowed_backends: Some(vec!["search".to_string()]),
            ..Default::default()
        });
        let err = e.check("exec", "t", 0).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("backend not allowed"), "unexpected msg: {msg}");
        assert!(msg.contains("exec"), "unexpected msg: {msg}");
    }

    #[test]
    fn none_allowed_backends_permits_any_backend() {
        let e = enforcer(SessionSandbox {
            allowed_backends: None,
            ..Default::default()
        });
        assert!(e.check("any_backend", "t", 0).is_ok());
    }

    #[test]
    fn empty_allowed_backends_list_rejects_all() {
        let e = enforcer(SessionSandbox {
            allowed_backends: Some(vec![]),
            ..Default::default()
        });
        let err = e.check("any", "t", 0).unwrap_err();
        assert!(err.to_string().contains("backend not allowed"));
    }

    // ── denied_tools ─────────────────────────────────────────────────────────

    #[test]
    fn denied_tool_is_rejected() {
        let e = enforcer(SessionSandbox {
            denied_tools: vec!["exec".to_string(), "shell".to_string()],
            ..Default::default()
        });
        let err = e.check("b", "exec", 0).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("tool denied"), "unexpected msg: {msg}");
        assert!(msg.contains("exec"), "unexpected msg: {msg}");
    }

    #[test]
    fn denied_tool_second_entry_also_rejected() {
        let e = enforcer(SessionSandbox {
            denied_tools: vec!["exec".to_string(), "shell".to_string()],
            ..Default::default()
        });
        let err = e.check("b", "shell", 0).unwrap_err();
        assert!(err.to_string().contains("shell"));
    }

    #[test]
    fn non_denied_tool_is_allowed() {
        let e = enforcer(SessionSandbox {
            denied_tools: vec!["exec".to_string()],
            ..Default::default()
        });
        assert!(e.check("b", "search", 0).is_ok());
    }

    #[test]
    fn empty_denied_tools_allows_all() {
        let e = enforcer(SessionSandbox {
            denied_tools: vec![],
            ..Default::default()
        });
        assert!(e.check("b", "exec", 0).is_ok());
    }

    // ── max_payload_bytes ─────────────────────────────────────────────────────

    #[test]
    fn payload_within_limit_is_allowed() {
        let e = enforcer(SessionSandbox {
            max_payload_bytes: 1024,
            ..Default::default()
        });
        assert!(e.check("b", "t", 1024).is_ok());
        assert!(e.check("b", "t", 0).is_ok());
    }

    #[test]
    fn payload_over_limit_is_rejected() {
        let e = enforcer(SessionSandbox {
            max_payload_bytes: 512,
            ..Default::default()
        });
        let err = e.check("b", "t", 513).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("payload too large"), "unexpected msg: {msg}");
        assert!(msg.contains("513"), "unexpected msg: {msg}");
        assert!(msg.contains("512"), "unexpected msg: {msg}");
    }

    #[test]
    fn payload_exactly_at_limit_is_allowed() {
        let e = enforcer(SessionSandbox {
            max_payload_bytes: 256,
            ..Default::default()
        });
        assert!(e.check("b", "t", 256).is_ok());
    }

    #[test]
    fn zero_max_payload_bytes_means_unlimited() {
        let e = enforcer(SessionSandbox {
            max_payload_bytes: 0,
            ..Default::default()
        });
        assert!(e.check("b", "t", usize::MAX).is_ok());
    }

    // ── check order ───────────────────────────────────────────────────────────

    #[test]
    fn expired_session_beats_backend_denylist() {
        // Both expire AND backend denylist would fire; expire comes first.
        let past = Instant::now() - Duration::from_secs(10);
        let sandbox = SessionSandbox {
            max_duration: Duration::from_secs(1),
            allowed_backends: Some(vec!["allowed".to_string()]),
            ..Default::default()
        };
        let e = SandboxEnforcer::new_at(sandbox, past);
        let msg = e.check("blocked", "t", 0).unwrap_err().to_string();
        assert!(msg.contains("expired"), "expected expire first, got: {msg}");
    }

    #[test]
    fn backend_check_before_tool_check() {
        // Backend not allowed AND tool denied; backend error comes first.
        let e = enforcer(SessionSandbox {
            allowed_backends: Some(vec!["ok".to_string()]),
            denied_tools: vec!["bad_tool".to_string()],
            ..Default::default()
        });
        let msg = e.check("blocked", "bad_tool", 0).unwrap_err().to_string();
        assert!(
            msg.contains("backend not allowed"),
            "expected backend error first, got: {msg}"
        );
    }

    // ── SandboxConfig / resolve ───────────────────────────────────────────────

    #[test]
    fn config_resolve_returns_named_profile() {
        let mut cfg = SandboxConfig::default();
        cfg.profiles.insert(
            "strict".to_string(),
            SessionSandbox {
                max_calls: 10,
                ..Default::default()
            },
        );
        let s = cfg.resolve(Some("strict"));
        assert_eq!(s.max_calls, 10);
    }

    #[test]
    fn config_resolve_falls_back_to_default_profile() {
        let mut cfg = SandboxConfig {
            default_profile: "base".to_string(),
            profiles: HashMap::new(),
        };
        cfg.profiles.insert(
            "base".to_string(),
            SessionSandbox {
                max_calls: 50,
                ..Default::default()
            },
        );
        let s = cfg.resolve(None);
        assert_eq!(s.max_calls, 50);
    }

    #[test]
    fn config_resolve_unknown_profile_returns_default_sandbox() {
        let cfg = SandboxConfig::default();
        let s = cfg.resolve(Some("nonexistent"));
        assert_eq!(s, SessionSandbox::default());
    }

    // ── serde round-trip ──────────────────────────────────────────────────────

    #[test]
    fn sandbox_serde_round_trip_json() {
        let original = SessionSandbox {
            max_calls: 42,
            max_duration: Duration::from_secs(300),
            allowed_backends: Some(vec!["a".to_string(), "b".to_string()]),
            denied_tools: vec!["exec".to_string()],
            max_payload_bytes: 8192,
        };
        let json = serde_json::to_string(&original).unwrap();
        let restored: SessionSandbox = serde_json::from_str(&json).unwrap();
        assert_eq!(original, restored);
    }

    #[test]
    fn sandbox_config_serde_round_trip_json() {
        let mut cfg = SandboxConfig {
            default_profile: "prod".to_string(),
            profiles: HashMap::new(),
        };
        cfg.profiles.insert("prod".to_string(), SessionSandbox {
            max_calls: 100,
            max_duration: Duration::from_secs(1800),
            allowed_backends: None,
            denied_tools: vec!["shell".to_string()],
            max_payload_bytes: 65536,
        });
        let json = serde_json::to_string(&cfg).unwrap();
        let restored: SandboxConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.default_profile, "prod");
        assert_eq!(restored.profiles["prod"].max_calls, 100);
        assert_eq!(restored.profiles["prod"].max_duration, Duration::from_secs(1800));
    }

    #[test]
    fn sandbox_defaults_deserialize_from_empty_object() {
        let s: SessionSandbox = serde_json::from_str("{}").unwrap();
        assert_eq!(s, SessionSandbox::default());
    }

    // ── SandboxViolation display ──────────────────────────────────────────────

    #[test]
    fn violation_display_call_limit() {
        let v = SandboxViolation::CallLimitExceeded {
            attempted: 11,
            limit: 10,
        };
        let s = v.to_string();
        assert!(s.contains("11"));
        assert!(s.contains("10"));
        assert!(s.contains("call limit"));
    }

    #[test]
    fn violation_display_session_expired() {
        let v = SandboxViolation::SessionExpired {
            elapsed_secs: 120,
            limit_secs: 60,
        };
        let s = v.to_string();
        assert!(s.contains("120"));
        assert!(s.contains("60"));
        assert!(s.contains("expired"));
    }

    #[test]
    fn violation_display_backend_not_allowed() {
        let v = SandboxViolation::BackendNotAllowed {
            backend: "dangerous".to_string(),
        };
        assert!(v.to_string().contains("dangerous"));
    }

    #[test]
    fn violation_display_tool_denied() {
        let v = SandboxViolation::ToolDenied {
            tool: "exec".to_string(),
        };
        assert!(v.to_string().contains("exec"));
    }

    #[test]
    fn violation_display_payload_too_large() {
        let v = SandboxViolation::PayloadTooLarge {
            actual_bytes: 2048,
            limit_bytes: 1024,
        };
        let s = v.to_string();
        assert!(s.contains("2048"));
        assert!(s.contains("1024"));
    }

    // ── combined limits ───────────────────────────────────────────────────────

    #[test]
    fn all_limits_combined_pass_when_all_satisfied() {
        let e = enforcer(SessionSandbox {
            max_calls: 5,
            max_duration: Duration::from_secs(3600),
            allowed_backends: Some(vec!["search".to_string()]),
            denied_tools: vec!["exec".to_string()],
            max_payload_bytes: 1024,
        });
        assert!(e.check("search", "web_search", 512).is_ok());
    }

    #[test]
    fn all_limits_combined_rejects_when_tool_denied() {
        let e = enforcer(SessionSandbox {
            max_calls: 100,
            max_duration: Duration::from_secs(3600),
            allowed_backends: Some(vec!["search".to_string()]),
            denied_tools: vec!["exec".to_string()],
            max_payload_bytes: 65536,
        });
        let err = e.check("search", "exec", 100).unwrap_err();
        assert!(err.to_string().contains("tool denied"));
    }
}

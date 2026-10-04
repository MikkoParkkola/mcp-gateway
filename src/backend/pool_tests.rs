// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Unit tests for the MIK-6735 per-identity transport/session pool: slot
//! isolation, cross-tenant circuit-breaker independence, notification
//! routing, idle eviction, and the evictor-vs-start race in
//! `Backend::reconcile_after_start`.

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use async_trait::async_trait;
use serde_json::{Value, json};

use super::*;
use crate::backend::registry::BackendLifecycle;
use crate::config::TransportConfig;
use crate::protocol::{JsonRpcResponse, RequestId};
use crate::{Error, Result, transport::Transport};

mod close_timeouts;
mod idle_stop;
mod recovery_and_shutdown;
mod slots;

// ---- MIK-6735: per-user transport/session pool ----

// Method-agnostic transport that echoes the session tag it was built for,
// so a routed request proves which pool slot served it.
struct SessionMock {
    session: String,
    requests: AtomicUsize,
    notifications: AtomicUsize,
    closed: AtomicBool,
}

impl SessionMock {
    fn new(session: &str) -> Self {
        Self {
            session: session.to_string(),
            requests: AtomicUsize::new(0),
            notifications: AtomicUsize::new(0),
            closed: AtomicBool::new(false),
        }
    }
}

#[async_trait]
impl Transport for SessionMock {
    async fn request(&self, _method: &str, _params: Option<Value>) -> Result<JsonRpcResponse> {
        self.requests.fetch_add(1, Ordering::SeqCst);
        Ok(JsonRpcResponse::success_serialized(
            RequestId::Number(1),
            json!({ "session": self.session }),
        ))
    }

    async fn notify(&self, _method: &str, _params: Option<Value>) -> Result<()> {
        self.notifications.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }

    fn is_connected(&self) -> bool {
        true
    }

    async fn close(&self) -> Result<()> {
        self.closed.store(true, Ordering::SeqCst);
        Ok(())
    }
}

fn per_user_backend() -> Arc<Backend> {
    let idp = crate::identity_propagation::IdentityPropagationConfig {
        strategy: crate::identity_propagation::PropagationStrategyKind::SignedAssertion,
        audience: "https://mem.internal".to_string(),
        required: true,
        session_mode: crate::identity_propagation::SessionMode::PerUser,
        token_exchange_endpoint: None,
        token_exchange_scope: None,
    };
    let cfg = BackendConfig {
        transport: TransportConfig::Http {
            http_url: "https://mem.internal/mcp".to_string(),
            streamable_http: false,
            protocol_version: None,
        },
        identity_propagation: Some(idp),
        ..BackendConfig::default()
    };
    Arc::new(Backend::new(
        "mem",
        cfg,
        &crate::config::FailsafeConfig::default(),
        Duration::from_secs(60),
    ))
}

/// A gateway-OWNED backend (declared with a command) that opts into being
/// stopped when idle. Ownership is what makes stopping meaningful: the gateway
/// spawned this process, so it can stop it.
fn stoppable_backend(idle_for: Duration) -> Arc<Backend> {
    stoppable_backend_with_command("echo hi", idle_for)
}

/// A stoppable backend whose start command is observable from outside the
/// process. Tests that need to prove a start did NOT happen need a witness in
/// the world - a file, the process table - rather than an in-memory flag.
fn stoppable_backend_with_command(command: &str, idle_for: Duration) -> Arc<Backend> {
    let cfg = BackendConfig {
        transport: TransportConfig::Stdio {
            command: command.to_string(),
            cwd: None,
            protocol_version: None,
        },
        stop_when_idle_for: Some(idle_for),
        max_frame_bytes: None,
        ..BackendConfig::default()
    };
    Arc::new(Backend::new(
        "ownedtool",
        cfg,
        &crate::config::FailsafeConfig::default(),
        Duration::from_secs(60),
    ))
}

fn per_user_key(binding: &str) -> PoolKey {
    PoolKey::PerUser {
        binding: binding.to_string(),
    }
}

/// How many times this backend's command has been spawned, read from the file
/// the command itself appends to. An external witness: it reflects the process
/// table, not a field the code under test maintains.
fn spawn_count(log: &std::path::Path) -> usize {
    std::fs::read_to_string(log).map_or(0, |s| s.lines().count())
}

// ---------------------------------------------------------------------------
// Does a close() that TIMES OUT leave the child process alive?
//
// pool.rs's Err(_) arm warns "Child process may be orphaned" and bumps
// `mcp_backend_idle_stop_close_failures`. "May be" is not an answer, and it is
// not reachable by reading: it depends on who still holds an Arc to the
// transport when the timeout fires.
//
// The real StdioTransport cannot answer it. Its close() body is
//   *self.writer.lock().await = None;
//   if let Some(ref mut child) = *self.child.lock().await { child.kill().await }
// An uncontended tokio Mutex returns Ready inline, so with a tiny close_stage
// the future still runs to `child.kill()` (SIGKILL, uncatchable) before the
// timeout can ever preempt it -- the child dies from close(), not from drop,
// and the measurement is contaminated.
//
// So the mock below reproduces StdioTransport's OWNERSHIP shape (it owns a real
// tokio::process::Child with kill_on_drop(true)) while making close() genuinely
// unresumable. What survives the timeout is then decided purely by Arc
// ownership, which is the actual question.
//
// Second leg of the argument, already in the tree:
// `transport::stdio::tests::dropping_the_last_handle_reaps_the_child` proves
// the same drop-reaps-child property for the REAL StdioTransport, including its
// reader task's deliberate Weak handle.
#[cfg(unix)]
pub(super) struct RealChildWedgedClose {
    pub(super) child: tokio::sync::Mutex<Option<tokio::process::Child>>,
}

#[cfg(unix)] // Process reaping and pid liveness (ps state, zombie detection); unix-only.
#[async_trait]
impl Transport for RealChildWedgedClose {
    async fn request(&self, _method: &str, _params: Option<Value>) -> Result<JsonRpcResponse> {
        Ok(JsonRpcResponse::success_serialized(
            RequestId::Number(1),
            json!({}),
        ))
    }

    async fn notify(&self, _method: &str, _params: Option<Value>) -> Result<()> {
        Ok(())
    }

    fn is_connected(&self) -> bool {
        true
    }

    async fn close(&self) -> Result<()> {
        // Wedged exactly like a real close() blocked on the writer mutex that a
        // stuck write_all still holds: it never reaches the child.kill() below.
        std::future::pending::<()>().await;
        let _ = &self.child;
        Ok(())
    }
}

// `kill -0` is the wrong probe here: it succeeds on a ZOMBIE, i.e. a child that
// kill_on_drop already SIGKILLed but tokio's orphan queue has not reaped yet.
// That would report a dead process as orphaned. Process STATE is the honest
// probe: None = gone, Some("Z...") = dead awaiting reap, anything else = alive.
#[cfg(unix)]
pub(super) fn process_state(pid: u32) -> Option<String> {
    let out = std::process::Command::new("ps")
        .args(["-o", "stat=", "-p", &pid.to_string()])
        .output()
        .expect("ps must be runnable to probe the process table");
    if !out.status.success() {
        return None;
    }
    let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if s.is_empty() { None } else { Some(s) }
}

#[cfg(unix)] // Process reaping and pid liveness (ps state, zombie detection); unix-only.
pub(super) fn is_alive(pid: u32) -> bool {
    process_state(pid).is_some_and(|s| !s.starts_with('Z'))
}

#[cfg(unix)] // Process reaping and pid liveness (ps state, zombie detection); unix-only.
pub(super) async fn spawn_probe_child() -> (tokio::process::Child, u32) {
    let child = tokio::process::Command::new("sleep")
        .arg("300")
        .kill_on_drop(true)
        .spawn()
        .expect("spawn a long-lived probe child");
    let pid = child.id().expect("a freshly spawned child has a pid");
    assert!(
        is_alive(pid),
        "probe child must be alive before the test acts"
    );
    (child, pid)
}

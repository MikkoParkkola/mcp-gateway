// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-7215.CONTROL.3 — the transparency log's correlation key must survive
//! the removal of sessions.
//!
//! Plan: `docs/requirements/RELEASE-4.0.0-test-plan.md` §"Increment 7".
//!
//! The defect this guards: `invoke_tool_traced` had a `trace_id` in scope
//! (used in its own `debug!`/`warn!` calls) and logged `session_id.unwrap_or
//! ("unknown")` anyway, so every stateless call's audit entry correlated as
//! the literal string `"unknown"` — indistinguishable from every other
//! stateless call in the same window.

use std::sync::Arc;

use serde_json::{Value, json};

use crate::backend::{Backend, BackendRegistry};
use crate::config::{BackendConfig, FailsafeConfig};
use crate::gateway::authz::AllowAll;
use crate::gateway::meta_mcp::{MetaMcp, MetaMcpCallerContext};
use crate::protocol::RequestId;
use crate::security::TransparencyLogger;
use crate::security::transparency_log::TransparencyLogConfig;
use crate::transport::Transport;

/// A backend transport that always answers with a fixed, successful result —
/// the log entry is what these tests examine, not the backend's reply.
struct OkTransport;

#[async_trait::async_trait]
impl Transport for OkTransport {
    async fn request(
        &self,
        _method: &str,
        _params: Option<Value>,
    ) -> crate::Result<crate::protocol::JsonRpcResponse> {
        Ok(crate::protocol::JsonRpcResponse::success_serialized(
            RequestId::Number(1),
            json!({"content": [{"type": "text", "text": "ok"}], "isError": false}),
        ))
    }
    async fn notify(&self, _method: &str, _params: Option<Value>) -> crate::Result<()> {
        Ok(())
    }
    fn is_connected(&self) -> bool {
        true
    }
    async fn close(&self) -> crate::Result<()> {
        Ok(())
    }
}

/// A `MetaMcp` with one backend and a real, file-backed transparency logger.
/// Returns the log's path so a test can read back what was actually written.
fn meta_with_transparency_log() -> (MetaMcp, std::path::PathBuf) {
    let registry = Arc::new(BackendRegistry::new());
    let backend = Arc::new(Backend::new(
        "srv",
        BackendConfig::default(),
        &FailsafeConfig::default(),
        std::time::Duration::from_secs(300),
    ));
    backend.set_transport_for_test(Arc::new(OkTransport));
    let _ = registry.register(backend);

    let file = tempfile::NamedTempFile::new().expect("tempfile");
    let path = file.path().to_path_buf();
    std::mem::forget(file); // kept alive for the test; reclaimed at process exit

    let cfg = Arc::new(TransparencyLogConfig {
        enabled: true,
        path: path.to_string_lossy().to_string(),
        key_id: "test".to_string(),
        shared_secret: String::new(),
    });
    let logger = Arc::new(TransparencyLogger::open(cfg).expect("logger opens"));

    let mut meta = MetaMcp::new(registry);
    meta.enable_transparency_log(logger);
    (meta, path)
}

fn ctx() -> MetaMcpCallerContext<'static> {
    MetaMcpCallerContext {
        authorizer: &AllowAll,
        api_key_name: Some("test-caller"),
        agent_id: None,
        grant_subject: None,
        verified_identity: None,
        is_admin: false,
        input_capabilities: &[],
        retry: &crate::protocol::mrtr::NO_RETRY,
        confirmation: crate::gateway::destructive_confirmation::ConfirmationChannel::Unavailable,
    }
}

/// A syntactically valid W3C `traceparent`: `version-traceid-spanid-flags`,
/// all lower-hex, trace id not all-zero (`TraceContext::from_meta`'s rules).
const TRACEPARENT: &str = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01";
const TRACE_ID: &str = "4bf92f3577b34da6a3ce929d0e0e4736";

#[tokio::test]
async fn ac_control_3_a_trace_id_in_meta_is_the_correlation_key_not_the_session() {
    let (meta, log_path) = meta_with_transparency_log();
    let args = json!({
        "server": "srv",
        "tool": "read",
        "arguments": {},
        "_meta": { "traceparent": TRACEPARENT },
    });

    meta.invoke_tool(&args, Some("legacy-session-1"), &ctx())
        .await
        .expect("invoke ok");

    let raw = std::fs::read_to_string(&log_path).expect("read log");
    assert!(
        raw.contains(TRACE_ID),
        "the OTel trace id must be the log's correlation key when present: {raw}"
    );
    assert!(
        !raw.contains("legacy-session-1"),
        "the session id must not be used once a trace id is present: {raw}"
    );
    assert!(
        !raw.contains("\"session_id\":\"unknown\""),
        "a present trace id must never fall through to the 'unknown' sentinel: {raw}"
    );
}

#[tokio::test]
async fn ac_control_3_no_trace_id_falls_back_to_the_session_id() {
    // Regression guard for a legacy caller that never sends `_meta.traceparent`:
    // the fallback this control replaces must keep working.
    let (meta, log_path) = meta_with_transparency_log();
    let args = json!({ "server": "srv", "tool": "read", "arguments": {} });

    meta.invoke_tool(&args, Some("legacy-session-2"), &ctx())
        .await
        .expect("invoke ok");

    let raw = std::fs::read_to_string(&log_path).expect("read log");
    assert!(
        raw.contains("legacy-session-2"),
        "with no trace id, the session id must still be the correlation key: {raw}"
    );
}

#[tokio::test]
async fn ac_control_3_neither_trace_id_nor_session_id_logs_unknown() {
    // The pre-existing sentinel for the fully-anonymous case is preserved —
    // this control narrows when "unknown" fires, it does not remove it.
    let (meta, log_path) = meta_with_transparency_log();
    let args = json!({ "server": "srv", "tool": "read", "arguments": {} });

    meta.invoke_tool(&args, None, &ctx())
        .await
        .expect("invoke ok");

    let raw = std::fs::read_to_string(&log_path).expect("read log");
    assert!(
        raw.contains("\"session_id\":\"unknown\""),
        "with neither a trace id nor a session id, the sentinel must still fire: {raw}"
    );
}

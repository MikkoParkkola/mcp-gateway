// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The R4a submit traced end to end (MIK-8326): what a refused task call left
//! in the audit log, the task store and both idempotency stores.

use std::path::Path;
use std::sync::atomic::Ordering;

use serde_json::Value;

use super::super::direct_guards_fixture::Answer;
use super::{Destructive, Surfacing, TASK_SUBMIT_HEADERS, surfacing, task_submit_params};
use crate::gateway::meta_mcp::MetaMcp;

/// What a refused submit left behind (MIK-8326): the answer and HTTP status,
/// the backend's call count, the firewall audit log's event names, the tasks
/// committed, the legacy idempotency responses stored and the execution
/// admission entries (the store modern keyed calls reserve in).
pub(crate) struct Trace {
    pub(crate) status: axum::http::StatusCode,
    pub(crate) body: Value,
    pub(crate) backend_calls: usize,
    pub(crate) events: Vec<String>,
    pub(crate) committed: usize,
    pub(crate) stored_keys: usize,
    pub(crate) admitted: usize,
}

/// The event names in a firewall audit log; none when nothing was written.
pub(crate) fn audit_events(path: &Path) -> Vec<String> {
    let log = match std::fs::read_to_string(path) {
        Ok(log) => log,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Vec::new(),
        Err(e) => panic!("unreadable audit log {}: {e}", path.display()),
    };
    log.lines()
        .map(|line| {
            let row: Value = serde_json::from_str(line)
                .unwrap_or_else(|e| panic!("malformed audit row {line:?}: {e}"));
            row["event"]
                .as_str()
                .unwrap_or_else(|| panic!("audit row without an event: {line}"))
                .to_owned()
        })
        .collect()
}

/// [`task_submit_read_as`] on the same fixture with the production firewall
/// on both layers writing to `audit`, returning everything the submit left.
pub(crate) async fn task_submit_traced(
    key: &str,
    surfacing_mode: Surfacing,
    audit: &Path,
) -> Trace {
    let calls = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let transport = std::sync::Arc::new(Destructive {
        calls: std::sync::Arc::clone(&calls),
    });
    let build: fn(MetaMcp) -> MetaMcp = match surfacing_mode {
        Surfacing::On => surfacing,
        Surfacing::Off => |meta| meta,
    };
    let fx = super::super::direct_guards_fixture::with_transport(
        transport,
        Box::pin(
            super::super::direct_guards_fixture::fixture_firewalled_audited_built(
                Answer::Ok,
                audit.to_path_buf(),
                build,
            ),
        ),
    )
    .await;
    let params = task_submit_params();
    let (status, body) = super::super::direct_guards_fixture::send_with_headers(
        &fx,
        "/mcp",
        key,
        "tools/call",
        params,
        None,
        &TASK_SUBMIT_HEADERS,
    )
    .await;
    Trace {
        status,
        body,
        backend_calls: calls.load(Ordering::SeqCst),
        events: audit_events(audit),
        committed: fx
            .state
            .task_executor
            .service
            .store
            .committed_count_for_test(),
        stored_keys: fx.state.meta_mcp.idempotency_completed_for_test().len(),
        admitted: fx.state.meta_mcp.execution_admission().snapshot().entries,
    }
}

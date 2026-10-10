// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The live rows of the route x check matrix: each drives a real entry route
//! with a scenario that trips exactly one stage and checks the table's claim.

use serde_json::{Value, json};

use super::{Expect, MethodKind, Route, Stage, expect};
use crate::gateway::router::route_matrix_driver_tests as router;
use crate::gateway::server::route_matrix_driver_tests as stdio;

/// A shell-injection argument the request firewall blocks (a High finding).
const BLOCKED: &str = "; rm -rf / ";

/// The firewall audit rows of `event` in `path`. Panics on an unreadable
/// file or a malformed line, so a gap row can never pass because the audit
/// log was not collected.
fn audit_rows(path: &std::path::Path, event: &str) -> Vec<Value> {
    let text = std::fs::read_to_string(path)
        .unwrap_or_else(|e| panic!("audit log {} unreadable: {e}", path.display()));
    text.lines()
        .map(|line| {
            serde_json::from_str::<Value>(line)
                .unwrap_or_else(|e| panic!("malformed audit row {line:?}: {e}"))
        })
        .filter(|row| row["event"] == event)
        .collect()
}

/// One blocked call on `route`, firewalled on every layer.
async fn blocked_call(route: Route, audit: &std::path::Path) -> (Value, usize) {
    let args = json!({ "cmd": BLOCKED });
    match route {
        Route::Invoke => {
            let sent = router::invoke_firewalled(audit, args).await;
            (sent.body, sent.backend_calls)
        }
        Route::Direct => {
            let sent = router::direct_firewalled(audit, args).await;
            (sent.body, sent.backend_calls)
        }
        Route::Stdio => {
            let sent = stdio::stdio_firewalled(audit, args).await;
            (sent.body, sent.backend_calls)
        }
        other => unreachable!("not driven here: {other:?}"),
    }
}

/// RouteFirewall: on an Applies route a blocked argument gets a blocking
/// `event=request` row and reaches no backend. On the stdio gap there is no
/// request row at all; the dispatch-time rescan still stops the send.
#[tokio::test]
async fn route_firewall_rows() {
    for route in [Route::Invoke, Route::Direct, Route::Stdio] {
        let dir = tempfile::tempdir().expect("tempdir");
        let audit = dir.path().join("audit.jsonl");
        let (body, backend_calls) = blocked_call(route, &audit).await;
        let requests = audit_rows(&audit, "request");
        let blocked = requests.iter().any(|row| row["action"] == "block");
        assert_eq!(backend_calls, 0, "{route:?}: reached its backend: {body}");
        match expect(MethodKind::ToolsCall, route, Stage::RouteFirewall) {
            Expect::Applies => assert!(blocked, "{route:?}: no blocking request row: {body}"),
            Expect::ExpectedGap(ticket) => assert!(
                requests.is_empty(),
                "{route:?}: a request row appeared ({requests:?}); {ticket:?} may have \
                 closed this gap, so flip the row to Applies"
            ),
            other => panic!("{route:?}: the table says {other:?}; this row drives it"),
        }
    }
}

/// ChokepointRescan, stdio: with no route-layer scan, the blocked argument
/// reaches the dispatch-time rescan, which writes a blocking `event=dispatch`
/// row and stops the send.
#[tokio::test]
async fn chokepoint_rescan_stdio_row() {
    let dir = tempfile::tempdir().expect("tempdir");
    let audit = dir.path().join("audit.jsonl");
    let (body, backend_calls) = blocked_call(Route::Stdio, &audit).await;
    assert_eq!(
        expect(MethodKind::ToolsCall, Route::Stdio, Stage::ChokepointRescan),
        Expect::Applies
    );
    let dispatched = audit_rows(&audit, "dispatch");
    assert!(
        dispatched.iter().any(|row| row["action"] == "block"),
        "no blocking dispatch row: {dispatched:?}; {body}"
    );
    assert_eq!(backend_calls, 0, "reached its backend: {body}");
}

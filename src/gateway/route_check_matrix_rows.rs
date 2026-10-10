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
            Expect::ExpectedGap(ticket) => {
                assert!(
                    requests.is_empty(),
                    "{route:?}: a request row appeared ({requests:?}); {ticket:?} may have \
                     closed this gap, so flip the row to Applies"
                );
                // The send was stopped, and by the dispatch-time rescan, not by
                // anything else.
                let dispatched = audit_rows(&audit, "dispatch");
                assert!(
                    dispatched.iter().any(|row| row["action"] == "block"),
                    "{route:?}: stopped, but not by the dispatch rescan: {dispatched:?}; {body}"
                );
            }
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

/// The sanitizer's refusal of a NUL byte (security/sanitize.rs).
const NUL_REFUSED: &str = "Input contains null bytes which are not allowed";

/// An argument holding a NUL byte, which sanitization refuses.
fn with_nul() -> Value {
    json!({ "cmd": "a\u{0}b" })
}

/// Whether a backend send carried the NUL argument unchanged.
fn nul_reached(seen: &[Value]) -> bool {
    seen.iter()
        .any(|params| params["arguments"]["cmd"] == "a\u{0}b")
}

/// Sanitize. R1 Applies: with `sanitize_input` on the NUL never reaches the
/// backend; off, it does (the control that shows the setting decides). R3 gap
/// (MIK-8154): the direct route sanitizes even with the setting off. R5 gap
/// (MIK-8149): stdio passes the NUL through.
#[tokio::test]
async fn sanitize_rows() {
    let row = |route| expect(MethodKind::ToolsCall, route, Stage::Sanitize);

    assert_eq!(row(Route::Invoke), Expect::Applies);
    let on = router::invoke_sanitizing(true, with_nul()).await;
    assert!(!nul_reached(&on.seen), "R1 on: the NUL reached the backend: {}", on.body);
    assert!(
        on.body.to_string().contains(NUL_REFUSED),
        "R1 on: stopped, but not by the sanitizer: {}",
        on.body
    );
    let off = router::invoke_sanitizing(false, with_nul()).await;
    assert!(nul_reached(&off.seen), "R1 off: the control failed: {}", off.body);

    assert_eq!(row(Route::Direct), Expect::ExpectedGap(super::Ticket::Mik8154));
    let direct_off = router::direct_sanitizing(false, with_nul()).await;
    assert!(
        !nul_reached(&direct_off.seen),
        "R3 off: the NUL reached the backend, so the direct route now honours the \
         setting; MIK-8154 may have closed this gap, flip the row to Applies"
    );
    assert!(
        direct_off.body.to_string().contains(NUL_REFUSED),
        "R3 off: stopped, but not by the sanitizer: {}",
        direct_off.body
    );

    assert_eq!(row(Route::Stdio), Expect::ExpectedGap(super::Ticket::Mik8149));
    let stdio = stdio::stdio_plain(with_nul()).await;
    assert!(
        nul_reached(&stdio.seen),
        "R5: the NUL no longer reaches the backend; MIK-8149 may have closed this \
         gap, flip the row to Applies: {}",
        stdio.body
    );
}

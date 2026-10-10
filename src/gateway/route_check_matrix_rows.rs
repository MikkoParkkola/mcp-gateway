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
        Route::Surfaced => {
            let sent = router::surfaced_firewalled(audit, args).await;
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
    for route in [Route::Invoke, Route::Surfaced, Route::Direct, Route::Stdio] {
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

/// A backend answer carrying a credential the response firewall blocks. Built
/// at compile time so no key-shaped literal sits in the source.
const WITH_SECRET: &str = concat!(
    "benign prefix ",
    "gh",
    "p_",
    "0123456789abcdefghij0123456789abcdef"
);

/// The response firewall's own refusal.
const RESPONSE_BLOCKED: &str = "Response blocked by security firewall";

/// ResponseFirewall: on every sending route the secret-bearing answer is
/// refused by the response firewall itself (its -32600 message) and the
/// secret never reaches the client.
#[tokio::test]
async fn response_firewall_rows() {
    let dir = tempfile::tempdir().expect("tempdir");
    let audit = dir.path().join("audit.jsonl");
    for route in [Route::Invoke, Route::Direct, Route::Stdio] {
        assert_eq!(
            expect(MethodKind::ToolsCall, route, Stage::ResponseFirewall),
            Expect::Applies,
            "{route:?}"
        );
        let body = match route {
            Route::Invoke => router::invoke_answering(WITH_SECRET).await.body,
            Route::Direct => router::direct_answering(WITH_SECRET).await.body,
            Route::Stdio => {
                stdio::stdio_firewalled_answering(&audit, json!({}), WITH_SECRET)
                    .await
                    .body
            }
            other => unreachable!("not driven here: {other:?}"),
        };
        assert_eq!(body["error"]["code"], -32600, "{route:?}: {body}");
        assert_eq!(body["error"]["message"], RESPONSE_BLOCKED, "{route:?}: {body}");
        assert!(
            !body.to_string().contains(&WITH_SECRET[14..]),
            "{route:?}: the secret leaked: {body}"
        );
    }
}

/// MrtrUndeclared: a backend question of a type the client never declared is
/// refused with the MRTR.9 capability refusal (-32021, naming the undeclared
/// capability), after exactly one backend send, on every sending route.
#[tokio::test]
async fn mrtr_undeclared_rows() {
    for route in [Route::Invoke, Route::Direct, Route::Stdio] {
        assert_eq!(
            expect(MethodKind::ToolsCall, route, Stage::MrtrUndeclared),
            Expect::Applies,
            "{route:?}"
        );
        let (body, backend_calls) = match route {
            Route::Invoke => {
                let sent = router::invoke_asking().await;
                (sent.body, sent.backend_calls)
            }
            Route::Direct => {
                let sent = router::direct_asking().await;
                (sent.body, sent.backend_calls)
            }
            Route::Stdio => {
                let sent = stdio::stdio_asking().await;
                (sent.body, sent.backend_calls)
            }
            other => unreachable!("not driven here: {other:?}"),
        };
        assert_eq!(body["error"]["code"], -32021, "{route:?}: {body}");
        assert!(
            body["error"]["message"]
                .as_str()
                .is_some_and(|m| m.contains("the client did not declare")),
            "{route:?}: refused, but not by the MRTR.9 gate: {body}"
        );
        assert_eq!(backend_calls, 1, "{route:?}: the question was asked once: {body}");
    }
}

/// ChainLink: with a chain signer emitting on request and a chain nonce on
/// the call, the answer carries the gateway's origin link on every route the
/// table says Applies.
#[tokio::test]
async fn chain_link_rows() {
    use crate::gateway::chain_test_support::chain_of;
    for route in [Route::Invoke, Route::Direct, Route::Stdio] {
        assert_eq!(
            expect(MethodKind::ToolsCall, route, Stage::ChainLink),
            Expect::Applies,
            "{route:?}"
        );
        let body = match route {
            Route::Invoke => router::invoke_chained().await.body,
            Route::Direct => router::direct_chained().await.body,
            Route::Stdio => stdio::stdio_chained().await.body,
            other => unreachable!("not driven here: {other:?}"),
        };
        assert!(body.get("error").is_none(), "{route:?}: refused: {body}");
        assert!(
            chain_of(&body["result"]).is_some(),
            "{route:?}: no origin link on the answer: {body}"
        );
    }
}

/// ChainLink, R2 gap (MIK-8159): the same signed request by surfaced name
/// succeeds and reaches its backend, but the answer carries no origin link,
/// because the surfaced reply drops the chain source.
#[tokio::test]
async fn chain_link_surfaced_gap_row() {
    use crate::gateway::chain_test_support::chain_of;
    assert_eq!(
        expect(MethodKind::ToolsCall, Route::Surfaced, Stage::ChainLink),
        Expect::ExpectedGap(super::Ticket::Mik8159)
    );
    let sent = router::surfaced_chained().await;
    assert!(sent.body.get("error").is_none(), "refused: {}", sent.body);
    assert_eq!(sent.backend_calls, 1, "premise: the call ran: {}", sent.body);
    assert!(
        chain_of(&sent.body["result"]).is_none(),
        "R2 now carries an origin link; MIK-8159 may have closed this gap, flip \
         the row to Applies: {}",
        sent.body
    );
}

/// ChokepointRescan, R1 and the R3 gap. A continuation retry whose answer
/// carries a blocked pattern reaches bytes the route-layer scan never judged.
/// R1 Applies: the dispatch rescan refuses it with a blocking `event=dispatch`
/// row and the backend is asked only once (the question). R3 gap (MIK-8154
/// SAN.3): the direct route never reaches the chokepoint, so no dispatch row
/// is ever written.
#[tokio::test]
async fn chokepoint_rescan_rows() {
    let row = |route| expect(MethodKind::ToolsCall, route, Stage::ChokepointRescan);

    assert_eq!(row(Route::Invoke), Expect::Applies);
    let dir = tempfile::tempdir().expect("tempdir");
    let audit = dir.path().join("audit.jsonl");
    let sent = router::invoke_retry_answering(&audit, BLOCKED).await;
    let dispatched = audit_rows(&audit, "dispatch");
    assert!(
        dispatched.iter().any(|row| row["action"] == "block"),
        "R1: not refused by the dispatch rescan: {dispatched:?}; {}",
        sent.body
    );
    assert_eq!(sent.body["error"]["code"], -32600, "R1: {}", sent.body);
    assert_eq!(sent.backend_calls, 1, "R1: the hostile answer was sent: {}", sent.body);

    assert_eq!(row(Route::Direct), Expect::ExpectedGap(super::Ticket::Mik8154));
    let dir = tempfile::tempdir().expect("tempdir");
    let audit = dir.path().join("audit.jsonl");
    let sent = router::direct_retry_answering(&audit, BLOCKED).await;
    let dispatched = audit_rows(&audit, "dispatch");
    assert!(
        dispatched.is_empty(),
        "R3 wrote a dispatch row, so the direct route now passes the chokepoint; \
         MIK-8154 SAN.3 may have closed this gap, flip the row to Applies: {dispatched:?}"
    );
    assert!(
        sent.backend_calls >= 1,
        "premise: the direct route ran the first round: {}",
        sent.body
    );
}

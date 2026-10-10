// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The continuation-slot release matrix (family `continuation-slot-release`,
//! MIK-8176 with MIK-8177): a sealed question's in-flight slot is given back
//! when its envelope does not reach the client, kept when it does, and an
//! unrelated exchange never loses its own. One cell per route x path x answer
//! kind; every failing cell is reported, not the first.
//!
//! There is no allow-list of leaking cells (MIK-8176 D7): a reintroduced leak
//! fails its cell. Every cell also checks the hold registry: its mint registered one
//! hold inside the route's scope, and no hold outlived the request unless
//! the route handed it off.

use std::sync::Arc;
use std::sync::atomic::Ordering;

use super::super::direct_guards_fixture::fixture_firewalled_on;
use super::{ROUTES, Route, answering_client, post_as, report, request};
use crate::gateway::egress_fixture::{Part, Planted, secret};
use crate::protocol::continuation::{Routing, now_unix_secs};

/// What the gateway did with a sealed answer, and so what its slot must do.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Path {
    /// Delivered: the slot stays held, for the client's answer to redeem.
    Delivered,
    /// Refused by the firewall: the slot is given back.
    FirewallRefused,
}

/// The interim answer's shape.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Kind {
    /// A round with `inputRequests`.
    Question,
    /// A round with `requestState` and no questions (`MIK-8177.STATE.1`).
    StateOnly,
    /// A question that follows a progress notification, so on `/mcp` it
    /// leaves on the stream's streaming arm, not the buffered one.
    ProgressFirst,
}

/// The backend answer for `kind` taking `path`: a credential makes the
/// firewall refuse it, harmless text lets it through.
fn backend(path: Path, kind: Kind) -> Planted {
    let text = match path {
        Path::Delivered => "nothing to see".to_string(),
        Path::FirewallRefused => secret(),
    };
    Planted::with_text("tools/call", part(kind), text)
}

/// The fixture part that plants `kind`'s answer.
fn part(kind: Kind) -> Part {
    match kind {
        Kind::Question => Part::InterimQuestion,
        Kind::StateOnly => Part::InterimStateOnly,
        Kind::ProgressFirst => Part::ProgressThenQuestion,
    }
}

/// The cells this stage covers. Paths the design names whose fixtures arrive
/// with their stage (read judge, delivery audit, `slot_http`, SSE, stdio,
/// tasks, confirmations, co-owners) are added there, with red proof each.
const CELLS: [(Path, Kind); 6] = [
    (Path::Delivered, Kind::Question),
    (Path::FirewallRefused, Kind::Question),
    (Path::Delivered, Kind::StateOnly),
    (Path::FirewallRefused, Kind::StateOnly),
    (Path::Delivered, Kind::ProgressFirst),
    (Path::FirewallRefused, Kind::ProgressFirst),
];

/// The JSON-RPC message a reply carries: the last SSE `data:` line, or the
/// whole body when the reply is plain JSON.
fn rpc(body: &str) -> serde_json::Value {
    let frame = body
        .lines()
        .filter_map(|line| line.strip_prefix("data: "))
        .next_back()
        .unwrap_or(body);
    serde_json::from_str(frame).unwrap_or(serde_json::Value::Null)
}

/// Whether `body` is the outcome `path` names: a delivered result carrying
/// the sealed state, or the firewall's own refusal without the credential.
fn took(path: Path, body: &str) -> bool {
    let reply = rpc(body);
    match path {
        Path::Delivered => {
            reply.get("error").is_none()
                && reply["result"].is_object()
                && body.contains("requestState")
        }
        Path::FirewallRefused => {
            reply["error"]["code"] == -32600
                && reply["error"]["message"]
                    .as_str()
                    .is_some_and(|m| m.contains("firewall"))
                && !body.contains(&secret())
        }
    }
}

/// The hold registry's counts for one state: registered, unscoped, dropped
/// without a handoff.
fn counts(continuation: &crate::protocol::continuation::ContinuationState) -> [u64; 3] {
    let counts = continuation.hold_counts();
    [
        counts.registered.load(Ordering::Relaxed),
        counts.unscoped.load(Ordering::Relaxed),
        counts.unhanded_drops.load(Ordering::Relaxed),
    ]
}

#[tokio::test]
async fn slot_release_matrix() {
    let mut failures = Vec::new();
    for route in ROUTES {
        for (path, kind) in CELLS {
            let label = format!("{route:?} {path:?} {kind:?}");
            let fx = fixture_firewalled_on(Arc::new(backend(path, kind)), None).await;
            let continuation = fx.state.meta_mcp.continuation();
            let now = now_unix_secs();
            let other = continuation
                .begin_exchange("other".into(), None, "fp".into(), "digest".into(), now)
                .await
                .expect("an unrelated exchange holds a slot");
            let before = counts(&continuation);
            let (uri, sent, mut params) = request(route, "tools/call", part(kind));
            params["_meta"] = answering_client();
            if kind == Kind::ProgressFirst {
                // Maps the backend's notification back to this request.
                params["_meta"]["progressToken"] = serde_json::json!("p1");
            }
            let body = post_as(&fx, (uri, sent), &params, Some("alice")).await;
            // The cell only counts if its path really happened.
            let want = match path {
                Path::Delivered => 2,
                Path::FirewallRefused => 1,
            };
            if !took(path, &body) {
                failures.push(format!("{label}: did not take its path: {body}"));
            }
            // On `/mcp` the notification goes first, so the answer leaves on
            // the stream's streaming arm; without it the cell would test the
            // buffered arm instead.
            if kind == Kind::ProgressFirst
                && route == Route::Meta
                && !body.contains("notifications/progress")
            {
                failures.push(format!(
                    "{label}: the notification did not go first: {body}"
                ));
            }
            let held = continuation.in_flight().len(now).await;
            if held != want {
                failures.push(format!("{label}: {held} slots held, want {want}: {body}"));
            }
            // One hold registered in the route's scope, none minted outside
            // one. A delivered answer is handed off where its bytes leave (the
            // direct reply, or the stream's answer event on `/mcp`), so it
            // drops no unhanded hold; every other hold is gone unhanded with
            // the request.
            let after = counts(&continuation);
            let delta: Vec<u64> = after.iter().zip(before).map(|(a, b)| a - b).collect();
            let handed = path == Path::Delivered;
            let want_delta = [1, 0, u64::from(!handed)];
            if delta != want_delta {
                failures.push(format!(
                    "{label}: holds registered/unscoped/dropped {delta:?}, want {want_delta:?}"
                ));
            }
            if continuation.in_flight().route(&other.hold_key, now).await != Routing::Here {
                failures.push(format!("{label}: the unrelated exchange lost its slot"));
            }
        }
    }
    report(&failures);
}

/// Every route the egress matrix serves is a row of this one.
#[test]
fn slot_release_matrix_covers_every_route() {
    assert_eq!(ROUTES, [Route::Meta, Route::Direct]);
}

/// MIK-8177.STATE.1, task arm: a task's state-only round (a sealed
/// `requestState`, no questions) that the settlement's firewall refuses gives
/// its slot back, on the initial round and on a resumed one (a state-only
/// round resumes without the client), while an unrelated exchange keeps its
/// slot. Red on base: the release keyed on `inputRequests`.
#[cfg(feature = "firewall")]
#[tokio::test]
async fn a_refused_state_only_task_round_gives_its_slot_back() {
    use super::super::direct_guards_fixture::{Answer, CREDENTIAL_KEY, fixture_firewalled};
    let mut failures = Vec::new();
    for (round, at) in [("initial", 0_usize), ("resumed", 1)] {
        let fx = fixture_firewalled(Answer::StateOnlyRounds(at, CREDENTIAL_KEY)).await;
        let continuation = fx.state.meta_mcp.continuation();
        let now = now_unix_secs();
        let other = continuation
            .begin_exchange("other".into(), None, "fp".into(), "digest".into(), now)
            .await
            .expect("an unrelated exchange holds a slot");
        let before = counts(&continuation);
        let mut params = serde_json::json!({
            "name": "gateway_invoke",
            "arguments": {"server": "alpha", "tool": "read", "arguments": {}},
            "task": {},
        });
        params["_meta"] = answering_client();
        params["_meta"]["io.modelcontextprotocol/clientCapabilities"]["extensions"] =
            serde_json::json!({ crate::gateway::meta_mcp::upstream::TASKS_EXTENSION: {} });
        params["_meta"][crate::protocol::mrtr::IDEMPOTENCY_KEY_META] =
            serde_json::json!(format!("state-only-{round}"));
        let created = rpc(&post_as(&fx, ("/mcp", "tools/call"), &params, Some("alice")).await);
        if created.pointer("/result/taskId").is_none() {
            failures.push(format!("{round}: no task handle: {created}"));
            continue;
        }
        // The worker dispatches every round up to the refused one, then
        // settles; bounded, never a bare sleep.
        let deadline = tokio::time::Instant::now() + crate::test_wait::HANG_BOUND;
        while fx.calls.load(Ordering::SeqCst) <= at && tokio::time::Instant::now() < deadline {
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        let mut held = continuation.in_flight().len(now_unix_secs()).await;
        while held != 1 && tokio::time::Instant::now() < deadline {
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            held = continuation.in_flight().len(now_unix_secs()).await;
        }
        let calls = fx.calls.load(Ordering::SeqCst);
        let minted = counts(&continuation)[0] - before[0];
        if calls != at + 1 || minted != u64::try_from(at + 1).expect("small") {
            failures.push(format!(
                "{round}: {calls} backend calls and {minted} rounds sealed, want {} each",
                at + 1
            ));
        }
        if held != 1 {
            failures.push(format!(
                "{round}: {held} slots held, want only the unrelated one"
            ));
        }
        if continuation.in_flight().route(&other.hold_key, now).await != Routing::Here {
            failures.push(format!("{round}: the unrelated exchange lost its slot"));
        }
    }
    report(&failures);
}

/// A backend whose first `tools/call` asks a question and whose later ones
/// answer a completed result quoting `quoted` beside a credential.
struct Quoting {
    calls: std::sync::atomic::AtomicUsize,
    quoted: std::sync::Mutex<String>,
}

#[async_trait::async_trait]
impl crate::transport::Transport for Quoting {
    async fn request(
        &self,
        method: &str,
        _params: Option<serde_json::Value>,
    ) -> crate::Result<crate::protocol::JsonRpcResponse> {
        let id = crate::protocol::RequestId::Number(1);
        let result = match method {
            "tools/list" => {
                serde_json::json!({"tools": [{"name": "read", "inputSchema": {"type": "object"}}]})
            }
            "tools/call" if self.calls.fetch_add(1, Ordering::SeqCst) == 0 => serde_json::json!({
                "resultType": "input_required",
                "inputRequests": {"k1": {"method": "elicitation/create",
                    "params": {"message": "Which?", "requestedSchema": {"type": "object"}}}},
                "requestState": "backend-state",
            }),
            "tools/call" => {
                let quoted = self.quoted.lock().expect("unpoisoned").clone();
                serde_json::json!({"content": [{"type": "text",
                    "text": format!("{quoted} {}", super::super::direct_guards_fixture::CREDENTIAL_KEY)}],
                    "isError": false})
            }
            _ => serde_json::json!({}),
        };
        Ok(crate::protocol::JsonRpcResponse::success(id, result))
    }
    async fn notify(&self, _method: &str, _params: Option<serde_json::Value>) -> crate::Result<()> {
        Ok(())
    }
    fn is_connected(&self) -> bool {
        true
    }
    async fn close(&self) -> crate::Result<()> {
        Ok(())
    }
}

/// MIK-8177.STATE.2 (guard): a refused answer that only QUOTES another
/// exchange's live envelope, in a completed (non-interim) result, never frees
/// that exchange's slot. A slot is released only by the scope that minted it.
#[cfg(feature = "firewall")]
#[tokio::test]
async fn a_refused_answer_quoting_another_envelope_keeps_that_slot() {
    let backend = Arc::new(Quoting {
        calls: std::sync::atomic::AtomicUsize::new(0),
        quoted: std::sync::Mutex::new(String::new()),
    });
    let fx = fixture_firewalled_on(Arc::clone(&backend) as _, None).await;
    let continuation = fx.state.meta_mcp.continuation();
    let (uri, sent, mut params) = request(Route::Meta, "tools/call", Part::InterimQuestion);
    params["_meta"] = answering_client();
    let asked = rpc(&post_as(&fx, (uri, sent), &params, Some("alice")).await);
    let envelope = asked
        .pointer("/result/content/0/text")
        .and_then(serde_json::Value::as_str)
        .and_then(|text| serde_json::from_str::<serde_json::Value>(text).ok())
        .and_then(|inner| inner["requestState"].as_str().map(str::to_owned))
        .or_else(|| {
            asked
                .pointer("/result/requestState")
                .and_then(serde_json::Value::as_str)
                .map(str::to_owned)
        })
        .unwrap_or_else(|| panic!("the question is delivered with an envelope: {asked}"));
    assert_eq!(
        continuation.in_flight().len(now_unix_secs()).await,
        1,
        "the question's slot is held"
    );
    *backend.quoted.lock().expect("unpoisoned") = envelope;
    let quoting = rpc(&post_as(&fx, (uri, sent), &params, Some("alice")).await);
    assert!(
        quoting.get("error").is_some(),
        "the firewall refuses the quoting answer: {quoting}"
    );
    assert_eq!(
        continuation.in_flight().len(now_unix_secs()).await,
        1,
        "the quoted envelope's slot is still held"
    );
}

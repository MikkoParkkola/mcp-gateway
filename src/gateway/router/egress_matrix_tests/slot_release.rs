// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The continuation-slot release matrix (family `continuation-slot-release`,
//! MIK-8176 with MIK-8177): a sealed question's in-flight slot is given back
//! when its envelope does not reach the client, kept when it does, and an
//! unrelated exchange never loses its own. One cell per route x path x answer
//! kind; every failing cell is reported, not the first.
//!
//! A cell in [`KNOWN_LEAK`] still leaks on this tree and must keep leaking:
//! the stage that fixes it removes it, and the last stage asserts the list is
//! empty. Every cell also checks the hold registry: its mint registered one
//! hold inside the route's scope, and no hold outlived the request.

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
    }
}

/// The cells this stage covers. Paths the design names whose fixtures arrive
/// with their stage (read judge, delivery audit, `slot_http`, SSE, stdio,
/// tasks, confirmations, co-owners) are added there, with red proof each.
const CELLS: [(Path, Kind); 4] = [
    (Path::Delivered, Kind::Question),
    (Path::FirewallRefused, Kind::Question),
    (Path::Delivered, Kind::StateOnly),
    (Path::FirewallRefused, Kind::StateOnly),
];

/// Cells that leak their slot on this tree, each with the stage that fixes it.
const KNOWN_LEAK: [(Route, Path, Kind); 1] = [
    // MIK-8177.STATE.1: stage 2's handoff release frees it.
    (Route::Meta, Path::FirewallRefused, Kind::StateOnly),
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
            let body = post_as(&fx, (uri, sent), &params, Some("alice")).await;
            // The cell only counts if its path really happened.
            let want = match path {
                Path::Delivered => 2,
                Path::FirewallRefused => 1,
            };
            if !took(path, &body) {
                failures.push(format!("{label}: did not take its path: {body}"));
            }
            let known_leak = KNOWN_LEAK.contains(&(route, path, kind));
            let want = if known_leak { want + 1 } else { want };
            let held = continuation.in_flight().len(now).await;
            if held != want {
                let note = if known_leak {
                    " (KNOWN_LEAK: fixed? remove the row)"
                } else {
                    ""
                };
                failures.push(format!(
                    "{label}: {held} slots held, want {want}{note}: {body}"
                ));
            }
            // Stage 1: one hold registered in the route's scope, none minted
            // outside one, and every hold gone with the request.
            let after = counts(&continuation);
            let delta: Vec<u64> = after.iter().zip(before).map(|(a, b)| a - b).collect();
            if delta != [1, 0, 1] {
                failures.push(format!(
                    "{label}: holds registered/unscoped/dropped {delta:?}, want [1, 0, 1]"
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

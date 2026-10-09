// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The continuation-slot release matrix (family `continuation-slot-release`,
//! MIK-8176 with MIK-8177): a sealed question's in-flight slot is given back
//! when its envelope does not reach the client, kept when it does, and an
//! unrelated exchange never loses its own. One cell per route x path x answer
//! kind; every failing cell is reported, not the first.

use std::sync::Arc;

use super::super::direct_guards_fixture::fixture_firewalled_on;
use super::{ROUTES, Route, answering_client, post_as, report, request};
use crate::gateway::egress_fixture::{Part, Planted, secret};
use crate::protocol::continuation::{Routing, now_unix_secs};

/// What the gateway did with a sealed answer, and so what its slot must do.
#[derive(Clone, Copy, Debug)]
enum Path {
    /// Delivered: the slot stays held, for the client's answer to redeem.
    Delivered,
    /// Refused by the firewall: the slot is given back.
    FirewallRefused,
}

/// The interim answer's shape.
#[derive(Clone, Copy, Debug)]
enum Kind {
    /// A round with `inputRequests`.
    Question,
    /// A round with `requestState` and no questions (MIK-8177.STATE.1).
    StateOnly,
}

/// The backend answer for `kind` taking `path`: a credential makes the
/// firewall refuse it, harmless text lets it through.
fn backend(path: Path, kind: Kind) -> Planted {
    let text = match path {
        Path::Delivered => "nothing to see".to_string(),
        Path::FirewallRefused => secret(),
    };
    let part = match kind {
        Kind::Question => Part::InterimQuestion,
        Kind::StateOnly => Part::InterimStateOnly,
    };
    Planted::with_text("tools/call", part, text)
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
            let (uri, sent, mut params) = request(route, "tools/call", Part::InterimQuestion);
            params["_meta"] = answering_client();
            let body = post_as(&fx, (uri, sent), &params, Some("alice")).await;
            // The cell only counts if its path really happened.
            let text = &body;
            let (want, took_path) = match path {
                Path::Delivered => (2, text.contains("requestState")),
                Path::FirewallRefused => (1, !text.contains(&secret())),
            };
            if !took_path {
                failures.push(format!("{label}: did not take its path: {body}"));
            }
            let held = continuation.in_flight().len(now).await;
            if held != want {
                failures.push(format!("{label}: {held} slots held, want {want}: {body}"));
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

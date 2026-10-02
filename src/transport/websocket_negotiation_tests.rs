// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-7721 NEG.2: the GH #517 version fallback on WebSocket, mirroring
//! `tests/gh517_neg_acs.rs` for HTTP. A backend that rejects the proposed
//! revision is retried once, on the same socket, at the highest revision both
//! sides speak, and whatever the backend selects must be one this gateway
//! speaks.

use std::collections::HashMap;
use std::time::Duration;

use super::{Transport, WebSocketTransport};
use crate::Error;
use crate::protocol::PROTOCOL_VERSION;
use crate::transport::websocket_test_server::{Behaviour, WsPeer};

const WAIT: Duration = Duration::from_secs(10);

/// Two revisions the gateway speaks, neither of them its own proposal. The
/// retry must pick the higher one; a one-entry list could not tell "highest"
/// from "first".
const PEER_SPEAKS: &[&str] = &["2024-11-05", "2025-06-18"];
const HIGHEST_SHARED: &str = "2025-06-18";

/// A revision no gateway release speaks.
const UNSUPPORTED: &str = "1999-01-01";

async fn connect(behaviour: Behaviour) -> (WsPeer, crate::Result<()>) {
    assert!(
        !PEER_SPEAKS.contains(&PROTOCOL_VERSION),
        "the peer must reject the gateway's own proposal, or no fallback is exercised"
    );
    let peer = WsPeer::start(behaviour).await;
    let transport = WebSocketTransport::new(&peer.url, HashMap::new(), WAIT, None);
    let outcome = tokio::time::timeout(WAIT, transport.connect())
        .await
        .expect("connect must not hang");
    let _ = transport.close().await;
    (peer, outcome)
}

/// The `protocolVersion` of every `initialize` the peer received, in order.
fn proposals(peer: &WsPeer) -> Vec<String> {
    peer.seen
        .initialize_params
        .lock()
        .iter()
        .map(|params| params["protocolVersion"].as_str().unwrap_or("").to_string())
        .collect()
}

#[tokio::test]
async fn a_version_rejection_is_retried_at_the_highest_shared_revision() {
    let (peer, outcome) = connect(Behaviour::Negotiates {
        speaks: PEER_SPEAKS,
        selects: HIGHEST_SHARED,
    })
    .await;

    assert_eq!(
        proposals(&peer),
        vec![PROTOCOL_VERSION.to_string(), HIGHEST_SHARED.to_string()],
        "one rejected proposal, then one retry at the highest revision both sides speak"
    );
    outcome.expect("a backend that speaks an older shared revision must start");
}

#[tokio::test]
async fn a_retry_that_selects_an_unsupported_revision_is_refused() {
    let (peer, outcome) = connect(Behaviour::Negotiates {
        speaks: PEER_SPEAKS,
        selects: UNSUPPORTED,
    })
    .await;

    assert_eq!(
        proposals(&peer).len(),
        2,
        "the rejection must have been retried before the selection is judged"
    );
    let error = outcome.expect_err("a revision the gateway does not speak must not be adopted");
    assert!(matches!(error, Error::Protocol(_)), "{error:?}");
    assert!(error.to_string().contains(UNSUPPORTED), "{error}");
}

#[tokio::test]
async fn a_first_answer_that_selects_an_unsupported_revision_is_refused() {
    const SPEAKS_OURS: &[&str] = &[PROTOCOL_VERSION];
    let peer = WsPeer::start(Behaviour::Negotiates {
        speaks: SPEAKS_OURS,
        selects: UNSUPPORTED,
    })
    .await;
    let transport = WebSocketTransport::new(&peer.url, HashMap::new(), WAIT, None);
    let error = tokio::time::timeout(WAIT, transport.connect())
        .await
        .expect("connect must not hang")
        .expect_err("a revision the gateway does not speak must not be adopted");

    assert_eq!(
        proposals(&peer).len(),
        1,
        "nothing was rejected, so nothing is retried"
    );
    assert!(matches!(error, Error::Protocol(_)), "{error:?}");
    assert!(error.to_string().contains(UNSUPPORTED), "{error}");
}

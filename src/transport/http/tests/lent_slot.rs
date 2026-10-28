// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A lent-only per-user slot's
//! transport sends only the credential a dispatch in flight lends, never its
//! static headers, and sends nothing with no dispatch in flight; a slot that
//! keeps its configured headers is unchanged.

use std::sync::atomic::Ordering;

use super::*;
use crate::transport::{Lender, SlotCredential};

/// A transport with a static credential header, marked as a per-user slot.
fn slot(url: &str, credential: SlotCredential) -> (Arc<HttpTransport>, Arc<Lender>) {
    let mut statics = HashMap::new();
    statics.insert(
        "X-Static-Credential".to_string(),
        "gateway-owned".to_string(),
    );
    let t = make_transport_with_headers(url, statics);
    let lender = Arc::new(Lender::default());
    t.mark_per_user_slot(credential, Arc::clone(&lender));
    (t, lender)
}

fn subscriber() -> Vec<(String, String)> {
    vec![("Authorization".to_string(), "Bearer subscriber".to_string())]
}

/// START.8: with no dispatch in flight, a lent-only slot builds no headers
/// for any send: there is no subscriber to send as.
#[tokio::test]
async fn a_lent_only_slot_sends_nothing_with_nothing_lent() {
    let (t, lender) = slot("http://localhost", SlotCredential::LentOnly);
    for mode in [
        HeaderMode::Request { method: "m" },
        HeaderMode::Notify,
        HeaderMode::Sse,
    ] {
        assert!(
            t.build_mcp_headers(mode, None).await.is_err(),
            "built headers with nothing lent"
        );
    }
    let empty = lender.lend(&[]);
    assert!(
        t.build_mcp_headers(HeaderMode::Request { method: "m" }, None)
            .await
            .is_err(),
        "an empty loan is no credential"
    );
    drop(empty);
}

/// START.7: while a dispatch lends its credential, every send carries that
/// credential and none of the slot's static headers.
#[tokio::test]
async fn a_lent_only_slot_sends_the_loan_and_no_static_header() {
    let (t, lender) = slot("http://localhost", SlotCredential::LentOnly);
    let loan = lender.lend(&subscriber());
    for mode in [
        HeaderMode::Request { method: "m" },
        HeaderMode::Notify,
        HeaderMode::Sse,
    ] {
        let map = t.build_mcp_headers(mode, None).await.unwrap();
        assert_eq!(map[header::AUTHORIZATION], "Bearer subscriber");
        assert!(!map.contains_key("x-static-credential"), "{map:?}");
    }
    drop(loan);
    assert!(
        t.build_mcp_headers(HeaderMode::Notify, None).await.is_err(),
        "the loan ended with its dispatch"
    );
}

/// START.9: a slot that keeps its configured headers still sends them, with
/// or without a loan.
#[tokio::test]
async fn a_configured_slot_keeps_its_static_headers() {
    let (t, _lender) = slot("http://localhost", SlotCredential::Configured);
    let map = t
        .build_mcp_headers(HeaderMode::Request { method: "m" }, None)
        .await
        .unwrap();
    assert_eq!(map["x-static-credential"], "gateway-owned");
}

/// START.8: closing a lent-only slot sends no session DELETE; a configured
/// slot still ends its session.
#[tokio::test]
async fn closing_a_lent_only_slot_sends_no_delete() {
    use axum::{Router, routing::delete};
    use std::sync::atomic::AtomicUsize;

    let deletes = Arc::new(AtomicUsize::new(0));
    let counted = Arc::clone(&deletes);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let app = Router::new().route(
        "/messages",
        delete(move || {
            counted.fetch_add(1, Ordering::SeqCst);
            async { axum::http::StatusCode::NO_CONTENT }
        }),
    );
    let server = tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    for (credential, want) in [
        (SlotCredential::LentOnly, 0),
        (SlotCredential::Configured, 1),
    ] {
        let before = deletes.load(Ordering::SeqCst);
        let (t, _lender) = slot(&format!("http://{addr}/mcp"), credential);
        *t.message_url.write() = Some(format!("http://{addr}/messages"));
        set_default_session(&t, "a-session");
        t.close().await.unwrap();
        assert_eq!(
            deletes.load(Ordering::SeqCst) - before,
            want,
            "{credential:?}: session DELETEs on close"
        );
    }
    server.abort();
}

/// A stream that lends its own credential through a credential source (an
/// event listener's) is not refused on a lent-only slot when no dispatch is
/// in flight: its source is its lender. It still carries no static header;
/// the source's credential is merged after these headers are built.
#[tokio::test]
async fn a_source_lent_stream_opens_with_nothing_on_loan() {
    let (t, _lender) = slot("http://localhost", SlotCredential::LentOnly);
    for mode in [HeaderMode::Request { method: "m" }, HeaderMode::Sse] {
        let map = t
            .build_lent_headers(mode, Some("subscriber"))
            .await
            .expect("a source-lent stream is refused with nothing on loan");
        assert!(!map.contains_key("x-static-credential"), "{map:?}");
        assert!(!map.contains_key(header::AUTHORIZATION), "{map:?}");
    }
}

/// START.9: an optional binding's per-user slot keeps today's sessions: its
/// start runs as the gateway, so a subscriber's call rides the subscriber's
/// own session bucket, never the one that start opened. A lent-only slot's
/// start runs as its one subscriber, so its calls ride that start's session.
#[tokio::test]
async fn only_a_lent_only_slot_rides_its_starts_session() {
    for (credential, rides) in [
        (SlotCredential::Configured, false),
        (SlotCredential::LentOnly, true),
    ] {
        let (t, lender) = slot("http://localhost", credential);
        set_default_session(&t, "the-starts-session");
        let _loan = lender.lend(&subscriber());
        let map = t
            .build_mcp_headers(HeaderMode::Request { method: "m" }, Some("subscriber"))
            .await
            .unwrap();
        let carried = map
            .get("mcp-session-id")
            .is_some_and(|v| v == "the-starts-session");
        assert_eq!(carried, rides, "{credential:?}: {map:?}");
    }
}

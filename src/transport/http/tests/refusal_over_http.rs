// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A lent-only resend the gateway refuses after an expired session may have
//! run. Built on the resend row's loopback helpers, which hold their port.

use super::session_expiry_resend::{held_listener, read_request, respond};
use super::*;
use serde_json::json;
use std::sync::atomic::{AtomicBool, Ordering};

const FRESH: &str = "fresh-session-after-refusal";

/// A server that answers the stale session's request with 404 (expired),
/// re-initialises, sets `healed` and stops listening once the client
/// confirms the new session. The port stays held as `held_listener` holds it.
fn healing_server(
    healed: Arc<AtomicBool>,
) -> (
    String,
    std::sync::mpsc::Receiver<usize>,
    Option<tokio::net::TcpSocket>,
) {
    let (listener, holder) = held_listener();
    let url = format!("http://{}/mcp", listener.local_addr().expect("address"));
    let (done, served_count) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let mut served = 0usize;
        let mut listener = Some(listener);
        while let Some(open) = listener.as_ref() {
            let (stream, _) = open.accept().expect("accept");
            let (first, headers, body) = read_request(&stream);
            served += 1;
            let method = body["method"].as_str().unwrap_or_default().to_owned();
            if !first.starts_with("POST") {
                respond(&stream, "405 Method Not Allowed", "", "");
            } else if method == "initialize" {
                let result = json!({"jsonrpc": "2.0", "id": body["id"], "result": {
                    "protocolVersion": PROTOCOL_VERSION, "capabilities": {},
                    "serverInfo": {"name": "mock", "version": "0"}}});
                respond(
                    &stream,
                    "200 OK",
                    &format!("mcp-session-id: {FRESH}\r\n"),
                    &result.to_string(),
                );
            } else if body.get("id").is_none() {
                // The new session is confirmed: the credential is refused from
                // here on, and nothing else is answered.
                healed.store(true, Ordering::SeqCst);
                drop(listener.take());
                respond(&stream, "202 Accepted", "", "");
            } else if !headers.contains(FRESH) {
                respond(&stream, "404 Not Found", "", "");
            } else {
                let result = json!({"jsonrpc": "2.0", "id": body["id"], "result": {"tools": []}});
                respond(&stream, "200 OK", "", &result.to_string());
            }
        }
        let _ = done.send(served);
    });
    (url, served_count, holder)
}

/// On a lent-only slot, the credential is refused once the session has
/// healed, so the resend is refused while its headers are built, after the
/// stale request reached the server. That refusal is the gateway's denial,
/// raised before the resend left, but the call may have run: it answers
/// `Transport`, never the never-sent denial that would free the key.
#[tokio::test]
async fn a_resend_the_lender_refuses_after_an_expired_session_may_have_run() {
    use crate::transport::{Lender, LentCredential, Refusal, SlotCredential};
    let healed = Arc::new(AtomicBool::new(false));
    let (url, served_count, _held) = healing_server(Arc::clone(&healed));
    let transport = make_transport(&url);
    let lender = Arc::new(Lender::default());
    transport.mark_per_user_slot(SlotCredential::LentOnly, Arc::clone(&lender));
    let call = vec![("Authorization".to_string(), "Bearer subscriber".to_string())];
    let refuse_once_healed = Arc::clone(&healed);
    let _loan = lender.lend(LentCredential {
        headers: call.clone().into(),
        check: Some(Arc::new(move || {
            let refuse = refuse_once_healed.load(Ordering::SeqCst);
            Box::pin(async move {
                if refuse {
                    Err(Refusal::ThisLoan)
                } else {
                    Ok(())
                }
            })
        })),
    });
    *transport.message_url.write() = Some(url.clone());
    set_default_session(&transport, "stale-session");
    let error = transport
        .request_with_headers(
            "tools/list",
            None,
            &call,
            None,
            crate::transport::ResendPermission::Permitted,
        )
        .await
        .expect_err("the resend was refused");
    let served = served_count
        .recv_timeout(Duration::from_secs(30))
        .expect("the server closed its listener");
    assert!(
        served >= 3,
        "premise: the stale request, initialize and its confirmation were served ({served})"
    );
    assert!(healed.load(Ordering::SeqCst), "premise: the session healed");
    assert!(
        matches!(error, crate::Error::Transport(_)),
        "a refused resend after a sent request read as never sent: {error:?}"
    );
    assert!(!error.is_pre_dispatch(), "{error:?}");
    assert!(
        error.to_string().contains("per-user send refused"),
        "the lender's refusal is the cause: {error}"
    );
}

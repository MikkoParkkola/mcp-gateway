// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! MIK-7246.CONFIRM.1a — the two unwitnessed producers of `Unsupported`.
//!
//! `require_destructive_confirmation` turns three distinct failures into the
//! single `ConfirmationOutcome::Unsupported` the modern gate refuses on
//! (`src/gateway/meta_mcp/mod.rs`, the `on_unconfirmable() == REFUSE` arm).
//! Only the `NoSession` producer was executed by a test
//! (`tests/mik_7215_acs.rs::ac_confirm_1_a_modern_destructive_call_with_nobody_to_ask_is_refused`).
//! These two cover the other two arms:
//!
//! * `Err(SamplingError::Timeout(_))` — a session exists, the operator is
//!   asked, and nobody ever answers.
//! * the catch-all `Err(e)` — reached honestly via `SamplingError::Cancelled`,
//!   the elicitation channel dying under a live session.
//!
//! Because all three arms return the SAME variant, a test that quietly lost
//! its session would go green on the already-witnessed `NoSession` path and
//! prove nothing. Both tests therefore first read the `elicitation/create`
//! frame off the session's own receiver: a delivered frame is positive proof
//! `NoSession` was not the branch taken. The timeout test additionally asserts
//! the full `ELICITATION_TIMEOUT` elapsed, which `NoSession` (immediate)
//! cannot produce.
//!
//! The 120-second constant is module-private and not worth 120 seconds of wall
//! clock, so the timeout test runs on tokio's paused clock: the runtime
//! auto-advances time when every task is idle on a timer, so the real deadline
//! is honoured at no cost.

use std::sync::Arc;
use std::time::Duration;

use mcp_gateway::backend::BackendRegistry;
use mcp_gateway::config::Config;
use mcp_gateway::gateway::destructive_confirmation::{
    ConfirmationOutcome, require_destructive_confirmation,
};
use mcp_gateway::gateway::proxy::ProxyManager;
use mcp_gateway::gateway::streaming::{NotificationMultiplexer, TaggedNotification};
use tokio::sync::broadcast::Receiver;

/// The gateway's own elicitation plumbing, plus one live session.
///
/// The returned `Receiver` MUST be held for the lifetime of the test:
/// `send_to_session` reports failure when a session has no live subscriber,
/// and that failure is exactly the `NoSession` arm these tests must avoid.
fn proxy_with_live_session(session_id: &str) -> (Arc<ProxyManager>, Receiver<TaggedNotification>) {
    let multiplexer = Arc::new(NotificationMultiplexer::new(
        Arc::new(BackendRegistry::new()),
        Config::default().streaming,
    ));
    let (id, rx) = multiplexer.get_or_create_session_for(Some(session_id), "confirm-1a-test");
    assert_eq!(id, session_id, "the multiplexer must hand back our own id");
    (Arc::new(ProxyManager::new(multiplexer)), rx)
}

/// Assert the frame is the confirmation prompt, and return its request id.
fn elicitation_id(frame: &TaggedNotification) -> String {
    assert_eq!(
        frame.data.get("method").and_then(serde_json::Value::as_str),
        Some("elicitation/create"),
        "the operator must actually have been asked; without a delivered \
         prompt the outcome would be the already-witnessed NoSession arm"
    );
    frame
        .data
        .get("id")
        .and_then(serde_json::Value::as_str)
        .expect("the elicitation frame carries the correlation id")
        .to_string()
}

/// The `Timeout` producer: asked, and never answered.
///
/// Pins `src/gateway/destructive_confirmation.rs` `Err(SamplingError::Timeout(d))`.
#[tokio::test(start_paused = true)]
async fn an_unanswered_confirmation_prompt_is_unconfirmable() {
    let (proxy, mut rx) = proxy_with_live_session("sess-timeout");
    let started = tokio::time::Instant::now();

    // Joined rather than spawned: on the paused clock the runtime advances
    // time only once every task is idle, and the receiving half must have
    // taken the frame before that happens.
    let (outcome, frame) = tokio::join!(
        require_destructive_confirmation(&proxy, "sess-timeout", "kill server 'payments'"),
        async {
            rx.recv()
                .await
                .expect("the gateway must deliver the prompt to the live session")
        },
    );

    let _id = elicitation_id(&frame);
    assert!(
        started.elapsed() >= Duration::from_secs(120),
        "the full elicitation timeout must have elapsed; a shorter wait means \
         some other arm produced this outcome (elapsed: {:?})",
        started.elapsed()
    );
    assert_eq!(
        outcome,
        ConfirmationOutcome::Unsupported,
        "a prompt nobody answers leaves the action unconfirmable"
    );
}

/// The catch-all producer: asked, and the channel died before any answer.
///
/// Pins `src/gateway/destructive_confirmation.rs` catch-all `Err(e)`, reached
/// through `SamplingError::Cancelled`.
#[tokio::test]
async fn a_confirmation_channel_that_dies_is_unconfirmable() {
    let (proxy, mut rx) = proxy_with_live_session("sess-cancelled");

    let asking = tokio::spawn({
        let proxy = Arc::clone(&proxy);
        async move {
            require_destructive_confirmation(&proxy, "sess-cancelled", "kill server 'payments'")
                .await
        }
    });

    let frame = tokio::time::timeout(Duration::from_secs(5), rx.recv())
        .await
        .expect("the prompt must be delivered promptly")
        .expect("the gateway must deliver the prompt to the live session");
    let id = elicitation_id(&frame);

    // Drops the responder half without delivering an answer: the caller's
    // receive fails rather than timing out, which is the catch-all's entry
    // condition.
    proxy.cancel_pending(&id);

    let outcome = tokio::time::timeout(Duration::from_secs(5), asking)
        .await
        .expect(
            "the call must return on the dead channel, not fall through to \
             the 120-second timeout arm",
        )
        .expect("the asking task must not panic");

    assert_eq!(
        outcome,
        ConfirmationOutcome::Unsupported,
        "a confirmation channel that dies leaves the action unconfirmable"
    );
}

// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A playbook or chain whose later step meets a gateway refusal after an
//! earlier step was sent ends on that refusal: its own code on the wire and
//! `refused` in the delivery record. The run's key stays held by its
//! execution lease, so a same-key retry is answered from the stored delivery
//! and sends nothing, even once the refusal no longer applies. A run refused
//! before any step was sent holds no key.

use std::cell::RefCell;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use serde_json::{Value, json};

use super::direct_guards_fixture::{Answer, Fx, fixture_hardened_signed_logged};
use super::playbook_key_tests::{call, calls, reads};
use super::route_matrix_driver_tests::response::{delivery_rows, temp_log};

thread_local! {
    /// Run once while the backend answers the next `tools/call`: after that
    /// call was sent, before the next step is dispatched.
    static AFTER_SEND: RefCell<Option<Box<dyn FnOnce()>>> = const { RefCell::new(None) };
}

/// The backend's answer: it runs the pending [`AFTER_SEND`] hook, then
/// succeeds.
fn answer_then_hook() -> Value {
    if let Some(hook) = AFTER_SEND.with(|slot| slot.borrow_mut().take()) {
        hook();
    }
    json!({"content": [{"type": "text", "text": "ok"}], "isError": false})
}

/// The operator switches `alpha` off once its next call has been sent. The
/// flag says the switch happened, so a row cannot pass without it.
fn switch_off_after_next_send(fx: &Fx) -> Arc<AtomicBool> {
    let switched = Arc::new(AtomicBool::new(false));
    let kill = Arc::clone(&fx.state.meta_mcp.kill_switch);
    let flag = Arc::clone(&switched);
    AFTER_SEND.with(|slot| {
        *slot.borrow_mut() = Some(Box::new(move || {
            kill.kill("alpha");
            flag.store(true, Ordering::SeqCst);
        }));
    });
    switched
}

/// A signed, keyed fixture serving the two-step playbook `two` (both steps
/// `alpha/read`), recording deliveries in its own log.
async fn fixture() -> (
    Fx,
    tempfile::TempDir,
    Arc<crate::security::TransparencyLogger>,
) {
    let (dir, log) = temp_log(None);
    let meta_log = Arc::clone(&log);
    let fx = fixture_hardened_signed_logged(Answer::Built(answer_then_hook), Arc::clone(&log), {
        move |mut meta| {
            meta.enable_transparency_log(meta_log);
            let mut engine = crate::playbook::PlaybookEngine::new();
            engine.register(reads("two", &["one", "two"], json!({})));
            meta.set_playbook_engine(engine);
            meta
        }
    })
    .await;
    (fx, dir, log)
}

async fn run_playbook(fx: &Fx, key: &str, nonce: &str) -> Value {
    call(
        fx,
        ("/mcp", "gateway_run_playbook"),
        json!({"name": "gateway_run_playbook",
               "arguments": {"name": "two", "arguments": {}}}),
        (Some(key), nonce),
        json!({}),
    )
    .await
}

async fn run_chain(fx: &Fx, key: &str, nonce: &str) -> Value {
    call(
        fx,
        ("/mcp", "gateway_execute"),
        json!({"name": "gateway_execute", "arguments": {"chain": [
            {"tool": "alpha:read", "arguments": {"cmd": "one"}},
            {"tool": "alpha:read", "arguments": {"cmd": "two"}},
        ]}}),
        (Some(key), nonce),
        json!({}),
    )
    .await
}

/// The latest delivery record: the run's own, written after its steps'.
async fn last_delivery(log: &crate::security::TransparencyLogger) -> Value {
    let rows = delivery_rows(log).await;
    rows.last()
        .cloned()
        .unwrap_or_else(|| panic!("no delivery record: {rows:?}"))
}

/// A playbook whose second step meets the kill switch after its first was
/// sent ends on the switch's refusal (-32000), recorded refused; the same-key
/// retry after the switch is lifted is the stored refusal, and nothing is
/// sent again.
#[tokio::test]
async fn a_playbook_ended_by_a_late_refusal_keeps_its_key() {
    let (fx, _dir, log) = fixture().await;
    let switched = switch_off_after_next_send(&fx);
    let first = run_playbook(&fx, "late-pb", "late-pb-1").await;
    assert!(
        switched.load(Ordering::SeqCst),
        "premise: the switch was flipped"
    );
    assert_eq!(
        calls(&fx),
        1,
        "premise: step one was sent, step two was not: {first}"
    );
    assert_eq!(first["error"]["code"], -32000, "{first}");
    assert_eq!(last_delivery(&log).await["response_effect"], "refused");

    fx.state.meta_mcp.kill_switch.revive("alpha");
    let again = run_playbook(&fx, "late-pb", "late-pb-2").await;
    assert_eq!(again, first, "the retry is not the stored refusal");
    assert_eq!(calls(&fx), 1, "the retry sent a step again");
}

/// The same for a chain: its late refusal keeps the switch's own code
/// (-32000), not an internal error's, and is recorded refused; the same-key
/// retry is the stored refusal.
#[tokio::test]
async fn a_chain_ended_by_a_late_refusal_keeps_its_code_and_its_key() {
    let (fx, _dir, log) = fixture().await;
    let switched = switch_off_after_next_send(&fx);
    let first = run_chain(&fx, "late-chain", "late-chain-1").await;
    assert!(
        switched.load(Ordering::SeqCst),
        "premise: the switch was flipped"
    );
    assert_eq!(
        calls(&fx),
        1,
        "premise: step one was sent, step two was not: {first}"
    );
    assert_eq!(first["error"]["code"], -32000, "{first}");
    assert_eq!(last_delivery(&log).await["response_effect"], "refused");

    fx.state.meta_mcp.kill_switch.revive("alpha");
    let again = run_chain(&fx, "late-chain", "late-chain-2").await;
    assert_eq!(again, first, "the retry is not the stored refusal");
    assert_eq!(calls(&fx), 1, "the retry sent a step again");
}

/// Control: a playbook refused before any step was sent holds no key: once
/// the switch is lifted, the same key runs both steps.
#[tokio::test]
async fn a_run_refused_before_any_send_holds_no_key() {
    let (fx, _dir, _log) = fixture().await;
    fx.state.meta_mcp.kill_switch.kill("alpha");
    let refused = run_playbook(&fx, "early-pb", "early-pb-1").await;
    assert!(
        refused.get("error").is_some(),
        "premise: refused: {refused}"
    );
    assert_eq!(calls(&fx), 0, "premise: nothing was sent: {refused}");

    fx.state.meta_mcp.kill_switch.revive("alpha");
    let ran = run_playbook(&fx, "early-pb", "early-pb-2").await;
    assert!(
        ran.get("error").is_none(),
        "the freed key did not run: {ran}"
    );
    assert_eq!(calls(&fx), 2, "both steps ran under the freed key");
}

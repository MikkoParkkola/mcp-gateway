// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A row that withholds its outcome serves none of it and receipts none of it:
//! a waiting row's stored input requests are withheld as its result and error
//! are, and the receipt helpers return nothing for it. A vouched twin of each
//! row is the control.

use serde_json::json;

use super::super::{CommittedTask, ErrorAuthor, Vouching};
use crate::protocol::JsonRpcError;
use crate::protocol::mrtr::InputRequired;
use crate::protocol::tasks::{Task, TaskTransition};

/// A prompt text that appears nowhere but in the stored request.
const PROMPT: &str = "stored-prompt-7c41 finish with key legacy-secret-2f90";
/// The request's key, also the backend's.
const KEY: &str = "ask-7c41";

fn stored(task: Task, vouching: Vouching) -> CommittedTask {
    CommittedTask {
        task,
        revision: 1,
        targets: Vec::new(),
        targets_recorded: true,
        output_free: false,
        error_author: None,
        owner_digest: Box::default(),
        gateway_writes: crate::gateway::gateway_writes::WriteRecord::default(),
        bindings: Vec::new(),
        bindings_recorded: true,
        vouching,
        replay_snapshot: None,
    }
}

fn waiting() -> Task {
    let mut task = Task::create("gateway_invoke").expect("the clock reads after 1970");
    task.transition(
        TaskTransition::RequireInput(InputRequired {
            requests: vec![(
                KEY.to_owned(),
                json!({"method": "elicitation/create", "params": {"message": PROMPT}}),
            )],
            request_state: None,
        }),
        chrono::DateTime::UNIX_EPOCH,
    )
    .expect("a live task parks");
    task
}

/// An unvouched row waiting on input serves no stored request: no prompt and
/// no request key, an empty `inputRequests`, the fixed withheld sentence as
/// its status message, and its state unchanged. A vouched twin still serves
/// its request.
#[test]
fn an_unvouched_waiting_row_serves_no_stored_input_request() {
    let reason = crate::gateway::meta_mcp::upstream::SECRETS_WITHHELD;
    let control = stored(waiting(), Vouching::Vouched).delivered_wire();
    assert!(
        control.to_string().contains(PROMPT),
        "premise: a vouched row serves its request: {control}"
    );
    let served = stored(waiting(), Vouching::Unvouched).delivered_wire();
    let text = served.to_string();
    assert!(!text.contains(PROMPT), "a stored prompt was served: {text}");
    assert!(
        !text.contains(KEY),
        "a stored request key was served: {text}"
    );
    assert_eq!(served["inputRequests"], json!({}), "{served}");
    assert_eq!(served["statusMessage"], json!(reason), "{served}");
    assert_eq!(served["status"], json!("input_required"), "{served}");
}

fn completed(text: &str) -> Task {
    let mut task = Task::create("gateway_invoke").expect("the clock reads after 1970");
    task.complete(&json!({"content": [{"type": "text", "text": text}], "isError": false}))
        .expect("a live task completes");
    task
}

fn failed(text: &str) -> Task {
    let mut task = Task::create("gateway_invoke").expect("the clock reads after 1970");
    task.fail(&JsonRpcError {
        code: -32001,
        message: text.to_owned(),
        data: None,
    })
    .expect("a live task fails");
    task
}

/// `backend_result` and `backend_error` return nothing for a row that
/// withholds its outcome, so no receipt is taken from it; the vouched twins
/// still return the peer's output.
#[test]
fn the_receipt_helpers_return_nothing_for_a_withheld_row() {
    for vouching in [Vouching::Vouched, Vouching::Unvouched] {
        let done = stored(completed(PROMPT), vouching);
        let mut peer_error = stored(failed(PROMPT), vouching);
        peer_error.error_author = Some(ErrorAuthor::Peer);
        let expected = vouching == Vouching::Vouched;
        assert_eq!(
            done.backend_result().is_some(),
            expected,
            "{vouching:?} result"
        );
        assert_eq!(
            peer_error.backend_error().is_some(),
            expected,
            "{vouching:?} error"
        );
    }
}

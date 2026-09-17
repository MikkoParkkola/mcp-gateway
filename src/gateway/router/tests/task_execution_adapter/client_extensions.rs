// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! E4 and E5 — the client half of conformance minor 1: a client's declared
//! protocol extensions must be **recovered by production code**, not merely
//! parseable in isolation.
//!
//! Written from `docs/design/2026-08-31-cluster-b-capability-and-trace-metadata-test-plan.md`
//! §EXT.1.c. That plan proposed both rows as exact deltas on the adoption
//! counter, serialised against each other, on the stated assumption that
//! "nothing else in the tree declares this extension with a valid settings
//! object". The assumption is false: `support.rs` declares it with `{}` on
//! every task-adapter request, so the counter is process-wide **and** moved by
//! every sibling test running concurrently. Exact deltas were red for that
//! reason and no other. The split below keeps both claims and drops the
//! arithmetic that could not hold:
//!
//! * **E4 is the wiring claim, and monotonic.** A `tools/call` through the real
//!   router must leave the counter strictly higher. Concurrency can only add,
//!   and the only writer of this series is the recovery under test — remove the
//!   call in `handlers.rs` and no test in the process can move it — so a strict
//!   increase is an oracle and an exact delta is a race.
//! * **E5 bounds the classifier, and is deterministic.** It drives the
//!   production classifier directly, with the params and header version the
//!   fixture sends, and reads the recovered set with no global in the path. An
//!   implementation answering from `declared_capabilities` — the name list at
//!   `meta.rs` — passes the control and fails this row, because that path
//!   filters only nulls and `3` is not null. The specification requires an
//!   object of settings; presence of the key is not agreement.
//!
//! What the pair does **not** bound, recorded because an independent review of
//! the closing commit raised it: a handler that counted extension keys itself
//! while the classifier stayed correct would pass both rows. E4 cannot separate
//! its own request's contribution from a concurrent sibling's, so it cannot
//! carry a negative, and E5 never reaches the handler. Closing that needs a
//! request-scoped observation seam; the process-wide counter cannot be made
//! into one. The single line in `handlers.rs` that feeds `client_extensions()`
//! to the counter is the unguarded link.
//!
//! The identifier must be a recognised one. `from_capabilities` filters through
//! `Extension::from_id`, so a synthetic identifier is discarded *by a correct
//! implementation* and a row asserting its recovery could never go green.

use super::support::*;
use crate::protocol::extensions::ExtensionSet;
use crate::protocol::meta::classify_request;
use crate::protocol_revision_telemetry::extension_adoption;
use serde_json::{Value, json};

/// Times `io.modelcontextprotocol/tasks` has been recovered so far.
fn tasks_recovered() -> u64 {
    extension_adoption()
        .get(TASKS_EXTENSION)
        .copied()
        .unwrap_or(0)
}

/// Replace the settings object under the tasks identifier with `settings`.
///
/// Written against the literal wire key rather than against
/// `ExtensionSet::to_extensions`, so the row states the shape it sends instead
/// of agreeing with the implementation it is measuring.
fn with_tasks_settings(mut body: Value, settings: &Value) -> Value {
    body["params"]["_meta"]["io.modelcontextprotocol/clientCapabilities"]["extensions"] =
        json!({ TASKS_EXTENSION: settings });
    body
}

/// What production recovers from `body`, through the classifier the router
/// runs and the protocol-version header the fixture sends.
fn recovered(body: &Value) -> ExtensionSet {
    classify_request(body.get("params"), Some("2026-07-28")).client_extensions()
}

#[tokio::test]
async fn ac_ext_1_d_a_declared_extension_is_recovered_on_the_tools_call_path() {
    let mock = MockBackend::answering(Answer::ok());
    let (state, _dir) = state_with(&mock).await;

    let before = tasks_recovered();
    let answer = post(
        &state,
        "key-a",
        keyed(sync_invoke(1, json!({ "value": "e4" })), "e4-key"),
    )
    .await;

    assert!(
        answer.get("error").is_none(),
        "the call must succeed, or the row measures a refusal instead of a recovery: {answer}"
    );
    assert!(
        tasks_recovered() > before,
        "a client declaring {TASKS_EXTENSION} with a settings object must have it recovered \
         on the production tools/call path"
    );
}

#[test]
fn ac_ext_1_e_a_non_object_settings_value_is_not_a_declaration() {
    let body = keyed(sync_invoke(1, json!({ "value": "e5" })), "e5-key");

    assert!(
        !recovered(&with_tasks_settings(body.clone(), &json!({}))).is_empty(),
        "control: an empty settings object is still a declaration, and without this the \
         discriminator below would pass against a classifier that recovers nothing at all"
    );
    assert!(
        recovered(&with_tasks_settings(body, &json!(3))).is_empty(),
        "settings that are not an object are not agreement, and a name-list implementation \
         that kept them would be indistinguishable from a correct one without this row"
    );
}

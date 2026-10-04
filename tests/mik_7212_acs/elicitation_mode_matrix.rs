// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

use mcp_gateway::protocol::meta::{Declared, classify_request};
use mcp_gateway::protocol::mrtr::{InputRequired, Refusal};
use serde_json::{Value, json};

/// A declaration carrying `elicitation` set to whatever the row says, or
/// carrying no `elicitation` key at all when the row is `None`.
fn declaring(elicitation: Option<Value>) -> Declared {
    let mut capabilities = serde_json::Map::new();
    if let Some(value) = elicitation {
        capabilities.insert("elicitation".to_string(), value);
    }
    let params = json!({
        "_meta": {
            "io.modelcontextprotocol/protocolVersion": "2026-07-28",
            "io.modelcontextprotocol/clientCapabilities": capabilities
        }
    });
    classify_request(Some(&params), Some("2026-07-28")).declared_capabilities()
}

/// One elicitation request asking in `mode`, or omitting the field when the
/// column is `None`.
fn asking(mode: Option<&str>) -> InputRequired {
    let mut params = serde_json::Map::new();
    params.insert("message".to_string(), json!("Which one?"));
    if let Some(mode) = mode {
        params.insert("mode".to_string(), json!(mode));
    }
    InputRequired::from_result(&json!({
        "resultType": "input_required",
        "inputRequests": { "only": { "method": "elicitation/create", "params": params } },
        "requestState": "backend-opaque"
    }))
    .expect("a well-formed interim result")
}

/// The four columns, in the table's order: `"form"`, `"url"`, absent,
/// `"telepathy"`.
const COLUMNS: [Option<&str>; 4] = [Some("form"), Some("url"), None, Some("telepathy")];

/// `true` where the table says `R`.
fn assert_row(label: &str, declaration: Option<Value>, relays: [bool; 4]) {
    let declared = declaring(declaration);
    // Whether the parse *accepted* a declaration of elicitation, which is
    // not the same as the row's JSON carrying the key: the non-object row
    // names it and declares nothing. That distinction decides which refusal
    // is the right one below, so the table needs no fifth column to say it.
    let names_elicitation = declared.has("elicitation");
    for (column, expected) in COLUMNS.iter().zip(relays) {
        let refusal = asking(*column)
            .undeclared(declared)
            .map(|entry| entry.reason);
        let requested = column.unwrap_or("an absent mode");
        assert_eq!(
            refusal.is_none(),
            expected,
            "row {label}, requested mode {requested}: the table says {}, the gate says {}",
            if expected { "relay" } else { "refuse" },
            if refusal.is_some() { "refuse" } else { "relay" },
        );
        // A refusal for the wrong reason passes a relay/refuse check. It
        // does not pass this one: a client that declared elicitation must
        // never be told the capability is missing, and one that did not
        // must never be answered about a mode it was never asked to name.
        match refusal {
            None => {}
            Some(Refusal::Capability(name)) => assert!(
                !names_elicitation,
                "row {label}, requested mode {requested}: refused as capability \
                 {name:?}, but this client declared elicitation"
            ),
            Some(other) => assert!(
                names_elicitation,
                "row {label}, requested mode {requested}: refused as {other:?}, but \
                 this client never declared elicitation and the capability arm owns it"
            ),
        }
    }
}

#[test]
fn ac_mrtr_9a_a_client_that_never_declared_elicitation_is_refused_every_mode() {
    assert_row("no elicitation key", None, [false, false, false, false]);
}

#[test]
fn ac_mrtr_9a_an_empty_declaration_is_the_form_mode() {
    // The specification's own way of declaring a capability with no
    // options, and elicitation's option-less shape is form.
    assert_row("{}", Some(json!({})), [true, false, true, false]);
}

#[test]
fn ac_mrtr_9a_a_form_only_client_is_refused_url() {
    assert_row(
        r#"{"form":{}}"#,
        Some(json!({ "form": {} })),
        [true, false, true, false],
    );
}

#[test]
fn ac_mrtr_9a_a_url_only_client_is_refused_form_and_an_absent_mode() {
    // The row both review legs raised. Without it, "refuse url unless
    // declared, leave form ungated" passes every other row and violates the
    // criterion for every url-only client. The absent column is the second
    // half: an omitted mode *is* form, so it is refused here too.
    assert_row(
        r#"{"url":{}}"#,
        Some(json!({ "url": {} })),
        [false, true, false, false],
    );
}

#[test]
fn ac_mrtr_9a_a_client_declaring_both_modes_is_relayed_both() {
    assert_row(
        r#"{"form":{},"url":{}}"#,
        Some(json!({ "form": {}, "url": {} })),
        [true, true, true, false],
    );
}

#[test]
fn ac_mrtr_9a_a_declaration_of_only_unrecognised_modes_declares_no_mode() {
    // The empty-object default belongs to a *syntactically* empty object and
    // is applied before unrecognised keys are dropped. Applied after, this
    // row would become form-capable — "absent stays absent", inverted.
    assert_row(
        r#"{"telepathy":{}}"#,
        Some(json!({ "telepathy": {} })),
        [false, false, false, false],
    );
}

#[test]
fn ac_mrtr_9a_a_non_object_elicitation_declares_nothing() {
    // A client declaring elicitation MUST support at least one mode. A
    // non-object value names none, so it declares nothing — where today's
    // flattening reads any non-null value as a declaration of the
    // capability. Four values, each run in full.
    for value in [json!(null), json!("form"), json!(7), json!([])] {
        assert_row(
            &format!("elicitation: {value}"),
            Some(value.clone()),
            [false, false, false, false],
        );
    }
}

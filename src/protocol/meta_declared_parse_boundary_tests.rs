// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
use super::{Declared, ElicitationMode, classify_request, declares_modern_era};
use serde_json::{Value, json};

fn declaring(capabilities: &Value) -> Declared {
    let params = json!({
        "_meta": {
            "io.modelcontextprotocol/protocolVersion": "2026-07-28",
            "io.modelcontextprotocol/clientCapabilities": capabilities
        }
    });
    classify_request(Some(&params), Some("2026-07-28")).declared_capabilities()
}

/// Case 3. A declaration of arbitrary size reduces to a fixed set of flags.
///
/// Three assertions, because no one of them suffices. The contents check
/// cannot observe a retained allocation; `size_of` catches an owning field
/// only through the width it happens to add, and a same-sized substitution
/// would slip past it; the `Copy` bound rejects an owning field by kind
/// rather than by width. The last two fail the *build*, which is the case a
/// contents assertion cannot reach.
#[test]
fn a_declaration_of_any_size_parses_to_a_fixed_heapless_value() {
    const fn assert_copy<T: Copy>() {}
    assert_copy::<Declared>();
    assert!(
        size_of::<Declared>() <= 8,
        "Declared must stay a handful of flags; a growth here is a caller-sized field \
         arriving by the back door"
    );

    let mut modes = serde_json::Map::new();
    let mut capabilities = serde_json::Map::new();
    for index in 0..10_000 {
        modes.insert(format!("mode_{index}"), json!({}));
        capabilities.insert(format!("capability_{index}"), json!({}));
    }
    modes.insert("form".to_string(), json!({}));
    capabilities.insert("elicitation".to_string(), Value::Object(modes));

    let declared = declaring(&Value::Object(capabilities));
    assert_eq!(
        declared,
        Declared {
            sampling: false,
            elicitation: true,
            roots: false,
            elicitation_form: true,
            elicitation_url: false,
        },
        "twenty thousand caller keys must reduce to the one recognised capability and the \
         one recognised mode, and to nothing else"
    );
}

/// Case 4. Only an object declares — on both levels.
#[test]
fn a_non_object_value_declares_neither_a_capability_nor_a_mode() {
    for value in [json!(null), json!("form"), json!(7), json!([])] {
        let declared = declaring(&json!({ "elicitation": value }));
        assert_eq!(
            declared,
            Declared::NONE,
            "elicitation set to {value} names no mode, so it declares nothing"
        );

        let declared = declaring(&json!({ "elicitation": { "form": value } }));
        assert!(
            !declared.has_elicitation_mode(ElicitationMode::Form),
            "a form key set to {value} is not a declaration of form mode"
        );
    }
}

/// Case 4, the other half: a *populated* object is still a declaration, so
/// the rule cannot be implemented as "empty objects only".
#[test]
fn a_populated_mode_object_still_declares_that_mode() {
    let declared = declaring(&json!({ "elicitation": { "form": { "maxLength": 40 } } }));
    assert!(declared.has_elicitation_mode(ElicitationMode::Form));
    assert!(!declared.has_elicitation_mode(ElicitationMode::Url));
}

/// Case 5. The request side takes strings, and only the two this gateway
/// services.
#[test]
fn an_unreadable_requested_mode_is_no_mode_at_all() {
    for value in [json!(7), json!([]), json!({}), json!("Form")] {
        assert_eq!(
            ElicitationMode::from_params(Some(&json!({ "mode": value }))),
            None,
            "mode {value} is not one this gateway can service, and must not be honoured as one"
        );
    }
}

/// Case 5, the boundary the plan pins deliberately: an explicit `null`
/// resolves through the same default as an omitted field. `Option` cannot
/// tell the two apart, the specification draws no distinction between them,
/// and so neither does the gateway.
#[test]
fn an_explicit_null_mode_resolves_the_same_way_as_an_absent_one() {
    let absent = ElicitationMode::from_params(Some(&json!({ "message": "Which one?" })));
    let null = ElicitationMode::from_params(Some(&json!({ "mode": Value::Null })));
    assert_eq!(absent, Some(ElicitationMode::Form));
    assert_eq!(null, absent, "an explicit null is not a fifth thing");
    assert_eq!(ElicitationMode::from_params(None), absent);
}

/// The row the fail-forward default exists for: a revision minted after
/// 2026 is still stateless, and a year-prefix test stops seeing it.
#[test]
fn a_2027_revision_declares_the_modern_era() {
    assert!(declares_modern_era("2027-03-01"));
}

/// The other side of the boundary: a pre-stateless revision negotiates a
/// session, and reading it as modern would delete that handshake.
#[test]
fn a_2025_revision_does_not() {
    assert!(!declares_modern_era("2025-11-25"));
}

/// The shape check earns its place here: plain text sorts above the
/// constant, and a bare comparison would wave it through.
#[test]
fn a_non_revision_string_does_not() {
    assert!(!declares_modern_era("2026"));
    assert!(!declares_modern_era("banana"));
}

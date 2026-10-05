// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
use super::classify_request;
use crate::protocol::extensions::Extension;
use serde_json::{Value, json};

/// The extensions a modern request declaring `capabilities` recovers.
fn declaring(capabilities: &Value) -> crate::protocol::extensions::ExtensionSet {
    let params = json!({
        "_meta": {
            "io.modelcontextprotocol/protocolVersion": "2026-07-28",
            "io.modelcontextprotocol/clientCapabilities": capabilities
        }
    });
    classify_request(Some(&params), Some("2026-07-28")).declared_extensions()
}

#[test]
fn ac_ext_1_e4_a_declared_extension_is_recovered_from_the_request() {
    // GIVEN a modern request declaring the tasks extension in the shape the
    // specification requires: an object of identifiers to settings objects.
    let declared = declaring(&json!({
        "extensions": { Extension::Tasks.id(): {} }
    }));

    // WHEN the envelope is classified
    // THEN the set the gateway acts on carries that extension. Without
    // this, a client that declared correctly is indistinguishable from one
    // that declared nothing.
    assert!(
        declared.contains(Extension::Tasks),
        "a validly declared extension must survive classification"
    );
}

#[test]
fn ac_ext_1_e5a_an_absent_extensions_key_recovers_nothing() {
    // GIVEN a modern request that declares capabilities but no extensions.
    let declared = declaring(&json!({ "elicitation": {} }));

    // THEN absence is absence: silence is not a declaration, and inventing
    // one here would hand task handles to a client that never asked.
    assert!(
        !declared.contains(Extension::Tasks),
        "an absent `extensions` key must not declare anything"
    );
}

#[test]
fn ac_ext_1_e5b_a_non_object_settings_value_declares_nothing() {
    // GIVEN the same identifier carrying a scalar instead of the settings
    // object the specification requires. This is the shape the pre-MIK-7272
    // gate accepted: presence is not agreement.
    for malformed in [json!(3), json!(null), json!("yes"), json!([]), json!(true)] {
        let declared = declaring(&json!({
            "extensions": { Extension::Tasks.id(): malformed }
        }));

        // THEN nothing is declared. A peer that cannot spell the
        // declaration has not negotiated the behaviour behind it.
        assert!(
            !declared.contains(Extension::Tasks),
            "a non-object settings value must not declare the extension, \
             but {malformed} did"
        );
    }
}

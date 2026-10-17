// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8382 unit rows A1-A3: the one key reader and the intake predicate.

use super::{
    IDEMPOTENCY_KEY_META, KeyField, RetryFields, idempotency_key_of, intake_requires_principal,
};
use serde_json::{Value, json};

fn keyed(key: &Value) -> Value {
    json!({ "_meta": { IDEMPOTENCY_KEY_META: key } })
}

#[test]
fn a1_key_field_reads_each_shape() {
    assert_eq!(idempotency_key_of(&json!({})), KeyField::Absent);
    assert_eq!(
        idempotency_key_of(&json!({ "_meta": {} })),
        KeyField::Absent
    );
    assert_eq!(
        idempotency_key_of(&keyed(&json!("k1"))),
        KeyField::Valid("k1")
    );
    // Whitespace is not empty: it is a key the client chose.
    assert_eq!(
        idempotency_key_of(&keyed(&json!("  "))),
        KeyField::Valid("  ")
    );
    for bad in [json!(""), json!(7), json!({ "k": 1 }), Value::Null] {
        assert_eq!(
            idempotency_key_of(&keyed(&bad)),
            KeyField::Malformed,
            "{bad}"
        );
    }
}

#[test]
fn a2_retry_fields_keeps_malformed_key() {
    for bad in [json!(""), json!(7)] {
        let fields = RetryFields::from_params(Some(&keyed(&bad)));
        assert!(fields.is_malformed(), "{bad}");
        assert_eq!(fields.idempotency_key, None, "{bad}");
    }
    let fields = RetryFields::from_params(Some(&keyed(&json!("k1"))));
    assert!(!fields.is_malformed());
    assert_eq!(fields.idempotency_key.as_deref(), Some("k1"));
}

#[test]
fn a3_intake_predicate_table() {
    let call = |params: Value| json!({ "jsonrpc": "2.0", "id": 5, "method": "tools/call", "params": params });
    let named = |key: Value| {
        let mut p = keyed(&key);
        p["name"] = json!("t");
        p
    };
    assert!(
        intake_requires_principal(&call(named(json!("k1")))),
        "valid key"
    );
    assert!(
        intake_requires_principal(&call(named(json!("")))),
        "malformed key"
    );
    assert!(
        !intake_requires_principal(&call(json!({ "name": "t" }))),
        "no key"
    );
    assert!(
        !intake_requires_principal(&call(json!({ "name": "t", IDEMPOTENCY_KEY_META: "k1" }))),
        "key in params, not _meta"
    );
    let mut no_id = call(named(json!("k1")));
    no_id
        .as_object_mut()
        .expect("a tools/call request is an object")
        .remove("id");
    assert!(!intake_requires_principal(&no_id), "no id member");
    // Presence, not validity: an unrecognised id shape still asks for an answer.
    for id in [
        Value::Null,
        json!(true),
        json!(1.5),
        json!({}),
        serde_json::from_str::<Value>("18446744073709551616")
            .expect("an integer above u64 parses as a JSON number"),
    ] {
        let mut r = call(named(json!("k1")));
        r["id"] = id.clone();
        assert!(intake_requires_principal(&r), "id {id}");
    }
    for method in [
        json!("notifications/x"),
        json!("tools/list"),
        json!("tasks/get"),
        json!(3),
    ] {
        let mut r = call(named(json!("k1")));
        r["method"] = method.clone();
        assert!(!intake_requires_principal(&r), "method {method}");
    }
    let mut no_method = call(named(json!("k1")));
    no_method
        .as_object_mut()
        .expect("a tools/call request is an object")
        .remove("method");
    assert!(!intake_requires_principal(&no_method), "missing method");
    for params in [json!([1]), json!("x"), Value::Null] {
        assert!(
            !intake_requires_principal(&call(params.clone())),
            "params {params}"
        );
    }
}

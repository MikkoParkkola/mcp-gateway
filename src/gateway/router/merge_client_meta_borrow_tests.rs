// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! No-copy contract for [`super::merge_client_meta_ref`].
//!
//! No-insertion results must be `Cow::Borrowed` aliasing `arguments`.
//! Insertion must still match [`super::merge_client_meta`] without mutating inputs.

use super::{merge_client_meta, merge_client_meta_ref};
use serde_json::{Value, json};
use std::borrow::Cow;

fn nested_payload() -> Value {
    json!({
        "query": "find",
        "payload": {
            "nested": {"deep": [1, {"k": null}], "keep": true},
            "flag": false
        }
    })
}

#[track_caller]
fn assert_borrowed_alias_eq_owned(arguments: &Value, params: Option<&Value>, is_meta_tool: bool) {
    let owned = merge_client_meta(arguments.clone(), params, is_meta_tool);
    let result = merge_client_meta_ref(arguments, params, is_meta_tool);
    assert!(
        matches!(result, Cow::Borrowed(_)),
        "expected Cow::Borrowed so the no-copy path is observable"
    );
    assert!(
        std::ptr::eq(&*result, arguments),
        "Cow::Borrowed must alias the original arguments Value"
    );
    assert_eq!(result.as_ref(), &owned);
}

#[test]
fn no_outer_meta_or_params_none_is_borrowed_ptr_eq_and_matches_owned() {
    let arguments = nested_payload();
    assert_borrowed_alias_eq_owned(&arguments, None, true);
    assert_borrowed_alias_eq_owned(&arguments, None, false);

    let params = json!({"name": "gateway_execute", "arguments": {"q": 1}});
    assert_borrowed_alias_eq_owned(&arguments, Some(&params), true);
    assert_eq!(arguments, nested_payload());
    assert_eq!(
        params,
        json!({"name": "gateway_execute", "arguments": {"q": 1}})
    );
}

#[test]
fn non_meta_tool_with_outer_meta_is_borrowed_and_does_not_inject() {
    let arguments = nested_payload();
    let params = json!({
        "name": "backend_search",
        "_meta": {"progressToken": "t", "extra": null}
    });
    assert_borrowed_alias_eq_owned(&arguments, Some(&params), false);
    assert!(arguments.get("_meta").is_none());
    assert_eq!(
        merge_client_meta(arguments.clone(), Some(&params), false),
        arguments
    );
}

#[test]
fn existing_arguments_meta_wins_byte_for_byte_even_null_or_nonobject() {
    let params = json!({"_meta": {"injected": true, "n": null}});
    let existing_metas = [
        json!(null),
        json!("raw"),
        json!([1, null]),
        json!(false),
        json!({"keep": true, "n": null}),
    ];
    for existing in existing_metas {
        let arguments = json!({
            "payload": {"nested": 1},
            "_meta": existing
        });
        let before_meta = arguments.get("_meta").cloned();
        assert_borrowed_alias_eq_owned(&arguments, Some(&params), true);
        assert_eq!(arguments.get("_meta"), before_meta.as_ref());
        assert_eq!(
            merge_client_meta(arguments.clone(), Some(&params), true).get("_meta"),
            before_meta.as_ref()
        );
    }
}

#[test]
fn nonobject_arguments_are_borrowed_and_unchanged_with_outer_meta() {
    let params = json!({"_meta": {"injected": true}});
    let cases = [
        Value::Null,
        json!([1, {"n": null}]),
        json!("args"),
        json!(true),
        json!(false),
    ];
    for arguments in cases {
        let before = arguments.clone();
        assert_borrowed_alias_eq_owned(&arguments, Some(&params), true);
        assert_eq!(arguments, before);
        assert_eq!(
            merge_client_meta(arguments.clone(), Some(&params), true),
            before
        );
    }
}

#[test]
fn insertion_required_matches_owned_merge_without_mutating_inputs() {
    let arguments = nested_payload();
    let params = json!({
        "name": "gateway_search_tools",
        "_meta": {"progressToken": "abc", "explicit_null": null}
    });
    let args_before = arguments.clone();
    let params_before = params.clone();
    let owned = merge_client_meta(arguments.clone(), Some(&params), true);
    let result = merge_client_meta_ref(&arguments, Some(&params), true);

    assert_eq!(result.as_ref(), &owned);
    assert_ne!(&owned, &args_before);
    assert_eq!(owned.get("_meta"), params.get("_meta"));
    assert_eq!(owned["query"], args_before["query"]);
    assert_eq!(owned["payload"], args_before["payload"]);
    assert_eq!(owned["payload"]["nested"]["deep"], json!([1, {"k": null}]));
    assert_eq!(owned["_meta"]["progressToken"], "abc");
    assert_eq!(owned["_meta"]["explicit_null"], Value::Null);
    assert_eq!(arguments, args_before);
    assert_eq!(params, params_before);
    assert!(arguments.get("_meta").is_none());

    let params_null = json!({"_meta": Value::Null});
    let params_null_before = params_null.clone();
    let owned_null = merge_client_meta(arguments.clone(), Some(&params_null), true);
    let result_null = merge_client_meta_ref(&arguments, Some(&params_null), true);
    assert_eq!(result_null.as_ref(), &owned_null);
    assert_eq!(owned_null.get("_meta"), Some(&Value::Null));
    assert_eq!(owned_null["payload"], args_before["payload"]);
    assert_eq!(arguments, args_before);
    assert_eq!(params_null, params_null_before);
}

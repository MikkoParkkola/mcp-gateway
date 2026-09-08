// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

use super::*;

fn failed_data(data: Option<Value>) -> Option<Value> {
    let response = match data {
        Some(data) => JsonRpcResponse::error_with_data(None, -32042, "backend refused", data),
        None => JsonRpcResponse::error(None, -32042, "backend refused"),
    };
    let DispatchSettlement::Fail(error) = classify_dispatch(response) else {
        panic!("a JSON-RPC error must remain a failed settlement");
    };
    assert_eq!(error.code, -32042);
    assert_eq!(error.message, "backend refused");
    error.data
}

#[test]
fn non_object_error_data_survives_settlement() {
    let mut mismatches = Vec::new();
    for data in [
        Value::Null,
        json!(true),
        json!(42),
        json!(1.25),
        json!("backend diagnostic"),
        json!(["detail", { "retry": false }]),
    ] {
        let actual = failed_data(Some(data.clone()));
        if actual.as_ref() != Some(&data) {
            mismatches.push(format!("{data}: got {actual:?}"));
        }
    }
    assert!(
        mismatches.is_empty(),
        "lost backend error data: {mismatches:?}"
    );
}

#[test]
fn only_top_level_internal_http_status_is_removed() {
    let mut expected = json!({ "detail": "quota", "nested": { "retry": false } });
    expected["nested"][HTTP_STATUS_DATA_KEY] = json!(429);
    assert_eq!(failed_data(Some(expected.clone())), Some(expected.clone()));
    let mut input = expected.clone();
    input[HTTP_STATUS_DATA_KEY] = json!(503);
    assert_eq!(failed_data(Some(input)), Some(expected));
}

#[test]
fn absent_or_empty_metadata_stays_absent() {
    let mut only_status = json!({});
    only_status[HTTP_STATUS_DATA_KEY] = json!(503);
    for data in [None, Some(json!({})), Some(only_status)] {
        assert_eq!(failed_data(data), None);
    }
}

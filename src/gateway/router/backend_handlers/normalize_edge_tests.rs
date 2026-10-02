// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! `normalize_tools_list_response` edges: an error reply, a result with no
//! usable list, and a list with nothing the gateway can judge.

use serde_json::json;

use super::super::normalize_tools_list_response;
use crate::protocol::{JsonRpcResponse, RequestId};

fn backend() -> crate::backend::Backend {
    crate::backend::Backend::new(
        "edge",
        crate::config::BackendConfig::default(),
        &crate::config::FailsafeConfig::default(),
        std::time::Duration::from_secs(60),
    )
}

#[test]
fn an_error_reply_forwards_no_list() {
    let mut response = JsonRpcResponse::error(Some(RequestId::Number(1)), -32603, "backend down");
    response.result = Some(json!({"tools": [{"name": "leak"}]}));

    normalize_tools_list_response(&backend(), &mut response);

    assert!(response.result.is_none(), "{response:?}");
    assert!(response.error.is_some());
}

#[test]
fn a_result_without_a_usable_list_is_left_as_the_backend_sent_it() {
    for result in [
        json!({"nextCursor": "c"}),
        json!({"tools": "not-an-array"}),
        json!({"tools": {"name": "x"}}),
    ] {
        let mut response = JsonRpcResponse::success(RequestId::Number(2), result.clone());
        normalize_tools_list_response(&backend(), &mut response);
        assert_eq!(response.result, Some(result));
    }
    let mut empty = JsonRpcResponse::success(RequestId::Number(3), json!({}));
    empty.result = None;
    normalize_tools_list_response(&backend(), &mut empty);
    assert!(empty.result.is_none());
}

#[test]
fn a_list_of_unjudgeable_entries_becomes_an_empty_list() {
    let mut response = JsonRpcResponse::success(
        RequestId::Number(4),
        json!({"tools": [{"description": "no name"}, 7], "nextCursor": "c"}),
    );

    normalize_tools_list_response(&backend(), &mut response);

    assert_eq!(response.result, Some(json!({"tools": []})));
}

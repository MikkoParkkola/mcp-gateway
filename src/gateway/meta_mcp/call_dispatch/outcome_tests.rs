// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8498 DISPATCH.2/3: `live_or_stored`, the one split of a sourced
//! invocation that both the named route and the `gateway_invoke` arm read.

use std::ops::ControlFlow;

use serde_json::json;

use super::invoke::SourcedOutcome;
use super::live_or_stored;
use crate::protocol::{ChainSource, JsonRpcResponse, RequestId};

#[test]
fn a_live_result_carries_its_chain_source() {
    let live = SourcedOutcome::Live((json!({"ok": 1}), ChainSource::Backend, None));
    let ControlFlow::Continue((result, (source, upstream))) = live_or_stored(Ok(live)) else {
        panic!("a live result goes on to be shaped");
    };
    assert_eq!(result.ok(), Some(json!({"ok": 1})));
    assert!(matches!(source, ChainSource::Backend));
    assert!(upstream.is_none());
}

#[test]
fn an_error_keeps_the_ineligible_chain() {
    let ControlFlow::Continue((result, (source, upstream))) =
        live_or_stored(Err(crate::Error::Config("refused".into())))
    else {
        panic!("an error goes on to be shaped");
    };
    assert!(result.is_err());
    assert!(matches!(source, ChainSource::NotEligible));
    assert!(upstream.is_none());
}

#[test]
fn a_stored_answer_is_returned_unchanged() {
    let stored = JsonRpcResponse::success(RequestId::Number(9), json!({"stored": true}));
    let ControlFlow::Break(answer) = live_or_stored(Ok(SourcedOutcome::Stored(stored))) else {
        panic!("a stored answer is delivered as it is");
    };
    assert_eq!(answer.id, Some(RequestId::Number(9)));
    assert_eq!(answer.result, Some(json!({"stored": true})));
}

// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Round partitioning through the production synchronous admission entry point.
use super::*;
use crate::backend::BackendRegistry;
use crate::protocol::mrtr::RetryFields;
use std::sync::Arc;

fn retry(key: &str, state: Option<&str>) -> RetryFields {
    RetryFields {
        idempotency_key: Some(key.into()),
        request_state: state.map(str::to_owned),
        ..RetryFields::default()
    }
}

fn call(meta: &MetaMcp, retry: &RetryFields, args: Value, id: i64) -> Result<SyncAdmission> {
    meta.admit_sync(
        true,
        None,
        Some("owner"),
        retry,
        "backend",
        "tool",
        &args,
        &json!({"wire":"modern"}),
        &RequestId::Number(id),
    )
}

fn owned(result: Result<SyncAdmission>) -> SyncLease {
    match result {
        Ok(SyncAdmission::Owned(lease)) => lease,
        Err(error) => panic!("round must acquire its own admission: {error}"),
        _ => panic!("round must acquire its own admission"),
    }
}

#[test]
fn continuation_original_client_key_admits_each_round_once() {
    let meta = MetaMcp::new(Arc::new(BackendRegistry::new()));
    let fresh = retry("original-key", None);
    let _initial = owned(call(&meta, &fresh, json!({"q":1}), 1));
    let round = retry("original-key", Some("opaque-round-one"));
    let first = owned(call(&meta, &round, json!({"q":1}), 2));
    let duplicate = call(&meta, &round, json!({"q":1}), 3);
    assert!(matches!(duplicate, Err(error) if error.to_rpc_code() == 409));
    first.mark_dispatched();
    first.complete_secured(&JsonRpcResponse::success(
        RequestId::Number(2),
        json!({"marker":"round-one"}),
    ));
    let replay = call(&meta, &round, json!({"q":1}), 4);
    match replay {
        Ok(SyncAdmission::Replay(response)) => {
            assert_eq!(response.id, Some(RequestId::Number(4)));
            assert_eq!(response.result, Some(json!({"marker":"round-one"})));
        }
        _ => panic!("same round must replay its secured result"),
    }
    let changed = call(&meta, &round, json!({"q":2}), 5);
    assert!(matches!(changed, Err(error) if error.to_rpc_code() == 409));
    let _second = owned(call(
        &meta,
        &retry("original-key", Some("opaque-round-two")),
        json!({"q":1}),
        6,
    ));
}

#[test]
fn continuation_answers_partition_even_when_state_is_unchanged() {
    let meta = MetaMcp::new(Arc::new(BackendRegistry::new()));
    let mut yes = retry("same-key", Some("opaque"));
    yes.input_responses = Some(json!({"answer":true}));
    let _yes = owned(call(&meta, &yes, json!({}), 1));
    let mut no = yes.clone();
    no.input_responses = Some(json!({"answer":false}));
    let _no = owned(call(&meta, &no, json!({}), 2));
    assert!(matches!(call(&meta, &yes, json!({}), 3), Err(error) if error.to_rpc_code() == 409));
}

#[test]
fn continuation_partition_cannot_alias_a_caller_supplied_key() {
    let meta = MetaMcp::new(Arc::new(BackendRegistry::new()));
    let round = retry("key", Some("opaque"));
    let _round = owned(call(&meta, &round, json!({}), 1));
    // A naive concatenation of client key and discriminator aliases this key.
    let forged = format!("key{}", round.key_discriminator());
    let _fresh = owned(call(&meta, &retry(&forged, None), json!({}), 2));
    // Even a caller encoding a tuple cannot enter the internal hash domain.
    let tuple = crate::hashing::canonical_json(&json!(["key", round.key_discriminator()]));
    let _tuple = owned(call(&meta, &retry(&tuple, None), json!({}), 3));
}

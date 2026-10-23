// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8747 / MIK-8748: a keyed replay across the protocol transition.

use super::*;

/// MIK-8747 / MIK-8748: the same owner's key reused across the protocol
/// transition is refused. A result stored for a modern call is never served
/// to a legacy one: the call already ran, so the refusal says so, and the
/// stored result is still served to its own era.
#[test]
fn sub4_a_key_reused_across_the_protocol_transition_is_refused() {
    let meta = MetaMcp::new(Arc::new(BackendRegistry::new()));
    let policy = MutablePolicy::new(FIRST);
    let retry = RetryFields {
        idempotency_key: Some("same-key".into()),
        ..RetryFields::default()
    };
    let mut caller = context(&policy, &retry);
    let args = json!({"server":FIRST.0, "tool":FIRST.1, "arguments":{"record":"original"}});
    retained_operation(&meta, &caller, "gateway_invoke", &args);
    caller.is_modern = false;
    let error = refusal(admit(&meta, &caller, "gateway_invoke", &args, 3));
    let Error::JsonRpc { code, data, .. } = &error else {
        panic!("a cross-era replay is the era refusal: {error}");
    };
    assert_eq!(*code, 409, "{error}");
    assert_eq!(
        data.as_ref()
            .map(|d| (&d["reason"], &d["already_executed"])),
        Some((&json!("idempotency_era_mismatch"), &json!(true))),
        "{error}"
    );
    caller.is_modern = true;
    assert_replay(admit(&meta, &caller, "gateway_invoke", &args, 4), 4);
}

/// E6: a keyed plan replay is refused across the protocol transition with
/// the same exact data: a plan's stored answer is shaped for its era too.
#[test]
fn e6_a_plan_key_reused_across_the_protocol_transition_is_refused() {
    let meta = MetaMcp::new(Arc::new(BackendRegistry::new()));
    install_plan(&meta, original_plan());
    let policy = MutablePolicy::new(SECOND);
    let retry = RetryFields {
        idempotency_key: Some("plan-key".into()),
        ..RetryFields::default()
    };
    let mut caller = context(&policy, &retry);
    let args = json!({"name":"protected-plan", "arguments":{"record":"original"}});
    retained_operation(&meta, &caller, "gateway_run_playbook", &args);
    caller.is_modern = false;
    let error = refusal(admit(&meta, &caller, "gateway_run_playbook", &args, 3));
    let Error::JsonRpc { code, data, .. } = &error else {
        panic!("E6: a cross-era plan replay is the era refusal: {error}");
    };
    assert_eq!(*code, 409, "{error}");
    assert_eq!(
        data.as_ref()
            .map(|d| (&d["reason"], &d["already_executed"])),
        Some((&json!("idempotency_era_mismatch"), &json!(true))),
        "E6: {error}"
    );
}

/// E5 (store level): Direct stores unshaped bytes and reshapes them for the
/// replaying era (MIK-8022), so its lease records no era and a cross-era
/// replay of a Direct key is served, never refused (MIK-8747 r3 scope).
#[test]
fn e5_a_direct_key_replays_across_eras() {
    let meta = MetaMcp::new(Arc::new(BackendRegistry::new()));
    let policy = MutablePolicy::new(FIRST);
    let retry = RetryFields {
        idempotency_key: Some("direct-key".into()),
        ..RetryFields::default()
    };
    let caller = context(&policy, &retry);
    let params = json!({"name": FIRST.1, "arguments": {"record": "original"}});
    let direct = |is_modern: bool, id: i64| {
        meta.direct_route_admission(
            crate::gateway::meta_mcp::AdmissionOwner::for_test(caller.owner_principal()),
            (caller.credential_principal, None, None),
            is_modern,
            None,
            &retry,
            (FIRST.0, FIRST.1, Some(&params)),
            &RequestId::Number(id),
        )
    };
    let Ok(SyncAdmission::Owned(owner)) = direct(true, 1) else {
        panic!("E5: the first Direct call owns the key");
    };
    owner.mark_dispatched();
    owner.complete_secured(&JsonRpcResponse::success(
        RequestId::Number(1),
        json!({"secret": SECRET}),
    ));
    assert_replay(direct(false, 2), 2);
}

/// E7: a stored delivery that names no era (Direct's, or one written before
/// the field) is compared with nothing; a named era refuses only the other.
#[test]
fn e7_a_record_without_an_era_is_compared_with_nothing() {
    let response = json!({"jsonrpc": "2.0", "id": null, "result": {"secret": SECRET}});
    let unnamed = serde_json::to_vec(&json!({"response": response})).unwrap();
    let bare = serde_json::to_vec(&response).unwrap();
    let modern = serde_json::to_vec(&json!({"response": response, "era": "modern"})).unwrap();
    for is_modern in [true, false] {
        assert!(
            refuse_another_era(&unnamed, is_modern).is_ok(),
            "E7 unnamed"
        );
        assert!(refuse_another_era(&bare, is_modern).is_ok(), "E7 bare");
    }
    assert!(refuse_another_era(&modern, true).is_ok(), "E7 same era");
    assert!(
        matches!(
            refuse_another_era(&modern, false),
            Err(Error::JsonRpc { code: 409, .. })
        ),
        "E7: a named era refuses the other"
    );
}

/// E9: the era is checked before the stored record is decoded for serving,
/// so a refusal restores none of the record's read or write scope
/// (`stored_response` restores both).
#[test]
fn e9_the_era_is_refused_before_the_record_is_restored() {
    let path =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/gateway/meta_mcp/admission.rs");
    let text = std::fs::read_to_string(&path).unwrap_or_default();
    let refused = text.find("refuse_another_era(&bytes, is_modern)?;");
    let restored = text.find("stored_response(&bytes).ok_or_else(");
    assert!(
        matches!((refused, restored), (Some(a), Some(b)) if a < b),
        "E9: the era refusal precedes stored_response in the replay arm ({refused:?}, {restored:?})"
    );
}

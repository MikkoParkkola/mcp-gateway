// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The already-admitted replay recognition, split from `slot_tests` for the
//! file-size ceiling.

use super::*;

/// Mutant: a caller with no routed owner is treated as having an
/// already-admitted task, or replay recognition is dropped for everyone.
#[test]
fn an_unattributable_caller_is_never_an_admitted_replay() {
    let admission = ExecutionAdmission::new(Arc::new(|| 1_000));
    let (arguments, retry) = (json!({ "id": 1 }), fresh());
    let alice = identity().stable_actor_id();
    // The same operation, held under the routed owner's key.
    let owned =
        super::super::task_admission_request(alice.clone(), KEY.to_owned(), TOOL, &arguments);
    let _held = admission.admit_task(owned.borrow());
    let request = |owner| TaskConfirmationRequest {
        id: RequestId::Number(7),
        tool_name: TOOL,
        arguments: &arguments,
        task: None,
        retry: &retry,
        verified_identity: None,
        principal: Some("bound".to_string()),
        quota: Some(crate::protocol::continuation::QuotaKey::for_test("bound")),
        owner,
        input_capabilities: Declared::NONE,
        is_modern: true,
        admission: &admission,
    };
    assert!(
        MetaMcp::already_admitted(&request(&alice), KEY),
        "control: the routed owner's operation is recognised"
    );
    assert!(!MetaMcp::already_admitted(&request(""), KEY));
    assert!(!MetaMcp::already_admitted(
        &request("credential:other"),
        KEY
    ));
}

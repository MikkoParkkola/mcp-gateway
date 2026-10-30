// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
use serde_json::{Value, json};

use super::{Declared, PROTOCOL_UNSCOPED, SCOPED, misplaced, undeclared_task};
use crate::protocol::reserved_members::{MEMBERS, Origin, strip_ingress};
use crate::protocol::{JsonRpcResponse, RequestId};

/// A result of `result_type` (absent when `None`) carrying all four scoped
/// members.
fn all_four(result_type: Option<&str>) -> Value {
    let mut result = json!({
        "content": [], "taskId": "t", "requestState": "s", "cacheScope": "private", "ttlMs": 5,
    });
    if let Some(value) = result_type {
        result["resultType"] = json!(value);
    }
    result
}

fn kept(method: &str, result: &Value, declared: Declared) -> Vec<&'static str> {
    let gone = misplaced(method, result, declared);
    SCOPED
        .iter()
        .map(|scope| scope.member)
        .filter(|member| !gone.contains(member))
        .collect()
}

/// Every allowed placement keeps exactly what the table allows there.
#[test]
fn allowed_placements_keep_their_members() {
    let interim = all_four(Some("input_required"));
    for method in ["tools/call", "resources/read", "prompts/get"] {
        assert_eq!(
            kept(method, &interim, Declared::Nothing),
            ["requestState"],
            "{method}"
        );
    }
    for final_shape in [Some("complete"), None] {
        let result = all_four(final_shape);
        for method in ["tools/list", "resources/read", "server/discover"] {
            assert_eq!(
                kept(method, &result, Declared::Nothing),
                ["cacheScope", "ttlMs"],
                "{method} {final_shape:?}"
            );
        }
    }
    let handle = all_four(Some("task"));
    assert_eq!(
        kept("tools/call", &handle, Declared::Tasks),
        ["ttlMs", "taskId"]
    );
    assert_eq!(
        kept("tasks/get", &all_four(Some("complete")), Declared::Nothing),
        ["ttlMs", "taskId"]
    );
}

/// Each member on a method or shape no row allows is misplaced.
#[test]
fn misplacements_are_named() {
    let complete = all_four(Some("complete"));
    assert_eq!(
        misplaced("tools/call", &complete, Declared::Tasks),
        ["requestState", "cacheScope", "ttlMs", "taskId"]
    );
    assert_eq!(
        misplaced("prompts/get", &complete, Declared::Nothing),
        ["requestState", "cacheScope", "ttlMs", "taskId"]
    );
    assert_eq!(
        misplaced(
            "resources/read",
            &all_four(Some("input_required")),
            Declared::Nothing
        ),
        ["cacheScope", "ttlMs", "taskId"]
    );
    // A task handle the send did not declare keeps no task member.
    assert_eq!(
        misplaced("tools/call", &all_four(Some("task")), Declared::Nothing),
        ["requestState", "cacheScope", "ttlMs", "taskId"]
    );
    // An error is not a cacheable answer, final or not.
    let mut error = all_four(Some("complete"));
    error["isError"] = json!(true);
    assert_eq!(
        misplaced("resources/read", &error, Declared::Nothing),
        ["requestState", "cacheScope", "ttlMs", "taskId"]
    );
    // A method no row lists loses all four.
    assert_eq!(
        misplaced("vendor/thing", &complete, Declared::Tasks),
        ["requestState", "cacheScope", "ttlMs", "taskId"]
    );
    // resultType itself is never misplaced.
    assert!(
        misplaced(
            "vendor/thing",
            &json!({"resultType": "complete"}),
            Declared::Nothing
        )
        .is_empty()
    );
}

/// An undeclared task handle is refused, naming the method; a declared one
/// and any other shape are not.
#[test]
fn only_an_undeclared_task_handle_is_refused() {
    let handle = json!({"resultType": "task", "taskId": "t"});
    let refusal = undeclared_task("tools/call", &handle, Declared::Nothing).expect("refused");
    assert!(refusal.contains("tools/call"), "{refusal}");
    assert!(undeclared_task("tools/call", &handle, Declared::Tasks).is_none());
    let complete = json!({"resultType": "complete"});
    assert!(undeclared_task("tools/call", &complete, Declared::Nothing).is_none());
}

/// A task envelope's slot loses all four whatever it claims to be.
#[test]
fn the_task_slot_loses_every_scoped_member() {
    for claim in [Some("complete"), Some("input_required"), Some("task"), None] {
        let mut response =
            JsonRpcResponse::success(RequestId::Number(1), json!({"result": all_four(claim)}));
        strip_ingress("b", "tasks/result", Declared::Tasks, &mut response);
        let slot = &response.result.expect("a result")["result"];
        for scope in SCOPED {
            assert!(slot.get(scope.member).is_none(), "{claim:?}: {slot}");
        }
        assert_eq!(slot.get("resultType").is_some(), claim.is_some(), "{slot}");
    }
}

/// SCOPE.3: the warn names backend, method and member, never the value.
#[test]
fn the_scope_warn_names_member_never_value() {
    let mut response = JsonRpcResponse::success(
        RequestId::Number(1),
        json!({"messages": [], "cacheScope": "planted-scope-value"}),
    );
    let ((), warnings) = crate::test_log_capture::capture_warnings(|| {
        strip_ingress(
            "hostile-backend",
            "prompts/get",
            Declared::Nothing,
            &mut response,
        );
    });
    for named in ["hostile-backend", "prompts/get", "cacheScope"] {
        assert!(warnings.contains(named), "{named}: {warnings}");
    }
    assert!(!warnings.contains("planted-scope-value"), "{warnings}");
}

/// Both directions: every protocol row of the member table is scoped or
/// deliberately unscoped, and every scoped or unscoped name has a row.
#[test]
fn the_scope_table_and_the_member_table_agree() {
    // `structuredContent` is the tool's own output, not a protocol directive.
    let mut protocol: Vec<&str> = MEMBERS
        .iter()
        .filter(|m| m.origin == Origin::BackendMayCarry && m.path.len() == 1)
        .map(|m| m.path[0])
        .filter(|name| *name != "structuredContent")
        .collect();
    let mut listed: Vec<&str> = SCOPED.iter().map(|scope| scope.member).collect();
    listed.extend(PROTOCOL_UNSCOPED);
    protocol.sort_unstable();
    listed.sort_unstable();
    assert_eq!(protocol, listed);
}

/// Every row cites the specification text that places it.
#[test]
fn every_row_cites_its_spec() {
    for scope in SCOPED {
        assert!(!scope.spec.trim().is_empty(), "{}", scope.member);
        assert!(!scope.allowed.is_empty(), "{}", scope.member);
    }
}

/// The cacheable methods are exactly the methods the scope table assessed.
#[test]
fn cacheable_methods_are_the_assessed_methods() {
    let mut assessed: Vec<&str> = crate::protocol::cacheable::assessed_methods()
        .iter()
        .map(|(method, _)| *method)
        .collect();
    let mut cacheable = super::CACHEABLE_METHODS.to_vec();
    assessed.sort_unstable();
    cacheable.sort_unstable();
    assert_eq!(assessed, cacheable);
}

// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Source-shape checks: the direct route ends in its dispatch and runs its stages in order.

use super::*;

/// The dispatch is the orchestrator's tail expression: its answer is returned
/// as it is, so nothing runs after it and nothing can refuse it. It is the
/// whole final statement (the one before it is complete, ending in `;` or `}`),
/// so a wrapper such as `match x { _ => dispatch(..).await }` does not qualify.
/// Threat model: this guards an accidental edit (a statement added after the
/// dispatch, a wrapper, an adapter), not an adversarial reformulation; review
/// and the stage mutants cover that.
fn dispatch_is_the_tail(body: &str) -> bool {
    let Some(at) = body.rfind("direct_dispatch::dispatch(") else {
        return false;
    };
    let before = body[..at].trim_end();
    let open = at + "direct_dispatch::dispatch".len();
    let mut depth = 0usize;
    let mut close = None;
    for (i, c) in body[open..].char_indices() {
        match c {
            '(' => depth += 1,
            ')' => {
                depth -= 1;
                if depth == 0 {
                    close = Some(open + i);
                    break;
                }
            }
            _ => {}
        }
    }
    // Only `.await` and the closing brace may follow the call's own
    // parenthesis, so an adapter such as `.map(..)` or `.then(..)` fails.
    let Some(close) = close else { return false };
    (before.ends_with(';') || before.ends_with('}')) && body[close + 1..].trim() == ".await\n}"
}

#[test]
fn t8_the_tail_check_rejects_a_wrapped_or_followed_dispatch() {
    let tail = "{\n    let a = 1;\n    direct_dispatch::dispatch(scope, x).await\n}";
    assert!(dispatch_is_the_tail(tail));
    let wrapped =
        "{\n    let a = 1;\n    match a { _ => direct_dispatch::dispatch(scope, x).await }\n}";
    assert!(!dispatch_is_the_tail(wrapped));
    let followed = "{\n    let r = direct_dispatch::dispatch(scope, x).await;\n    r\n}";
    assert!(!dispatch_is_the_tail(followed));
    let mapped = "{\n    let a = 1;\n    direct_dispatch::dispatch(scope, x).await.map(f)\n}";
    assert!(!dispatch_is_the_tail(mapped));
    let replaced =
        "{\n    let a = 1;\n    direct_dispatch::dispatch(scope, x).then(|_| ready(no)).await\n}";
    assert!(!dispatch_is_the_tail(replaced));
}

/// T8, order: the orchestrator calls every stage, in the order that carries
/// the refusal precedence (scope before lookup, attestation before the mint,
/// the notification arm between routing and preflight), and every stage is
/// defined in a scanned file. A stage dropped, reordered, or moved to an
/// unscanned file fails here, not only in review.
#[test]
fn t8_the_direct_route_calls_its_stages_in_order() {
    let body = fn_body(DIRECT_ROUTE[0], "backend_handler_inner");
    let mut from = 0;
    for stage in STAGES {
        let at = body[from..].find(stage).unwrap_or_else(|| {
            panic!("{stage} missing, or out of order, in backend_handler_inner")
        });
        from += at + stage.len();
    }
    assert!(
        dispatch_is_the_tail(body),
        "the terminal dispatch is not the orchestrator's tail expression"
    );
    let scanned = DIRECT_ROUTE.concat();
    for stage in STAGES {
        let name = stage.trim_end_matches('(');
        assert!(
            scanned.contains(&format!("fn {name}(")) || scanned.contains(&format!("fn {name}<")),
            "stage {name} is defined outside the scanned files"
        );
    }
}

/// `active_profile(` followed, across whitespace and newlines, by `.check`.
fn has_profile_check(body: &str) -> bool {
    body.match_indices("active_profile(").any(|(i, _)| {
        let rest = &body[i..];
        let close = rest.find(')').unwrap_or(0);
        rest[close + 1..].trim_start().starts_with(".check")
    })
}

/// T8, structure: no route calls a control primitive directly; each goes
/// through the one stage method. A control added inline on one route, or left
/// behind at its old site, fails here.
#[test]
fn t8_no_control_primitive_runs_outside_the_shared_stages() {
    let invoke = include_str!("../meta_mcp/invoke.rs");
    let policy = include_str!("../meta_mcp/invoke/policy.rs");
    let dispatch = include_str!("../meta_mcp/invoke/dispatch.rs");
    let guards = include_str!("direct_guards.rs");
    let sites = [
        ("invoke_tool_traced", fn_body(invoke, "invoke_tool_traced")),
        // `invoke_tool_traced`'s steps live in whole files of their own.
        (
            "pre_dispatch.rs",
            include_str!("../meta_mcp/invoke/pre_dispatch.rs"),
        ),
        (
            "post_dispatch.rs",
            include_str!("../meta_mcp/invoke/post_dispatch.rs"),
        ),
        (
            "legacy_bridge.rs",
            include_str!("../meta_mcp/invoke/legacy_bridge.rs"),
        ),
        (
            "check_invocation_policy",
            fn_body(policy, "check_invocation_policy"),
        ),
        (
            "accounted_dispatch",
            fn_body(dispatch, "accounted_dispatch"),
        ),
        // The direct route's stages live in whole files, so a primitive moved
        // into any of them is still scanned.
        ("backend_handlers.rs", DIRECT_ROUTE[0]),
        ("direct_caller.rs", DIRECT_ROUTE[1]),
        ("direct_preflight.rs", DIRECT_ROUTE[2]),
        ("direct_dispatch.rs", DIRECT_ROUTE[3]),
        ("direct_audit.rs", DIRECT_ROUTE[4]),
        ("direct_list.rs", DIRECT_ROUTE[5]),
        ("direct_guards.rs", guards),
    ];
    let mut found = Vec::new();
    for (site, body) in sites {
        for primitive in BANNED {
            if body.contains(primitive) {
                found.push(format!("{site}: {primitive}"));
            }
        }
        if has_profile_check(body) {
            found.push(format!("{site}: active_profile(..).check"));
        }
    }
    assert!(
        found.is_empty(),
        "control primitives outside the shared stages: {found:#?}"
    );
}

/// T3c, source half: the bridged round admits spend through the shared stage,
/// not the old inline call.
#[test]
fn t3c_the_bridged_round_admits_spend_through_the_shared_stage() {
    let invoke = include_str!("../meta_mcp/invoke/bridge_dispatch.rs");
    let at = invoke
        .find("impl crate::gateway::input_bridge::BackendInvoker for BridgeDispatcher")
        .expect("bridge dispatcher impl");
    let body = fn_body(&invoke[at..], "invoke");
    assert!(
        body.contains("admit_spend_for"),
        "bridged round skips admit_spend_for"
    );
    assert!(
        !body.contains(".admit_spend("),
        "bridged round still calls admit_spend"
    );
}

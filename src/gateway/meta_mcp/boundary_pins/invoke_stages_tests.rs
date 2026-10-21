// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8488 PR-B1: scanner proof rows for R1-R6, R8 and R10 over parsed fixtures.

use super::invoke_stages_allow::ExtraKind;
use super::invoke_stages_r6::check_r6;
use super::invoke_stages_rules::{
    check_r0, check_r1, check_r2, check_r3, check_r4, check_r5, check_r8, check_r10, find_function,
};

fn all_for(
    source: &str,
    func: &str,
    in_type: &str,
    extra: &[ExtraKind],
    allow: &[&str],
) -> Vec<String> {
    let file = syn::parse_str::<syn::File>(source).expect("the fixture parses");
    let mut out = check_r0("fixture.rs", func, Some(source), Some(&file));
    let found = find_function(&file, func).expect("the fixture names its stage");
    out.extend(check_r1(&found, in_type));
    out.extend(check_r2(&found, in_type));
    out.extend(check_r3(&found, in_type));
    out.extend(check_r4(&found, &file, in_type));
    out.extend(check_r5(&found, in_type, extra));
    out.extend(check_r6(&found, allow));
    out.extend(check_r8(&found));
    out.extend(check_r10(&found, in_type));
    out
}

fn expect_one(rule: &str, detail: &str, violations: &[String]) {
    assert_eq!(
        violations.len(),
        1,
        "{rule}: want one hit, got {violations:?}"
    );
    let hit = &violations[0];
    assert!(hit.contains(rule), "{rule}: missing tag in {hit}");
    assert!(hit.contains(detail), "{rule}: missing `{detail}` in {hit}");
}

/// R1 fires on a `..` rest pattern in the `In` destructure.
#[test]
fn r1_flags_a_rest_pattern() {
    let source = r"
        #[forbid(unused_variables)]
        fn intake(input: IntakeIn) {
            let IntakeIn { args, .. } = input;
        }
    ";
    expect_one(
        "R1:",
        "`..`",
        &all_for(source, "intake", "IntakeIn", &[], &[]),
    );
}

/// R1 fires when the `In` parameter is discarded as `_`.
#[test]
fn r1_flags_a_wild_param() {
    let source = r"
        #[forbid(unused_variables)]
        fn intake(_: IntakeIn) {
        }
    ";
    expect_one(
        "R1:",
        "`_`",
        &all_for(source, "intake", "IntakeIn", &[], &[]),
    );
}

/// R1 fires on field access through the undestructured input binding.
#[test]
fn r1_flags_field_access_on_input() {
    let source = r"
        #[forbid(unused_variables)]
        fn intake(input: IntakeIn) {
            let IntakeIn { args, session_id, caller } = input;
            let x = input.args;
        }
    ";
    expect_one(
        "R1:",
        "field access",
        &all_for(source, "intake", "IntakeIn", &[], &[]),
    );
}

/// R1 fires when the input binding is passed on after its destructure.
#[test]
fn r1_flags_input_passed_on() {
    let source = r"
        #[forbid(unused_variables)]
        fn intake(input: IntakeIn) {
            let IntakeIn { args, session_id, caller } = input;
            helper(input);
        }
    ";
    expect_one(
        "R1:",
        "passed on",
        &all_for(source, "intake", "IntakeIn", &[], &["helper"]),
    );
}

/// R1 fires on an `_`-led `In` parameter name, which never destructures.
#[test]
fn r1_flags_an_underscore_param() {
    let source = r"
        #[forbid(unused_variables)]
        fn intake(_input: IntakeIn) {
        }
    ";
    expect_one(
        "R1:",
        "_input",
        &all_for(source, "intake", "IntakeIn", &[], &[]),
    );
}

/// R1 fires on a `ref` `In` parameter, which borrows instead of moving.
#[test]
fn r1_flags_a_ref_param() {
    let source = r"
        #[forbid(unused_variables)]
        fn intake(ref input: IntakeIn) {
        }
    ";
    expect_one(
        "R1:",
        "never destructured",
        &all_for(source, "intake", "IntakeIn", &[], &[]),
    );
}

/// R2 fires on a `_` sub-pattern in the `In` destructure.
#[test]
fn r2_flags_a_wild_field() {
    let source = r"
        #[forbid(unused_variables)]
        fn intake(input: IntakeIn) {
            let IntakeIn { args: _, caller } = input;
        }
    ";
    expect_one(
        "R2:",
        "`_`",
        &all_for(source, "intake", "IntakeIn", &[], &[]),
    );
}

/// R2 fires on a second `_` shape, so either wild form is pinned alone.
#[test]
fn r2_flags_a_second_wild_field() {
    let source = r"
        #[forbid(unused_variables)]
        fn intake(input: IntakeIn) {
            let IntakeIn { args, session_id: _ } = input;
        }
    ";
    expect_one(
        "R2:",
        "`_`",
        &all_for(source, "intake", "IntakeIn", &[], &[]),
    );
}

/// R3 fires on a `_`-led binding in the `In` destructure.
#[test]
fn r3_flags_an_underscore_binding() {
    let source = r"
        #[forbid(unused_variables)]
        fn intake(input: IntakeIn) {
            let IntakeIn { args: _x, caller } = input;
        }
    ";
    expect_one(
        "R3:",
        "_x",
        &all_for(source, "intake", "IntakeIn", &[], &[]),
    );
}

/// R4 fires on a group destructure that skips a field.
#[test]
fn r4_flags_a_skipped_group_field() {
    let source = r"
        struct DirectivesIn { args: Args, session_id: Sid, caller: Caller, trace_id: Tid, step: Step }
        struct Step { server: S, tool: T }
        #[forbid(unused_variables)]
        fn directives(input: DirectivesIn) {
            let DirectivesIn { args, session_id, caller, trace_id, step } = input;
            let Step { server } = step;
        }
    ";
    expect_one(
        "R4:",
        "`tool`",
        &all_for(source, "directives", "DirectivesIn", &[], &[]),
    );
}

/// R4 fires when a `Step`-typed field keeps its name but not its destructure.
#[test]
fn r4_flags_a_group_typed_field_left_bound() {
    let source = r"
        struct IntakeIn { args: Args, route: Step }
        struct Step { server: S, tool: T }
        #[forbid(unused_variables)]
        fn intake(input: IntakeIn) {
            let IntakeIn { args, route } = input;
        }
    ";
    expect_one(
        "R4:",
        "`route`",
        &all_for(source, "intake", "IntakeIn", &[], &[]),
    );
}

/// R5 fires on a signature with an extra parameter.
#[test]
fn r5_flags_an_extra_parameter() {
    let source = r"
        #[forbid(unused_variables)]
        fn intake(input: IntakeIn, extra: u32) {
            let IntakeIn { args, session_id, caller } = input;
        }
    ";
    expect_one(
        "R5:",
        "unexpected",
        &all_for(source, "intake", "IntakeIn", &[], &[]),
    );
}

/// R6 fires on an undeclared `self` field.
#[test]
fn r6_flags_an_undeclared_self_field() {
    let source = r"
        #[forbid(unused_variables)]
        fn intake(&self, input: IntakeIn) {
            let IntakeIn { args, session_id, caller } = input;
            let a = self.secret_field;
        }
    ";
    expect_one(
        "R6:",
        "self.secret_field",
        &all_for(source, "intake", "IntakeIn", &[], &[]),
    );
}

/// R6 fires on an undeclared bare imported call.
#[test]
fn r6_flags_an_undeclared_bare_call() {
    let source = r"
        #[forbid(unused_variables)]
        fn intake(input: IntakeIn) {
            let IntakeIn { args, session_id, caller } = input;
            let a = mystery_call(args);
        }
    ";
    expect_one(
        "R6:",
        "mystery_call",
        &all_for(source, "intake", "IntakeIn", &[], &[]),
    );
}

/// R6 fires on an undeclared callback item.
#[test]
fn r6_flags_an_undeclared_callback() {
    let source = r"
        #[forbid(unused_variables)]
        fn intake(input: IntakeIn) {
            let IntakeIn { args, session_id, caller } = input;
            let a = args.map(mystery_callback);
        }
    ";
    expect_one(
        "R6:",
        "mystery_callback",
        &all_for(source, "intake", "IntakeIn", &[], &[]),
    );
}

/// R6 fires on an associated call on another stage's output type.
#[test]
fn r6_flags_an_associated_call_on_another_output() {
    let source = r"
        #[forbid(unused_variables)]
        fn intake(input: IntakeIn) {
            let IntakeIn { args, session_id, caller } = input;
            let a = Cacheable::helper();
        }
    ";
    expect_one(
        "R6:",
        "Cacheable::helper",
        &all_for(source, "intake", "IntakeIn", &[], &[]),
    );
}

/// R6 fires on a qualified `<T as Trait>::f` call.
#[test]
fn r6_flags_a_qualified_call() {
    let source = r"
        #[forbid(unused_variables)]
        fn intake(input: IntakeIn) {
            let IntakeIn { args, session_id, caller } = input;
            let a = <Helper as Trait>::run();
        }
    ";
    expect_one(
        "R6:",
        "<Helper as Trait>::run",
        &all_for(source, "intake", "IntakeIn", &[], &[]),
    );
}

/// R8 fires on a `self` alias bound as a value.
#[test]
fn r8_flags_a_self_alias() {
    let source = r"
        #[forbid(unused_variables)]
        fn intake(&self, input: IntakeIn) {
            let IntakeIn { args, session_id, caller } = input;
            let g = self;
        }
    ";
    expect_one(
        "R8:",
        "bare",
        &all_for(source, "intake", "IntakeIn", &[], &[]),
    );
}

/// R8 fires on `self` behind a reference and paren, not a plain receiver.
#[test]
fn r8_flags_a_parenthesized_self_receiver() {
    let source = r"
        #[forbid(unused_variables)]
        fn intake(&self, input: IntakeIn) {
            let IntakeIn { args, session_id, caller } = input;
            let x = (&self).secret();
        }
    ";
    expect_one(
        "R8:",
        "bare",
        &all_for(source, "intake", "IntakeIn", &[], &[]),
    );
}

/// R8 fires on `self` passed to an allowlisted call; the allowlist does not excuse it.
#[test]
fn r8_flags_self_passed_to_an_allowlisted_call() {
    let source = r"
        #[forbid(unused_variables)]
        fn intake(&self, input: IntakeIn) {
            let IntakeIn { args, session_id, caller } = input;
            let x = allowlisted(self);
        }
    ";
    expect_one(
        "R8:",
        "bare",
        &all_for(source, "intake", "IntakeIn", &[], &["allowlisted"]),
    );
}

/// R10 fires on a missing `forbid`.
#[test]
fn r10_flags_a_missing_forbid() {
    let source = r"
        fn intake(input: IntakeIn) {
            let IntakeIn { args, session_id, caller } = input;
        }
    ";
    expect_one(
        "R10:",
        "forbid",
        &all_for(source, "intake", "IntakeIn", &[], &[]),
    );
}

/// R10 fires on a discard of a field binding with the `forbid` present.
#[test]
fn r10_flags_a_discard_of_a_field_binding() {
    let source = r"
        #[forbid(unused_variables)]
        fn intake(input: IntakeIn) {
            let IntakeIn { args, session_id, caller } = input;
            let _ = args;
        }
    ";
    expect_one(
        "R10:",
        "discard",
        &all_for(source, "intake", "IntakeIn", &[], &[]),
    );
}

/// Method calls on locals never count as stage dependencies.
#[test]
fn clean_local_method_calls_are_silent() {
    let source = r"
        #[forbid(unused_variables)]
        fn intake(input: IntakeIn) {
            let IntakeIn { args, session_id, caller } = input;
            let error = 1;
            let reservation = 1;
            let code = error.to_rpc_code();
            let key = reservation.key();
        }
    ";
    let hits = all_for(source, "intake", "IntakeIn", &[], &[]);
    assert!(hits.is_empty(), "clean locals: {hits:?}");
}

/// A call through a local closure never counts as a dependency.
#[test]
fn clean_closure_calls_are_silent() {
    let source = r"
        #[forbid(unused_variables)]
        fn intake(input: IntakeIn) {
            let IntakeIn { args, session_id, caller } = input;
            let fills = || 0;
            let before = fills();
        }
    ";
    let hits = all_for(source, "intake", "IntakeIn", &[], &[]);
    assert!(hits.is_empty(), "clean closure: {hits:?}");
}

/// A `super::`-prefixed call matches its canonical allowlist entry.
#[test]
fn clean_canonical_paths_match() {
    let source = r"
        #[forbid(unused_variables)]
        fn intake(input: IntakeIn) {
            let IntakeIn { args, session_id, caller } = input;
            let a = super::super::support::step_scoped(args);
        }
    ";
    let hits = all_for(source, "intake", "IntakeIn", &[], &["support::step_scoped"]);
    assert!(hits.is_empty(), "canonical: {hits:?}");
}

/// Struct literals name no callee and stay silent.
#[test]
fn clean_struct_literals_are_silent() {
    let source = r"
        #[forbid(unused_variables)]
        fn intake(input: IntakeIn) {
            let IntakeIn { args, session_id, caller } = input;
            let out = Cacheable { field: 1 };
        }
    ";
    let hits = all_for(source, "intake", "IntakeIn", &[], &[]);
    assert!(hits.is_empty(), "struct literal: {hits:?}");
}

/// A closed-table row naming an absent function is R0, never a skip.
#[test]
fn closed_table_absent_function_is_r0() {
    let source = r"
        #[forbid(unused_variables)]
        fn intake(input: IntakeIn) {
            let IntakeIn { args, session_id, caller } = input;
        }
    ";
    let file = syn::parse_str::<syn::File>(source).expect("the fixture parses");
    let hits = check_r0("fixture.rs", "missing_fn", Some(source), Some(&file));
    expect_one("R0:", "missing_fn", &hits);
}

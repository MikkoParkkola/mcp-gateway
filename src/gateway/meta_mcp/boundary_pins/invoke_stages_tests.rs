// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8488 PR-B1: scanner proof rows for R1-R10 over parsed fixtures.

use super::invoke_stages_allow::ExtraKind;
use super::invoke_stages_r6::{check_r6, check_r9};
use super::invoke_stages_rules::{
    check_r0, check_r1, check_r2, check_r3, check_r4, check_r5, check_r7, check_r8, check_r10,
    find_function,
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
    out.extend(check_r4(&found, in_type));
    out.extend(check_r5(&found, in_type, extra));
    out.extend(check_r6(&found, allow, in_type));
    out.extend(check_r7(&found, &file));
    out.extend(check_r8(&found));
    out.extend(check_r9(&found, allow));
    out.extend(check_r10(&found, in_type));
    out
}

fn only(rule: &str, violations: &[String]) {
    let tag = format!("{rule}:");
    assert!(
        !violations.is_empty(),
        "{rule}: the fixture reported nothing"
    );
    for hit in violations {
        assert!(hit.contains(&tag), "{rule}: off-rule hit: {hit}");
    }
    for other in [
        "R0", "R1", "R2", "R3", "R4", "R5", "R6", "R7", "R8", "R9", "R10",
    ] {
        if other == rule {
            continue;
        }
        let ban = format!("{other}:");
        for hit in violations {
            assert!(!hit.contains(&ban), "{rule}: leaked {other}: {hit}");
        }
    }
}

/// R1 fires on a `..` rest pattern in the `In` destructure.
#[test]
fn r1_flags_a_rest_pattern() {
    let source = r#"
        #[forbid(unused_variables)]
        fn intake(input: IntakeIn) {
            let IntakeIn { args, .. } = input;
        }
    "#;
    only("R1", &all_for(source, "intake", "IntakeIn", &[], &[]));
}

/// R2 fires on `_` sub-patterns in the `In` destructure.
#[test]
fn r2_flags_wild_subpatterns() {
    let source = r#"
        #[forbid(unused_variables)]
        fn intake(input: IntakeIn) {
            let IntakeIn { args: _, caller } = input;
            let IntakeIn { args, session_id: _ } = input;
        }
    "#;
    only("R2", &all_for(source, "intake", "IntakeIn", &[], &[]));
}

/// R3 fires on a `_`-led binding in the `In` destructure.
#[test]
fn r3_flags_an_underscore_binding() {
    let source = r#"
        #[forbid(unused_variables)]
        fn intake(input: IntakeIn) {
            let IntakeIn { args: _x, caller } = input;
        }
    "#;
    only("R3", &all_for(source, "intake", "IntakeIn", &[], &[]));
}

/// R4 fires on a group destructure that skips a field.
#[test]
fn r4_flags_a_skipped_group_field() {
    let source = r#"
        #[forbid(unused_variables)]
        fn directives(input: DirectivesIn) {
            let DirectivesIn { args, session_id, caller, trace_id, step } = input;
            let Step { server } = step;
        }
    "#;
    only(
        "R4",
        &all_for(source, "directives", "DirectivesIn", &[], &[]),
    );
}

/// R5 fires on a signature with an extra parameter.
#[test]
fn r5_flags_an_extra_parameter() {
    let source = r#"
        #[forbid(unused_variables)]
        fn intake(input: IntakeIn, extra: u32) {
            let IntakeIn { args, session_id, caller } = input;
        }
    "#;
    only("R5", &all_for(source, "intake", "IntakeIn", &[], &[]));
}

/// R6 fires on undeclared `self`, bare-call and callback dependencies.
#[test]
fn r6_flags_undeclared_dependencies() {
    let source = r#"
        #[forbid(unused_variables)]
        fn intake(&self, input: IntakeIn) {
            let IntakeIn { args, session_id, caller } = input;
            let _a = self.secret_field;
            let _b = mystery_call(args);
            let _c = args.map(mystery_callback);
        }
    "#;
    only("R6", &all_for(source, "intake", "IntakeIn", &[], &[]));
}

/// R7 fires on silencing attributes on a `let` and in the file header.
#[test]
fn r7_flags_silencing_attributes() {
    let source = r#"
        #![allow(warnings)]
        #[forbid(unused_variables)]
        fn intake(input: IntakeIn) {
            let IntakeIn { args, session_id, caller } = input;
            #[allow(unused_variables)]
            let extra = 1;
        }
    "#;
    only("R7", &all_for(source, "intake", "IntakeIn", &[], &[]));
}

/// R8 fires on a `self` alias bound as a value.
#[test]
fn r8_flags_a_self_alias() {
    let source = r#"
        #[forbid(unused_variables)]
        fn intake(&self, input: IntakeIn) {
            let IntakeIn { args, session_id, caller } = input;
            let g = self;
        }
    "#;
    only("R8", &all_for(source, "intake", "IntakeIn", &[], &[]));
}

/// R9 fires on undeclared calls inside `warn!` and `json!` arguments.
#[test]
fn r9_flags_calls_inside_macros() {
    let source = r#"
        #[forbid(unused_variables)]
        fn intake(input: IntakeIn) {
            let IntakeIn { args, session_id, caller } = input;
            let X = 1;
            let a = 1;
            let b = 1;
            let x = 1;
            warn!(target: X, a, "m {}", helper(b));
            json!({"k": helper(x)});
        }
    "#;
    only("R9", &all_for(source, "intake", "IntakeIn", &[], &[]));
}

/// R10 fires on a missing `forbid` and a discard of an input binding.
#[test]
fn r10_flags_a_missing_forbid_and_a_discard() {
    let source = r#"
        fn intake(input: IntakeIn) {
            let IntakeIn { args, session_id, caller } = input;
            let _ = input;
        }
    "#;
    only("R10", &all_for(source, "intake", "IntakeIn", &[], &[]));
}

/// A conforming stage with allowlisted macro callees stays silent.
#[test]
fn clean_allowlisted_macros_are_silent() {
    let source = r#"
        #[forbid(unused_variables)]
        fn intake(input: IntakeIn) {
            let IntakeIn { args, session_id, caller } = input;
            let a = 1;
            let b = 1;
            let x = 1;
            warn!(target: "t", a, "m {}", helper(b));
            json!({"k": helper(x)});
        }
    "#;
    let hits = all_for(source, "intake", "IntakeIn", &[], &["helper"]);
    assert!(hits.is_empty(), "clean macros: {hits:?}");
}

/// Method calls on locals never count as stage dependencies.
#[test]
fn clean_local_method_calls_are_silent() {
    let source = r#"
        #[forbid(unused_variables)]
        fn intake(input: IntakeIn) {
            let IntakeIn { args, session_id, caller } = input;
            let error = 1;
            let reservation = 1;
            let code = error.to_rpc_code();
            let key = reservation.key();
        }
    "#;
    let hits = all_for(source, "intake", "IntakeIn", &[], &[]);
    assert!(hits.is_empty(), "clean locals: {hits:?}");
}

/// A call through a local closure never counts as a dependency.
#[test]
fn clean_closure_calls_are_silent() {
    let source = r#"
        #[forbid(unused_variables)]
        fn intake(input: IntakeIn) {
            let IntakeIn { args, session_id, caller } = input;
            let fills = || 0;
            let before = fills();
        }
    "#;
    let hits = all_for(source, "intake", "IntakeIn", &[], &[]);
    assert!(hits.is_empty(), "clean closure: {hits:?}");
}

/// A closed-table row naming an absent function is R0, never a skip.
#[test]
fn closed_table_absent_function_is_r0() {
    let source = r#"
        #[forbid(unused_variables)]
        fn intake(input: IntakeIn) {
            let IntakeIn { args, session_id, caller } = input;
        }
    "#;
    let file = syn::parse_str::<syn::File>(source).expect("the fixture parses");
    let hits = check_r0("fixture.rs", "missing_fn", Some(source), Some(&file));
    assert!(
        !hits.is_empty() && hits.iter().all(|hit| hit.contains("R0:")),
        "R0: {hits:?}"
    );
}

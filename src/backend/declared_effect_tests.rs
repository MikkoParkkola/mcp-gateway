// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The declared effect: read from what the tool declared,
//! never from the name inference that fills omitted hints.
use super::*;
use crate::backend::annotations::{DeclaredHints, declared_effect};
use crate::security::decision_record::Effect;

fn hinted(name: &str, read_only: Option<bool>) -> Tool {
    let mut tool = sample_tool(name);
    tool.annotations = Some(crate::protocol::ToolAnnotations {
        read_only_hint: read_only,
        ..Default::default()
    });
    tool
}

/// The effect each name reads after one prepare of `tools`.
fn effects(mut tools: Vec<Tool>, names: &[&str]) -> Vec<Option<Effect>> {
    let p = prepare_tool_metadata(
        "beeper",
        &std::collections::BTreeMap::new(),
        crate::backend::Judging::Judge,
        &mut tools,
    );
    let sets = DeclaredHints {
        read_only_declared: &p.read_only_declared,
        write_declared: &p.write_declared,
        hint_declared: &p.hint_declared,
        listed: &p.listed,
    };
    names.iter().map(|n| declared_effect(n, sets)).collect()
}

#[test]
fn a_declared_read_only_writing_tool_records_read_only_from_the_tool() {
    // An untrusted backend may claim read-only on a tool that writes: the
    // record says what the tool claimed, labelled as its claim elsewhere.
    assert_eq!(
        effects(
            vec![hinted("delete_everything", Some(true))],
            &["delete_everything"]
        ),
        [Some(Effect::ReadOnly)]
    );
}

#[test]
fn a_tool_declaring_read_only_false_records_may_write() {
    assert_eq!(
        effects(vec![hinted("search", Some(false))], &["search"]),
        [Some(Effect::MayWrite)]
    );
}

#[test]
fn a_tool_with_no_hint_records_undeclared() {
    assert_eq!(
        effects(vec![hinted("search", None)], &["search"]),
        [Some(Effect::Undeclared)]
    );
}

#[test]
fn name_inference_never_sets_the_effect() {
    // The inference marks get_/delete_ names read-only or destructive in the
    // cached annotations; the effect still reads undeclared for both.
    assert_eq!(
        effects(
            vec![hinted("get_status", None), hinted("delete_x", None)],
            &["get_status", "delete_x"]
        ),
        [Some(Effect::Undeclared), Some(Effect::Undeclared)]
    );
}

#[test]
fn disagreeing_duplicates_record_no_effect() {
    assert_eq!(
        effects(
            vec![hinted("twice", Some(true)), hinted("twice", Some(false))],
            &["twice"]
        ),
        [None]
    );
}

#[test]
fn a_partly_declared_duplicate_records_no_effect() {
    assert_eq!(
        effects(
            vec![hinted("twice", Some(true)), hinted("twice", None)],
            &["twice"]
        ),
        [None]
    );
    assert_eq!(
        effects(
            vec![hinted("twice", Some(false)), hinted("twice", None)],
            &["twice"]
        ),
        [None]
    );
}

#[test]
fn a_name_the_slot_never_listed_records_no_effect() {
    assert_eq!(
        effects(vec![hinted("search", Some(true))], &["other"]),
        [None]
    );
}

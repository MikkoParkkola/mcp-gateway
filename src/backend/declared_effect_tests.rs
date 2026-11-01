// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The declared effect: read from what the tool declared,
//! never from the name inference that fills omitted hints.
use super::*;
use crate::backend::annotations::{DeclaredHints, declared_effect};
use crate::security::decision_record::Effect;
use std::sync::Arc;
use std::time::Duration;

use serde_json::Value;

use crate::backend::Listing;

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

/// A slot that never listed its tools has no evidence, so the effect is
/// absent: never undeclared, which claims the tool was seen to omit it. (The
/// dispatch fills a cold slot before it reads the effect, so this is the
/// accessor's own answer, not a dispatched call's.)
#[test]
fn a_cold_slot_records_no_effect() {
    let backend = crate::backend::Backend::new(
        "cold",
        crate::config::BackendConfig::default(),
        &crate::config::FailsafeConfig::default(),
        std::time::Duration::from_secs(300),
    );
    assert_eq!(backend.declared_effect_for(None, "read"), None);
}

/// A tool as a page lists it, with `readOnlyHint` set only when `read_only`
/// is `Some`.
fn listed(name: &str, read_only: Option<bool>) -> Value {
    serde_json::to_value(hinted(name, read_only)).expect("tool")
}

/// A shared slot holding `tools` from one accepted fill, with `read_only`
/// admitted to the cache as that fill would have admitted them.
fn slot(tools: Vec<Tool>, read_only: &[&str]) -> Arc<Backend> {
    let backend = Arc::new(Backend::new(
        "beeper",
        crate::config::BackendConfig::default(),
        &crate::config::FailsafeConfig::default(),
        Duration::from_secs(300),
    ));
    backend.prefill_tools_for_test(tools);
    backend.set_read_only_declared_for_test(read_only);
    backend
}

fn effect_of(backend: &Backend, names: &[&str]) -> Vec<Option<Effect>> {
    names
        .iter()
        .map(|n| backend.declared_effect_for(None, n))
        .collect()
}

#[test]
fn revocation_lifecycle() {
    let backend = slot(
        vec![
            hinted("a", Some(true)),
            hinted("b", Some(false)),
            hinted("c", None),
        ],
        &["a"],
    );
    // Relisting the admitted `a` as a write revokes; `b` drops its hint.
    let page = [listed("a", Some(false)), listed("b", None)];
    let _ = backend.remember_listed_tools_as(None, false, &page, Listing::Truncated);
    assert_eq!(
        effect_of(&backend, &["a", "b", "c"]),
        [None, None, Some(Effect::Undeclared)]
    );
}

/// A page that trips no cache or resend revocation still withdraws the
/// may-write declaration it no longer makes.
#[test]
fn a_withdrawn_write_declaration_records_no_effect_without_a_revocation() {
    let backend = slot(vec![hinted("b", Some(false))], &[]);
    let _ = backend.remember_listed_tools_as(None, false, &[listed("b", None)], Listing::Truncated);
    assert_eq!(effect_of(&backend, &["b"]), [None]);
}

#[test]
fn abandoned_fill_lifecycle() {
    let backend = slot(
        vec![
            hinted("a", Some(true)),
            hinted("b", Some(false)),
            hinted("c", None),
            hinted("d", Some(true)),
            hinted("e", None),
        ],
        &["a", "d"],
    );
    // Observed: `a` as before, `b` without its hint, `c` now declaring one.
    // Never reached: `d` and `e`.
    let seen = vec![
        listed("a", Some(true)),
        listed("b", None),
        listed("c", Some(true)),
    ];
    let hook = backend.abandoned_fill_hook(
        backend.shared_entry(),
        Arc::new(parking_lot::Mutex::new(seen)),
    );
    hook();
    assert_eq!(
        effect_of(&backend, &["a", "b", "c", "d", "e"]),
        [
            Some(Effect::ReadOnly),
            None,
            None,
            Some(Effect::ReadOnly),
            Some(Effect::Undeclared)
        ]
    );
}

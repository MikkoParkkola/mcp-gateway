// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! `MIK-8113` at the POST route: two short fields a plan delivered side by
//! side, one from each of two steps, are text the caller received
//! contiguously, so a relay of them together is matched (`SEAM.2`); text the
//! engine wrote is never a step's, so it joins no seam (`SEAM.3`).
use super::super::*;
use super::support::*;
use pretty_assertions::assert_eq;

use crate::security::firewall::{CollusionAction, CollusionConfig, Firewall, FirewallConfig};

/// Step one's field and step two's, each under a k-gram (48 chars), so every
/// fingerprint across them spans the two steps; together they pass the
/// 63-char run that guarantees a shared fingerprint.
const FIELD_A: &str = "north slope rows seven to twelve, late pears";
const FIELD_B: &str = "south terrace rows one to six, early quinces";

/// Engine text longer than a k-gram: no window reaches across it.
const LONG_FALLBACK: &str =
    "No reading was available for this field, so the playbook used its default text.";

fn text(text: &str) -> Value {
    json!({"content": [{"type": "text", "text": text}], "isError": false})
}

/// The `block` relay detector over every `mock` tool, one shared fingerprint
/// enough to refuse, and `playbook` registered.
async fn seam_state(mock: &Arc<MockBackend>, playbook: &str) -> (Arc<AppState>, tempfile::TempDir) {
    let relay = Arc::new(Firewall::from_config(
        FirewallConfig {
            collusion: CollusionConfig {
                action: CollusionAction::Block,
                min_matches: 1,
                sources: vec![format!("{BACKEND}:*")],
                ..CollusionConfig::default()
            },
            ..FirewallConfig::default()
        },
        None,
    ));
    let definition: crate::playbook::PlaybookDefinition =
        serde_yaml::from_str(playbook).expect("playbook fixture must parse");
    let (state, store) = super::super::meta_fixture::test_router_app_state_with_meta_and_firewall(
        &two_principal_auth(),
        None,
        None,
        |mut meta| {
            meta.set_firewall(Some(relay));
            let mut engine = crate::playbook::PlaybookEngine::new();
            engine.register(definition);
            meta.set_playbook_engine(engine);
            meta
        },
    )
    .await;
    register(&state, BACKEND, mock);
    (state, store)
}

/// A playbook of two steps against `mock` whose output maps `properties`.
fn playbook(properties: &str) -> String {
    format!(
        "name: seam\ndescription: two steps\non_error: continue\ninputs: {{}}\nsteps:\n  \
         - name: s1\n    server: {BACKEND}\n    tool: {TOOL}\n  \
         - name: s2\n    server: {BACKEND}\n    tool: {TOOL}\n\
         output:\n  type: object\n  properties:\n{properties}"
    )
}

/// Run the `seam` playbook as `key-a` and return its `output`, parsed.
async fn run_seam(state: &Arc<AppState>, inputs: Value) -> Value {
    let read = post(
        state,
        "key-a",
        modern(
            1,
            "tools/call",
            json!({"name": "gateway_run_playbook", "arguments": {"name": "seam", "arguments": inputs}}),
            false,
        ),
    )
    .await;
    assert!(read.get("error").is_none(), "base: delivered: {read}");
    let block = read["result"]["content"][0]["text"]
        .as_str()
        .unwrap_or_default();
    let result: Value = serde_json::from_str(block).unwrap_or_else(|_| panic!("base: {read}"));
    result["output"].clone()
}

async fn refused(state: &Arc<AppState>, who: &str, id: i64, relayed: &str) -> bool {
    let reply = post(state, who, sync_invoke(id, json!({"text": relayed}))).await;
    reply["error"]["code"] == -32002
}

fn backend(answers: &[&str]) -> Arc<MockBackend> {
    let mut seq: Vec<Value> = answers.iter().map(|a| text(a)).collect();
    seq.extend(std::iter::repeat_with(|| text("ok")).take(6));
    MockBackend::answering(Answer::Sequence(seq))
}

/// `MIK-8113.SEAM.2`: two steps' short fields mapped to adjacent output
/// properties: bob relaying the pair is refused, alice is excused.
#[tokio::test]
async fn short_fields_of_two_steps_delivered_adjacent_keep_their_seam() {
    let mock = backend(&[FIELD_A, FIELD_B]);
    let (state, _store) = seam_state(
        &mock,
        &playbook(
            "    a:\n      path: $s1.content[0].text\n    b:\n      path: $s2.content[0].text\n",
        ),
    )
    .await;
    let output = run_seam(&state, json!({})).await;
    assert_eq!(
        output,
        json!({"a": FIELD_A, "b": FIELD_B}),
        "base: both fields delivered"
    );
    let pair = format!("{FIELD_A}{FIELD_B}");
    assert!(
        !refused(&state, "key-b", 2, FIELD_A).await && !refused(&state, "key-b", 3, FIELD_B).await,
        "premise: neither field alone is matched"
    );
    assert!(
        !refused(&state, "key-a", 4, &pair).await,
        "the holder is excused"
    );
    assert!(
        refused(&state, "key-b", 5, &pair).await,
        "the seam was not receipted"
    );
}

/// `MIK-8113.SEAM.3` (fallback): `b` is filled by its fallback, whose text
/// equals step two's own output, so equality alone would credit it to step
/// two. It is engine text: no seam with step one's field beside it.
#[tokio::test]
async fn a_fallback_beside_a_steps_field_joins_no_seam() {
    let mock = backend(&[FIELD_A, FIELD_B]);
    let props = format!(
        "    a:\n      path: $s1.content[0].text\n    b:\n      path: $s2.content[9].text\n      \
         fallback: \"{FIELD_B}\"\n    c:\n      path: $missing.x\n      fallback: \"{LONG_FALLBACK}\"\n    \
         d:\n      path: $s2.content[0].text\n"
    );
    let (state, _store) = seam_state(&mock, &playbook(&props)).await;
    let output = run_seam(&state, json!({})).await;
    assert_eq!(output["a"], FIELD_A, "base: {output}");
    assert_eq!(
        output["b"], FIELD_B,
        "base: the fallback filled b: {output}"
    );
    assert_eq!(
        output["d"], FIELD_B,
        "base: step two's field delivered: {output}"
    );
    let pair = format!("{FIELD_A}{FIELD_B}");
    assert!(
        !refused(&state, "key-b", 2, &pair).await,
        "a seam joined a step's field to a fallback"
    );
}

/// `MIK-8113.SEAM.3` (caller inputs): `b` echoes the caller's own input,
/// equal to step two's output. It is engine text: no seam beside it.
#[tokio::test]
async fn a_caller_input_beside_a_steps_field_joins_no_seam() {
    let mock = backend(&[FIELD_A, FIELD_B]);
    let props = format!(
        "    a:\n      path: $s1.content[0].text\n    b:\n      path: $inputs.note\n    \
         c:\n      path: $missing.x\n      fallback: \"{LONG_FALLBACK}\"\n    \
         d:\n      path: $s2.content[0].text\n"
    );
    let (state, _store) = seam_state(&mock, &playbook(&props)).await;
    let output = run_seam(&state, json!({"note": FIELD_B})).await;
    assert_eq!(output["b"], FIELD_B, "base: the input echoed: {output}");
    assert_eq!(
        output["d"], FIELD_B,
        "base: step two's field delivered: {output}"
    );
    let pair = format!("{FIELD_A}{FIELD_B}");
    assert!(
        !refused(&state, "key-b", 2, &pair).await,
        "a seam joined a step's field to the caller's input"
    );
}

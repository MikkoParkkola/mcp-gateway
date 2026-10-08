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
    seam_state_with(mock, playbook, &[], blocking(&[BACKEND])).await
}

/// `collusion` with the `block` action and one shared fingerprint enough to
/// refuse, over every tool of each of `servers`.
fn blocking(servers: &[&str]) -> CollusionConfig {
    CollusionConfig {
        action: CollusionAction::Block,
        min_matches: 1,
        sources: servers.iter().map(|s| format!("{s}:*")).collect(),
        ..CollusionConfig::default()
    }
}

/// [`seam_state`] with `collusion`, and `mock` also registered under each of
/// `more` servers, which both principals may reach.
async fn seam_state_with(
    mock: &Arc<MockBackend>,
    playbook: &str,
    more: &[&str],
    collusion: CollusionConfig,
) -> (Arc<AppState>, tempfile::TempDir) {
    let relay = Arc::new(Firewall::from_config(
        FirewallConfig {
            collusion,
            ..FirewallConfig::default()
        },
        None,
    ));
    let definition: crate::playbook::PlaybookDefinition =
        serde_yaml::from_str(playbook).expect("playbook fixture must parse");
    let mut auth = two_principal_auth();
    for key in &mut auth.api_keys {
        key.backends.extend(more.iter().map(ToString::to_string));
    }
    let (state, store) = super::super::meta_fixture::test_router_app_state_with_meta_and_firewall(
        &auth,
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
    for server in more {
        register(&state, server, mock);
    }
    (state, store)
}

/// A playbook of two steps against `mock` whose output maps `properties`.
fn playbook(properties: &str) -> String {
    playbook_on(&[BACKEND, BACKEND], properties)
}

/// A playbook of one step per server in `servers`, named `s1`, `s2`, ...
/// in order, whose output maps `properties`.
fn playbook_on(servers: &[&str], properties: &str) -> String {
    let steps = servers
        .iter()
        .enumerate()
        .map(|(i, server)| {
            format!(
                "  - name: s{}\n    server: {server}\n    tool: {TOOL}\n",
                i + 1
            )
        })
        .collect::<Vec<_>>()
        .concat();
    format!(
        "name: seam\ndescription: plan steps\non_error: continue\ninputs: {{}}\nsteps:\n\
         {steps}output:\n  type: object\n  properties:\n{properties}"
    )
}

/// One output property per step, `p1` from `s1` and so on, in step order.
fn each_step(steps: usize) -> String {
    (1..=steps)
        .map(|i| format!("    p{i}:\n      path: $s{i}.content[0].text\n"))
        .collect::<Vec<_>>()
        .concat()
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

/// Sixteen chars each: three or four of them fill one k-gram window.
const SHORT: [&str; 5] = [
    "amber gate seven",
    "brick lane north",
    "cedar dock three",
    "delta yard south",
    "elder mill eight",
];

/// `MIK-8113` R2: nine steps from nine sources deliver the same short field
/// side by side. Each seam fingerprint is held once for the delivery (its
/// composite), so it stays judged: bob relaying the run is refused. Held
/// once per step, nine holders would stop the detector judging it.
#[tokio::test]
async fn a_seam_across_nine_sources_stays_judged() {
    let servers = ["mock", "m2", "m3", "m4", "m5", "m6", "m7", "m8", "m9"];
    let mock = backend(&[SHORT[0]; 9]);
    let (state, _store) = seam_state_with(
        &mock,
        &playbook_on(&servers, &each_step(9)),
        &servers[1..],
        blocking(&servers),
    )
    .await;
    let output = run_seam(&state, json!({})).await;
    assert_eq!(output["p9"], SHORT[0], "base: all nine delivered: {output}");
    let run = [SHORT[0]; 5].join("\n");
    assert!(
        !refused(&state, "key-a", 2, &run).await,
        "the holder is excused"
    );
    assert!(
        refused(&state, "key-b", 3, &run).await,
        "a seam across nine sources was not judged"
    );
}

/// `MIK-8113` R4: a seam is sensitive when any step it joins is. Step one's
/// source is sensitive, step two's is not: bob relaying the pair is refused.
#[tokio::test]
async fn a_seam_beside_one_sensitive_step_is_sensitive() {
    let mock = backend(&[FIELD_A, FIELD_B]);
    let props =
        "    a:\n      path: $s1.content[0].text\n    b:\n      path: $s2.content[0].text\n";
    let (state, _store) = seam_state_with(
        &mock,
        &playbook_on(&[BACKEND, "plain"], props),
        &["plain"],
        blocking(&[BACKEND]),
    )
    .await;
    let output = run_seam(&state, json!({})).await;
    assert_eq!(output["b"], FIELD_B, "base: {output}");
    assert!(
        refused(&state, "key-b", 2, &format!("{FIELD_A}{FIELD_B}")).await,
        "a seam beside a sensitive step was not sensitive"
    );
}

/// A two-source seam (`mock` then `alt`) under `flows`: (source, egress)
/// globs. Bob relays the pair through `mock`'s tool; whether he is refused.
async fn seam_relay_refused(flows: &[(&str, &str)]) -> bool {
    let mock = backend(&[FIELD_A, FIELD_B]);
    let props =
        "    a:\n      path: $s1.content[0].text\n    b:\n      path: $s2.content[0].text\n";
    let mut collusion = blocking(&[BACKEND, "alt"]);
    collusion.allowed_flows = flows
        .iter()
        .map(|(source, egress)| crate::security::firewall::AllowedFlow {
            source: (*source).to_string(),
            egress: (*egress).to_string(),
        })
        .collect();
    let (state, _store) = seam_state_with(
        &mock,
        &playbook_on(&[BACKEND, "alt"], props),
        &["alt"],
        collusion,
    )
    .await;
    let output = run_seam(&state, json!({})).await;
    assert_eq!(output["b"], FIELD_B, "base: {output}");
    refused(&state, "key-b", 2, &format!("{FIELD_A}{FIELD_B}")).await
}

/// `MIK-8113` R7 (control): each source may leave through `mock` by its own
/// `allowed_flows` entry, so the seam may too.
#[tokio::test]
async fn a_seam_leaves_by_a_flow_every_step_allows() {
    assert!(
        !seam_relay_refused(&[("mock:*", "mock:*"), ("alt:*", "mock:*")]).await,
        "a flow every contributing source allows was refused"
    );
}

/// `MIK-8113` R7: only step one's source may leave through `mock`, so the
/// seam, which holds step two's text too, may not.
#[tokio::test]
async fn a_seam_does_not_leave_by_a_flow_one_step_lacks() {
    assert!(
        seam_relay_refused(&[("mock:*", "mock:*")]).await,
        "a seam left by a flow one contributing source lacks"
    );
}

/// `MIK-8113` R5: padding whitespace and decomposed Hangul are normalized
/// before any k-gram is read, so the seam is still matched.
#[tokio::test]
async fn a_seam_of_padded_and_decomposed_fields_is_matched() {
    let hangul = "남쪽 계단식 밭 일번부터 육번 줄까지 이른 모과 수확";
    let decomposed: String = icu_normalizer::DecomposingNormalizerBorrowed::new_nfd()
        .normalize(hangul)
        .into_owned();
    assert_ne!(decomposed, hangul, "premise: the field is decomposed");
    let padded = format!("  {FIELD_A}   ");
    let mock = backend(&[padded.as_str(), decomposed.as_str()]);
    let (state, _store) = seam_state(
        &mock,
        &playbook(
            "    a:\n      path: $s1.content[0].text\n    b:\n      path: $s2.content[0].text\n",
        ),
    )
    .await;
    let output = run_seam(&state, json!({})).await;
    assert_eq!(output["b"], decomposed.as_str(), "base: {output}");
    assert!(
        refused(&state, "key-b", 2, &format!("{FIELD_A}\n{hangul}")).await,
        "a seam of normalized text was not matched"
    );
}

/// `MIK-8113` R6: five sixteen-char fields from five steps. A k-gram spans
/// three or four of them, so a run of four fields from the middle is
/// matched, not only a pair beside one boundary.
#[tokio::test]
async fn a_seam_across_more_than_two_short_fields_is_matched() {
    let mock = backend(&SHORT);
    let (state, _store) = seam_state(&mock, &playbook_on(&[BACKEND; 5], &each_step(5))).await;
    let output = run_seam(&state, json!({})).await;
    assert_eq!(output["p5"], SHORT[4], "base: {output}");
    assert!(
        refused(&state, "key-b", 2, &SHORT[1..].join("\n")).await,
        "a seam over four steps' fields was not matched"
    );
}

/// `MIK-8113` R8: a short fallback between two steps' fields is text the
/// caller received in between; the fields still form a seam around it.
#[tokio::test]
async fn a_short_template_between_two_fields_keeps_their_seam() {
    let mock = backend(&[FIELD_A, FIELD_B]);
    let props = "    a:\n      path: $s1.content[0].text\n    b:\n      path: $missing.x\n      \
                 fallback: \", \"\n    c:\n      path: $s2.content[0].text\n";
    let (state, _store) = seam_state(&mock, &playbook(props)).await;
    let output = run_seam(&state, json!({})).await;
    assert_eq!(output["b"], ", ", "base: the fallback filled b: {output}");
    assert!(
        refused(&state, "key-b", 2, &format!("{FIELD_A}\n, \n{FIELD_B}")).await,
        "a short template broke the seam"
    );
}

/// `MIK-8113` R9: step one's field delivered twice stays step one's, so the
/// seam between step two's field and its second copy is matched.
#[tokio::test]
async fn a_duplicated_field_still_forms_a_seam() {
    let mock = backend(&[FIELD_A, FIELD_B]);
    let props = "    a:\n      path: $s1.content[0].text\n    b:\n      path: $s2.content[0].text\n    \
                 c:\n      path: $s1.content[0].text\n";
    let (state, _store) = seam_state(&mock, &playbook(props)).await;
    let output = run_seam(&state, json!({})).await;
    assert_eq!(output["c"], FIELD_A, "base: {output}");
    assert!(
        refused(&state, "key-b", 2, &format!("{FIELD_B}{FIELD_A}")).await,
        "a duplicated field broke the seam"
    );
}

/// `MIK-8113` (cap order): step one delivers a short field between two large
/// ones, more than one receipt's recording cap together. Which leaves the
/// step produced is read before that cap cuts its middle, so the short
/// field beside step two's still forms a seam.
#[tokio::test]
async fn a_short_field_between_large_ones_keeps_its_seam() {
    let large = |tag: &str| {
        (0..700)
            .map(|i| format!("{tag}{i:04} "))
            .collect::<Vec<_>>()
            .concat()
    };
    let (head, tail) = (large("h"), large("t"));
    let blocks = json!({"content": [
        {"type": "text", "text": head},
        {"type": "text", "text": FIELD_A},
        {"type": "text", "text": tail},
    ], "isError": false});
    let mut seq = vec![blocks, text(FIELD_B)];
    seq.extend(std::iter::repeat_with(|| text("ok")).take(6));
    let mock = MockBackend::answering(Answer::Sequence(seq));
    let props = "    a:\n      path: $s1.content[0].text\n    b:\n      path: $s1.content[1].text\n    \
                 c:\n      path: $s2.content[0].text\n    d:\n      path: $s1.content[2].text\n";
    let (state, _store) = seam_state(&mock, &playbook(props)).await;
    let output = run_seam(&state, json!({})).await;
    assert_eq!(output["c"], FIELD_B, "base: {output}");
    assert!(
        refused(&state, "key-b", 2, &format!("{FIELD_A}{FIELD_B}")).await,
        "a capped step lost the seam beside its short field"
    );
}

/// `MIK-8113` (ownership): step one's field carries a credential the
/// router's response pass redacts, so the field delivered is no longer step
/// one's text. It joins no seam: bob relaying it beside step two's field,
/// as delivered, is not refused.
#[tokio::test]
async fn a_redacted_field_is_no_steps_text() {
    let canary = concat!("ghp", "_abcdefghijklmnopqrstuvwxyz1234567890");
    let field = format!("north slope {canary}");
    let mock = backend(&[&field, FIELD_B]);
    let router = Arc::new(Firewall::from_config(
        FirewallConfig {
            enabled: true,
            scan_responses: true,
            scan_requests: false,
            credential_redaction: true,
            rules: vec![crate::security::firewall::FirewallRule {
                tool_match: "*".to_string(),
                action: crate::security::firewall::FirewallAction::Allow,
                reason: None,
                scan: Vec::new(),
            }],
            ..FirewallConfig::default()
        },
        None,
    ));
    let relay = Arc::new(Firewall::from_config(
        FirewallConfig {
            collusion: blocking(&[BACKEND]),
            ..FirewallConfig::default()
        },
        None,
    ));
    let definition: crate::playbook::PlaybookDefinition = serde_yaml::from_str(&playbook(
        "    a:\n      path: $s1.content[0].text\n    b:\n      path: $s2.content[0].text\n",
    ))
    .expect("playbook fixture must parse");
    let (state, _store) = super::super::meta_fixture::test_router_app_state_with_meta_and_firewall(
        &two_principal_auth(),
        None,
        Some(router),
        |mut meta| {
            meta.set_firewall(Some(relay));
            let mut engine = crate::playbook::PlaybookEngine::new();
            engine.register(definition);
            meta.set_playbook_engine(engine);
            meta
        },
    )
    .await;
    register(&state, BACKEND, &mock);
    let output = run_seam(&state, json!({})).await;
    let delivered = output["a"].as_str().unwrap_or_default().to_owned();
    assert!(
        !delivered.contains(canary) && !delivered.is_empty(),
        "premise: the field was redacted: {output}"
    );
    assert!(
        !refused(&state, "key-b", 2, &format!("{delivered}{FIELD_B}")).await,
        "a redacted field was credited to its step"
    );
}

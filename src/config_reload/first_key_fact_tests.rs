// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The rest of the question's table, the writer's audited trace of a held
//! write, and the classes of the waiting fact beyond the first rows: each
//! reload that reads the file sets or clears it by its own verdict alone.

use std::sync::Arc;
use std::sync::atomic::Ordering;

use super::{
    BEARER, FIRST, FaultCause, Gw, RefusalCode, Waiting, ask, first_key_with, replace, starter,
};
use crate::config_reload::reload_context::replace::{
    Audit, Intent, IntentId, IntentKind, IntentSink, RefusalClass, ReplaceError, ReplaceReload,
    StatusChange, replace_audited,
};

/// A start refusal the running starter does not have.
const START_FAULT: &str = "server:\n  replicas: 2\n  modern_protocol: true\n";
/// A posture setting: a reload refuses it before the question is asked.
const POSTURE_CHANGE: &str = "security:\n  hardened:\n    private_backends: [\"elsewhere\"]\n";

/// W8, the sixth class: a key colliding with the running bearer AND a
/// distinct start fault is faulty with the collision's text, because the key
/// table is checked first; and the question never builds a generation, so the
/// test-only refusal hook armed beside it is left unconsumed.
#[test]
fn w8_a_collision_and_a_start_fault_report_the_collision() {
    let gw = Gw::start(&starter(&[]));
    let candidate = format!(
        "{START_FAULT}{}",
        starter(&[("clash", BEARER)]).replacen(
            &format!("bearer_token: \"{BEARER}\""),
            "bearer_token: \"first-key-tests-another-bearer-0123456789\"",
            1,
        )
    );
    let hook = crate::config_reload::generation::refuse_hook::arm(
        "first-key-tests: a generation was built",
    );
    let answer = ask(&gw, &candidate);
    assert!(
        !hook.load(Ordering::SeqCst),
        "the question built a generation"
    );
    match answer {
        Waiting::Faulty { reason, cause } => {
            assert_eq!(cause, FaultCause::KeyTable);
            assert!(reason.contains("auth.api_keys"), "{reason}");
            assert!(!reason.contains("replicas"), "{reason}");
            assert!(!super::says_status_change(&reason), "{reason}");
        }
        other => panic!("expected Faulty, got {other:?}"),
    }
}

/// Takes every intent; only the trace is read.
struct Taking;

impl IntentSink for Taking {
    fn append(&mut self, _: &Intent) -> Result<IntentId, String> {
        Ok(IntentId("first-key-tests".to_owned()))
    }
}

/// The first key, written held through the audited entry point, and the
/// writer's own trace of it.
async fn audited_hold(gw: &Gw) -> (Result<ReplaceReload, ReplaceError>, Vec<&'static str>) {
    let target = crate::identity_grants::journal::resolved(&gw.path);
    drop(crate::config_reload::reload_context::replace::order::take(
        &target,
    ));
    let audit = Audit::Required {
        sink: Box::new(Taking),
        kind: IntentKind::Save { fields: Vec::new() },
        writer: None,
    };
    let answer = replace_audited(
        Arc::clone(&gw.ctx),
        replace(&starter(&[("first", FIRST)]), StatusChange::HoldForRestart),
        audit,
        crate::config_reload::history::Source::Ui { who: String::new() },
        super::WAIT,
    )
    .await
    .map(|outcome| outcome.reload);
    let trace = crate::config_reload::reload_context::replace::order::take(&target);
    (answer, trace)
}

/// W1's trace: the intent, then the write; the refused reload keeps the
/// bytes (no roll-back) and holds the key.
#[tokio::test]
async fn w1_the_held_write_traces_intent_then_write_and_keeps_the_bytes() {
    let gw = Gw::start(&starter(&[]));
    let (answer, trace) = audited_hold(&gw).await;
    assert!(
        matches!(answer, Ok(ReplaceReload::HeldForRestart { .. })),
        "{answer:?}"
    );
    assert_eq!(trace, ["traced", "intent", "commit"]);
    assert_eq!(gw.file(), starter(&[("first", FIRST)]));
}

/// W5's trace: the same order, then the roll-back to the old bytes.
#[tokio::test]
async fn w5_a_rolled_back_hold_traces_intent_then_write_and_restores() {
    let gw = Gw::start_refusing_reloads(&starter(&[]));
    let (answer, trace) = audited_hold(&gw).await;
    assert!(
        matches!(answer, Err(ReplaceError::ReloadRefused { .. })),
        "{answer:?}"
    );
    // The writer's trace names the roll-back step since the line added it,
    // and the traced writer's own first step since every write runs it.
    assert_eq!(trace, ["traced", "intent", "commit", "rollback"]);
    assert_eq!(gw.file(), starter(&[]));
}

/// W5, the posture class: the reload after a held write refuses with kind
/// `Posture` (its load sees a public URL the running listener would serve
/// in cleartext; the writer's own check before the write saw the file as
/// it is). Rolled back: the old bytes, no journal, the posture class, no
/// fact.
#[tokio::test]
async fn w5_a_held_write_refused_as_posture_rolls_back() {
    fn exposed(
        path: &std::path::Path,
        live: &Arc<crate::config_reload::LiveConfig>,
        env: &crate::config::LiveEnv,
    ) -> Result<crate::config_reload::reload_context::EvaluatedReload, String> {
        let mut evaluated = crate::config_reload::load_config_patch(path, live, env)?;
        evaluated.config.server.public_url = Some("https://first-key.example.test".to_owned());
        Ok(evaluated)
    }
    let gw = Gw::start_with(&starter(&[]), Some(exposed));
    let before = gw.file();
    let error = gw
        .write(&starter(&[("first", FIRST)]), StatusChange::HoldForRestart)
        .await
        .expect_err("rolled back");
    match error {
        ReplaceError::ReloadRefused { class, reason } => {
            assert_eq!(class, RefusalClass::Posture);
            assert!(reason.contains("refusing to serve HTTP"), "{reason}");
        }
        other => panic!("expected ReloadRefused, got {other:?}"),
    }
    assert!(gw.wrote(), "premise: the write happened before the refusal");
    assert_eq!(gw.file(), before);
    assert!(!gw.journal_left());
    assert_eq!(gw.live.waiting_keys(), None);
}

/// A gateway on the starter with the first key held for a restart.
async fn held() -> Gw {
    let gw = Gw::start(&starter(&[]));
    gw.write(&starter(&[("first", FIRST)]), StatusChange::HoldForRestart)
        .await
        .expect("held");
    assert_eq!(
        gw.live.waiting_keys(),
        Some(vec!["first".to_owned()]),
        "premise: the key waits"
    );
    gw
}

/// The fact and the restart-pending entry it adds are both gone.
fn nothing_waits(gw: &Gw) {
    assert_eq!(gw.live.waiting_keys(), None);
    assert!(
        !gw.live.pending_restart().contains(&"auth.api_keys"),
        "{:?}",
        gw.live.pending_restart()
    );
}

/// The fact names `keys` and a start from the file would be refused for
/// `fault` (a word of the start check's sentence).
fn waits_unstartable(gw: &Gw, keys: &[&str], fault: &str) {
    let wait = gw.live.first_key_wait().expect("the fact is kept");
    assert_eq!(wait.keys, keys);
    let refusal = wait.start_refusal.expect("a start would be refused");
    assert!(refusal.contains(fault), "{refusal}");
}

/// L2, the start-refusal class: after a clean hold, a hand edit that keeps
/// the key and adds a start fault keeps the fact's names, now with the start
/// check's refusal; the ledger shows the invalid-config code.
#[tokio::test]
async fn l2_a_start_fault_by_hand_after_a_hold_keeps_the_names() {
    let gw = held().await;
    let error = gw
        .hand_edit(&first_key_with(START_FAULT))
        .await
        .expect_err("refused");
    assert!(error.contains("replicas"), "{error}");
    waits_unstartable(&gw, &["first"], "replicas");
    assert!(gw.live.pending_restart().contains(&"auth.api_keys"));
    assert_eq!(gw.newest_code(), Some(RefusalCode::InvalidConfig));
}

/// L2, the swap class: after a hold, a hand edit that replaces the waiting
/// key by another and adds a start fault: the fact names the file's waiting
/// key now, not the one it named before, and a start would be refused.
#[tokio::test]
async fn l2_a_swapped_key_with_a_start_fault_names_the_new_key() {
    let gw = held().await;
    let swapped = format!(
        "{START_FAULT}{}",
        starter(&[("second", "first-key-tests-secret-second")])
    );
    gw.hand_edit(&swapped).await.expect_err("refused");
    waits_unstartable(&gw, &["second"], "replicas");
}

/// L2, the unparseable class: a file that does not parse clears the fact.
#[tokio::test]
async fn l2_an_unparseable_file_after_a_hold_clears_the_fact() {
    let gw = held().await;
    gw.hand_edit("auth: [\n")
        .await
        .expect_err("a file that does not parse is refused");
    nothing_waits(&gw);
    assert_eq!(gw.newest_code(), Some(RefusalCode::InvalidConfig));
}

/// L2, an earlier reload check: the file is still a clean first key, but it
/// also changes a posture setting, which the reload refuses before it asks
/// the question. The fact keeps the names, still startable; the ledger
/// keeps the posture code.
#[tokio::test]
async fn l2_a_posture_change_beside_a_clean_first_key_keeps_the_names() {
    let gw = held().await;
    let candidate = first_key_with(POSTURE_CHANGE);
    assert!(
        matches!(ask(&gw, &candidate), Waiting::Yes { .. }),
        "premise: still a clean first key"
    );
    let error = gw.hand_edit(&candidate).await.expect_err("refused");
    assert!(error.contains("security.hardened"), "{error}");
    let wait = gw.live.first_key_wait().expect("the fact is kept");
    assert_eq!(wait.keys, ["first"]);
    assert_eq!(wait.start_refusal, None);
    assert_eq!(gw.newest_code(), Some(RefusalCode::Posture));
}

/// L2, a reload that never read the file: once the gateway is shutting
/// down, a reload stops before reading, and the fact stays as it was.
#[tokio::test]
async fn l2_a_reload_stopped_by_shutdown_leaves_the_fact() {
    let gw = held().await;
    gw.ctx.stop.cancel();
    gw.hand_edit(&starter(&[]))
        .await
        .expect_err("a stopping gateway reloads nothing");
    assert_eq!(gw.live.waiting_keys(), Some(vec!["first".to_owned()]));
}

/// L3, a first key with a start fault, by hand: refused with the start
/// check's sentence and the invalid-config code; never told to restart.
#[tokio::test]
async fn l3_a_first_key_with_a_start_fault_by_hand_is_not_told_to_restart() {
    let gw = Gw::start(&starter(&[]));
    let error = gw
        .hand_edit(&first_key_with(START_FAULT))
        .await
        .expect_err("refused");
    assert!(error.contains("replicas"), "{error}");
    assert!(!super::says_status_change(&error), "{error}");
    assert_eq!(gw.newest_code(), Some(RefusalCode::InvalidConfig));
    assert_eq!(gw.live.waiting_keys(), None);
}

/// L3, a removal that changes the status of a multi-user gateway, by hand:
/// refused with the question's removal sentence (no restart claim) and the
/// invalid-config code, recorded by type; no fact.
#[tokio::test]
async fn l3_a_status_changing_removal_by_hand_is_invalid_without_a_restart_claim() {
    let gw = Gw::start(&starter(&[("first", FIRST)]));
    let error = gw.hand_edit(&starter(&[])).await.expect_err("refused");
    assert!(error.contains("multi-user"), "{error}");
    assert!(!error.to_lowercase().contains("restart"), "{error}");
    assert_eq!(gw.newest_code(), Some(RefusalCode::InvalidConfig));
    assert_eq!(gw.live.waiting_keys(), None);
}

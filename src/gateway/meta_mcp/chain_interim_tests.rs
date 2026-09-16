// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! MRTR.12: the ten behaviours a chain stop owes, pinned before the fix.
//!
//! Design: `docs/design/2026-09-16-mrtr-12-chain-interim-stop.md`.
//! Ratified rules: `docs/release/2026-09-16-declaration-adjudication.md`.

use serde_json::{Value, json};

use super::CONFIRMATION_INPUT_KEY;
use super::chain_interim::{
    ChainResumePlan, MAX_CHAIN_ROUNDS, classify_step_result, drive_chain, malformed_interim_error,
    plan_chain_resume, reseal_chain_resume,
};
use crate::Result;
use crate::protocol::continuation::{ContinuationPurpose, ContinuationState, Payload};
use crate::protocol::mrtr::InputRequired;

const NOW: u64 = 1_780_000_000;
const CALLER: &str = "fingerprint-of-the-caller-who-started-the-chain";
const OTHER_CALLER: &str = "fingerprint-of-somebody-else";
const BACKEND_STATE: &str = "backend-opaque-state";
/// How long the held exchange stays open, so no row expires for a reason it is
/// not about.
const HOLD_SECONDS: u64 = 300;

/// Three steps: two harmless reads around one that can ask.
fn three_step_chain() -> Vec<Value> {
    vec![
        json!({"tool": "srv:read_one", "arguments": {}}),
        json!({"tool": "srv:asks", "arguments": {"id": 7}}),
        json!({"tool": "srv:read_two", "arguments": {}}),
    ]
}

/// A well-formed interim round: one question and the backend's own state.
fn interim_result() -> Value {
    json!({
        "resultType": "input_required",
        "inputRequests": {
            "q1": {"method": "elicitation/create", "params": {"message": "which one?"}}
        },
        "requestState": BACKEND_STATE,
    })
}

/// The round a step held at the destructive-confirmation gate comes back with.
fn gate_result() -> Value {
    json!({
        "resultType": "input_required",
        "inputRequests": {
            CONFIRMATION_INPUT_KEY: {
                "method": "elicitation/create",
                "params": {"message": "confirm delete?"}
            }
        },
        "requestState": BACKEND_STATE,
    })
}

fn completed_result(step: usize) -> Value {
    json!({"ok": true, "step": step})
}

/// What the chain digest binds: the whole chain array, canonically.
fn chain_digest(chain: &[Value]) -> String {
    let canonical = crate::hashing::canonical_json(&json!(chain));
    crate::hashing::sha256_hex_chunks([canonical.as_bytes()])
}

/// A `ChainResume` payload sealed over `chain`, stopped at `next_step`.
///
/// The hold is opened on the same state the resume is presented to. An
/// envelope naming an exchange nobody holds is refused on that alone —
/// `InFlight::route` answers `Gone` for a key the table never knew — so a
/// hardcoded key would make every positive redemption below fail for a reason
/// its row is not about, and would leave the wrong-hold case in row 8 unable
/// to fail.
async fn chain_payload(
    state: &ContinuationState,
    chain: &[Value],
    next_step: Option<usize>,
    rounds_used: u32,
) -> Payload {
    let hold_key = state
        .in_flight()
        .hold("srv", NOW + HOLD_SECONDS, NOW)
        .await
        .expect("the in-flight table has room for one exchange");
    let mut payload = Payload::mint(
        "srv".into(),
        Some(BACKEND_STATE.into()),
        CALLER.into(),
        chain_digest(chain),
        "replica-a".into(),
        hold_key,
        NOW,
    )
    .with_purpose(ContinuationPurpose::ChainResume);
    payload.next_step = next_step;
    payload.rounds_used = rounds_used;
    payload
}

/// Records which steps actually ran, and answers each with `reply`.
struct StepLog {
    ran: Vec<usize>,
    reply: Box<dyn Fn(usize) -> Result<Value>>,
}

impl StepLog {
    fn new(reply: impl Fn(usize) -> Result<Value> + 'static) -> Self {
        Self {
            ran: Vec::new(),
            reply: Box::new(reply),
        }
    }
}

/// ROW 1. A chain stops at the first validated interim round.
///
/// The invariant: a question is not an answer. A step that asks has not acted,
/// so nothing after it may run on the assumption that it did, and the caller
/// must be told which step is waiting rather than left to infer it from a
/// count.
#[tokio::test]
async fn chain_stops_at_the_asking_step_and_names_it_as_pending() {
    let chain = three_step_chain();
    let mut log = StepLog::new(|idx| {
        Ok(if idx == 1 {
            interim_result()
        } else {
            completed_result(idx)
        })
    });
    let mut sealed: Vec<usize> = Vec::new();

    let response = {
        let mut run = |idx: usize, _tool: String, _args: Value| {
            log.ran.push(idx);
            std::future::ready((log.reply)(idx))
        };
        let mut seal = |idx: usize, _round: &InputRequired| {
            sealed.push(idx);
            Ok("sealed-token".to_string())
        };
        drive_chain(&chain, 0, &mut run, &mut seal).await
    };

    let response = response.expect("a stop is a successful result, not an error");
    assert_eq!(response["pendingStep"], json!(1));
    assert_eq!(response["pendingTool"], json!("srv:asks"));
    assert_eq!(response["resultType"], json!("input_required"));
    assert_eq!(
        response["requestState"],
        json!("sealed-token"),
        "the stop response dropped the sealed token, so the chain cannot be resumed"
    );
    assert_eq!(log.ran, vec![0, 1], "the successor of an asking step ran");
    assert_eq!(sealed, vec![1]);
    let classified = classify_step_result(1, "srv:asks", &interim_result())
        .expect("a well-formed interim round is not an error");
    assert!(
        classified.is_some(),
        "a well-formed interim round was not classified as a stop"
    );
}

/// ROW 2. A resume runs the tail and re-runs nothing.
///
/// The invariant: the steps before the stop are exactly the ones most likely to
/// have had effects, so replaying them is not a conservative fallback — it is
/// a second execution of work the caller already paid for.
#[tokio::test]
async fn resume_runs_the_unrun_tail_and_never_re_runs_a_completed_step() {
    let chain = three_step_chain();
    let mut log = StepLog::new(|idx| Ok(completed_result(idx)));

    let response = {
        let mut run = |idx: usize, _tool: String, _args: Value| {
            log.ran.push(idx);
            std::future::ready((log.reply)(idx))
        };
        let mut seal = |_idx: usize, _round: &InputRequired| Ok(String::new());
        drive_chain(&chain, 1, &mut run, &mut seal).await
    };

    let response = response.expect("the tail of an answered chain runs to completion");
    assert!(
        !log.ran.contains(&0),
        "a completed step was run a second time"
    );
    assert_eq!(log.ran, vec![1, 2]);
    assert_eq!(response["steps"], json!(2));
}

/// ROW 3. A resume presenting a different chain does not redeem.
///
/// The invariant: skipping is only ever relative to the chain that produced the
/// token. A resume that may present a different chain turns `next_step` into a
/// licence to run steps nobody authorised alongside steps nobody ran.
#[tokio::test]
async fn resume_presenting_a_different_chain_is_refused() {
    let state = ContinuationState::new();
    let chain = three_step_chain();
    let token = state
        .keyring()
        .mint(&chain_payload(&state, &chain, Some(1), 1).await)
        .expect("mint");

    let mut substituted = chain.clone();
    substituted[2] = json!({"tool": "srv:delete_everything", "arguments": {}});
    let refused = plan_chain_resume(&state, &token, &substituted, CALLER, NOW + 1).await;

    assert!(
        refused.is_err(),
        "a substituted chain redeemed a token minted for another"
    );
}

/// ROW 4. A resume presented by a different caller does not redeem.
///
/// The invariant: the steps already run were run as that caller, and their
/// results travelled to that caller. A second principal finishing the chain
/// inherits an execution it never authorised.
#[tokio::test]
async fn resume_presented_by_a_different_caller_is_refused() {
    let state = ContinuationState::new();
    let chain = three_step_chain();
    let token = state
        .keyring()
        .mint(&chain_payload(&state, &chain, Some(1), 1).await)
        .expect("mint");

    let refused = plan_chain_resume(&state, &token, &chain, OTHER_CALLER, NOW + 1).await;

    assert!(refused.is_err(), "another caller resumed this chain");
}

/// ROW 5. A resume redeems once.
///
/// The invariant: `jti` is what stops a replay from running the tail twice.
/// Without single use, a captured token re-executes every step after the stop
/// as many times as it is presented.
#[tokio::test]
async fn resume_presented_twice_is_refused_the_second_time() {
    let state = ContinuationState::new();
    let chain = three_step_chain();
    let token = state
        .keyring()
        .mint(&chain_payload(&state, &chain, Some(1), 1).await)
        .expect("mint");

    let first = plan_chain_resume(&state, &token, &chain, CALLER, NOW + 1).await;
    let second = plan_chain_resume(&state, &token, &chain, CALLER, NOW + 2).await;

    assert!(first.is_ok(), "the first redemption was refused");
    assert!(second.is_err(), "a consumed token redeemed a second time");
}

/// ROW 6. A malformed interim claim aborts the chain, fail-closed.
///
/// The invariant: `resultType: "input_required"` is a claim, not a
/// qualification. If an unvalidated claim could stop a chain resumably — or
/// worse, be stepped past — an untrusted backend would run the chain's tail
/// behind a control result nobody parsed. No token, no successor, and an error
/// that names which step lied.
#[tokio::test]
async fn malformed_interim_claim_aborts_with_no_token_and_no_successor() {
    let malformed = json!({"resultType": "input_required", "inputRequests": "surprise"});
    assert!(
        InputRequired::claims_input_required(&malformed)
            && InputRequired::from_result(&malformed).is_none(),
        "precondition: this shape claims the type and fails the parse"
    );

    let chain = three_step_chain();
    let mut log = StepLog::new(move |idx| {
        Ok(if idx == 1 {
            json!({"resultType": "input_required", "inputRequests": "surprise"})
        } else {
            completed_result(idx)
        })
    });
    let mut sealed: Vec<usize> = Vec::new();

    let outcome = {
        let mut run = |idx: usize, _tool: String, _args: Value| {
            log.ran.push(idx);
            std::future::ready((log.reply)(idx))
        };
        let mut seal = |idx: usize, _round: &InputRequired| {
            sealed.push(idx);
            Ok("must-not-be-minted".to_string())
        };
        drive_chain(&chain, 0, &mut run, &mut seal).await
    };

    let error = outcome.expect_err("a malformed claim must not succeed");
    let message = error.to_string();
    assert!(
        message.contains("step 1") && message.contains("srv:asks"),
        "the error does not name the failing step: {message}"
    );
    assert_eq!(message, malformed_interim_error(1, "srv:asks").to_string());
    assert!(sealed.is_empty(), "a malformed claim minted a resume token");
    assert!(
        !log.ran.contains(&2),
        "a successor ran behind an unvalidated interim claim"
    );

    // The classifier is the seam that decides this, so pin it there too: an
    // abort, never a `Completed` that the loop would push and walk past.
    let direct = classify_step_result(1, "srv:asks", &malformed);
    assert!(direct.is_err(), "the classifier accepted a malformed claim");
}

/// ROW 7. A step held at the destructive-confirmation gate stops the chain.
///
/// The invariant: this is the worst case the defect produces. The gated step
/// has not performed its action, so a successor that runs has been handed a
/// world its predecessor never created — and nothing in today's response tells
/// the caller which of the two happened.
#[tokio::test]
async fn destructive_gate_hold_stops_the_chain_before_its_successor() {
    let chain = three_step_chain();
    let mut log = StepLog::new(|idx| {
        Ok(if idx == 1 {
            gate_result()
        } else {
            completed_result(idx)
        })
    });

    let response = {
        let mut run = |idx: usize, _tool: String, _args: Value| {
            log.ran.push(idx);
            std::future::ready((log.reply)(idx))
        };
        let mut seal = |_idx: usize, _round: &InputRequired| Ok("sealed-token".to_string());
        drive_chain(&chain, 0, &mut run, &mut seal).await
    };

    let response = response.expect("a gate hold stops the chain, it does not fail it");
    assert_eq!(response["pendingStep"], json!(1));
    assert!(
        response["inputRequests"][CONFIRMATION_INPUT_KEY].is_object(),
        "the confirmation request did not reach the caller under its own key"
    );
    assert_eq!(
        response["requestState"],
        json!("sealed-token"),
        "the stop response dropped the sealed token, so the gate cannot be answered"
    );
    assert!(
        !log.ran.contains(&2),
        "a successor ran while its predecessor waited at the gate"
    );
}

/// ROW 8. The redemption invariants, one assertion each.
///
/// The invariant: `next_step` is the only thing licensing the gateway to skip
/// work, so every way of presenting one that was never sealed for this chain —
/// absent, out of range, borrowed from another domain, or naming an exchange
/// nobody holds — must be refused before a single step runs.
#[tokio::test]
async fn redemption_refuses_every_next_step_it_did_not_seal() {
    let state = ContinuationState::new();
    let chain = three_step_chain();

    // Absent: an envelope from another domain carries no step to resume at.
    let absent = chain_payload(&state, &chain, None, 1).await;
    // Out of range: a step index the sealed chain does not contain.
    let out_of_range = chain_payload(&state, &chain, Some(chain.len() + 1), 1).await;
    // Wrong domain: a confirmation grant is not a chain resume.
    let mut wrong_purpose = chain_payload(&state, &chain, Some(1), 1).await;
    wrong_purpose.purpose = ContinuationPurpose::DestructiveConfirm;
    // Wrong hold: an envelope naming an exchange this gateway is not holding.
    let mut wrong_hold = chain_payload(&state, &chain, Some(1), 1).await;
    wrong_hold.hold_key = "hold-key-nobody-opened".into();
    // Past the end: `next_step` is the index of the step that asked, so the
    // first index outside the chain names a step that never existed.
    let past_end = chain_payload(&state, &chain, Some(chain.len()), 1).await;
    // Expired: a stalled chain stops being resumable when its deadline passes.
    let mut expired = chain_payload(&state, &chain, Some(1), 1).await;
    expired.expires_at = NOW;

    for (case, payload) in [
        ("absent next_step", absent),
        ("out-of-range next_step", out_of_range),
        ("purpose is not ChainResume", wrong_purpose),
        ("envelope does not match its hold", wrong_hold),
        ("next_step past the end of the chain", past_end),
        ("envelope has expired", expired),
    ] {
        let token = state.keyring().mint(&payload).expect("mint");
        let refused = plan_chain_resume(&state, &token, &chain, CALLER, NOW + 1).await;
        assert!(refused.is_err(), "redeemed despite: {case}");
    }
}

/// ROW 9. A destructive-gated step resumed across a chain acts exactly once.
///
/// The invariant: no double execution. The answered step acts exactly once
/// across the two phases, and resuming does not re-enter a step that already
/// acted — a delete that happens twice is the failure this forecloses.
///
/// What this row does *not* pin is the other direction, that a `ChainResume`
/// token carries no authority to act in place of a confirmation. An injected
/// step closure cannot show it: the closure *is* the step, so "it did not act
/// while held" would be true of the mock rather than of the gate. Row 8 pins
/// the reverse domain separation — a confirmation grant cannot resume a chain.
/// The forward direction needs a gateway-level test against the confirmation
/// redemption path (`meta_mcp::mod::redeem_confirmation`), not this seam.
#[tokio::test]
async fn destructive_gated_step_resumed_across_a_chain_acts_exactly_once() {
    let chain = three_step_chain();
    let mut actions: Vec<&'static str> = Vec::new();
    let mut ran: Vec<(u8, usize)> = Vec::new();

    // Phase one: the gated step is held, so it must not act.
    {
        let mut run = |idx: usize, _tool: String, _args: Value| {
            ran.push((1, idx));
            std::future::ready(Ok(if idx == 1 {
                gate_result()
            } else {
                completed_result(idx)
            }))
        };
        let mut seal = |_idx: usize, _round: &InputRequired| Ok("sealed-token".to_string());
        let stopped = drive_chain(&chain, 0, &mut run, &mut seal)
            .await
            .expect("the gate hold stops the chain");
        assert_eq!(stopped["pendingStep"], json!(1));
    }
    // Phase two: the answered step redeems its confirmation and acts, once.
    {
        let mut run = |idx: usize, _tool: String, _args: Value| {
            ran.push((2, idx));
            if idx == 1 {
                actions.push("srv:asks");
            }
            std::future::ready(Ok(completed_result(idx)))
        };
        let mut seal = |_idx: usize, _round: &InputRequired| Ok(String::new());
        drive_chain(&chain, 1, &mut run, &mut seal)
            .await
            .expect("the answered chain completes");
    }

    assert_eq!(
        actions,
        vec!["srv:asks"],
        "the gated action did not happen exactly once"
    );
    assert_eq!(
        ran,
        vec![(1, 0), (1, 1), (2, 1), (2, 2)],
        "a step was entered in a phase it does not belong to"
    );
}

/// ROW 10. A step that keeps asking is refused at the round cap.
///
/// The invariant: a native resume never enters the legacy bridge, so it
/// inherits none of the bridge's per-exchange bound. Each re-ask seals the same
/// `next_step`, so the step index cannot bound anything — only a count carried
/// forward and never re-initialised stops a backend asking one question
/// forever.
#[tokio::test]
async fn a_re_asking_step_is_refused_at_the_round_cap_with_next_step_unchanged() {
    let state = ContinuationState::new();
    let chain = three_step_chain();

    let below_cap = chain_payload(&state, &chain, Some(1), MAX_CHAIN_ROUNDS - 1).await;
    let below_token = state.keyring().mint(&below_cap).expect("mint");
    let planned: ChainResumePlan = plan_chain_resume(&state, &below_token, &chain, CALLER, NOW + 1)
        .await
        .expect("a resume below the cap is allowed");
    assert_eq!(planned.next_step, 1);

    let resealed = reseal_chain_resume(&below_cap, Some(BACKEND_STATE.into()));
    assert_eq!(
        resealed.next_step,
        Some(1),
        "a re-ask moved the step it is allowed to resume at"
    );
    assert_eq!(
        resealed.rounds_used, MAX_CHAIN_ROUNDS,
        "a replacement envelope reset the round count"
    );
    assert_eq!(
        resealed.expires_at, below_cap.expires_at,
        "a replacement envelope extended the deadline"
    );

    let at_cap_token = state.keyring().mint(&resealed).expect("mint");
    let refused = plan_chain_resume(&state, &at_cap_token, &chain, CALLER, NOW + 2).await;
    assert!(refused.is_err(), "a step asked past the round cap");
}

/// ROW 11. A completed step keeps the envelope `gateway_execute` already ships.
///
/// The invariant: `execute_chain` records each step as `{step, tool, result}`,
/// and that array is the response its callers parse today. A driver that
/// recorded the bare result would change the shipped payload — a breaking
/// change arriving inside a security fix, which is the shape of change nobody
/// reads the release notes for.
#[tokio::test]
async fn a_completed_step_is_recorded_with_its_index_and_tool() {
    let chain = three_step_chain();
    let mut run =
        |idx: usize, _tool: String, _args: Value| std::future::ready(Ok(completed_result(idx)));
    let mut seal = |_idx: usize, _round: &InputRequired| Ok(String::new());

    let response = drive_chain(&chain, 0, &mut run, &mut seal)
        .await
        .expect("a chain of completed steps runs to the end");

    assert_eq!(response["steps"], json!(3));
    let first = &response["results"][0];
    assert_eq!(first["step"], json!(0));
    assert_eq!(
        first["tool"],
        json!("srv:read_one"),
        "the step's tool reference is what tells a caller which result is whose"
    );
    assert_eq!(first["result"], completed_result(0));
}

/// ROW 12. A step with no tool reference is refused, not run unnamed.
///
/// The invariant: the driver used to read the reference with
/// `unwrap_or_default`, so a malformed step ran under the empty tool name and
/// its successors ran after it. Fail-open on a malformed step is the same
/// defect class this module exists to close — the successor runs on the
/// strength of something that never properly happened.
#[tokio::test]
async fn a_step_with_no_tool_reference_is_refused_before_it_runs() {
    let chain = vec![json!({"tool": "srv:read_one"}), json!({"arguments": {}})];
    let mut ran: Vec<usize> = Vec::new();
    let mut seal = |_idx: usize, _round: &InputRequired| Ok(String::new());

    let outcome = {
        let mut run = |idx: usize, _tool: String, _args: Value| {
            ran.push(idx);
            std::future::ready(Ok(completed_result(idx)))
        };
        drive_chain(&chain, 0, &mut run, &mut seal).await
    };

    let error = outcome.expect_err("an unnamed step must not be run");
    assert!(
        error.to_string().contains("missing 'tool' field"),
        "the refusal must name what is missing: {error}"
    );
    assert_eq!(ran, vec![0], "the unnamed step was run anyway");
}

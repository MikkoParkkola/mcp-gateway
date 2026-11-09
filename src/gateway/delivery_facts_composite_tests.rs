// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A composite records `refused` only when it ends on a step the gateway
//! refused. A step it carries on past, recovers from or follows with another
//! error never marks what it delivers: over-claiming is the worse failure.

use serde_json::Map;

use super::*;

/// What the recorder writes for a composite whose steps `run` leaves behind.
async fn recorded<F: std::future::Future<Output = ()>>(run: F) -> Map<String, serde_json::Value> {
    scope(async move {
        unvouched();
        run.await;
        let mut fields = Map::new();
        record_fields(snapshot().as_ref(), false, &mut fields);
        fields
    })
    .await
}

/// A step the gateway refuses: its own cell is refused, and it fails.
async fn refused_step() -> crate::Result<()> {
    step(async {
        raise(ResponseEffect::Refused);
        Err(crate::Error::json_rpc(-32001, "refused"))
    })
    .await
}

/// A step that fails for an ordinary reason.
async fn failed_step() -> crate::Result<()> {
    step(async { Err(crate::Error::Internal("backend down".into())) }).await
}

/// A step that succeeds.
async fn served_step() -> crate::Result<()> {
    step(async { Ok(()) }).await
}

/// Rows 1 and 2 at the cell: the composite ends on the refused step.
#[tokio::test]
async fn a_composite_ending_on_a_refused_step_records_refused() {
    let fields = recorded(async {
        let ended = refused_step().await;
        composite_ended(CompositeEnd::of_outcome(&ended));
    })
    .await;
    assert_eq!(fields["response_effect"], "refused", "{fields:?}");
}

/// Row 4: the composite carries on past the refused step, then ends on an
/// ordinary error (the plan's timeout, or a later step's failure).
#[tokio::test]
async fn a_composite_ending_on_a_later_error_records_no_refused() {
    let past_then_ended = recorded(async {
        let _ = refused_step().await;
        step_absorbed();
        composite_ended(CompositeEnd::Failed);
    })
    .await;
    assert!(
        past_then_ended.get("response_effect").is_none(),
        "{past_then_ended:?}"
    );
    let later_step_failed = recorded(async {
        let _ = refused_step().await;
        let ended = failed_step().await;
        composite_ended(CompositeEnd::of_outcome(&ended));
    })
    .await;
    assert!(
        later_step_failed.get("response_effect").is_none(),
        "{later_step_failed:?}"
    );
}

/// Row 5: a step after the refused one recovers; the composite succeeds, or
/// ends on an error no refused step caused.
#[tokio::test]
async fn a_composite_recovering_from_a_refused_step_records_no_refused() {
    let recovered = recorded(async {
        let _ = refused_step().await;
        let ended = served_step().await;
        composite_ended(CompositeEnd::of_outcome(&ended));
    })
    .await;
    assert!(recovered.get("response_effect").is_none(), "{recovered:?}");
    let then_failed = recorded(async {
        let _ = refused_step().await;
        let _ = served_step().await;
        composite_ended(CompositeEnd::Failed);
    })
    .await;
    assert!(
        then_failed.get("response_effect").is_none(),
        "{then_failed:?}"
    );
}

/// A refused step's facts stay in its own cell: the composite's cell is not
/// marked refused until it ends on that step.
#[tokio::test]
async fn a_refused_step_alone_marks_nothing() {
    let fields = recorded(async {
        let _ = refused_step().await;
    })
    .await;
    assert!(fields.get("response_effect").is_none(), "{fields:?}");
}

/// A step the gateway refused with `code` after its record was written under
/// `trace`.
async fn refused_step_noted(trace: &str, code: i32) -> crate::Result<()> {
    step(async {
        note_step_trace(trace);
        gateway_folded(code);
        raise(ResponseEffect::Refused);
        Err(crate::Error::json_rpc(-32603, "plan step refused"))
    })
    .await
}

/// The plan cell's facts after `run`, as a task worker's dispatch cell reads them.
async fn plan_cell<F: std::future::Future<Output = ()>>(run: F) -> DeliveryFacts {
    scope(async move {
        unvouched();
        run.await;
        snapshot().expect("inside a cell")
    })
    .await
}

/// A plan that ends Failed on a refused step keeps that step's record trace
/// and moves the refusing gate's code into the plan cell.
#[tokio::test]
async fn a_plan_ending_on_a_refused_step_keeps_its_trace_and_gate_code() {
    let facts = plan_cell(async {
        let _ = served_step().await;
        let ended = refused_step_noted("step-trace", -32003).await;
        composite_ended(CompositeEnd::of_outcome(&ended));
    })
    .await;
    assert!(facts.refused(), "{facts:?}");
    assert_eq!(facts.ended_on().as_deref(), Some("step-trace"));
    assert_eq!(facts.withheld_code(), Some(-32003));
}

/// A refusal carried past, then an ordinary failure that ends the plan:
/// neither the refused step's trace and code nor the failing step's trace
/// survive the plan's end.
#[tokio::test]
async fn an_absorbed_refusal_then_a_backend_failure_keeps_no_trace_or_code() {
    let facts = plan_cell(async {
        let _ = refused_step_noted("refused-trace", -32003).await;
        step_absorbed();
        let ended = step(async {
            note_step_trace("failed-trace");
            Err::<(), _>(crate::Error::Internal("backend down".into()))
        })
        .await;
        composite_ended(CompositeEnd::of_outcome(&ended));
    })
    .await;
    assert!(!facts.refused(), "{facts:?}");
    assert_eq!(facts.ended_on(), None);
    assert_eq!(facts.withheld_code(), None);
}

/// A refused step's trace reaches the plan cell's `ended_on` only through
/// `composite_ended`: before the plan ends it is not published.
#[tokio::test]
async fn a_refused_steps_trace_is_published_only_by_the_plans_end() {
    let facts = plan_cell(async {
        let ended = refused_step_noted("step-trace", -32003).await;
        let before = snapshot().expect("inside a cell");
        assert_eq!(before.ended_on(), None, "{before:?}");
        composite_ended(CompositeEnd::of_outcome(&ended));
    })
    .await;
    assert_eq!(facts.ended_on().as_deref(), Some("step-trace"));
}

/// A refused step's trace and code never outlive a plan that succeeds.
#[tokio::test]
async fn a_plan_that_succeeds_after_a_refused_step_keeps_no_trace_or_code() {
    let facts = plan_cell(async {
        let _ = refused_step_noted("refused-trace", -32003).await;
        composite_ended(CompositeEnd::Succeeded);
    })
    .await;
    assert!(!facts.refused(), "{facts:?}");
    assert_eq!(facts.ended_on(), None);
    assert_eq!(facts.withheld_code(), None);
}

/// A refusal carried past, then a second refused step the plan fails on:
/// the second step's trace and code are kept, never the first's.
#[tokio::test]
async fn a_plan_ending_on_a_later_refused_step_keeps_that_steps_trace_and_code() {
    let facts = plan_cell(async {
        let _ = refused_step_noted("first-trace", -32602).await;
        step_absorbed();
        let ended = refused_step_noted("second-trace", -32003).await;
        composite_ended(CompositeEnd::of_outcome(&ended));
    })
    .await;
    assert!(facts.refused(), "{facts:?}");
    assert_eq!(facts.ended_on().as_deref(), Some("second-trace"));
    assert_eq!(facts.withheld_code(), Some(-32003));
}

/// A traced refused step, then a refusal before the next step runs: the plan
/// ends refused on the later refusal, which has no step trace.
#[tokio::test]
async fn a_refusal_before_a_step_leaves_no_ended_on_trace() {
    let facts = plan_cell(async {
        let _ = refused_step_noted("refused-trace", -32003).await;
        refused_before_step();
        composite_ended(CompositeEnd::Failed);
    })
    .await;
    assert!(facts.refused(), "{facts:?}");
    assert_eq!(facts.ended_on(), None);
}

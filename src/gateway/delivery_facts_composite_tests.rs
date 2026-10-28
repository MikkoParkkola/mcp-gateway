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
        composite_ended(ended.as_ref().err());
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
        composite_ended(Some(&crate::Error::Internal("timed out".into())));
    })
    .await;
    assert!(
        past_then_ended.get("response_effect").is_none(),
        "{past_then_ended:?}"
    );
    let later_step_failed = recorded(async {
        let _ = refused_step().await;
        let ended = failed_step().await;
        composite_ended(ended.as_ref().err());
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
        composite_ended(ended.as_ref().err());
    })
    .await;
    assert!(recovered.get("response_effect").is_none(), "{recovered:?}");
    let then_failed = recorded(async {
        let _ = refused_step().await;
        let _ = served_step().await;
        composite_ended(Some(&crate::Error::Internal("output mapping".into())));
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

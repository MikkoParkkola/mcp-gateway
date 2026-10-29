// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! An answer re-worded as an absent name records refused only for a
//! one-target call this request still vouches for.

use serde_json::Map;

use super::*;

/// The fields the recorder writes for the cell `steps` leave behind.
async fn recorded(steps: fn()) -> Map<String, serde_json::Value> {
    scope(async move {
        steps();
        let mut fields = Map::new();
        record_fields(snapshot().as_ref(), false, &mut fields);
        fields
    })
    .await
}

#[tokio::test]
async fn a_lone_target_answered_absent_records_refused() {
    let fields = recorded(|| {
        lone_target();
        withheld();
    })
    .await;
    assert_eq!(fields["response_effect"], "refused", "{fields:?}");
}

/// Not a one-target call: a withheld target among others raises nothing.
#[tokio::test]
async fn a_withheld_target_among_others_records_no_refusal() {
    let fields = recorded(withheld).await;
    assert_ne!(
        fields.get("response_effect").and_then(|v| v.as_str()),
        Some("refused")
    );
}

/// R15: a composite is unvouched before its steps run, so a one-step chain
/// whose step is answered absent states neither field.
#[tokio::test]
async fn a_step_answered_absent_in_a_composite_states_no_effect() {
    let fields = recorded(|| {
        lone_target();
        unvouched();
        withheld();
    })
    .await;
    assert!(fields.get("response_effect").is_none(), "{fields:?}");
    assert!(fields.get("response_findings").is_none(), "{fields:?}");
}

/// Context integrity's whole withhold, per step: raised only while vouched.
#[tokio::test]
async fn a_whole_withhold_in_a_composite_states_no_effect() {
    let vouched = recorded(refused_while_vouched).await;
    assert_eq!(vouched["response_effect"], "refused", "{vouched:?}");
    let composite = recorded(|| {
        unvouched();
        refused_while_vouched();
    })
    .await;
    assert!(composite.get("response_effect").is_none(), "{composite:?}");
}

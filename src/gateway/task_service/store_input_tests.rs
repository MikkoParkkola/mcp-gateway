// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8202: `closed_at` on a clock before 1970. The store's answer path
//! reads its own clock, so the row calls the decision with `now` directly.

use chrono::{DateTime, Utc};
use serde_json::json;

use super::{RoundClosed, closed_at};
use crate::gateway::task_service::record::{InputRound, PreparedTask, Record};
use crate::protocol::mrtr::InputRequired;
use crate::protocol::tasks::{Task, TaskOptions, TaskStatus, TaskTransition};

const OWNER: &str = "1111111111111111111111111111111111111111111111111111111111111111";

fn created() -> DateTime<Utc> {
    DateTime::parse_from_rfc3339("2026-09-07T00:00:00Z")
        .unwrap()
        .with_timezone(&Utc)
}

/// A task with a one-day TTL parked in `input_required`, and its record with
/// a round that stored no continuation: the TTL alone bounds it.
fn parked() -> (Task, Record) {
    let mut task = Task::create_at(
        "private-tool",
        created(),
        TaskOptions {
            ttl_ms: Some(86_400_000),
            poll_interval_ms: Some(1_000),
        },
    );
    task.transition(
        TaskTransition::RequireInput(InputRequired {
            requests: vec![(
                "confirm".to_owned(),
                json!({ "method": "elicitation/create", "params": {} }),
            )],
            request_state: None,
        }),
        created() + crate::duration_bound::delta!(seconds, 1),
    )
    .expect("a working task takes an input round");
    assert_eq!(task.status(), TaskStatus::InputRequired, "premise");
    let mut record = PreparedTask::for_test(&task, OWNER, 1).record;
    record.input_round = Some(InputRound {
        request_state: None,
        tool: "gateway_invoke".to_owned(),
        arguments: json!({}),
        accepted_inputs: serde_json::Map::new(),
        continuation_deadline: None,
    });
    (task, record)
}

/// MIK-8202: a clock before 1970 closes an input round with no continuation
/// deadline at its TTL; a 1969 `now` reads a finite TTL as never reached.
#[test]
fn a_clock_before_the_epoch_closes_a_round_without_a_deadline() {
    let (task, record) = parked();
    assert_eq!(
        closed_at(
            &task,
            &record,
            created() + crate::duration_bound::delta!(hours, 1)
        ),
        None,
        "control: a round inside its TTL closed"
    );

    let before_epoch = DateTime::<Utc>::from_timestamp(-1, 0).expect("one second before 1970");
    assert_eq!(
        closed_at(&task, &record, before_epoch),
        Some(RoundClosed::Ttl),
        "an unreadable clock kept a round open"
    );
}

// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A read of an unvouched row waiting on input stages no receipt from its
//! stored input requests: the caller was served none of them. The same row
//! vouched is the control. Once the receipt helpers return nothing for a
//! withheld row, this read is the only one that still needs the read path's
//! own withhold check, so it is what keeps that check in place.

use serde_json::json;

use super::{PROSE, RelayKey, relay_meta, relayed_by_bob, stored_task};
use crate::gateway::task_service::Vouching;
use crate::protocol::mrtr::InputRequired;
use crate::protocol::tasks::TaskTransition;

#[tokio::test]
async fn reading_an_unvouched_waiting_row_stages_no_receipt() {
    for vouching in [Vouching::Vouched, Vouching::Unvouched] {
        let (meta, firewall) = relay_meta();
        let mut stored = stored_task(|task| {
            task.transition(
                TaskTransition::RequireInput(InputRequired {
                    requests: vec![(
                        "ask".to_owned(),
                        json!({"method": "elicitation/create", "params": {"message": PROSE}}),
                    )],
                    request_state: None,
                }),
                chrono::DateTime::UNIX_EPOCH,
            )
            .expect("a live task parks");
        });
        stored.vouching = vouching;
        let ((), staged) = meta
            .collecting_staged(async {
                meta.stage_stored_receipt(RelayKey::new("alice", true), None, &stored);
            })
            .await;
        staged.commit(true, &firewall.paired_generation_for_test());
        assert_eq!(
            relayed_by_bob(&firewall, PROSE),
            vouching == Vouching::Vouched,
            "{vouching:?}"
        );
    }
}

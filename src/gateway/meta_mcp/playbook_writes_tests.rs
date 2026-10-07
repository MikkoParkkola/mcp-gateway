// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! `MIK-7993` r5: a playbook's steps' gateway notes are carried onto its
//! answer as stored: under each step's name with no output mapping, under
//! each mapped property otherwise, both inside the serialized `output`.

use serde_json::{Value, json};

use crate::gateway::authz::AllowAll;
use crate::gateway::meta_mcp::MetaMcp;
use crate::gateway::meta_mcp::authz_tests::{counted_backend, ctx};
use crate::protocol::RequestId;

const UNMAPPED: &str = r"
name: unmapped
description: one step, its value stored under its name
on_error: abort
steps:
  - name: read
    server: alpha
    tool: read
";

const MAPPED: &str = r"
name: mapped
description: one step, projected into a property
on_error: abort
steps:
  - name: read
    server: alpha
    tool: read
output:
  type: object
  properties:
    answer:
      path: $read
";

/// The destinations the delivery's record holds after `playbook` ran.
async fn dests_after(playbook: &str, name: &str) -> Vec<Value> {
    let (registry, _calls) = counted_backend("alpha");
    let meta = MetaMcp::new(registry);
    let definition: crate::playbook::PlaybookDefinition =
        serde_yaml::from_str(playbook).expect("the playbook fixture parses");
    let mut engine = crate::playbook::PlaybookEngine::new();
    engine.register(definition);
    meta.set_playbook_engine(engine);
    let stored = crate::gateway::meta_mcp::invoke::relay::collecting(async {
        let response = Box::pin(meta.handle_tools_call(
            RequestId::Number(1),
            "gateway_run_playbook",
            json!({"name": name}),
            None,
            ctx(&AllowAll),
        ))
        .await;
        assert!(
            response.error.is_none(),
            "premise: the playbook ran: {response:?}"
        );
        serde_json::to_value(crate::gateway::gateway_writes::recorded())
            .expect("the record serializes")
    })
    .await;
    stored
        .as_array()
        .expect("a list")
        .iter()
        .map(|entry| entry["dest"].clone())
        .collect()
}

#[tokio::test]
async fn an_unmapped_steps_notes_sit_under_its_name_in_the_output() {
    let dests = dests_after(UNMAPPED, "unmapped").await;
    assert!(
        dests.contains(&json!(["output", "read", "trace_id"])),
        "the step's trace_id note was not carried under its name: {dests:?}"
    );
}

#[tokio::test]
async fn a_mapped_steps_notes_sit_under_its_property_in_the_output() {
    let dests = dests_after(MAPPED, "mapped").await;
    assert!(
        dests.contains(&json!(["output", "answer", "trace_id"])),
        "the step's trace_id note was not carried under its property: {dests:?}"
    );
}

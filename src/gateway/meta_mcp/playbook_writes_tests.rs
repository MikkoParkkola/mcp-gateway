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
        crate::yaml::from_str(playbook).expect("the playbook fixture parses");
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
        dests.contains(&json!(["output", "read", "_trace_id"])),
        "the step's _trace_id note was not carried under its name: {dests:?}"
    );
}

#[tokio::test]
async fn a_mapped_steps_notes_sit_under_its_property_in_the_output() {
    let dests = dests_after(MAPPED, "mapped").await;
    assert!(
        dests.contains(&json!(["output", "answer", "_trace_id"])),
        "the step's _trace_id note was not carried under its property: {dests:?}"
    );
}

/// `value` placed at `under` inside an otherwise empty result: a numeric
/// segment is an array index, any other an object key.
fn nested(value: Value, under: &[String]) -> Value {
    under.iter().rev().fold(value, |whole, segment| {
        if let Ok(index) = segment.parse::<usize>() {
            let mut items = vec![json!({}); index + 1];
            items[index] = whole;
            Value::Array(items)
        } else {
            let mut map = serde_json::Map::new();
            map.insert(segment.clone(), whole);
            Value::Object(map)
        }
    })
}

/// `MIK-7993` impl F3-F5: notes are carried as the engine reads its
/// mappings. A wildcard reaches each element it walks; a repeated step name
/// means its last result; `inputs` is the caller's namespace, never a step's.
#[tokio::test]
async fn a_carry_follows_the_engines_reading_of_its_mappings() {
    use crate::gateway::gateway_writes::{Layer, mark, note, recorded, take_since};
    use crate::gateway::meta_mcp::support::MetaMcpInvoker;

    let (registry, _calls) = counted_backend("alpha");
    let meta = MetaMcp::new(registry);
    let caller = ctx(&AllowAll);
    let mapping = |props: &[(&str, &str)]| -> crate::playbook::PlaybookOutput {
        serde_json::from_value(json!({
            "type": "object",
            "properties": props
                .iter()
                .map(|(prop, path)| ((*prop).to_owned(), json!({"path": path})))
                .collect::<serde_json::Map<String, Value>>(),
        }))
        .expect("an output mapping")
    };
    let carried = |steps: Vec<(&'static [&'static str], Value, Vec<String>)>,
                   completed: Vec<&str>,
                   output: Option<crate::playbook::PlaybookOutput>| {
        let (meta, caller) = (&meta, &caller);
        let completed: Vec<String> = completed.into_iter().map(str::to_owned).collect();
        crate::gateway::meta_mcp::invoke::relay::collecting(async move {
            let invoker = MetaMcpInvoker {
                meta,
                caller,
                steps: parking_lot::Mutex::default(),
            };
            for (path, value, under) in steps {
                let at = mark();
                note(Layer::Value, path, &value);
                let record = take_since(at).rebased(&under);
                invoker.steps.lock().push((record, nested(value, &under)));
            }
            invoker.carry_writes(output.as_ref(), &completed);
            let stored = serde_json::to_value(recorded()).expect("serializes");
            stored
                .as_array()
                .expect("a list")
                .iter()
                .map(|entry| entry["dest"].clone())
                .collect::<Vec<Value>>()
        })
    };

    // F3: `$s.items[]` stores both elements as an array; the second one's
    // advice is carried under its index.
    let advice = json!({"v": 2, "_cost_warnings": ["w"]});
    let dests = carried(
        vec![(
            &["_cost_warnings"],
            advice,
            vec!["items".to_owned(), "1".to_owned()],
        )],
        vec!["s"],
        Some(mapping(&[("p", "$s.items[]")])),
    )
    .await;
    assert_eq!(dests, vec![json!(["output", "p", "1", "_cost_warnings"])]);

    // F4: a repeated step name means its last result.
    let first = json!({"_trace_id": "first"});
    let last = json!({"_cost_warnings": ["last"]});
    let dests = carried(
        vec![
            (&["_trace_id"], first, Vec::new()),
            (&["_cost_warnings"], last, Vec::new()),
        ],
        vec!["s", "s"],
        Some(mapping(&[("p", "$s")])),
    )
    .await;
    assert_eq!(dests, vec![json!(["output", "p", "_cost_warnings"])]);

    // Delta D2: with no mapping too, a repeated step name means its last
    // result: the first call's note is not carried under the name.
    let dests = carried(
        vec![
            (&["_trace_id"], json!({"_trace_id": "first"}), Vec::new()),
            (
                &["_cost_warnings"],
                json!({"_cost_warnings": ["last"]}),
                Vec::new(),
            ),
        ],
        vec!["s", "s"],
        None,
    )
    .await;
    assert_eq!(dests, vec![json!(["output", "s", "_cost_warnings"])]);

    // F5: `$inputs.x` is the caller's input, even beside a step of that name.
    let named_inputs = json!({"_trace_id": "t"});
    let dests = carried(
        vec![(&["_trace_id"], named_inputs, Vec::new())],
        vec!["inputs"],
        Some(mapping(&[("p", "$inputs")])),
    )
    .await;
    assert!(dests.is_empty(), "{dests:?}");
}

/// MIK-8429 PBERR.1: a step whose tool answers `isError` is a failed step
/// under `continue`, so it is not one of the completed steps the notes are
/// paired with. The completed step's notes are still carried under its name.
/// Mutant: the invoker keeps the failed step's notes too, the counts differ,
/// and nothing is carried.
#[tokio::test]
async fn a_failed_tool_error_step_leaves_the_completed_steps_notes_carried() {
    let (registry, _calls) = counted_backend("alpha");
    let _failing = crate::gateway::meta_mcp::authz_tests::register_answering(
        &registry,
        "beta",
        json!({"content": [{"type": "text", "text": "upstream failed"}], "isError": true}),
    );
    let meta = MetaMcp::new(registry);
    let definition: crate::playbook::PlaybookDefinition = crate::yaml::from_str(
        r"
name: partly
description: a failing step, then a served one
on_error: continue
steps:
  - name: bad
    server: beta
    tool: read
  - name: read
    server: alpha
    tool: read
",
    )
    .expect("the playbook fixture parses");
    let mut engine = crate::playbook::PlaybookEngine::new();
    engine.register(definition);
    meta.set_playbook_engine(engine);
    let (stored, answer) = crate::gateway::meta_mcp::invoke::relay::collecting(async {
        let response = Box::pin(meta.handle_tools_call(
            RequestId::Number(1),
            "gateway_run_playbook",
            json!({"name": "partly"}),
            None,
            ctx(&AllowAll),
        ))
        .await;
        (
            serde_json::to_value(crate::gateway::gateway_writes::recorded())
                .expect("the record serializes"),
            serde_json::to_value(&response).expect("the response serializes"),
        )
    })
    .await;
    let result: Value = answer
        .pointer("/result/content/0/text")
        .and_then(Value::as_str)
        .and_then(|text| serde_json::from_str(text).ok())
        .unwrap_or_else(|| panic!("premise: a playbook result: {answer}"));
    assert_eq!(
        (&result["steps_failed"], &result["steps_completed"]),
        (&json!(["bad"]), &json!(["read"])),
        "PBERR.1: {result}"
    );
    let dests: Vec<Value> = stored
        .as_array()
        .expect("a list")
        .iter()
        .map(|entry| entry["dest"].clone())
        .collect();
    assert!(
        dests.contains(&json!(["output", "read", "_trace_id"])),
        "PBERR.1: the completed step's notes were not carried: {dests:?}"
    );
    assert!(
        !dests.iter().any(|dest| dest.get(1) == Some(&json!("bad"))),
        "PBERR.1: the failed step's notes were carried onto its null: {dests:?}"
    );
}

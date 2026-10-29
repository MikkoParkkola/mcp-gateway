// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
use serde_json::json;

use super::*;

/// A noted member is removed while it holds what was written; a member
/// of the same name with other text (a replaced value) stays.
#[tokio::test]
async fn a_note_removes_only_what_was_written() {
    scope(async {
        let written = json!({"_trace_id": "t-1", "text": "x"});
        note(Layer::Value, &["_trace_id"], &written);
        let mut same = written.clone();
        strip(&mut same, Layer::Value);
        assert!(same.get("_trace_id").is_none(), "{same}");
        let mut replaced = json!({"_trace_id": "backend", "text": "x"});
        strip(&mut replaced, Layer::Value);
        assert_eq!(replaced["_trace_id"], "backend");
    })
    .await;
}

/// An in-place rewrite of an owned member keeps it owned; a stale note
/// is dropped and stays dropped through a later rewrite.
#[tokio::test]
async fn a_rebind_follows_only_owned_members() {
    scope(async {
        let written = json!({"_recovery": {"hint": "a b"}});
        note(Layer::Value, &["_recovery"], &written);
        let redacted = json!({"_recovery": {"hint": "a [redacted]"}});
        rebind(Layer::Value, &written, &redacted);
        let mut delivered = redacted.clone();
        strip(&mut delivered, Layer::Value);
        assert!(delivered.get("_recovery").is_none(), "{delivered}");

        let replaced = json!({"_recovery": {"hint": "backend"}});
        rebind(
            Layer::Value,
            &replaced,
            &json!({"_recovery": {"hint": "back"}}),
        );
        let mut later = json!({"_recovery": {"hint": "back"}});
        strip(&mut later, Layer::Value);
        assert_eq!(later["_recovery"]["hint"], "back", "a stale note revived");
    })
    .await;
}

/// MIK-7991: a record taken from a mark holds only the notes made after
/// it, also after a rewrite drops an earlier step's note, and
/// restored into another delivery it strips as that delivery's own.
#[tokio::test]
async fn a_record_since_a_mark_holds_only_its_own_notes() {
    let advice = json!({"_cost_suggestion": {"message": "cheaper"}, "text": "x"});
    let traced = json!({"_trace_id": "t-1", "text": "x"});
    let record = scope(async {
        note(Layer::Value, &["_cost_suggestion"], &advice);
        let mark = mark();
        assert!(
            snapshot_since(mark).0.is_empty(),
            "an earlier step's note is in this call's record"
        );
        note(Layer::Value, &["_trace_id"], &traced);
        // Drops the earlier step's note, which sits before the mark.
        rebind(Layer::Value, &traced, &traced);
        snapshot_since(mark)
    })
    .await;
    assert_eq!(record.0.len(), 1, "{record:?}");
    let both = json!({"_trace_id": "t-1", "_cost_suggestion": {"message": "cheaper"}});
    let cached = without(&both, &record);
    assert!(cached.get("_trace_id").is_none(), "{cached}");
    assert!(cached.get("_cost_suggestion").is_some(), "{cached}");
    assert!(
        matches!(without(&both, &WriteRecord::default()), Cow::Borrowed(_)),
        "an empty record copies the value"
    );
    scope(async {
        restore(&record);
        let mut delivered = both.clone();
        strip(&mut delivered, Layer::Value);
        assert!(delivered.get("_trace_id").is_none(), "{delivered}");
        assert!(delivered.get("_cost_suggestion").is_some(), "{delivered}");
    })
    .await;
}

/// MIK-7991 r4 (R9): a record as the sync admission stores it keeps every
/// noted path on both layers through a round trip; a stored path
/// this build does not note drops only that entry; restored, the record
/// lands after the replay's mark and strips what it wrote.
#[tokio::test]
async fn a_stored_record_round_trips_every_noted_path() {
    let value = json!({
        "_recovery": {"hint": "retry"}, "_signature": {"sig": "s"}, "taskId": "t-9",
        "_trace_id": "t-1", "_predicted_next": ["b"], "_meta": {"provenance": {"p": 1}},
        "_security_findings": ["f"], "_cost_warnings": ["w"],
        "_cost_suggestion": {"message": "m"}, "requestState": "rs-1", "resultType": "complete",
        "cacheScope": "private", "ttlMs": 5000,
        "_contract_violation": true, "_contract_reason": "no_contract_declared",
        "text": "backend",
    });
    let stored = scope(async {
        for layer in [Layer::Value, Layer::Answer] {
            for path in crate::protocol::reserved_members::noted() {
                note(layer, path, &value);
            }
        }
        serde_json::to_value(recorded()).expect("serializes")
    })
    .await;
    let mut entries = stored.as_array().expect("a list").clone();
    let noted = crate::protocol::reserved_members::noted().count();
    assert_eq!(entries.len(), 2 * noted, "{stored}");
    entries.push(json!({"layer": "value", "path": ["not_noted"], "digest": 1}));
    let decoded: WriteRecord = serde_json::from_value(Value::Array(entries)).expect("deserializes");
    assert_eq!(decoded.0.len(), 2 * noted, "{decoded:?}");
    let receipt = without(&value, &decoded);
    assert_eq!(
        receipt.as_ref(),
        &json!({"_meta": {}, "text": "backend"}),
        "{receipt}"
    );
    scope(async {
        note(Layer::Value, &["_trace_id"], &value);
        let mark = mark();
        restore(&decoded);
        assert_eq!(snapshot_since(mark).0.len(), decoded.0.len());
    })
    .await;
}

/// MIK-7993 T6': the digest is SHA-256 over RFC 8785 canonical JSON, pinned
/// by a vector computed outside this crate. The member differs from its plain
/// `to_string` form in more than key order (number spelling, a non-ASCII
/// string, a supplementary-plane key), and a reordered copy hashes the same.
#[test]
fn the_digest_is_sha256_over_canonical_json() {
    let member: Value =
        serde_json::from_str(r#"{"b":[1.0,1e2,"é"],"a":{"z":null,"y":true},"😀":"x"}"#)
            .expect("the vector parses");
    let pinned = "636810988c0638ebda7b64c4fcac77cae55b300084dd6c553983f9c1aaf350db";
    assert_eq!(hex::encode(digest(&member).expect("hashes")), pinned);
    let reordered: Value =
        serde_json::from_str(r#"{"😀":"x","a":{"y":true,"z":null},"b":[1,100,"é"]}"#)
            .expect("the reordered copy parses");
    assert_eq!(digest(&reordered), digest(&member));
}

/// MIK-7993 r5a: an array segment is a canonical index; an object keeps a
/// numeric-looking segment as a key; anything else is no member.
#[test]
fn a_path_indexes_arrays_only_by_canonical_index() {
    let value = json!({"results": [{"r": 0}, {"r": 1}], "1": "key"});
    assert_eq!(member(&value, &["results", "1", "r"]), Some(&json!(1)));
    assert_eq!(member(&value, &["results", "0", "r"]), Some(&json!(0)));
    assert_eq!(member(&value, &["1"]), Some(&json!("key")));
    for bad in ["01", "+1", "-1", "", "1.0", "2"] {
        assert_eq!(member(&value, &["results", bad, "r"]), None, "{bad:?}");
    }
    assert_eq!(member(&value, &["1", "0"]), None, "a string has no members");
}

/// MIK-7993 T9 (r5c): a stored record never fails to decode. Whatever its
/// top-level shape it reads, and each entry that is not a note this build
/// makes (an older shape, a bad digest, a kind or layer this build does not
/// note) is dropped on its own, leaving the good ones.
#[test]
fn a_damaged_record_drops_only_its_bad_entries() {
    for whole in [json!(null), json!({"layer": "value"}), json!(7), json!("x")] {
        let decoded: WriteRecord = serde_json::from_value(whole.clone()).expect("never fails");
        assert!(decoded.is_empty(), "{whole}");
    }
    let good = json!({
        "layer": "value", "dest": ["results", "0", "result", "_trace_id"], "kind": ["_trace_id"],
        "within": [], "digest": "636810988c0638ebda7b64c4fcac77cae55b300084dd6c553983f9c1aaf350db",
    });
    let with = |key: &str, value: Value| {
        let mut entry = good.clone();
        entry[key] = value;
        entry
    };
    let bad = [
        json!({"layer": "value", "path": ["trace_id"], "digest": 1}),
        with(
            "digest",
            json!("636810988C0638EBDA7B64C4FCAC77CAE55B300084DD6C553983F9C1AAF350DB"),
        ),
        with("digest", json!("6368")),
        with("digest", json!(1)),
        with("kind", json!(["not_noted"])),
        with("layer", json!("elsewhere")),
        with("dest", json!([])),
        with("within", json!(null)),
        json!("not an entry"),
    ];
    let mut entries = vec![good.clone()];
    entries.extend(bad.iter().cloned());
    entries.push(good.clone());
    let decoded: WriteRecord = serde_json::from_value(Value::Array(entries)).expect("never fails");
    assert_eq!(decoded.0.len(), 2, "{decoded:?}");
    assert_eq!(
        serde_json::to_value(&decoded).expect("serializes"),
        json!([good.clone(), good]),
        "a kept entry round-trips unchanged"
    );
}

/// MIK-7993 impl F2: every record this build writes reads back whole: many
/// entries, deep paths and long segments included.
#[test]
fn every_record_written_reads_back() {
    let entry = json!({
        "layer": "value",
        "dest": std::iter::repeat_n("x".repeat(300), 40).collect::<Vec<_>>(),
        "kind": ["_cost_warnings"], "within": [],
        "digest": "636810988c0638ebda7b64c4fcac77cae55b300084dd6c553983f9c1aaf350db",
    });
    let stored = Value::Array(vec![entry; 300]);
    let decoded: WriteRecord = serde_json::from_value(stored.clone()).expect("never fails");
    assert_eq!(decoded.0.len(), 300);
    assert_eq!(serde_json::to_value(&decoded).expect("serializes"), stored);
}

/// The record of `notes` made on `value`, as a step's own.
async fn noted(value: &Value, notes: &[&'static [&'static str]]) -> WriteRecord {
    scope(async {
        for &path in notes {
            note(Layer::Value, path, value);
        }
        recorded()
    })
    .await
}

fn dests(record: &WriteRecord) -> Vec<Vec<String>> {
    record.0.iter().map(|w| w.dest.clone()).collect()
}

fn path(segments: &[&str]) -> Vec<String> {
    segments.iter().map(|s| (*s).to_owned()).collect()
}

/// `MIK-7993` r5 T10: with no output mapping a playbook stores each step's
/// value under its name, inside the serialized result's `output`.
#[tokio::test]
async fn a_rebased_note_sits_under_its_prefix_in_the_value() {
    let step = json!({"text": "t", "_cost_warnings": ["w"]});
    let record = noted(&step, &[&["_cost_warnings"]]).await;
    let rebased = record.rebased(&path(&["output", "fetch"]));
    assert_eq!(
        dests(&rebased),
        vec![path(&["output", "fetch", "_cost_warnings"])]
    );
    assert!(rebased.0.iter().all(|w| w.layer == Layer::Value));
    let answer = json!({"output": {"fetch": step}});
    let receipt = without(&answer, &rebased);
    assert_eq!(
        receipt.as_ref(),
        &json!({"output": {"fetch": {"text": "t"}}})
    );
}

/// `MIK-7993` r5 T11: a mapping carries the notes inside what it projects
/// (i), the noted member itself (ii), a part of a noted member while the
/// member still holds what was written (iv), each projection on its own
/// (v); a member of the same name elsewhere is not carried (iii).
#[tokio::test]
async fn a_projection_carries_only_the_notes_it_takes() {
    let findings = json!([{"description": "a pattern", "severity": "low"}]);
    let step = json!({
        "text": "t",
        "_security_findings": findings,
        "nested": {"_security_findings": ["the backend's own"]},
    });
    let record = noted(&step, &[&["_security_findings"]]).await;
    let to = path(&["output", "p"]);

    // (i) the whole step value.
    let whole = record.projected(&step, &[], &to);
    assert_eq!(
        dests(&whole),
        vec![path(&["output", "p", "_security_findings"])]
    );
    // (ii) the noted member itself.
    let member_itself = record.projected(&step, &path(&["_security_findings"]), &to);
    assert_eq!(dests(&member_itself), vec![to.clone()]);
    assert_eq!(member_itself.0[0].digest, record.0[0].digest);
    // (iii) a member of that name the gateway did not write.
    let elsewhere = record.projected(&step, &path(&["nested", "_security_findings"]), &to);
    assert!(elsewhere.is_empty(), "{elsewhere:?}");
    // (iv) a part of the noted member, while it holds what was written.
    let part_path = path(&["_security_findings", "0", "description"]);
    let part = record.projected(&step, &part_path, &to);
    assert_eq!(dests(&part), vec![to.clone()]);
    assert_eq!(part.0[0].within, path(&["0", "description"]));
    assert_eq!(part.0[0].digest, digest(&json!("a pattern")).unwrap());
    // ...and not once the member no longer holds it, even though the
    // projected bytes are the same.
    let mut changed = step.clone();
    changed["_security_findings"][0]["severity"] = json!("high");
    assert!(record.projected(&changed, &part_path, &to).is_empty());
    // (v) one member projected into two properties: one note each.
    let twice: Vec<Vec<String>> = ["p", "q"]
        .iter()
        .flat_map(|prop| {
            dests(&record.projected(
                &step,
                &path(&["_security_findings"]),
                &path(&["output", prop]),
            ))
        })
        .collect();
    assert_eq!(twice, vec![path(&["output", "p"]), path(&["output", "q"])]);
}

/// MIK-7993 impl F3: a mapping path names the concrete paths the resolver
/// visits in a step's value, a wildcard each element in order.
#[test]
fn a_mapping_path_names_the_paths_it_reaches() {
    let value = json!({"results": [{"title": "a"}, {"title": "b"}], "one": {"x": 1}});
    assert_eq!(
        mapping_paths(&value, "results[0].title"),
        vec![path(&["results", "0", "title"])]
    );
    assert_eq!(
        mapping_paths(&value, "results[].title"),
        vec![
            path(&["results", "0", "title"]),
            path(&["results", "1", "title"])
        ]
    );
    assert_eq!(mapping_paths(&value, ""), vec![Vec::<String>::new()]);
    assert!(
        mapping_paths(&value, "one[0]").is_empty(),
        "an index needs an array"
    );
    assert!(mapping_paths(&value, "missing").is_empty());
}

/// A composite step's notes are taken out of the delivery's record, leaving
/// the notes made before it.
#[tokio::test]
async fn taking_since_a_mark_leaves_the_earlier_notes() {
    let value = json!({"_trace_id": "t-1", "_cost_warnings": ["w"]});
    let (taken, left) = scope(async {
        note(Layer::Value, &["_trace_id"], &value);
        let mark = mark();
        note(Layer::Value, &["_cost_warnings"], &value);
        let taken = take_since(mark);
        (taken, recorded())
    })
    .await;
    assert_eq!(dests(&taken), vec![path(&["_cost_warnings"])]);
    assert_eq!(dests(&left), vec![path(&["_trace_id"])]);
}

/// `MIK-7993` r4 M1: the response-contract annotations the gateway writes,
/// on both branches of the gate (no contract declared; a declared contract
/// violated), are noted as its own; a backend member of the same name with
/// other bytes is not.
#[tokio::test]
async fn the_contract_annotations_are_the_gateways() {
    use std::sync::Arc;
    let declared = crate::config::ToolContractConfig {
        max_bytes: Some(1),
        forbidden_patterns: Vec::new(),
        action_mode: None,
    };
    for (tool, reason) in [("undeclared", "no_contract_declared"), ("declared", "")] {
        let mut meta = crate::gateway::meta_mcp::MetaMcp::new(Arc::new(
            crate::backend::BackendRegistry::new(),
        ));
        meta.set_response_contract(crate::config::ResponseContractConfig {
            enabled: true,
            action_mode: false,
            fail_closed: true,
            tools: [("declared".to_owned(), declared.clone())].into(),
            ..Default::default()
        });
        scope(async {
            let mut result = json!({"content": [{"type": "text", "text": "longer than one byte"}]});
            meta.apply_response_contract_gate("alpha", tool, "t-1", &mut result)
                .expect("observe mode annotates");
            assert_eq!(
                result["_contract_violation"], true,
                "premise {tool}: {result}"
            );
            if !reason.is_empty() {
                assert_eq!(
                    result["_contract_reason"], reason,
                    "premise {tool}: {result}"
                );
            }
            let mut delivered = result.clone();
            strip(&mut delivered, Layer::Value);
            assert!(
                delivered.get("_contract_violation").is_none(),
                "{tool}: {delivered}"
            );
            assert!(
                delivered.get("_contract_reason").is_none(),
                "{tool}: {delivered}"
            );
            let mut backend = json!({"_contract_reason": "the backend's own"});
            strip(&mut backend, Layer::Value);
            assert_eq!(backend["_contract_reason"], "the backend's own", "{tool}");
        })
        .await;
    }
}

/// MIK-7993 F1 (c), deltas D1/D4: a task stores its native result whatever
/// tool started it, so the strip removes each noted member at the path it
/// names in that result and nowhere else: a backend member of the same
/// name and bytes inside `structuredContent` or a text block stays.
#[tokio::test]
async fn the_strip_removes_a_noted_member_only_at_its_path() {
    let stored = json!({
        "content": [{"type": "text", "text": "{\"_contract_violation\":true}"}],
        "_contract_violation": true,
        "_trace_id": "gw-1",
        "structuredContent": {"_contract_violation": true, "_trace_id": "gw-1"},
    });
    let record = noted(&stored, &[CONTRACT_VIOLATION, &["_trace_id"]]).await;
    let mut result = stored.clone();
    let stripped = strip_recorded(&mut result, &record);
    assert_eq!(
        stripped,
        vec!["_contract_violation".to_owned(), "_trace_id".to_owned()]
    );
    assert!(result.get("_contract_violation").is_none(), "{result}");
    assert!(result.get("_trace_id").is_none(), "{result}");
    assert_eq!(
        result["structuredContent"], stored["structuredContent"],
        "{result}"
    );
    assert_eq!(result["content"], stored["content"], "{result}");
}

/// Delta D3: notes naming array elements empty those slots, keeping every
/// other element where its note says it is, a backend element between
/// them included.
#[tokio::test]
async fn noted_array_elements_become_null() {
    let step = json!({"_cost_warnings": ["first", "second", "third"]});
    let record = noted(&step, &[&["_cost_warnings"]]).await;
    let mut carried = WriteRecord::default();
    for (from, to) in [("0", "0"), ("2", "2")] {
        carried.0.extend(
            record
                .projected(
                    &step,
                    &path(&["_cost_warnings", from]),
                    &path(&["items", to]),
                )
                .0,
        );
    }
    let answer = json!({"items": ["first", "the backend's", "third"]});
    let receipt = without(&answer, &carried);
    assert_eq!(
        receipt.as_ref(),
        &json!({"items": [null, "the backend's", null]})
    );
}

/// A record stored before the rename names the plain kinds.
/// Each decodes as its renamed row with its stored `dest` and `within` kept
/// (a composite's rebased path and a projected part included), and is
/// written back under the new kind.
#[test]
fn a_pre_rename_kind_decodes_as_its_renamed_row() {
    let digest = "636810988c0638ebda7b64c4fcac77cae55b300084dd6c553983f9c1aaf350db";
    for (old, new, dest, within) in [
        ("recovery", "_recovery", json!(["recovery"]), json!([])),
        (
            "trace_id",
            "_trace_id",
            json!(["results", "0", "result", "trace_id"]),
            json!([]),
        ),
        (
            "predicted_next",
            "_predicted_next",
            json!(["output", "p"]),
            json!(["0"]),
        ),
    ] {
        let stored = json!([{
            "layer": "value", "dest": dest, "kind": [old], "within": within, "digest": digest,
        }]);
        let decoded: WriteRecord = serde_json::from_value(stored).expect("never fails");
        assert_eq!(decoded.0.len(), 1, "{old} was dropped");
        let entry = &decoded.0[0];
        assert_eq!(entry.kind, &[new][..], "{old}");
        assert_eq!(json!(entry.dest), dest, "{old}: the stored dest moved");
        assert_eq!(json!(entry.within), within, "{old}");
        let again = serde_json::to_value(&decoded).expect("serializes");
        assert_eq!(
            again[0]["kind"],
            json!([new]),
            "{old} written back: {again}"
        );
        assert_eq!(again[0]["dest"], dest, "{old} written back: {again}");
    }
}

/// The raise reads the reserved-member table: noting a counted member raises
/// `annotated`, noting an identity stamp leaves `delivered`, and neither
/// needs a write record open.
#[tokio::test]
async fn noting_a_counted_member_raises_annotated() {
    let value = json!({"_security_findings": ["f"], "_trace_id": "t-1"});
    let counted: &'static [&'static str] = &["_security_findings"];
    let stamp: &'static [&'static str] = &["_trace_id"];
    for (path, expected) in [(counted, "annotated"), (stamp, "delivered")] {
        let effect = crate::gateway::delivery_facts::scope(async {
            note(Layer::Value, path, &value);
            let mut fields = serde_json::Map::new();
            crate::gateway::delivery_facts::record_fields(
                crate::gateway::delivery_facts::snapshot().as_ref(),
                false,
                &mut fields,
            );
            fields["response_effect"].clone()
        })
        .await;
        assert_eq!(effect, expected, "{path:?}");
    }
}

/// The response-contract gate's annotations make the delivery `annotated`
/// on both branches that write them (no contract declared; a declared
/// contract violated), and an answer the declared contract admits stays
/// `delivered`: each noted contract member is counted where it is written.
///
/// "No contract declared" annotates by design, not by accident: with
/// `fail_closed` on, a tool with no declared contract is itself a violation,
/// and in observe mode (`action_mode` off) the gate writes
/// `_contract_violation: true` and `_contract_reason: "no_contract_declared"`
/// through `write_contract` (src/gateway/meta_mcp/invoke/policy.rs:527-547).
#[tokio::test]
async fn a_contract_annotation_records_annotated() {
    use std::sync::Arc;
    let declared = crate::config::ToolContractConfig {
        max_bytes: Some(1),
        forbidden_patterns: Vec::new(),
        action_mode: None,
    };
    let roomy = crate::config::ToolContractConfig {
        max_bytes: Some(1 << 20),
        forbidden_patterns: Vec::new(),
        action_mode: None,
    };
    // (tool, the effect, the reason the gate writes: `None` writes none).
    let cases = [
        ("undeclared", "annotated", Some("no_contract_declared")),
        ("declared", "annotated", Some("max_bytes_exceeded")),
        ("roomy", "delivered", None),
    ];
    // Every case's effect is collected and compared at once, so a failure
    // shows each branch's answer, not only the first that differs.
    let mut effects = Vec::new();
    for (tool, _, reason) in cases {
        let mut meta = crate::gateway::meta_mcp::MetaMcp::new(Arc::new(
            crate::backend::BackendRegistry::new(),
        ));
        meta.set_response_contract(crate::config::ResponseContractConfig {
            enabled: true,
            action_mode: false,
            fail_closed: true,
            tools: [
                ("declared".to_owned(), declared.clone()),
                ("roomy".to_owned(), roomy.clone()),
            ]
            .into(),
            ..Default::default()
        });
        let (effect, written) = crate::gateway::delivery_facts::scope(async {
            let mut result = json!({"content": [{"type": "text", "text": "longer than one byte"}]});
            meta.apply_response_contract_gate("alpha", tool, "t-1", &mut result)
                .expect("observe mode annotates");
            let mut fields = serde_json::Map::new();
            crate::gateway::delivery_facts::record_fields(
                crate::gateway::delivery_facts::snapshot().as_ref(),
                false,
                &mut fields,
            );
            (
                fields["response_effect"].clone(),
                (
                    result.get("_contract_violation").cloned(),
                    result.get("_contract_reason").cloned(),
                ),
            )
        })
        .await;
        // Premise: each case reached the branch it names.
        let annotation = reason.map(|reason| (json!(true), json!(reason)));
        assert_eq!(
            written,
            annotation.map_or((None, None), |(v, r)| (Some(v), Some(r))),
            "premise {tool}: the gate's annotation"
        );
        effects.push((tool, effect));
    }
    let expected: Vec<_> = cases
        .iter()
        .map(|&(tool, effect, _)| (tool, json!(effect)))
        .collect();
    assert_eq!(effects, expected);
}

/// Each contract member is counted on its own: noting either one alone
/// makes the delivery `annotated`, so neither can lose its counted status
/// behind the other (the gate always writes both together).
#[tokio::test]
async fn each_contract_member_alone_records_annotated() {
    let value = json!({"_contract_violation": true, "_contract_reason": "r"});
    let mut effects = Vec::new();
    for path in [CONTRACT_VIOLATION, CONTRACT_REASON] {
        let effect = crate::gateway::delivery_facts::scope(async {
            note(Layer::Value, path, &value);
            let mut fields = serde_json::Map::new();
            crate::gateway::delivery_facts::record_fields(
                crate::gateway::delivery_facts::snapshot().as_ref(),
                false,
                &mut fields,
            );
            fields["response_effect"].clone()
        })
        .await;
        effects.push((path[0], effect));
    }
    assert_eq!(
        effects,
        [
            ("_contract_violation", json!("annotated")),
            ("_contract_reason", json!("annotated")),
        ]
    );
}

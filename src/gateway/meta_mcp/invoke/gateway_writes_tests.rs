// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
use serde_json::json;

use super::*;

/// A noted member is removed while it holds what was written; a member
/// of the same name with other text (a replaced value) stays.
#[tokio::test]
async fn a_note_removes_only_what_was_written() {
    scope(async {
        let written = json!({"trace_id": "t-1", "text": "x"});
        note(Layer::Value, &["trace_id"], &written);
        let mut same = written.clone();
        strip(&mut same, Layer::Value);
        assert!(same.get("trace_id").is_none(), "{same}");
        let mut replaced = json!({"trace_id": "backend", "text": "x"});
        strip(&mut replaced, Layer::Value);
        assert_eq!(replaced["trace_id"], "backend");
    })
    .await;
}

/// An in-place rewrite of an owned member keeps it owned; a stale note
/// is dropped and stays dropped through a later rewrite.
#[tokio::test]
async fn a_rebind_follows_only_owned_members() {
    scope(async {
        let written = json!({"recovery": {"hint": "a b"}});
        note(Layer::Value, &["recovery"], &written);
        let redacted = json!({"recovery": {"hint": "a [redacted]"}});
        rebind(Layer::Value, &written, &redacted);
        let mut delivered = redacted.clone();
        strip(&mut delivered, Layer::Value);
        assert!(delivered.get("recovery").is_none(), "{delivered}");

        let replaced = json!({"recovery": {"hint": "backend"}});
        rebind(
            Layer::Value,
            &replaced,
            &json!({"recovery": {"hint": "back"}}),
        );
        let mut later = json!({"recovery": {"hint": "back"}});
        strip(&mut later, Layer::Value);
        assert_eq!(later["recovery"]["hint"], "back", "a stale note revived");
    })
    .await;
}

/// MIK-7991: a record taken from a mark holds only the notes made after
/// it, also after a rewrite drops an earlier step's note, and
/// restored into another delivery it strips as that delivery's own.
#[tokio::test]
async fn a_record_since_a_mark_holds_only_its_own_notes() {
    let advice = json!({"_cost_suggestion": {"message": "cheaper"}, "text": "x"});
    let traced = json!({"trace_id": "t-1", "text": "x"});
    let record = scope(async {
        note(Layer::Value, &["_cost_suggestion"], &advice);
        let mark = mark();
        assert!(
            snapshot_since(mark).0.is_empty(),
            "an earlier step's note is in this call's record"
        );
        note(Layer::Value, &["trace_id"], &traced);
        // Drops the earlier step's note, which sits before the mark.
        rebind(Layer::Value, &traced, &traced);
        snapshot_since(mark)
    })
    .await;
    assert_eq!(record.0.len(), 1, "{record:?}");
    let both = json!({"trace_id": "t-1", "_cost_suggestion": {"message": "cheaper"}});
    let cached = without(&both, &record);
    assert!(cached.get("trace_id").is_none(), "{cached}");
    assert!(cached.get("_cost_suggestion").is_some(), "{cached}");
    assert!(
        matches!(without(&both, &WriteRecord::default()), Cow::Borrowed(_)),
        "an empty record copies the value"
    );
    scope(async {
        restore(&record);
        let mut delivered = both.clone();
        strip(&mut delivered, Layer::Value);
        assert!(delivered.get("trace_id").is_none(), "{delivered}");
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
        "recovery": {"hint": "retry"}, "_signature": {"sig": "s"}, "taskId": "t-9",
        "trace_id": "t-1", "predicted_next": ["b"], "_meta": {"provenance": {"p": 1}},
        "_security_findings": ["f"], "_cost_warnings": ["w"],
        "_cost_suggestion": {"message": "m"}, "requestState": "rs-1",
        "_contract_violation": true, "_contract_reason": "no_contract_declared",
        "text": "backend",
    });
    let stored = scope(async {
        for layer in [Layer::Value, Layer::Answer] {
            for &path in NOTED_PATHS {
                note(layer, path, &value);
            }
        }
        serde_json::to_value(recorded()).expect("serializes")
    })
    .await;
    let mut entries = stored.as_array().expect("a list").clone();
    assert_eq!(entries.len(), 2 * NOTED_PATHS.len(), "{stored}");
    entries.push(json!({"layer": "value", "path": ["not_noted"], "digest": 1}));
    let decoded: WriteRecord = serde_json::from_value(Value::Array(entries)).expect("deserializes");
    assert_eq!(decoded.0.len(), 2 * NOTED_PATHS.len(), "{decoded:?}");
    let receipt = without(&value, &decoded);
    assert_eq!(
        receipt.as_ref(),
        &json!({"_meta": {}, "text": "backend"}),
        "{receipt}"
    );
    scope(async {
        note(Layer::Value, &["trace_id"], &value);
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
/// note, a path past the bounds) is dropped on its own, leaving the good ones.
#[test]
fn a_damaged_record_drops_only_its_bad_entries() {
    for whole in [json!(null), json!({"layer": "value"}), json!(7), json!("x")] {
        let decoded: WriteRecord = serde_json::from_value(whole.clone()).expect("never fails");
        assert!(decoded.is_empty(), "{whole}");
    }
    let good = json!({
        "layer": "value", "dest": ["results", "0", "result", "trace_id"], "kind": ["trace_id"],
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
        with("dest", json!(vec!["x"; 33])),
        with("dest", json!(["x".repeat(257)])),
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

/// MIK-7993 r5b: a record holds at most 256 entries; the rest are dropped.
#[test]
fn a_record_reads_at_most_its_bound_of_entries() {
    let entry = json!({
        "layer": "answer", "dest": ["taskId"], "kind": ["taskId"], "within": [],
        "digest": "636810988c0638ebda7b64c4fcac77cae55b300084dd6c553983f9c1aaf350db",
    });
    let decoded: WriteRecord =
        serde_json::from_value(Value::Array(vec![entry; 300])).expect("never fails");
    assert_eq!(decoded.0.len(), 256);
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

/// A playbook mapping path names the same segments a note does; a wildcard
/// names none.
#[test]
fn a_mapping_path_reads_as_note_segments() {
    assert_eq!(
        mapping_segments("results[0].title"),
        Some(path(&["results", "0", "title"]))
    );
    assert_eq!(mapping_segments(""), Some(Vec::new()));
    assert_eq!(mapping_segments("items[].v"), None);
}

/// A composite step's notes are taken out of the delivery's record, leaving
/// the notes made before it.
#[tokio::test]
async fn taking_since_a_mark_leaves_the_earlier_notes() {
    let value = json!({"trace_id": "t-1", "_cost_warnings": ["w"]});
    let (taken, left) = scope(async {
        note(Layer::Value, &["trace_id"], &value);
        let mark = mark();
        note(Layer::Value, &["_cost_warnings"], &value);
        let taken = take_since(mark);
        (taken, recorded())
    })
    .await;
    assert_eq!(dests(&taken), vec![path(&["_cost_warnings"])]);
    assert_eq!(dests(&left), vec![path(&["trace_id"])]);
}

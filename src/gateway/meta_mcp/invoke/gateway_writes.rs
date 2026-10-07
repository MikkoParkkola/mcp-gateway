// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-7939: the members the gateway wrote into an answer on this call, so a
//! relay receipt rebuilt from the delivered answer leaves exactly those out.
//!
//! A receipt exempts its receiver for the text in it (collusion.rs), so text
//! the gateway wrote must not be in it; a backend member of the same name the
//! gateway did not write must stay. A note binds to what was written: it
//! removes a member only while the member still hashes to the note's digest,
//! so a note left over from a value replaced wholesale removes nothing.

use std::borrow::Cow;
use std::cell::RefCell;
use std::hash::{Hash, Hasher};

use serde_json::Value;

/// Where a noted member lives.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Layer {
    /// The tool value: a wrapped answer's decoded value, or the answer
    /// itself when it is not wrapped.
    Value,
    /// The delivered `result` object (`_signature`).
    Answer,
}

/// One member the gateway wrote.
#[derive(Debug, Clone)]
#[cfg_attr(not(feature = "firewall"), allow(dead_code))]
struct Written {
    layer: Layer,
    path: &'static [&'static str],
    digest: u64,
    /// Order of noting within the delivery, so one invocation's own notes
    /// are told apart from an earlier step's (MIK-7991). Never reused: a
    /// [`rebind`] that drops a note does not free its number.
    seq: u64,
}

/// A delivery's write record.
#[derive(Default)]
struct Writes {
    next: u64,
    list: Vec<Written>,
}

impl Writes {
    fn push(&mut self, written: Written) {
        self.list.push(Written {
            seq: self.next,
            ..written
        });
        self.next += 1;
    }
}

tokio::task_local! {
    static GATEWAY_WRITES: RefCell<Writes>;
}

/// Where an invocation's own notes begin in its delivery's record.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Mark(u64);

/// The members one invocation wrote, stored beside its answer in the
/// response and idempotency caches so a hit served from either restores
/// them (MIK-7991): the hit writes nothing itself, yet serves what the
/// original call wrote.
#[derive(Debug, Clone, Default)]
pub(crate) struct WriteRecord(Vec<Written>);

impl WriteRecord {
    pub(crate) fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

/// Every member the gateway notes. A stored record names its path by these
/// segments, and decoding maps them back here: a path this build does not
/// note is dropped, so that member stays receipted (MIK-7991 r4).
const NOTED_PATHS: &[&[&str]] = &[
    &["recovery"],
    &["_signature"],
    TASK_ID,
    &["trace_id"],
    &["predicted_next"],
    &["_meta", "provenance"],
    &["_security_findings"],
    &["_cost_warnings"],
    &["_cost_suggestion"],
    // MIK-7994: the continuation envelope the gateway mints into an interim
    // answer.
    &["requestState"],
];

/// A note as the sync admission stores it beside a delivery. `seq` is not
/// kept: a restored note is numbered in the replay's own record.
#[derive(serde::Serialize, serde::Deserialize)]
struct StoredWrite {
    layer: Layer,
    path: Vec<String>,
    digest: u64,
}

impl serde::Serialize for WriteRecord {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_seq(self.0.iter().map(|w| {
            StoredWrite {
                layer: w.layer,
                path: w
                    .path
                    .iter()
                    .map(|segment| (*segment).to_string())
                    .collect(),
                digest: w.digest,
            }
        }))
    }
}

impl<'de> serde::Deserialize<'de> for WriteRecord {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let stored = Vec::<StoredWrite>::deserialize(deserializer)?;
        let known = |w: &StoredWrite| {
            NOTED_PATHS
                .iter()
                .copied()
                .find(|path| path.iter().copied().eq(w.path.iter().map(String::as_str)))
        };
        Ok(Self(
            stored
                .iter()
                .filter_map(|w| {
                    Some(Written {
                        layer: w.layer,
                        path: known(w)?,
                        digest: w.digest,
                        seq: 0,
                    })
                })
                .collect(),
        ))
    }
}

/// The current end of the delivery's record; `0` outside a scope.
pub(crate) fn mark() -> Mark {
    Mark(GATEWAY_WRITES.try_with(|w| w.borrow().next).unwrap_or(0))
}

/// The notes made since `mark`, still bound to what they wrote. Empty
/// outside a scope.
pub(crate) fn snapshot_since(mark: Mark) -> WriteRecord {
    WriteRecord(
        GATEWAY_WRITES
            .try_with(|w| {
                w.borrow()
                    .list
                    .iter()
                    .filter(|written| written.seq >= mark.0)
                    .cloned()
                    .collect()
            })
            .unwrap_or_default(),
    )
}

/// The whole delivery's record: what a sync admission stores beside the
/// response it secures (MIK-7991 r4). Empty outside a scope.
pub(crate) fn recorded() -> WriteRecord {
    snapshot_since(Mark(0))
}

/// Add `record` to the delivery's record, as notes of this call. A no-op
/// outside a scope.
pub(crate) fn restore(record: &WriteRecord) {
    let _ = GATEWAY_WRITES.try_with(|w| {
        let mut writes = w.borrow_mut();
        for written in &record.0 {
            writes.push(written.clone());
        }
    });
}

/// Run `delivery` with a write record, beside its receipt collector.
///
/// Not an `async fn`: one would hold `delivery` twice (as its argument and
/// inside the scope it awaits), and the dispatch future it wraps is large
/// enough that the copy overflowed a 2 MiB test thread.
pub(super) fn scope<F: std::future::Future>(
    delivery: F,
) -> impl std::future::Future<Output = F::Output> {
    GATEWAY_WRITES.scope(RefCell::new(Writes::default()), delivery)
}

// ponytail: a DefaultHasher over the member's JSON text; a member the gateway
// writes is small (an id, a hint, advice, a signature block).
fn digest(member: &Value) -> u64 {
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    member.to_string().hash(&mut hasher);
    hasher.finish()
}

fn member<'v>(value: &'v Value, path: &[&str]) -> Option<&'v Value> {
    path.iter().try_fold(value, |at, key| at.get(key))
}

/// Note that the gateway wrote `path` of `value` (at `layer`). A no-op
/// outside a delivery scope or when the member is absent.
pub(crate) fn note(layer: Layer, path: &'static [&'static str], value: &Value) {
    debug_assert!(
        NOTED_PATHS.contains(&path),
        "{path:?} is not in NOTED_PATHS, so a stored record would drop it"
    );
    let Some(written) = member(value, path) else {
        return;
    };
    let _ = GATEWAY_WRITES.try_with(|writes| {
        writes.borrow_mut().push(Written {
            layer,
            path,
            digest: digest(written),
            seq: 0,
        });
    });
}

/// The member a task envelope the gateway built is known by: the task id
/// the gateway minted.
const TASK_ID: &[&str] = &["taskId"];

/// Note that `answer` is a task envelope the gateway built
/// (`BeginOutcome::into_response`).
pub(crate) fn note_task_envelope(answer: &Value) {
    note(Layer::Answer, TASK_ID, answer);
}

/// Whether `answer` is a task envelope the gateway built on this call: a
/// backend answer that merely looks like one is not.
#[cfg(feature = "firewall")]
pub(super) fn built_task_envelope(answer: &Value) -> bool {
    let Some(id) = member(answer, TASK_ID) else {
        return false;
    };
    GATEWAY_WRITES
        .try_with(|writes| {
            let digest = digest(id);
            writes
                .borrow()
                .list
                .iter()
                .any(|w| w.layer == Layer::Answer && w.path == TASK_ID && w.digest == digest)
        })
        .unwrap_or(false)
}

/// Remove from `value` each `layer` member the gateway wrote that still
/// holds what it wrote.
#[cfg(feature = "firewall")]
pub(super) fn strip(value: &mut Value, layer: Layer) {
    let _ = GATEWAY_WRITES.try_with(|writes| remove_owned(value, &writes.borrow().list, layer));
}

/// `value` without what `record` wrote, for a cache or replay hit's receipt:
/// stripped by that entry's own record, never by another step's notes.
/// Borrowed when there is nothing to remove, so a plain hit copies nothing.
#[cfg_attr(not(feature = "firewall"), allow(unused_variables))]
pub(crate) fn without<'v>(value: &'v Value, record: &WriteRecord) -> Cow<'v, Value> {
    #[cfg(feature = "firewall")]
    if !record.0.is_empty() {
        let mut copy = value.clone();
        remove_owned(&mut copy, &record.0, Layer::Value);
        return Cow::Owned(copy);
    }
    Cow::Borrowed(value)
}

#[cfg(feature = "firewall")]
fn remove_owned(value: &mut Value, writes: &[Written], layer: Layer) {
    for w in writes.iter().filter(|w| w.layer == layer) {
        let Some((last, parent)) = w.path.split_last() else {
            continue;
        };
        let owned = member(value, w.path).is_some_and(|m| digest(m) == w.digest);
        if owned && let Some(map) = member_mut(value, parent).and_then(Value::as_object_mut) {
            map.remove(*last);
        }
    }
}

#[cfg(feature = "firewall")]
fn member_mut<'v>(value: &'v mut Value, path: &[&str]) -> Option<&'v mut Value> {
    path.iter().try_fold(value, |at, key| at.get_mut(key))
}

/// A final check rewrote the answer in place (`before` to `after`, both read
/// at `layer`): a note that still owned its member in `before` follows the
/// rewrite; every other note is stale and is dropped, so a later rewrite
/// cannot revive it.
#[cfg(feature = "firewall")]
pub(super) fn rebind(layer: Layer, before: &Value, after: &Value) {
    let _ = GATEWAY_WRITES.try_with(|writes| {
        writes.borrow_mut().list.retain_mut(|w| {
            if w.layer != layer {
                return true;
            }
            let owned = member(before, w.path).is_some_and(|m| digest(m) == w.digest);
            match member(after, w.path) {
                Some(now) if owned => {
                    w.digest = digest(now);
                    true
                }
                _ => false,
            }
        });
    });
}

#[cfg(all(test, feature = "firewall"))]
mod tests {
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

    /// MIK-7991 r4 (R9): a record as the sync admission stores it keeps all
    /// ten noted paths on both layers through a round trip; a stored path
    /// this build does not note drops only that entry; restored, the record
    /// lands after the replay's mark and strips what it wrote.
    #[tokio::test]
    async fn a_stored_record_round_trips_every_noted_path() {
        let value = json!({
            "recovery": {"hint": "retry"}, "_signature": {"sig": "s"}, "taskId": "t-9",
            "trace_id": "t-1", "predicted_next": ["b"], "_meta": {"provenance": {"p": 1}},
            "_security_findings": ["f"], "_cost_warnings": ["w"],
            "_cost_suggestion": {"message": "m"}, "requestState": "rs-1", "text": "backend",
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
        let decoded: WriteRecord =
            serde_json::from_value(Value::Array(entries)).expect("deserializes");
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
}

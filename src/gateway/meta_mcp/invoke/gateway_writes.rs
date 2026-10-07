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

use serde_json::Value;

/// A noted member's fingerprint: SHA-256 over its RFC 8785 canonical JSON
/// (MIK-7993). Durable in a task row, so key order and number spelling must
/// not change it across builds, and a backend that controls the bytes at a
/// known path must not be able to steer a collision.
type Digest = [u8; 32];

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
    /// Where the member lives in the value this record travels with. Starts
    /// as the noted path; a composite boundary rebases it onto the composite's
    /// answer (MIK-7993).
    dest: Vec<String>,
    /// The [`NOTED_PATHS`] entry the note was made as: which gateway member
    /// this is, whatever `dest` became.
    kind: &'static [&'static str],
    /// The part of the noted member that `dest` holds, when a projection
    /// took out less than the whole member; empty otherwise.
    within: Vec<String>,
    digest: Digest,
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
    // MIK-7993 (r4 M1): the response-contract annotations the gateway adds.
    CONTRACT_VIOLATION,
    CONTRACT_REASON,
];

/// The response-contract verdict the gateway writes on a violating answer.
pub(super) const CONTRACT_VIOLATION: &[&str] = &["_contract_violation"];

/// The response-contract reason the gateway writes beside the verdict.
pub(super) const CONTRACT_REASON: &[&str] = &["_contract_reason"];

/// A note as a task row or the sync admission stores it. `seq` is not kept:
/// a restored note is numbered in the replay's own record.
///
/// A stored record is a TRUSTED ownership assertion: the gateway wrote it
/// into a store only its owner can write. The digest binds a note to bytes;
/// it does not prove who wrote them. Reading it back only has to fail open on
/// damage (a dropped note leaves its member receipted), never authenticate.
#[derive(serde::Serialize)]
struct StoredWrite<'w> {
    layer: Layer,
    dest: &'w [String],
    kind: &'static [&'static str],
    within: &'w [String],
    digest: String,
}

impl serde::Serialize for WriteRecord {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_seq(self.0.iter().map(|w| StoredWrite {
            layer: w.layer,
            dest: &w.dest,
            kind: w.kind,
            within: &w.within,
            digest: hex::encode(w.digest),
        }))
    }
}

/// Never fails: whatever the stored value is, a record decodes. A non-list
/// is an empty record, and each entry that does not read as a note this build
/// makes is dropped on its own, so a damaged or older record can never make
/// the row or delivery holding it unreadable (MIK-7993 r5c).
impl<'de> serde::Deserialize<'de> for WriteRecord {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let stored = Value::deserialize(deserializer)?;
        let entries = stored.as_array().map_or(&[][..], Vec::as_slice);
        let decoded: Vec<Written> = entries
            .iter()
            .filter_map(|entry| {
                let written = decode_entry(entry);
                if written.is_none() {
                    tracing::debug!(
                        "a stored gateway write did not read back; its member stays receipted"
                    );
                }
                written
            })
            .collect();
        Ok(Self(decoded))
    }
}

fn decode_entry(entry: &Value) -> Option<Written> {
    let layer = serde_json::from_value(entry.get("layer")?.clone()).ok()?;
    let dest = segments(entry.get("dest")?)?;
    let within = segments(entry.get("within")?)?;
    let kind = segments(entry.get("kind")?)?;
    let kind = NOTED_PATHS
        .iter()
        .copied()
        .find(|path| path.iter().copied().eq(kind.iter().map(String::as_str)))?;
    let hex_digest = entry.get("digest")?.as_str()?;
    if hex_digest.len() != 64
        || !hex_digest
            .bytes()
            .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
    {
        return None;
    }
    let mut digest = [0u8; 32];
    hex::decode_to_slice(hex_digest, &mut digest).ok()?;
    if dest.is_empty() {
        return None;
    }
    Some(Written {
        layer,
        dest,
        kind,
        within,
        digest,
        seq: 0,
    })
}

/// A stored path. No length bound of its own: every record this build writes
/// must read back (MIK-7993 impl F2), and the row it sits in is already held
/// to its record budget on write and on read.
fn segments(value: &Value) -> Option<Vec<String>> {
    value
        .as_array()?
        .iter()
        .map(|segment| segment.as_str().map(str::to_owned))
        .collect()
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

/// Take the notes made since `mark` out of the delivery's record: a
/// composite step's own, to be put back rebased onto the composite's answer
/// (MIK-7993 r5). Empty outside a scope.
pub(crate) fn take_since(mark: Mark) -> WriteRecord {
    WriteRecord(
        GATEWAY_WRITES
            .try_with(|w| {
                let mut writes = w.borrow_mut();
                let (taken, kept): (Vec<Written>, Vec<Written>) = std::mem::take(&mut writes.list)
                    .into_iter()
                    .partition(|written| written.seq >= mark.0);
                writes.list = kept;
                taken
            })
            .unwrap_or_default(),
    )
}

/// The concrete note paths a playbook output mapping's path (`a.b[].c`)
/// reaches inside `value`, in the order `transform::resolve_path` visits
/// them: a wildcard names each element it walks (MIK-7993 impl F3). The
/// engine stores one match as the value itself and several as an array of
/// them, in this order.
pub(crate) fn mapping_paths(value: &Value, path: &str) -> Vec<Vec<String>> {
    fn walk(
        value: &Value,
        path: &[crate::transform::JsonPathSegment],
        at: &mut Vec<String>,
        found: &mut Vec<Vec<String>>,
    ) {
        use crate::transform::JsonPathSegment;
        let Some((first, rest)) = path.split_first() else {
            found.push(at.clone());
            return;
        };
        let children: Vec<(String, &Value)> = match first {
            JsonPathSegment::Key(key) => value
                .as_object()
                .and_then(|map| map.get(key))
                .map(|child| vec![(key.clone(), child)])
                .unwrap_or_default(),
            JsonPathSegment::ArrayIndex(index) => value
                .as_array()
                .and_then(|items| items.get(*index))
                .map(|child| vec![(index.to_string(), child)])
                .unwrap_or_default(),
            JsonPathSegment::ArrayWildcard => value
                .as_array()
                .map(|items| {
                    items
                        .iter()
                        .enumerate()
                        .map(|(index, child)| (index.to_string(), child))
                        .collect()
                })
                .unwrap_or_default(),
        };
        for (segment, child) in children {
            at.push(segment);
            walk(child, rest, at, found);
            at.pop();
        }
    }
    let mut found = Vec::new();
    walk(
        value,
        &crate::transform::parse_json_path(path),
        &mut Vec::new(),
        &mut found,
    );
    found
}

impl WriteRecord {
    /// Every note moved under `prefix`: what it describes now sits at
    /// `prefix` of a composite's answer, inside its value.
    pub(crate) fn rebased(self, prefix: &[String]) -> Self {
        Self(
            self.0
                .into_iter()
                .map(|mut written| {
                    written.layer = Layer::Value;
                    written.dest = prefix.iter().cloned().chain(written.dest).collect();
                    written
                })
                .collect(),
        )
    }

    /// The notes a projection of `from` out of `step` (a step's value)
    /// carries to `to` in a composite's answer. A note inside the projected
    /// value moves with it. A note that holds the projected value (part of
    /// what the gateway wrote was taken out) becomes a note of that part,
    /// but only while the member still holds what was written: a part of
    /// backend bytes is never the gateway's. Any other note does not reach
    /// the answer, and its member there stays receipted.
    pub(crate) fn projected(&self, step: &Value, from: &[String], to: &[String]) -> Self {
        let mut carried = Vec::new();
        for written in &self.0 {
            if let Some(rest) = written.dest.strip_prefix(from) {
                carried.push(Written {
                    layer: Layer::Value,
                    dest: to.iter().chain(rest).cloned().collect(),
                    ..written.clone()
                });
            } else if let Some(inside) = from.strip_prefix(written.dest.as_slice()) {
                let holds = member(step, &written.dest).and_then(digest) == Some(written.digest);
                let Some(part) = member(step, from).filter(|_| holds).and_then(digest) else {
                    continue;
                };
                carried.push(Written {
                    layer: Layer::Value,
                    dest: to.to_vec(),
                    kind: written.kind,
                    within: written.within.iter().chain(inside).cloned().collect(),
                    digest: part,
                    seq: 0,
                });
            }
        }
        Self(carried)
    }
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

// ponytail: no extra bound: a gateway-written member is small (an id, a hint,
// advice, a signature block), and the record budget backs this up on a task
// row.
/// `None` only if `member` cannot be canonicalized, which a parsed `Value`
/// cannot fail; the note is then not taken, and the member stays receipted.
fn digest(member: &Value) -> Option<Digest> {
    let canonical = serde_json_canonicalizer::to_vec(member).ok()?;
    Some(<sha2::Sha256 as sha2::Digest>::digest(&canonical).into())
}

/// The member at `path`. An object segment is a key (a numeric-looking key
/// stays a key); an array segment must be a canonical index. Anything else
/// is no member, so the note is not applied and the member stays receipted.
fn member<'v, S: AsRef<str>>(value: &'v Value, path: &[S]) -> Option<&'v Value> {
    path.iter().try_fold(value, |at, segment| match at {
        Value::Object(map) => map.get(segment.as_ref()),
        Value::Array(items) => index(segment.as_ref()).and_then(|i| items.get(i)),
        _ => None,
    })
}

/// A canonical array index: decimal digits, no sign, no leading zero
/// unless it is `0` itself.
fn index(segment: &str) -> Option<usize> {
    let canonical = segment == "0"
        || (!segment.is_empty()
            && !segment.starts_with('0')
            && segment.bytes().all(|b| b.is_ascii_digit()));
    canonical.then(|| segment.parse().ok()).flatten()
}

/// Note that the gateway wrote `path` of `value` (at `layer`). A no-op
/// outside a delivery scope or when the member is absent.
pub(crate) fn note(layer: Layer, path: &'static [&'static str], value: &Value) {
    debug_assert!(
        NOTED_PATHS.contains(&path),
        "{path:?} is not in NOTED_PATHS, so a stored record would drop it"
    );
    let Some(digest) = member(value, path).and_then(digest) else {
        return;
    };
    let _ = GATEWAY_WRITES.try_with(|writes| {
        writes.borrow_mut().push(Written {
            layer,
            dest: path.iter().map(|segment| (*segment).to_owned()).collect(),
            kind: path,
            within: Vec::new(),
            digest,
            seq: 0,
        });
    });
}

/// Note the response-contract annotations the gateway just wrote into
/// `value` (MIK-7993 r4 M1): its own verdict, never the backend's text.
pub(super) fn note_contract(value: &Value) {
    note(Layer::Value, CONTRACT_VIOLATION, value);
    note(Layer::Value, CONTRACT_REASON, value);
}

/// The member a task envelope the gateway built is known by: the task id
/// the gateway minted.
const TASK_ID: &[&str] = &["taskId"];

/// The continuation the gateway mints in place of a backend's state
/// (MIK-7994).
pub(super) const REQUEST_STATE: &[&str] = &["requestState"];

/// Note that `answer` is a task envelope the gateway built
/// (`BeginOutcome::into_response`).
pub(crate) fn note_task_envelope(answer: &Value) {
    note(Layer::Answer, TASK_ID, answer);
}

/// Whether `answer` is a task envelope the gateway built on this call: a
/// backend answer that merely looks like one is not.
#[cfg(feature = "firewall")]
pub(super) fn built_task_envelope(answer: &Value) -> bool {
    owns(Layer::Answer, TASK_ID, answer)
}

/// Whether the gateway wrote `path` of `value` (at `layer`) on this call and
/// the member still holds what it wrote: a backend member of that name does
/// not count.
pub(super) fn owns(layer: Layer, path: &[&str], value: &Value) -> bool {
    let Some(digest) = member(value, path).and_then(digest) else {
        return false;
    };
    GATEWAY_WRITES
        .try_with(|writes| {
            writes.borrow().list.iter().any(|w| {
                w.layer == layer
                    && w.digest == digest
                    && w.dest.iter().map(String::as_str).eq(path.iter().copied())
            })
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
        let Some((last, parent)) = w.dest.split_last() else {
            continue;
        };
        let owned = member(value, &w.dest).and_then(digest) == Some(w.digest);
        if owned && let Some(map) = member_mut(value, parent).and_then(Value::as_object_mut) {
            map.remove(last);
        }
    }
}

/// [`member`], mutable: the same segment rules.
#[cfg(feature = "firewall")]
fn member_mut<'v>(value: &'v mut Value, path: &[String]) -> Option<&'v mut Value> {
    path.iter().try_fold(value, |at, segment| match at {
        Value::Object(map) => map.get_mut(segment),
        Value::Array(items) => index(segment).and_then(|i| items.get_mut(i)),
        _ => None,
    })
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
            let owned = member(before, &w.dest).and_then(digest) == Some(w.digest);
            match member(after, &w.dest).and_then(digest) {
                Some(now) if owned => {
                    w.digest = now;
                    true
                }
                _ => false,
            }
        });
    });
}

#[cfg(all(test, feature = "firewall"))]
#[path = "gateway_writes_tests.rs"]
mod tests;

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

use std::cell::RefCell;
use std::hash::{Hash, Hasher};

use serde_json::Value;

/// Where a noted member lives.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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
}

tokio::task_local! {
    static GATEWAY_WRITES: RefCell<Vec<Written>>;
}

/// Run `delivery` with a write record, beside its receipt collector.
///
/// Not an `async fn`: one would hold `delivery` twice (as its argument and
/// inside the scope it awaits), and the dispatch future it wraps is large
/// enough that the copy overflowed a 2 MiB test thread.
pub(super) fn scope<F: std::future::Future>(
    delivery: F,
) -> impl std::future::Future<Output = F::Output> {
    GATEWAY_WRITES.scope(RefCell::new(Vec::new()), delivery)
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
    let Some(written) = member(value, path) else {
        return;
    };
    let _ = GATEWAY_WRITES.try_with(|writes| {
        writes.borrow_mut().push(Written {
            layer,
            path,
            digest: digest(written),
        });
    });
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
    let Some(written) = member(value, path) else {
        return false;
    };
    let digest = digest(written);
    GATEWAY_WRITES
        .try_with(|writes| {
            writes
                .borrow()
                .iter()
                .any(|w| w.layer == layer && w.path == path && w.digest == digest)
        })
        .unwrap_or(false)
}

/// Remove from `value` each `layer` member the gateway wrote that still
/// holds what it wrote.
#[cfg(feature = "firewall")]
pub(super) fn strip(value: &mut Value, layer: Layer) {
    let _ = GATEWAY_WRITES.try_with(|writes| {
        for w in writes.borrow().iter().filter(|w| w.layer == layer) {
            let Some((last, parent)) = w.path.split_last() else {
                continue;
            };
            let owned = member(value, w.path).is_some_and(|m| digest(m) == w.digest);
            if owned && let Some(map) = member_mut(value, parent).and_then(Value::as_object_mut) {
                map.remove(*last);
            }
        }
    });
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
        writes.borrow_mut().retain_mut(|w| {
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
}

// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! `MIK-8408` stage 2: capture a stored plan delivery's committed in-plan
//! receipts into the firewall's replay store at commit (E1, F1, H2), and
//! stage them again for the reader when the stored answer is served
//! again (E2, F2, F5, H3). A child of `relay`, so it shares its staged
//! receipts and task-locals without widening any of them.

use std::cell::RefCell;
use std::future::Future;
use std::time::Duration;

use serde_json::Value;

#[cfg(feature = "firewall")]
use super::{Kind, RELAY_RECEIPTS, Receipt};
use super::{MetaMcp, PLAN_STEP, RelayKey};
use crate::gateway::task_service::CommittedTask;

/// The stored entry a delivery's answer is retained under, or a replay
/// serves (`MIK-8408` F1): carried beside the receipts so a commit
/// captures them under it, without changing `SyncAdmission::Replay`.
/// Only the firewall build reads a key (at capture and at replay), so
/// without it the key is the unit placeholder the `Staging` alias in
/// `relay` uses for the same split, and the notes below discard theirs.
#[cfg(feature = "firewall")]
#[derive(Clone)]
pub(super) enum CaptureKey {
    /// A retained sync delivery: admission identity, round, operation.
    Sync {
        identity: String,
        round: String,
        operation: String,
    },
    /// A stored task row, at one revision of it.
    Task { id: String, revision: u64 },
}
#[cfg(not(feature = "firewall"))]
pub(super) type CaptureKey = ();

/// A stored entry to capture this delivery's in-plan receipts under,
/// live for `retention` (the stored entry's own retention).
#[cfg(feature = "firewall")]
pub(super) struct Capture {
    key: CaptureKey,
    retention: Duration,
}
#[cfg(not(feature = "firewall"))]
pub(super) type Capture = ();

/// The calls one delivery dispatched, `(label, server, tool)` each (H2).
pub(super) type ReplayCallList = Vec<(Option<u32>, String, String)>;

/// Run `delivery` with only a gateway-writes record: a delivery with
/// relay detection off stages no receipt, but what the gateway writes
/// into its stored answer is still noted, so a later replay with
/// detection on never receipts the gateway's own text (`MIK-8408` D5).
pub(crate) fn collecting_writes<F: Future>(delivery: F) -> impl Future<Output = F::Output> {
    super::super::gateway_writes::scope(delivery)
}

/// Run `delivery` with the replay capture, lookup and call list of one
/// delivery, beside its receipt collector.
pub(super) fn scope<F: Future>(delivery: F) -> impl Future<Output = F::Output> {
    super::REPLAY_CAPTURE.scope(
        RefCell::new(None),
        super::REPLAY_LOOKUP.scope(
            RefCell::new(None),
            super::REPLAY_CALLS.scope(RefCell::new(Vec::new()), delivery),
        ),
    )
}

/// Note the call `args` (a `{server, tool, ..}` envelope) completed, under
/// the plan step label it ran under (H2): beside
/// `dispatch_log::note_completed`, under the same rule, into this
/// delivery's own list, which exists on the request path too. A no-op
/// outside a collector.
pub(crate) fn note_replay_call(args: &Value) {
    let (Some(server), Some(tool)) = (
        args.get("server").and_then(Value::as_str),
        args.get("tool").and_then(Value::as_str),
    ) else {
        return;
    };
    let label = PLAN_STEP.try_with(|label| *label).ok().flatten();
    let _ = super::REPLAY_CALLS.try_with(|calls| {
        let mut calls = calls.borrow_mut();
        let call = (label, server.to_owned(), tool.to_owned());
        if !calls.contains(&call) {
            calls.push(call);
        }
    });
}

/// The stored entry's replay key parts for a sync admission (F1): the
/// admission identity and operation hashes, recomputed from the same
/// request exactly as `Request::prepare` computes them.
pub(crate) fn sync_replay_key(principal: &str, key: &str, operation: &Value) -> (String, String) {
    let identity = crate::hashing::canonical_json_sha256(&serde_json::json!([
        "mcp-gateway.execution-admission.v1",
        principal,
        key
    ]));
    (identity, crate::hashing::canonical_json_sha256(operation))
}

/// [`note_sync_capture`] from a [`sync_replay_key`], when one was taken.
pub(crate) fn note_sync_capture_key(key: Option<&(String, String)>, round: &str) {
    if let Some((identity, operation)) = key {
        note_sync_capture(identity.clone(), round.to_owned(), operation.clone());
    }
}

/// [`note_sync_lookup`] from a [`sync_replay_key`], when one was taken.
pub(crate) fn note_sync_lookup_key(key: Option<&(String, String)>, round: &str) {
    if let Some((identity, operation)) = key {
        note_sync_lookup(identity.clone(), round.to_owned(), operation.clone());
    }
}

/// Note that this delivery's answer is stored under the sync admission
/// key `(identity, round, operation)`, recomputed from the same request
/// admission admitted (F1): its committed in-plan receipts are captured
/// under it at commit, live for the retained result's retention. The
/// first note wins: an inner keyed call never takes the outer
/// delivery's key.
pub(crate) fn note_sync_capture(identity: String, round: String, operation: String) {
    #[cfg(feature = "firewall")]
    {
        let capture = Capture {
            key: CaptureKey::Sync {
                identity,
                round,
                operation,
            },
            retention: Duration::from_secs(crate::idempotency::admission::RETENTION_SECS),
        };
        let _ = super::REPLAY_CAPTURE.try_with(|slot| {
            let mut slot = slot.borrow_mut();
            if slot.is_none() {
                *slot = Some(capture);
            }
        });
    }
    #[cfg(not(feature = "firewall"))]
    let _ = (identity, round, operation);
}

/// Note that this delivery serves the retained sync answer stored under
/// `(identity, round, operation)`: a plan replay stages its entry.
pub(crate) fn note_sync_lookup(identity: String, round: String, operation: String) {
    #[cfg(feature = "firewall")]
    {
        let key = CaptureKey::Sync {
            identity,
            round,
            operation,
        };
        let _ = super::REPLAY_LOOKUP.try_with(|slot| {
            let mut slot = slot.borrow_mut();
            if slot.is_none() {
                *slot = Some(key);
            }
        });
    }
    #[cfg(not(feature = "firewall"))]
    let _ = (identity, round, operation);
}

/// Note that this delivery settles task `id` at `revision`: its committed
/// in-plan receipts are captured under that key at commit, live for
/// `retention` (the task's remaining retention).
pub(crate) fn note_task_capture(id: String, revision: u64, retention: Duration) {
    #[cfg(feature = "firewall")]
    {
        let capture = Capture {
            key: CaptureKey::Task { id, revision },
            retention,
        };
        let _ = super::REPLAY_CAPTURE.try_with(|slot| *slot.borrow_mut() = Some(capture));
    }
    #[cfg(not(feature = "firewall"))]
    let _ = (id, revision, retention);
}

/// This delivery's answer was not retained: nothing is captured for it.
pub(crate) fn cancel_replay_capture() {
    let _ = super::REPLAY_CAPTURE.try_with(|slot| *slot.borrow_mut() = None);
}

/// Take this delivery's capture and calls, for a collector that hands
/// its staged receipts to a later commit (`collecting_staged`).
pub(super) fn take_capture() -> (Option<Capture>, ReplayCallList) {
    let capture = super::REPLAY_CAPTURE
        .try_with(|slot| slot.borrow_mut().take())
        .unwrap_or(None);
    let calls = super::REPLAY_CALLS
        .try_with(|calls| std::mem::take(&mut *calls.borrow_mut()))
        .unwrap_or_default();
    (capture, calls)
}

/// Capture `receipts`, the committed receipts about to be recorded,
/// under `capture`'s stored key: their in-plan and seam receipts exactly
/// as `record_digest` gets them (after the keep and seam passes), with
/// the delivery's `calls`. No in-plan receipt among them is a non-plan
/// commit under the key: its entry goes (F1).
#[cfg(feature = "firewall")]
pub(super) fn capture_commit(
    fw: &crate::security::firewall::Firewall,
    capture: Option<Capture>,
    receipts: &[Receipt],
    calls: ReplayCallList,
) {
    let Some(capture) = capture else {
        return;
    };
    let sources: Vec<crate::security::firewall::ReplaySource<'_>> = receipts
        .iter()
        .filter(|r| {
            !r.pending_retain && r.kind != Kind::Replayed && (r.in_plan || r.kind == Kind::Seam)
        })
        .map(|r| (&r.digest, r.step, r.server.as_str(), r.tool.as_str()))
        .collect();
    match &capture.key {
        CaptureKey::Sync {
            identity,
            round,
            operation,
        } => {
            if sources.is_empty() {
                fw.remove_sync_replay(identity, round, operation);
            } else {
                fw.store_sync_replay(
                    identity,
                    round,
                    operation,
                    &sources,
                    calls,
                    capture.retention,
                );
            }
        }
        CaptureKey::Task { id, revision } => {
            if sources.is_empty() {
                fw.remove_task_replay(id, *revision);
            } else {
                fw.store_task_replay(id, *revision, &sources, calls, capture.retention);
            }
        }
    }
}

/// Stage the replayed receipts of the retained sync plan answer this
/// delivery serves, for `who` (E2): only the stored entry's snapshot
/// receipts, never a rebuild from the stored answer (R9).
pub(super) fn stage_plan_replay(meta: &MetaMcp, who: RelayKey<'_>) {
    #[cfg(feature = "firewall")]
    {
        let Some(fw) = meta.firewall.as_deref().filter(|fw| fw.relay_active()) else {
            return;
        };
        let key = super::REPLAY_LOOKUP
            .try_with(|slot| slot.borrow().clone())
            .ok()
            .flatten();
        let Some(CaptureKey::Sync {
            identity,
            round,
            operation,
        }) = key
        else {
            return;
        };
        let Some((digests, calls)) = fw.sync_replay_digests(&identity, &round, &operation) else {
            return;
        };
        stage_entries(fw, who, digests, &calls, None);
    }
    #[cfg(not(feature = "firewall"))]
    let _ = (meta, who);
}

/// Stage the replayed receipts of the stored multi-target task
/// `stored`, for `who` (E2): looked up by `(task id, revision)`, each
/// source checked against the task's recorded targets.
pub(crate) fn stage_task_replay(meta: &MetaMcp, who: RelayKey<'_>, stored: &CommittedTask) {
    #[cfg(feature = "firewall")]
    {
        let Some(fw) = meta.firewall.as_deref().filter(|fw| fw.relay_active()) else {
            return;
        };
        let Some((digests, calls)) = fw.task_replay_digests(stored.task.id(), stored.revision)
        else {
            return;
        };
        let targets: Vec<(&str, &str)> =
            crate::gateway::task_service::Target::pairs(&stored.targets);
        stage_entries(fw, who, digests, &calls, Some(&targets));
    }
    #[cfg(not(feature = "firewall"))]
    let _ = (meta, who, stored);
}

/// Stage each of `digests` for `who`, under its own source and label
/// (the outer label inside a live plan step), marked replayed. With
/// `targets` (the task path), a plain source must be among them and a
/// seam's composite source only if every constituent is. If `calls`
/// show a label with more than one distinct call, every seam receipt
/// of the entry is dropped, counted (F5, H3); inner receipts still
/// stage under their own source.
#[cfg(feature = "firewall")]
fn stage_entries(
    fw: &crate::security::firewall::Firewall,
    who: RelayKey<'_>,
    digests: Vec<crate::security::firewall::ReplayedDigest>,
    calls: &ReplayCallList,
    targets: Option<&[(&str, &str)]>,
) {
    if RELAY_RECEIPTS.try_with(|_| ()).is_err() {
        return;
    }
    let nested = has_nested_label(calls);
    let in_plan = PLAN_STEP.try_with(|_| ()).is_ok();
    for entry in digests {
        if let Some(targets) = targets
            && !source_in_targets(&entry, targets)
        {
            continue;
        }
        if nested && entry.seam_sources.is_some() {
            fw.count_nested_seam_drop();
            continue;
        }
        let step = PLAN_STEP.try_with(|outer| *outer).unwrap_or(entry.label);
        let receipt = Receipt {
            key: who.key.to_owned(),
            keyed: who.keyed,
            server: entry.server,
            tool: entry.tool,
            digest: entry.digest,
            in_plan,
            pending_retain: false,
            step,
            kind: Kind::Replayed,
        };
        let _ = RELAY_RECEIPTS.try_with(|receipts| receipts.borrow_mut().push(receipt));
    }
}

/// Whether `entry`'s source is one of `targets`: a composite seam only
/// when every constituent `server:tool` is (E2's composite fix).
#[cfg(feature = "firewall")]
fn source_in_targets(
    entry: &crate::security::firewall::ReplayedDigest,
    targets: &[(&str, &str)],
) -> bool {
    match &entry.seam_sources {
        None => targets.contains(&(entry.server.as_str(), entry.tool.as_str())),
        Some(sources) => sources.iter().all(|source| {
            source
                .split_once(':')
                .is_some_and(|pair| targets.contains(&pair))
        }),
    }
}

/// Whether any label in `calls` ran more than one distinct call (a
/// nested plan under one step label).
#[cfg(feature = "firewall")]
fn has_nested_label(calls: &ReplayCallList) -> bool {
    let mut by_label: std::collections::HashMap<u32, Vec<(&str, &str)>> =
        std::collections::HashMap::new();
    for (label, server, tool) in calls {
        let Some(label) = label else {
            continue;
        };
        let seen = by_label.entry(*label).or_default();
        let call = (server.as_str(), tool.as_str());
        if !seen.contains(&call) {
            seen.push(call);
        }
    }
    by_label.values().any(|seen| seen.len() > 1)
}

#[cfg(all(test, feature = "firewall"))]
#[path = "relay_replay_tests.rs"]
mod tests;

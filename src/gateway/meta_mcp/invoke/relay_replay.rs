// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! `MIK-8408` stage 2: capture a stored plan delivery's committed in-plan
//! receipts into the firewall's replay store at commit (E1, F1, H2), and
//! stage them again for the reader when the stored answer is served
//! again (E2, F2, F5, H3). A child of `relay`, so it shares its staged
//! receipts and task-locals without widening any of them.

use std::cell::RefCell;
use std::future::Future;
#[cfg(feature = "firewall")]
use std::time::Duration;

use serde_json::Value;

#[cfg(feature = "firewall")]
use super::{Kind, RELAY_RECEIPTS, Receipt};
use super::{MetaMcp, PLAN_STEP, RelayKey};
use crate::gateway::task_service::CommittedTask;

/// The stored entry a delivery's answer is retained under, or a replay
/// serves (`MIK-8408` F1): carried beside the receipts so a commit
/// captures them under it, without changing `SyncAdmission::Replay`.
/// It is the firewall store's own key (MIK-8662), so capture and replay
/// cannot disagree on its shape. Only the firewall build reads a key (at
/// capture and at replay), so without it the key is the unit placeholder
/// the `Staging` alias in `relay` uses for the same split, and the notes
/// below discard theirs.
#[cfg(feature = "firewall")]
pub(super) use crate::security::firewall::StoredKey as CaptureKey;
#[cfg(not(feature = "firewall"))]
pub(super) type CaptureKey = ();

/// A stored entry to capture this delivery's in-plan receipts under,
/// live for `retention` (the stored entry's own retention).
#[cfg(feature = "firewall")]
pub(super) struct Capture {
    key: CaptureKey,
    retention: Duration,
    /// Digest of the delivered answer the captured receipts were kept
    /// against (F4), folded in at [`take_capture`] from the answer the
    /// final pass noted; `None` when it noted none.
    answer_digest: Option<String>,
}
#[cfg(not(feature = "firewall"))]
pub(super) type Capture = ();

tokio::task_local! {
    /// `canonical_json_sha256` of the plan answer this delivery's in-plan
    /// receipts were last kept against, for the capture (F4). Noted by
    /// the final pass, which holds the answer; the capture key may be
    /// noted only later (a task settles after its receipt pass), so it
    /// travels in its own slot and is folded into the capture when the
    /// collector takes it.
    static CAPTURE_ANSWER: RefCell<Option<String>>;
    /// The answer digest of the stored entry this delivery staged its
    /// replayed receipts from, for the final pass to gate each kept
    /// receipt on (F4). One stored entry stages into one delivery, as
    /// the lookup key beside it already assumes.
    static STORED_ANSWER: RefCell<Option<String>>;
    /// The pending replay entries this delivery holds: its own capture's
    /// (taken at judge) and each replayed entry's, settled at its write.
    static HELD: RefCell<Held>;
}

/// A delivery's handles on pending replay entries (ADR-029,
/// pending-snapshot rule).
#[derive(Debug, Default)]
pub(crate) struct Held {
    /// Its own capture's handle, discarded when admission does not retain
    /// the answer (E1).
    #[cfg(feature = "firewall")]
    pub(super) captured: Option<crate::security::firewall::ReplayHandle>,
    /// One per replayed entry it delivers.
    #[cfg(feature = "firewall")]
    pub(super) replayed: Vec<crate::security::firewall::ReplayHandle>,
}

impl Held {
    /// No handles.
    pub(super) const fn new() -> Self {
        Self {
            #[cfg(feature = "firewall")]
            captured: None,
            #[cfg(feature = "firewall")]
            replayed: Vec::new(),
        }
    }

    /// Settle every handle at the delivery's write under `generation`;
    /// dropped instead (released) when the write delivered no result.
    #[cfg(feature = "firewall")]
    pub(super) fn settle(
        self,
        fw: &crate::security::firewall::Firewall,
        delivered: bool,
        generation: &crate::config_reload::Generation,
    ) {
        if !delivered {
            return;
        }
        for handle in self.captured.into_iter().chain(self.replayed) {
            fw.settle_replay(handle, generation);
        }
    }

    /// Admission did not retain the answer (E1): its own capture goes.
    #[cfg_attr(not(feature = "firewall"), allow(clippy::unused_self))]
    pub(super) fn discard_captured(&mut self) {
        #[cfg(feature = "firewall")]
        if let Some(handle) = self.captured.take() {
            handle.discard();
        }
    }
}

/// Hold `handle` for this delivery's write.
#[cfg(feature = "firewall")]
fn hold_replay_handle(handle: Option<crate::security::firewall::ReplayHandle>) {
    if let Some(handle) = handle {
        let _ = HELD.try_with(|held| held.borrow_mut().replayed.push(handle));
    }
}

/// Take this delivery's held handles, for a collector that hands its
/// staged receipts to a later commit.
pub(super) fn take_held() -> Held {
    HELD.try_with(|held| std::mem::take(&mut *held.borrow_mut()))
        .unwrap_or_default()
}

/// The calls one delivery dispatched, `(label, server, tool)` each (H2).
pub(super) use crate::security::ReplayCalls as ReplayCallList;

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
            super::REPLAY_CALLS.scope(
                RefCell::new(Vec::new()),
                CAPTURE_ANSWER.scope(
                    RefCell::new(None),
                    STORED_ANSWER.scope(
                        RefCell::new(None),
                        HELD.scope(RefCell::new(Held::default()), delivery),
                    ),
                ),
            ),
        ),
    )
}

/// Note `answer`, the plan answer this delivery's in-plan receipts were
/// kept against, by its `canonical_json_sha256`: the digest the capture
/// stores beside the receipts (F4). The last note wins, as the final
/// pass is the last keep. Hashes on every call (relay detection on, a
/// delivery with in-plan receipts); the digest is kept only inside a
/// collector.
#[cfg(feature = "firewall")]
pub(super) fn note_capture_answer(answer: &Value) {
    let digest = crate::hashing::canonical_json_sha256(answer);
    let _ = CAPTURE_ANSWER.try_with(|slot| *slot.borrow_mut() = Some(digest));
}

/// The answer digest of the stored entry whose replayed receipts this
/// delivery staged, when one staged (F4).
#[cfg(feature = "firewall")]
pub(super) fn stored_answer_digest() -> Option<String> {
    STORED_ANSWER
        .try_with(|slot| slot.borrow().clone())
        .ok()
        .flatten()
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
/// request exactly as `Request::prepare` computes them — the identity
/// through admission's own [`admission_identity`], never a second
/// spelling of its domain or hash, so an admission change cannot make
/// every sync replay silently miss.
///
/// [`admission_identity`]: crate::idempotency::admission::admission_identity
pub(crate) fn sync_replay_key(principal: &str, key: &str, operation: &Value) -> (String, String) {
    let identity = crate::idempotency::admission::admission_identity(principal, key);
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
            answer_digest: None,
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

/// This delivery's answer was not retained: nothing is captured for it,
/// and a capture already taken pending goes (E1).
pub(crate) fn cancel_replay_capture() {
    let _ = super::REPLAY_CAPTURE.try_with(|slot| *slot.borrow_mut() = None);
    let _ = HELD.try_with(|held| held.borrow_mut().discard_captured());
}

/// Whether `capture` is a retained synchronous answer's (captured pending
/// at judge), not a task's (captured where it is stored).
#[cfg(feature = "firewall")]
pub(super) fn is_sync_capture(capture: Option<&Capture>) -> bool {
    matches!(
        capture,
        Some(Capture {
            key: CaptureKey::Sync { .. },
            ..
        })
    )
}

/// Capture this delivery's retained synchronous answer now, pending,
/// before admission publishes it for replay, so a retry that finds the
/// stored answer finds its snapshot too. `receipts` are its final
/// receipts. A task's entry is persisted in its row instead.
#[cfg(feature = "firewall")]
pub(super) fn capture_pending_now(fw: &crate::security::firewall::Firewall, receipts: &[Receipt]) {
    let is_sync = super::REPLAY_CAPTURE
        .try_with(|slot| is_sync_capture(slot.borrow().as_ref()))
        .unwrap_or(false);
    if !is_sync {
        return;
    }
    let (capture, calls) = take_capture();
    let handle = capture_commit(fw, capture, receipts, calls);
    let _ = HELD.try_with(|held| held.borrow_mut().captured = handle);
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
    let answer = CAPTURE_ANSWER
        .try_with(|slot| slot.borrow_mut().take())
        .unwrap_or(None);
    #[cfg(feature = "firewall")]
    let capture = capture.map(|mut capture| {
        capture.answer_digest = answer;
        capture
    });
    #[cfg(not(feature = "firewall"))]
    let _ = answer;
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
) -> Option<crate::security::firewall::ReplayHandle> {
    let Capture {
        key,
        retention,
        answer_digest,
    } = capture?;
    let sources = replay_sources(receipts);
    // No candidates removes, never stores: `store_replay` returns early
    // with relay detection off, which would keep the prior entry (F1).
    if sources.is_empty() {
        fw.remove_replay(&key);
        None
    } else {
        let answer_digest = answer_digest.as_deref().unwrap_or("");
        fw.store_replay(key, &sources, calls, answer_digest, retention)
    }
}

/// The committed receipts a capture snapshots: in-plan and seam receipts
/// as `record_digest` gets them, never one still pending its retain or
/// one itself replayed. The one filter a capture and a persisted task
/// snapshot share, so the two hold the same receipts.
#[cfg(feature = "firewall")]
fn replay_sources(receipts: &[Receipt]) -> Vec<crate::security::firewall::ReplaySource<'_>> {
    receipts
        .iter()
        .filter(|r| {
            !r.pending_retain && r.kind != Kind::Replayed && (r.in_plan || r.kind == Kind::Seam)
        })
        .map(|r| (&r.digest, r.step, r.server.as_str(), r.tool.as_str()))
        .collect()
}

/// The persisted replay snapshot of the task result `stored` this settle
/// writes: built from what this delivery staged so far, read in
/// place (the commit after the settle still records it), for the settle's
/// own compare-and-set to store. `None` with relay detection off or
/// nothing to replay.
pub(crate) fn persisted_task_replay(meta: &MetaMcp, stored: &Value) -> Option<Value> {
    #[cfg(feature = "firewall")]
    {
        let fw = meta.firewall.as_deref().filter(|fw| fw.relay_active())?;
        let answer = CAPTURE_ANSWER
            .try_with(|slot| slot.borrow().clone())
            .ok()
            .flatten()
            .unwrap_or_default();
        let calls = super::REPLAY_CALLS
            .try_with(|calls| calls.borrow().clone())
            .unwrap_or_default();
        RELAY_RECEIPTS
            .try_with(|receipts| {
                let receipts = receipts.borrow();
                fw.persisted_replay(&replay_sources(&receipts), &calls, &answer, stored)
            })
            .ok()
            .flatten()
    }
    #[cfg(not(feature = "firewall"))]
    {
        let _ = (meta, stored);
        None
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
        // Sync keys only: a task's stored entry stages through
        // `stage_task_replay`, never from the sync lookup slot.
        let Some(key @ CaptureKey::Sync { .. }) = key else {
            return;
        };
        let Some((digests, calls, handle)) = fw.replay_digests_for_delivery(&key) else {
            return;
        };
        hold_replay_handle(handle);
        stage_entries(fw, who, digests, &calls, None);
    }
    #[cfg(not(feature = "firewall"))]
    let _ = (meta, who);
}

/// Stage the replayed receipts of the stored task `stored`, for `who`
/// (E2): looked up by `(task id, revision)`, each source checked against
/// the task's recorded targets. Returns whether that one lookup found
/// an entry, so a caller with a fallback for a missing entry need not
/// look up (and count) a second time.
pub(crate) fn stage_task_replay(meta: &MetaMcp, who: RelayKey<'_>, stored: &CommittedTask) -> bool {
    #[cfg(feature = "firewall")]
    {
        let Some(fw) = meta.firewall.as_deref().filter(|fw| fw.relay_active()) else {
            return false;
        };
        let key = CaptureKey::Task {
            id: stored.task.id().to_owned(),
            revision: stored.revision,
        };
        // The entry in memory, else rebuilt from the row's own
        // snapshot, pending and held by this delivery until its write; the
        // task's TTL bounds it from this read (24 h without one).
        let retention = stored.task.ttl_ms().map_or(
            Duration::from_secs(crate::idempotency::admission::RETENTION_SECS),
            Duration::from_millis,
        );
        let crate::security::firewall::Adopted::Held(digests, calls, handle) =
            fw.adopt_replay(&key, stored.replay_snapshot.as_deref(), retention)
        else {
            return false;
        };
        hold_replay_handle(handle);
        let targets: Vec<(&str, &str)> =
            crate::gateway::task_service::Target::pairs(&stored.targets);
        stage_entries(fw, who, digests, &calls, Some(&targets));
        true
    }
    #[cfg(not(feature = "firewall"))]
    {
        let _ = (meta, who, stored);
        false
    }
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
    if let Some(first) = digests.first() {
        let _ =
            STORED_ANSWER.try_with(|slot| *slot.borrow_mut() = Some(first.answer_digest.clone()));
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
    let mut by_label: std::collections::HashMap<u32, (&str, &str)> =
        std::collections::HashMap::new();
    for (label, server, tool) in calls {
        let Some(label) = label else {
            continue;
        };
        let call = (server.as_str(), tool.as_str());
        match by_label.get(label) {
            Some(first) if *first != call => return true,
            Some(_) => {}
            None => {
                by_label.insert(*label, call);
            }
        }
    }
    false
}

#[cfg(all(test, feature = "firewall"))]
#[path = "relay_replay_tests.rs"]
mod tests;

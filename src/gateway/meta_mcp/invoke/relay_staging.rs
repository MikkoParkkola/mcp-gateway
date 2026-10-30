// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The receipt collection scope: a delivery's staged receipts, from the
//! collector that opens them to the commit or discard that closes them.
//! A child of `relay`, so it shares the task-locals without widening any.

use std::cell::RefCell;

use serde_json::Value;

use super::super::gateway_writes;
use super::{
    MetaMcp, PLAN_STEP, RELAY_DELIVERS, RELAY_RECEIPTS, RELAY_STAGED, Receipt, RelayKey, Staging,
    receipt_with, replay, seams,
};

/// Run one plan step's dispatch: the receipts it stages are a plan's, under
/// `label`, the step as the plan's answer names it. A plan run
/// inside a step keeps the outer step's label: the outer answer names that
/// step, and the inner plan's own labels mean nothing there.
pub(crate) async fn plan_step<F: std::future::Future>(label: Option<u32>, step: F) -> F::Output {
    let label = PLAN_STEP.try_with(|outer| *outer).unwrap_or(label);
    PLAN_STEP.scope(label, step).await
}

/// Whether this task is inside a plan step: a `gateway_execute` chain step or
/// a playbook step. Set on the step's call, so anything nested in it inherits
/// it. The task worker's clock wait is for a single direct call only;
/// a composite keeps refusing on a clock before 1970.
pub(crate) fn in_plan_step() -> bool {
    PLAN_STEP.try_with(|_| ()).is_ok()
}

/// Run `delivery` with a receipt collector: the HTTP and stdio dispatches
/// (finalize included) and a task's execution. Dropping the scope discards
/// what was staged; only a commit records.
pub(crate) async fn collecting<F: std::future::Future>(delivery: F) -> F::Output {
    RELAY_RECEIPTS
        .scope(
            RefCell::new(Vec::new()),
            RELAY_STAGED.scope(
                Staging::default(),
                gateway_writes::scope(seams::scope(replay::scope(delivery))),
            ),
        )
        .await
}

/// Receipts staged by one delivery whose recording waits for the frame's
/// verdict: the stdio route judges the answer after the dispatch that staged
/// them (COLLUDE.1 x MIN.2). Dropped uncommitted, they record nothing.
#[cfg_attr(not(feature = "firewall"), allow(dead_code))]
pub(crate) struct StagedReceipts {
    #[cfg(feature = "firewall")]
    fw: Option<std::sync::Arc<crate::security::firewall::Firewall>>,
    pub(super) receipts: Vec<Receipt>,
    /// The stored key the delivery's in-plan receipts are captured under
    /// at commit, taken from its collector.
    capture: Option<replay::Capture>,
    /// The calls the delivery dispatched, with their labels (H2).
    calls: replay::ReplayCallList,
}

impl StagedReceipts {
    /// Nothing staged: relay detection was off for the delivery.
    pub(crate) const fn none() -> Self {
        Self {
            #[cfg(feature = "firewall")]
            fw: None,
            receipts: Vec::new(),
            capture: None,
            calls: Vec::new(),
        }
    }

    /// The delivery's answer was not retained: capture nothing for it.
    pub(crate) fn drop_replay_capture(&mut self) {
        self.capture = None;
    }

    /// Record what was staged when the answer that was written `delivered` a
    /// result; drop it otherwise.
    #[cfg_attr(
        not(feature = "firewall"),
        allow(clippy::needless_pass_by_value, clippy::unused_self)
    )]
    pub(crate) fn commit(self, delivered: bool) {
        #[cfg(feature = "firewall")]
        if delivered && let Some(fw) = self.fw.as_deref() {
            // Snapshot before recording, exactly what
            // `record_digest` gets below.
            replay::capture_commit(fw, self.capture, &self.receipts, self.calls);
            for r in self.receipts.into_iter().filter(|r| !r.pending_retain) {
                let caller = crate::security::firewall::RelayCaller::new(&r.key, r.keyed);
                fw.record_digest(caller, &r.server, &r.tool, &r.digest);
            }
        }
        #[cfg(not(feature = "firewall"))]
        let _ = delivered;
    }
}

/// Run an HTTP `delivery` inside a receipt collector and hand what it staged to
/// the response as [`DeferredReceipts`]: `emit_http`, the last step that can
/// replace the answer, records them. With relay detection off nothing is
/// collected.
pub(crate) async fn collecting_http<F, R>(
    meta: std::sync::Arc<MetaMcp>,
    delivery: F,
) -> axum::response::Response
where
    F: std::future::Future<Output = R>,
    R: axum::response::IntoResponse,
{
    if !meta.relay_active() {
        // No receipts are collected, but what the gateway
        // writes into a stored answer is still noted for its replay.
        return gateway_writes::scope(delivery).await.into_response();
    }
    let ((mut response, answered), staged) = meta
        .collecting_staged(RELAY_DELIVERS.scope(std::cell::Cell::new(false), async {
            let response = delivery.await.into_response();
            (response, RELAY_DELIVERS.with(std::cell::Cell::get))
        }))
        .await;
    response
        .extensions_mut()
        .insert(DeferredReceipts::new(staged, answered));
    response
}

/// Receipts an HTTP answer carries to the last step that can still replace it
/// (the grant slot, the read record): `emit_http` records them only when the
/// answer goes out as built. A replacement is a new response and carries
/// none, so a replaced answer records nothing. `eligible`: the answer
/// delivers a result.
#[derive(Clone)]
pub(crate) struct DeferredReceipts {
    staged: std::sync::Arc<parking_lot::Mutex<Option<StagedReceipts>>>,
    eligible: bool,
}

impl DeferredReceipts {
    pub(crate) fn new(staged: StagedReceipts, eligible: bool) -> Self {
        Self {
            staged: std::sync::Arc::new(parking_lot::Mutex::new(Some(staged))),
            eligible,
        }
    }

    /// Record what was staged when the answer went out as built.
    pub(crate) fn commit(&self, written: bool) {
        if let Some(staged) = self.staged.lock().take() {
            staged.commit(written && self.eligible);
        }
    }
}

impl MetaMcp {
    /// [`collecting`], handing the staged receipts back instead of dropping
    /// them, for a caller that records them after the verdict.
    pub(crate) async fn collecting_staged<F: std::future::Future>(
        &self,
        delivery: F,
    ) -> (F::Output, StagedReceipts) {
        let (output, receipts, capture, calls) = RELAY_RECEIPTS
            .scope(
                RefCell::new(Vec::new()),
                replay::scope(async {
                    let writes = gateway_writes::scope(seams::scope(delivery));
                    let output = RELAY_STAGED.scope(Staging::default(), writes).await;
                    let staged = RELAY_RECEIPTS.with(|r| std::mem::take(&mut *r.borrow_mut()));
                    let (capture, calls) = replay::take_capture();
                    (output, staged, capture, calls)
                }),
            )
            .await;
        let staged = StagedReceipts {
            #[cfg(feature = "firewall")]
            fw: self.firewall.clone(),
            receipts,
            capture,
            calls,
        };
        (output, staged)
    }
}

/// Stage `value` under `fw`, for a route that holds the firewall but not a
/// Meta-MCP (the direct route). A no-op outside a collector.
#[cfg(feature = "firewall")]
pub(crate) fn stage_with(
    fw: &crate::security::firewall::Firewall,
    who: RelayKey<'_>,
    target: (&str, &str),
    value: &Value,
) {
    if let Some(receipt) = receipt_with(fw, who, target, value) {
        // Only a value a receipt was built from, so a row that sees nothing
        // staged also catches receipt construction switched off.
        #[cfg(test)]
        STAGED_FOR_TEST.with(|staged| staged.borrow_mut().push(value.clone()));
        let _ = RELAY_RECEIPTS.try_with(|receipts| receipts.borrow_mut().push(receipt));
    }
}

#[cfg(all(test, feature = "firewall"))]
thread_local! {
    /// Every value the direct route staged on this thread, so a route-level
    /// row can read what a receipt was built from.
    static STAGED_FOR_TEST: std::cell::RefCell<Vec<Value>> =
        const { std::cell::RefCell::new(Vec::new()) };
}

/// Take what [`stage_with`] staged on this thread since the last take.
#[cfg(all(test, feature = "firewall"))]
pub(crate) fn take_staged_for_test() -> Vec<Value> {
    STAGED_FOR_TEST.with(|staged| std::mem::take(&mut *staged.borrow_mut()))
}

/// Record every staged receipt into `fw` when `delivered`; drop them either way.
#[cfg(feature = "firewall")]
pub(crate) fn commit_with(fw: &crate::security::firewall::Firewall, delivered: bool) {
    let receipts = RELAY_RECEIPTS
        .try_with(|receipts| std::mem::take(&mut *receipts.borrow_mut()))
        .unwrap_or_default();
    let (capture, calls) = replay::take_capture();
    if !delivered {
        return;
    }
    // Snapshot before recording, exactly what
    // `record_digest` gets below.
    replay::capture_commit(fw, capture, &receipts, calls);
    for r in receipts.into_iter().filter(|r| !r.pending_retain) {
        let caller = crate::security::firewall::RelayCaller::new(&r.key, r.keyed);
        fw.record_digest(caller, &r.server, &r.tool, &r.digest);
    }
}

/// Drop every staged receipt: what was staged was never delivered (a
/// state-only round the gateway answered for itself).
pub(crate) fn discard_staged() {
    let _ = RELAY_RECEIPTS.try_with(|receipts| receipts.borrow_mut().clear());
}

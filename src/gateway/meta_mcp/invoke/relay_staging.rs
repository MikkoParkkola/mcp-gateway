// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The receipt collection scope: a delivery's staged receipts, from the
//! collector that opens them to the commit or discard that closes them.
//! A child of `relay`, so it shares the task-locals without widening any.

use std::cell::RefCell;

#[cfg(feature = "firewall")]
use serde_json::Value;

use super::super::gateway_writes;
use super::{
    MetaMcp, PLAN_STEP, RELAY_DELIVERS, RELAY_RECEIPTS, RELAY_STAGED, Receipt, Staging, replay,
    seams,
};
#[cfg(feature = "firewall")]
use super::{RelayKey, receipt_with};

/// The seam the funnel rows arm (patterned on `refuse_hook`): reached at the
/// top of each recording funnel, after its caller captured the generation
/// current at delivery and before the funnel records anything.
#[cfg(all(test, feature = "firewall"))]
pub(crate) mod commit_capture_hook {
    use crate::security::firewall::collusion_live_rig::Hook;

    thread_local! {
        static HOOK: Hook = Hook::default();
    }

    pub(crate) fn arm(action: impl FnOnce() + 'static) {
        HOOK.with(|h| h.arm(action));
    }

    /// Called at the top of each funnel.
    pub(crate) fn run() {
        HOOK.with(Hook::run);
    }

    pub(crate) fn reached() -> u32 {
        HOOK.with(Hook::reached)
    }
}

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
    /// Its handles on pending replay entries, settled at the write.
    held: replay::Held,
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
            held: replay::Held::new(),
        }
    }

    /// The delivery's answer was not retained: capture nothing for it.
    pub(crate) fn drop_replay_capture(&mut self) {
        self.capture = None;
        // E1: a capture already taken pending goes too.
        self.held.discard_captured();
    }

    /// Capture the retained synchronous answer now, pending, before
    /// admission publishes it for replay (the stdio route, whose receipts
    /// were handed out of their collector). A task's entry is persisted
    /// in its row instead. Before startup publishes a generation nothing is
    /// judged, so nothing is captured.
    #[cfg_attr(not(feature = "firewall"), allow(clippy::unused_self))]
    pub(crate) fn capture_pending(
        &mut self,
        generation: Option<&crate::config_reload::Generation>,
    ) {
        #[cfg(feature = "firewall")]
        if let (Some(fw), Some(_)) = (self.fw.clone(), generation)
            && replay::is_sync_capture(self.capture.as_ref())
        {
            let calls = std::mem::take(&mut self.calls);
            self.held.captured =
                replay::capture_commit(&fw, self.capture.take(), &self.receipts, calls);
        }
        #[cfg(not(feature = "firewall"))]
        let _ = generation;
    }

    /// Record what was staged when the answer that was written `delivered` a
    /// result; drop it otherwise.
    #[cfg_attr(
        not(feature = "firewall"),
        allow(clippy::needless_pass_by_value, clippy::unused_self)
    )]
    pub(crate) fn commit(self, delivered: bool, generation: &crate::config_reload::Generation) {
        #[cfg(all(test, feature = "firewall"))]
        commit_capture_hook::run();
        #[cfg(feature = "firewall")]
        if let Some(fw) = self.fw.as_deref() {
            let mut held = self.held;
            if delivered {
                // Snapshot before recording, exactly what
                // `record_digest` gets below. A synchronous capture not
                // yet taken pending is taken here and settled with it.
                if let Some(handle) =
                    replay::capture_commit(fw, self.capture, &self.receipts, self.calls)
                {
                    held.replayed.push(handle);
                }
                for r in self.receipts.into_iter().filter(|r| !r.pending_retain) {
                    let caller = crate::security::firewall::RelayCaller::new(&r.key, r.keyed);
                    fw.record_digest(caller, &r.server, &r.tool, &r.digest, generation);
                }
            }
            // Settled at this write, or released when it delivered nothing.
            held.settle(fw, delivered, generation);
        }
        #[cfg(not(feature = "firewall"))]
        let _ = (delivered, generation);
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
    // Boxed: the collector's state (the staged receipts and their replay
    // handles) would otherwise widen every HTTP call's boxed future, with
    // relay detection off too, where this branch never runs.
    let ((mut response, answered), staged) = Box::pin(meta.collecting_staged(
        RELAY_DELIVERS.scope(std::cell::Cell::new(false), async {
            let response = delivery.await.into_response();
            (response, RELAY_DELIVERS.with(std::cell::Cell::get))
        }),
    ))
    .await;
    response
        .extensions_mut()
        .insert(DeferredReceipts::new(staged, answered, meta.live_config()));
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
    /// Where the generation current at delivery is read from.
    live: Option<std::sync::Arc<crate::config_reload::LiveConfig>>,
}

impl DeferredReceipts {
    pub(crate) fn new(
        staged: StagedReceipts,
        eligible: bool,
        live: Option<std::sync::Arc<crate::config_reload::LiveConfig>>,
    ) -> Self {
        Self {
            staged: std::sync::Arc::new(parking_lot::Mutex::new(Some(staged))),
            eligible,
            live,
        }
    }

    /// Whether the answer delivers a result, so its commit can record.
    pub(crate) fn delivers(&self) -> bool {
        self.eligible
    }

    /// Record what was staged when the answer went out as built, under the
    /// generation current now, captured once before anything records.
    pub(crate) fn commit(&self, written: bool) {
        let generation = self.live.as_ref().map(|live| live.generation());
        let Some(staged) = self.staged.lock().take() else {
            return;
        };
        match generation {
            Some(generation) => staged.commit(written && self.eligible, &generation),
            None => unpublished("http funnel"),
        }
    }
}

/// A delivery found no published generation, so nothing is recorded; the
/// witness refuses in that state ([`unpublished_refusal`]), so no relay gets
/// past it unrecorded. Unreachable in production: startup publishes before
/// serving (HTTP `server/run.rs:217`, before `listener::serve` at `:630`;
/// stdio `server/stdio_loop.rs:127`, before the first read at `:319`; the
/// bridge commits only inside a call already being served), and the
/// `boundary_pins::live_config` rows fail on a reorder. Logged as an error,
/// so a reorder that slipped past them is loud.
pub(crate) fn unpublished(site: &'static str) {
    tracing::error!(
        site,
        "relay delivery before startup published a generation: nothing recorded"
    );
}

/// What a relay check refuses with while no generation is published: it
/// fails closed. In a test build a fixture that serves relays without a
/// live config panics instead, unless the row opted in
/// ([`unpublished_allow::arm`]), so a fixture that forgot to publish cannot
/// pass a refusal row by this path.
#[cfg(feature = "firewall")]
pub(crate) const UNPUBLISHED: &str = "no live config published; relays refused until one is";

/// [`UNPUBLISHED`], logged with the witness `site`.
#[cfg(feature = "firewall")]
pub(crate) fn unpublished_refusal(site: &'static str) -> String {
    #[cfg(test)]
    assert!(
        unpublished_allow::fire(),
        "no live config published in this fixture ({site}): publish one (set_live_config) \
         before serving relays"
    );
    tracing::error!(site, "relay refused: {UNPUBLISHED}");
    format!("Relay detection blocked: {UNPUBLISHED}")
}

/// The opt-in a row arms to reach [`unpublished_refusal`] in a test build,
/// with how often it fired (patterned on `refuse_hook`).
#[cfg(all(test, feature = "firewall"))]
pub(crate) mod unpublished_allow {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    thread_local! {
        static ALLOWED: std::cell::RefCell<Option<Arc<AtomicUsize>>> =
            const { std::cell::RefCell::new(None) };
    }

    /// Allow the unpublished refusal on this thread; the count is how often
    /// it fired.
    pub(crate) fn arm() -> Arc<AtomicUsize> {
        let fired = Arc::new(AtomicUsize::new(0));
        ALLOWED.with(|a| *a.borrow_mut() = Some(Arc::clone(&fired)));
        fired
    }

    /// Whether this thread allowed it, counting the firing.
    pub(super) fn fire() -> bool {
        ALLOWED.with(|a| {
            a.borrow()
                .as_ref()
                .map(|fired| fired.fetch_add(1, Ordering::SeqCst))
                .is_some()
        })
    }
}

impl MetaMcp {
    /// Capture this delivery's retained synchronous answer now, pending,
    /// from inside its collector (the HTTP route), when `response` delivers
    /// a result; before admission publishes it for replay.
    #[cfg_attr(not(feature = "firewall"), allow(clippy::unused_self))]
    pub(crate) fn capture_pending_now(&self, response: &crate::protocol::JsonRpcResponse) {
        #[cfg(feature = "firewall")]
        if response.error.is_none()
            && !response.wire_meta.delivery_refusal
            && let Some(fw) = self.firewall.as_deref()
            // Before startup publishes a generation nothing is judged, so
            // nothing is captured.
            && self.current_generation().is_some()
        {
            let _ = RELAY_RECEIPTS.try_with(|receipts| {
                replay::capture_pending_now(fw, &receipts.borrow());
            });
        }
        #[cfg(not(feature = "firewall"))]
        let _ = response;
    }

    /// `staged`'s commit for the frame that carries it, run when a sink
    /// writes that frame (`OutboundFrame::committing_on_write`), under the
    /// generation current at that write. A frame that delivers no result
    /// commits nothing now (its handles release); one dropped unwritten
    /// drops the commit, which records nothing and releases its handles.
    pub(crate) fn commit_on_write(
        &self,
        staged: StagedReceipts,
        delivered: bool,
    ) -> Option<crate::gateway::input_bridge::DeliveryCommit> {
        if !delivered {
            self.commit_staged(staged, false);
            return None;
        }
        // Checked here, not in the closure: a sink may run the commit
        // where nothing logs.
        let Some(live) = self.live_config() else {
            unpublished("staged commit");
            return None;
        };
        Some(crate::gateway::input_bridge::DeliveryCommit::new(
            move || {
                // Read when the frame is written, not when it was queued.
                let generation = live.generation();
                staged.commit(true, &generation);
            },
        ))
    }

    /// Commit `staged` under the generation current at delivery. Before
    /// startup publishes a live config nothing is judged, so nothing records.
    #[cfg_attr(not(feature = "firewall"), allow(clippy::unused_self))]
    pub(crate) fn commit_staged(&self, staged: StagedReceipts, delivered: bool) {
        #[cfg(feature = "firewall")]
        match self.current_generation() {
            Some(generation) => staged.commit(delivered, &generation),
            None => unpublished("staged commit"),
        }
        #[cfg(not(feature = "firewall"))]
        let _ = (staged, delivered);
    }
}

impl MetaMcp {
    /// [`collecting`], handing the staged receipts back instead of dropping
    /// them, for a caller that records them after the verdict.
    pub(crate) async fn collecting_staged<F: std::future::Future>(
        &self,
        delivery: F,
    ) -> (F::Output, StagedReceipts) {
        let (output, staged) = RELAY_RECEIPTS
            .scope(
                RefCell::new(Vec::new()),
                replay::scope(async {
                    let writes = gateway_writes::scope(seams::scope(delivery));
                    let output = RELAY_STAGED.scope(Staging::default(), writes).await;
                    #[cfg(feature = "firewall")]
                    let staged = take_staged_now(self.firewall.clone());
                    #[cfg(not(feature = "firewall"))]
                    let staged = take_staged_now();
                    (output, staged)
                }),
            )
            .await;
        (output, staged)
    }
}

/// Everything this collector staged so far, taken out for a commit that
/// runs later, under `fw` (the receipts, the capture and its calls, and the
/// handles held): the one construction every deferred commit uses.
pub(crate) fn take_staged_now(
    #[cfg(feature = "firewall")] fw: Option<std::sync::Arc<crate::security::firewall::Firewall>>,
) -> StagedReceipts {
    let receipts = RELAY_RECEIPTS
        .try_with(|receipts| std::mem::take(&mut *receipts.borrow_mut()))
        .unwrap_or_default();
    let (capture, calls) = replay::take_capture();
    StagedReceipts {
        #[cfg(feature = "firewall")]
        fw,
        receipts,
        capture,
        calls,
        held: replay::take_held(),
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
pub(crate) fn commit_with(
    fw: &crate::security::firewall::Firewall,
    delivered: bool,
    generation: &crate::config_reload::Generation,
) {
    #[cfg(all(test, feature = "firewall"))]
    commit_capture_hook::run();
    let receipts = RELAY_RECEIPTS
        .try_with(|receipts| std::mem::take(&mut *receipts.borrow_mut()))
        .unwrap_or_default();
    let (capture, calls) = replay::take_capture();
    let mut held = replay::take_held();
    if delivered {
        // Snapshot before recording, exactly what
        // `record_digest` gets below.
        if let Some(handle) = replay::capture_commit(fw, capture, &receipts, calls) {
            held.replayed.push(handle);
        }
        for r in receipts.into_iter().filter(|r| !r.pending_retain) {
            let caller = crate::security::firewall::RelayCaller::new(&r.key, r.keyed);
            fw.record_digest(caller, &r.server, &r.tool, &r.digest, generation);
        }
    }
    held.settle(fw, delivered, generation);
}

/// Drop every staged receipt: what was staged was never delivered (a
/// state-only round the gateway answered for itself).
pub(crate) fn discard_staged() {
    let _ = RELAY_RECEIPTS.try_with(|receipts| receipts.borrow_mut().clear());
}

// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! What the gateway did to the answer one delivery carries.
//!
//! One cell per delivered message, opened around everything that can still
//! change or replace the answer and read by the delivery recorder inside it.
//! The places where the gateway acts on an answer write into the cell: an
//! egress scan sets `scanned` and its findings, a rewrite or a refusal raises
//! the effect, and an answer this request did not produce (a cache hit, a
//! replay) clears `vouched`. The effect is the strongest one raised, so the
//! order the sites run in cannot lower it.
//!
//! A tools/call naming one target sets `lone_target` where the target is
//! parsed; an answer re-worded as an absent name then raises `Refused` through
//! `withheld`, which does so only for such a call while the cell is still
//! vouched. A composite step's own cell names one target too; its refusal
//! marks the composite only when the composite ends on that step, so a plan
//! that still delivers is never marked.
//!
//! A delivery the gateway cannot vouch for omits both fields; it never claims
//! `delivered` or an empty finding list for something no scan of this request
//! saw. It still records a refusal it ended on, and `rewritten` when the
//! injected-value scrub removed a value during the call, a fact of the whole
//! call rather than of any one step. Outside a cell every setter is a no-op and the recorder omits both.

use std::cell::RefCell;
use std::collections::BTreeSet;

use serde_json::{Map, Value};

use crate::security::Severity;

/// What the gateway did to the bytes it delivered, weakest first.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum ResponseEffect {
    /// Delivered as the gateway received it.
    #[default]
    Delivered,
    /// Delivered with a gateway annotation added (findings, contract notes).
    Annotated,
    /// Delivered with bytes the gateway changed, or, from the injected-value
    /// scrub: during this call the gateway removed an injected value from
    /// something this backend sent. That can be an answer the caller never
    /// received (a discarded page, a handshake, a retried attempt), so it
    /// does not mean the answer delivered was edited. Over-reporting is the
    /// safe direction for a secret-echo control: an under-report would hide
    /// that a backend sent a credential back.
    Rewritten,
    /// Not delivered: the gateway answered with a refusal.
    Refused,
}

impl ResponseEffect {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Delivered => "delivered",
            Self::Annotated => "annotated",
            Self::Rewritten => "rewritten",
            Self::Refused => "refused",
        }
    }
}

/// Which part of the answer a scan judged.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum Part {
    Result,
    Error,
}

impl Part {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Result => "result",
            Self::Error => "error",
        }
    }
}

/// One finding as recorded: a closed kind, its severity and the part, never
/// content. Ordered most severe first, then by kind.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct Finding {
    severity: std::cmp::Reverse<Severity>,
    kind: String,
    part: Part,
}

/// The facts one delivery's cell collects.
#[derive(Debug, Clone)]
pub(crate) struct DeliveryFacts {
    effect: ResponseEffect,
    /// What the transport's scrub did to an injected value this call sent.
    echo: Echo,
    scanned: bool,
    findings: BTreeSet<Finding>,
    vouched: bool,
    lone_target: bool,
    /// Whether a composite's latest step ended in a gateway refusal the
    /// composite has not carried on past.
    last_step: LastStep,
    /// What this delivery's backend sends did.
    sends: Sends,
}

/// What the injected-value scrub did during a delivery.
#[derive(Debug, Clone, Default)]
struct Echo {
    /// During this call the gateway removed an injected value from something
    /// this backend sent: an answer the caller got, or one it never did (a
    /// discarded page, a handshake, a retried attempt). Never cleared: an
    /// over-report is the safe direction for a secret-echo control, which an
    /// under-report would hide. Shared with every nested cell
    /// ([`discarded`], [`step`]), so a nested send writes it at once, even
    /// one later refused or cancelled; a fresh delivery ([`scope`]) has its own.
    redacted: std::sync::Arc<std::sync::atomic::AtomicBool>,
    /// The scrub replaced an answer with its refusal in this cell. Read with
    /// the delivered error ([`echo_refusal_delivered`]), so a replaced answer
    /// the call never delivered records nothing.
    refusal_built: bool,
}

/// The two facts a delivery keeps about its sends. Both can hold at once (a
/// later round refused before its send after an earlier one was sent), so
/// they are two facts, not one state.
#[derive(Debug, Clone, Copy, Default)]
struct Sends {
    /// Sends that entered a transport and were not proven unsent: while any
    /// is counted, the delivery may have reached its backend.
    entered: u32,
    /// The backend's send refused this delivery's call before any byte left.
    refused_before: bool,
}

/// How a composite's latest step ended, for the composite's own record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LastStep {
    /// No step, a served step, or one the composite carried on past.
    Settled,
    /// Refused by the gateway, and nothing has carried on past it.
    Refused,
}

impl Default for DeliveryFacts {
    fn default() -> Self {
        Self {
            effect: ResponseEffect::Delivered,
            echo: Echo::default(),
            scanned: false,
            findings: BTreeSet::new(),
            vouched: true,
            lone_target: false,
            last_step: LastStep::Settled,
            sends: Sends::default(),
        }
    }
}

/// At most this many findings are recorded; the total says how many there were.
const MAX_FINDINGS: usize = 32;

tokio::task_local! {
    static FACTS: RefCell<DeliveryFacts>;
}

impl DeliveryFacts {
    /// Whether a gateway refusal was raised in this cell.
    pub(crate) fn refused(&self) -> bool {
        self.effect == ResponseEffect::Refused
    }

    /// The strongest effect: this cell's own, raised to `Rewritten` when the
    /// scrub redacted anything during the call.
    fn effect(&self) -> ResponseEffect {
        if self.echo.redacted.load(std::sync::atomic::Ordering::SeqCst) {
            self.effect.max(ResponseEffect::Rewritten)
        } else {
            self.effect
        }
    }

    /// A nested cell: fresh facts, sharing this call's redaction fact.
    fn nested(&self) -> Self {
        Self {
            echo: Echo {
                redacted: std::sync::Arc::clone(&self.echo.redacted),
                refusal_built: false,
            },
            ..Self::default()
        }
    }
}

/// A nested cell inside the open one, or a fresh one outside any delivery.
fn nested_cell() -> DeliveryFacts {
    FACTS
        .try_with(|cell| cell.borrow().nested())
        .unwrap_or_default()
}

/// Run `future` with a fresh cell open: one delivery.
pub(crate) async fn scope<F: std::future::Future>(future: F) -> F::Output {
    FACTS
        .scope(RefCell::new(DeliveryFacts::default()), future)
        .await
}

/// Run an internal send whose error the caller never receives (a probe that
/// drops it) in a cell of its own, discarded: a refusal it meets, such as a
/// refused redirect hop, is not this call's answer. Every such send site is
/// listed in `boundary_pins/discarded_sends.rs`.
///
/// A redaction it meets is still this call's: the nested cell shares the
/// call's redaction fact.
pub(crate) async fn discarded<F: std::future::Future>(future: F) -> F::Output {
    // Boxed: the cell would otherwise sit inline in every dispatch future
    // that awaits a probe.
    Box::pin(FACTS.scope(RefCell::new(nested_cell()), future)).await
}

/// Run one composite step in a cell of its own, as [`scope`] does, and note
/// on the composite's cell whether this step ended in a gateway refusal.
/// Only the latest step's note is kept: a later step replaces it. A step
/// names one target, so a step answered absent for a policy reason is
/// refused ([`withheld`]).
pub(crate) async fn step<F: std::future::Future>(future: F) -> F::Output {
    let cell = DeliveryFacts {
        lone_target: true,
        ..nested_cell()
    };
    let (output, refused) = FACTS
        .scope(RefCell::new(cell), async {
            let output = future.await;
            let refused = FACTS.with(|cell| cell.borrow().refused());
            (output, refused)
        })
        .await;
    with(|facts| {
        facts.last_step = if refused {
            LastStep::Refused
        } else {
            LastStep::Settled
        };
    });
    output
}

/// The composite's next step was refused before it could run (a playbook's
/// refusal of a step's arguments, a resumed chain's pending step): the
/// composite now ends on that refusal unless it carries on past it.
pub(crate) fn refused_before_step() {
    with(|facts| facts.last_step = LastStep::Refused);
}

/// The composite carried on past its latest step's failure (a playbook's
/// `continue`, or its `retry` once attempts run out): that step's refusal is
/// no longer what the composite can end on.
pub(crate) fn step_absorbed() {
    with(|facts| facts.last_step = LastStep::Settled);
}

/// How a composite ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CompositeEnd {
    Succeeded,
    /// In an error, or a tool error result.
    Failed,
}

impl CompositeEnd {
    /// `Failed` for an error or a tool error result (`isError: true`).
    pub(crate) fn of(result: &crate::Result<Value>) -> Self {
        match result {
            Ok(answer) if !crate::protocol::cacheable::is_error(answer) => Self::Succeeded,
            _ => Self::Failed,
        }
    }

    /// `Failed` for an error: a composite whose output is not a tool result.
    #[cfg(test)]
    pub(crate) fn of_outcome<T>(result: &crate::Result<T>) -> Self {
        if result.is_err() {
            Self::Failed
        } else {
            Self::Succeeded
        }
    }
}

/// The composite ends as `end`. It records `refused` when it fails while its
/// latest step's refusal still stands: the step it ends on was refused.
pub(crate) fn composite_ended(end: CompositeEnd) {
    with(|facts| {
        if end == CompositeEnd::Failed && facts.last_step == LastStep::Refused {
            facts.effect = facts.effect.max(ResponseEffect::Refused);
        }
    });
}

/// Run `f` with the facts suspended: a scan of a value that is not delivered
/// (a receipt copy, a classification probe) writes into a cell that is thrown
/// away.
pub(crate) fn suspended<T>(f: impl FnOnce() -> T) -> T {
    FACTS.sync_scope(RefCell::new(DeliveryFacts::default()), f)
}

/// The open cell's facts, or `None` outside a cell.
pub(crate) fn snapshot() -> Option<DeliveryFacts> {
    FACTS.try_with(|cell| cell.borrow().clone()).ok()
}

fn with(update: impl FnOnce(&mut DeliveryFacts)) {
    let _ = FACTS.try_with(|cell| update(&mut cell.borrow_mut()));
}

/// The gateway did `effect` to this delivery's answer; the strongest one wins.
pub(crate) fn raise(effect: ResponseEffect) {
    with(|facts| facts.effect = facts.effect.max(effect));
}

/// A gateway refusal decided at a delivering site: raise `Refused` and hand
/// the error on unchanged.
pub(crate) fn refused<E>(error: E) -> E {
    raise(ResponseEffect::Refused);
    error
}

/// Where an error becomes the delivered frame: a refusal a gateway decision
/// sealed ([`crate::Error::GatewayRefused`]) raises `Refused`, and so does an
/// authorization refusal ([`crate::Error::Forbidden`]), a decision about the
/// caller wherever it was built, whatever its code, and the scrub's refusal
/// of an answer that echoed an injected value ([`echo_refusal_delivered`]).
/// Every `Forbidden` site is classified in
/// `boundary_pins/delivery_refusals.tsv`. Any other error raises nothing.
pub(crate) fn outlet(error: &crate::Error) {
    echo_refusal_delivered(error);
    if matches!(
        error,
        crate::Error::GatewayRefused { .. } | crate::Error::Forbidden { .. }
    ) {
        raise(ResponseEffect::Refused);
    }
}

/// Where a backend's error becomes the delivered answer outside [`outlet`]
/// (a tool result, a forwarded error, a composite step): `Refused` when the
/// error is the scrub's refusal of an answer that echoed an injected value
/// and this cell's scrub built one. The error alone is not enough: a backend
/// can send the same code and text, which the scrub leaves as it is.
pub(crate) fn echo_refusal_delivered(error: &crate::Error) {
    if crate::security::needles::is_echo_refusal(error) {
        with(|facts| {
            if facts.echo.refusal_built {
                facts.effect = facts.effect.max(ResponseEffect::Refused);
            }
        });
    }
}

/// A send of this delivery entered its backend's transport: from here it may
/// have reached the backend. Recorded before the transport call; a dropped or
/// panicking call never takes it back.
pub(crate) fn send_began() {
    with(|facts| facts.sends.entered += 1);
}

/// The transport's scrub removed an injected value from something this
/// backend sent during the call: recorded `rewritten` whether or not the
/// caller receives it.
pub(crate) fn echo_redacted() {
    with(|facts| {
        facts
            .echo
            .redacted
            .store(true, std::sync::atomic::Ordering::SeqCst);
    });
}

/// The transport's scrub replaced an answer with its refusal. It is
/// recorded `refused` only where that refusal is delivered
/// ([`echo_refusal_delivered`]).
pub(crate) fn echo_refusal_built() {
    with(|facts| facts.echo.refusal_built = true);
}

/// Run one transport call of this delivery as a counted send: counted when
/// it is first polled, taken back only if it returns an error that proves
/// nothing was sent. A call dropped before it returns stays counted.
pub(crate) async fn counted_send<T>(
    send: impl std::future::Future<Output = crate::Result<T>>,
) -> crate::Result<T> {
    send_began();
    let result = send.await;
    if let Err(error) = &result {
        send_returned(error);
    }
    result
}

/// The transport call [`send_began`] counted returned an error that proves
/// nothing was sent (`is_pre_dispatch`), so it is taken back.
pub(crate) fn send_returned(error: &crate::Error) {
    if error.is_pre_dispatch() {
        with(|facts| facts.sends.entered = facts.sends.entered.saturating_sub(1));
    }
}

/// The backend's send refused this call before any byte left: the fact only.
/// The settlement that delivers the refusal raises `Refused` ([`unsent`]).
pub(crate) fn refused_before_send<E>(error: E) -> E {
    with(|facts| facts.sends.refused_before = true);
    error
}

/// [`refused_before_send`] on the error of a pre-send step's `result`.
pub(crate) fn before_send<T>(result: crate::Result<T>) -> crate::Result<T> {
    result.map_err(refused_before_send)
}

/// Whether `error` ends a delivery that provably sent nothing: no send of it
/// is still counted, and the error is one the gateway raised before the
/// backend (`is_pre_dispatch`) or a refusal its send recorded. The one
/// predicate every settlement reads before it releases a key.
pub(crate) fn unsent(error: &crate::Error) -> bool {
    nothing_sent() && (error.is_pre_dispatch() || refused_before_send_seen())
}

/// Whether no send of this delivery is still counted: none entered a
/// transport, or each that did returned a never-sent error. Outside a cell
/// nothing is known, so `true`, and [`unsent`] falls back to the error's own
/// verdict.
pub(crate) fn nothing_sent() -> bool {
    FACTS
        .try_with(|cell| cell.borrow().sends.entered == 0)
        .unwrap_or(true)
}

/// Whether this delivery's send refused it before any byte left, read by the
/// settlement that raises `Refused` for it.
pub(crate) fn refused_before_send_seen() -> bool {
    FACTS
        .try_with(|cell| cell.borrow().sends.refused_before)
        .unwrap_or(false)
}

/// This delivery answers a tools/call that names exactly one target.
pub(crate) fn lone_target() {
    with(|facts| facts.lone_target = true);
}

/// The call was answered as an absent name for a policy reason: refused, but
/// only for a one-target call this request still vouches for. A composite is
/// unvouched before any step runs, so a step answered absent raises nothing.
pub(crate) fn withheld() {
    with(|facts| {
        if facts.lone_target && facts.vouched {
            facts.effect = facts.effect.max(ResponseEffect::Refused);
        }
    });
}

/// The gateway refused this delivery's answer at a site that also runs per
/// step in a composite: raised only while the cell is still vouched.
pub(crate) fn refused_while_vouched() {
    with(|facts| {
        if facts.vouched {
            facts.effect = facts.effect.max(ResponseEffect::Refused);
        }
    });
}

/// A scanner returned a verdict on a non-empty `part` of this delivery.
pub(crate) fn scanned() {
    with(|facts| facts.scanned = true);
}

/// A scanner found `kind` (from its closed set) at `severity` in `part`.
pub(crate) fn found(kind: String, severity: Severity, part: Part) {
    with(|facts| {
        facts.scanned = true;
        facts.findings.insert(Finding {
            severity: std::cmp::Reverse(severity),
            kind,
            part,
        });
    });
}

/// This delivery carries an answer this request did not produce, or one a
/// scan in another request judged: its effect and findings are not this
/// request's to state.
pub(crate) fn unvouched() {
    with(|facts| facts.vouched = false);
}

/// Write `response_effect` and `response_findings` for one delivery.
///
/// `facts` is the cell's snapshot (`None` outside a cell: both omitted).
/// `frame_refused` is whether the delivered frame is the gateway's own
/// refusal, read off what is actually sent, so no later rebuild can hide
/// it. A counted annotation raises `Annotated` in the cell where the gateway
/// notes it. An unvouched delivery still records a refusal this request
/// made, and `rewritten` when the scrub removed an injected value during the
/// call, and omits everything else.
pub(crate) fn record_fields(
    facts: Option<&DeliveryFacts>,
    frame_refused: bool,
    fields: &mut Map<String, Value>,
) {
    let Some(facts) = facts else {
        return;
    };
    let mut effect = facts.effect();
    if frame_refused {
        effect = effect.max(ResponseEffect::Refused);
    }
    if !facts.vouched {
        // No one step's facts describe what a composite delivers, but a
        // refusal it ends on does, and so does the scrub's redaction fact,
        // which is the whole call's.
        let echoed = facts
            .echo
            .redacted
            .load(std::sync::atomic::Ordering::SeqCst);
        if effect == ResponseEffect::Refused || echoed {
            fields.insert("response_effect".into(), effect.as_str().into());
        }
        return;
    }
    fields.insert("response_effect".into(), effect.as_str().into());
    if !facts.scanned {
        fields.insert("response_findings".into(), Value::Null);
        return;
    }
    let listed: Vec<Value> = facts
        .findings
        .iter()
        .take(MAX_FINDINGS)
        .map(|finding| {
            serde_json::json!({
                "kind": finding.kind,
                "severity": finding.severity.0,
                "where": finding.part.as_str(),
            })
        })
        .collect();
    fields.insert("response_findings".into(), Value::Array(listed));
    if facts.findings.len() > MAX_FINDINGS {
        fields.insert(
            "response_findings_total".into(),
            facts.findings.len().into(),
        );
    }
}

#[cfg(test)]
#[path = "delivery_facts_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "delivery_facts_withheld_tests.rs"]
mod withheld_tests;

#[cfg(test)]
#[path = "delivery_facts_composite_tests.rs"]
mod composite_tests;

#[cfg(test)]
#[path = "delivery_facts_send_tests.rs"]
mod send_tests;

#[cfg(test)]
#[path = "delivery_facts_calls_tests.rs"]
mod calls_tests;

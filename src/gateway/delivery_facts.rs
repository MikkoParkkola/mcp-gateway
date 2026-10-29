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
//! vouched, so a composite step answered absent never marks a plan that still
//! delivers.
//!
//! A delivery the gateway cannot vouch for omits both fields; it never claims
//! `delivered` or an empty finding list for something no scan of this request
//! saw. Outside a cell every setter is a no-op and the recorder omits both.

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
    /// Delivered with bytes the gateway changed.
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
    scanned: bool,
    findings: BTreeSet<Finding>,
    vouched: bool,
    lone_target: bool,
    /// Whether a composite's latest step ended in a gateway refusal the
    /// composite has not carried on past.
    last_step: LastStep,
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
            scanned: false,
            findings: BTreeSet::new(),
            vouched: true,
            lone_target: false,
            last_step: LastStep::Settled,
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
}

/// Run `future` with a fresh cell open: one delivery.
pub(crate) async fn scope<F: std::future::Future>(future: F) -> F::Output {
    FACTS
        .scope(RefCell::new(DeliveryFacts::default()), future)
        .await
}

/// Run one composite step in a cell of its own, as [`scope`] does, and note
/// on the composite's cell whether this step ended in a gateway refusal.
/// Only the latest step's note is kept: a later step replaces it.
pub(crate) async fn step<F: std::future::Future>(future: F) -> F::Output {
    let (output, refused) = FACTS
        .scope(RefCell::new(DeliveryFacts::default()), async {
            let output = future.await;
            let refused = FACTS.with(|cell| cell.borrow().effect == ResponseEffect::Refused);
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

/// The composite carried on past its latest step's failure (a playbook's
/// `continue`, or its `retry` once attempts run out): that step's refusal is
/// no longer what the composite can end on.
pub(crate) fn step_absorbed() {
    with(|facts| facts.last_step = LastStep::Settled);
}

/// The composite ends with `error` (`None`: it succeeded). It records
/// `refused` when it ends with an error while its latest step's refusal still
/// stands: the step it ends on was refused.
pub(crate) fn composite_ended(error: Option<&crate::Error>) {
    with(|facts| {
        if error.is_some() && facts.last_step == LastStep::Refused {
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
/// sealed ([`crate::Error::GatewayRefused`]) raises `Refused`; any other error
/// raises nothing.
pub(crate) fn outlet(error: &crate::Error) {
    if matches!(error, crate::Error::GatewayRefused { .. }) {
        raise(ResponseEffect::Refused);
    }
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
/// made, and omits everything else.
pub(crate) fn record_fields(
    facts: Option<&DeliveryFacts>,
    frame_refused: bool,
    fields: &mut Map<String, Value>,
) {
    let Some(facts) = facts else {
        return;
    };
    let mut effect = facts.effect;
    if frame_refused {
        effect = effect.max(ResponseEffect::Refused);
    }
    if !facts.vouched {
        if effect == ResponseEffect::Refused {
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

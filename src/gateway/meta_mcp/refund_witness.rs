// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The proof a signed call may give its nonce back (MIK-8353, design r3/r4).
//!
//! A signed call's nonce stays spent unless a refund site holds a
//! [`RefundWitness`]. One is minted when the call's signing context is
//! captured, before anything has acted, and it moves by value through every
//! step that may cause an effect. A step returns it only from an arm that
//! proves its own call effect-free; any other arm drops it, so a step that
//! forgets to hand it back fails closed: the nonce stays spent. The witness
//! cannot be cloned, copied, defaulted or deserialized, and its field is
//! private to this module.

/// Permission to give one signed call's nonce back: nothing that call did
/// before the refund site can have had an effect.
#[must_use = "a dropped witness keeps the nonce spent"]
pub(crate) struct RefundWitness(());

impl RefundWitness {
    /// The witness a signed call starts with, minted where its signing context
    /// is captured: on `/mcp` before X14, on stdio at nonce admission, when
    /// nothing has acted yet. The only constructor.
    pub(crate) fn at_capture() -> Self {
        Self(())
    }

    /// Use the witness up: at a refund site that gives the nonce back, or
    /// where something is about to act and the nonce must stay spent.
    pub(crate) fn spend(self) {
        let Self(()) = self;
    }
}

/// What a may-effect step did outside the gateway (MIK-8353 slice 3a): a
/// credential mint or provider refresh, a backend `tools/list`, a consumed
/// continuation. Gateway-local reversible writes do not count.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Effect {
    /// Nothing outside the gateway acted.
    None,
    /// Something outside the gateway may have acted.
    Took,
}

impl RefundWitness {
    /// The one place a may-effect step decides the witness: it survives only
    /// a step that reports [`Effect::None`].
    // STUB (red-first): keeps the witness whatever the report.
    pub(crate) fn carry(witness: Option<Self>, effect: Effect) -> Option<Self> {
        let _ = effect;
        witness
    }
}

/// `resolve_dispatch`'s report: `minted` is a propagation mint (never cached),
/// `account` an account credential resolved for the call.
// STUB (red-first): reports no effect.
pub(crate) fn dispatch_effect(minted: bool, account: bool) -> Effect {
    let _ = (minted, account);
    Effect::None
}

/// The undeclared-key check's report: `cached_before` is whether the binding's
/// tools were cached before the check. A cold slot fetches, or waits on
/// another request's fetch.
// STUB (red-first): reports no effect.
pub(crate) fn schema_effect(cached_before: bool) -> Effect {
    let _ = cached_before;
    Effect::None
}

/// `redeem_retry`'s report: `redeemed` is whether it consumed a continuation.
// STUB (red-first): reports no effect.
pub(crate) fn retry_effect(redeemed: bool) -> Effect {
    let _ = redeemed;
    Effect::None
}

#[cfg(test)]
#[path = "refund_witness_tests.rs"]
mod tests;

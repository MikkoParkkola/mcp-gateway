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
    pub(crate) fn carry(witness: Option<Self>, effect: Effect) -> Option<Self> {
        match effect {
            Effect::None => witness,
            Effect::Took => {
                if let Some(witness) = witness {
                    witness.spend();
                }
                None
            }
        }
    }
}

/// `resolve_dispatch`'s report: `minted` is a propagated credential resolved
/// for the call, `account` an account credential.
///
/// Conservative (lead ruling, 2026-10-11): both count whether or not they
/// contacted anyone. A propagated credential may come from a strategy's own
/// cache (token exchange keeps exchanged tokens), and the account resolver
/// does not yet say whether it refreshed.
pub(crate) fn dispatch_effect(minted: bool, account: bool) -> Effect {
    if minted || account {
        Effect::Took
    } else {
        Effect::None
    }
}

/// The undeclared-key check's report: `filled` is whether a list fill on the
/// backend passed admission while the check ran. Read from the fill itself,
/// not from the slot's freshness before the check: a slot that expires in
/// between still fetches, and a check that never fetches (enforcement `off`,
/// held metadata, joining a fill already under way) acted on nothing.
pub(crate) fn schema_effect(filled: bool) -> Effect {
    if filled { Effect::Took } else { Effect::None }
}

/// `redeem_retry`'s report: `redeemed` is whether it consumed a continuation.
pub(crate) fn retry_effect(redeemed: bool) -> Effect {
    if redeemed { Effect::Took } else { Effect::None }
}

#[cfg(test)]
#[path = "refund_witness_tests.rs"]
mod tests;

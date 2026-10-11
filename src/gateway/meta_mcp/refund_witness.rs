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
    pub(crate) fn spend(self) {}
}

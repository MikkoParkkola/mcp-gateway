// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A retained copy of an answer and the holds it carries (MIK-8176 stage 4).
//!
//! A stored task or a cached replay outlives the request scope that minted its
//! holds. It travels as `Held<T>`, and the only way to its payload is
//! [`Held::deliver`], which moves the holds to the reader: into the reader's
//! open scope, or onto the frame that will carry the payload. A path that
//! puts retained output on the wire without adopting its holds therefore does
//! not compile. The fields are private to this module; the A2 guard pins that
//! nothing here hands out the payload any other way.
use super::CarriedHolds;

/// A retained payload and the holds whose envelopes it carries.
pub(crate) struct Held<T> {
    value: T,
    holds: CarriedHolds,
}

/// Where [`Held::deliver`] moves the holds.
pub(crate) enum HoldSink<'a> {
    /// The reader's open request scope: its route hands them off on delivery.
    Scope,
    /// A frame emitted outside any scope, which hands them off at its yield.
    Frame(&'a mut CarriedHolds),
}

impl<T> Held<T> {
    /// `value` with the holds it carries.
    pub(crate) const fn new(value: T, holds: CarriedHolds) -> Self {
        Self { value, holds }
    }

    /// The payload, its holds moved to `sink`.
    pub(crate) fn deliver(self, sink: HoldSink<'_>) -> T {
        match sink {
            HoldSink::Scope => super::adopt(self.holds),
            HoldSink::Frame(frame) => frame.0.extend(self.holds.0),
        }
        self.value
    }
}

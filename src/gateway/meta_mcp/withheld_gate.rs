// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8361: the terminal withheld gate. A name the caller cannot see takes
//! the missing name's path and is answered absent before anything
//! caller-specific acts (design r4).

/// Test seams for the gate.
#[cfg(test)]
pub(crate) mod seams {
    use std::cell::Cell;

    thread_local! {
        static SKIP_GATE: Cell<bool> = const { Cell::new(false) };
    }

    /// Let the next calls on this thread past the gate, so a row can reach
    /// the dispatch-time backstop with a withheld target (test plan B1).
    pub(crate) fn skip_gate_for_test() {
        SKIP_GATE.with(|skip| skip.set(true));
    }

    /// Whether the gate is skipped on this thread. Read by the gate once it
    /// exists; until then nothing reads it, and B1 is red on base.
    #[expect(dead_code, reason = "read by the gate, which lands after the red rows")]
    pub(crate) fn gate_skipped() -> bool {
        SKIP_GATE.with(Cell::get)
    }
}

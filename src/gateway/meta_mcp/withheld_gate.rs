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
        static AFTER_GATE: std::cell::RefCell<Option<Box<dyn FnOnce()>>> =
            const { std::cell::RefCell::new(None) };
    }

    /// Run `hook` once, the next time the `/mcp` route stage on this thread
    /// has run the gate's judgement (test plan D1).
    pub(crate) fn after_gate(hook: impl FnOnce() + 'static) {
        AFTER_GATE.with(|slot| *slot.borrow_mut() = Some(Box::new(hook)));
    }

    /// Called where the route stage's gate judgement hands over.
    pub(crate) fn gate_done() {
        if let Some(hook) = AFTER_GATE.with(|slot| slot.borrow_mut().take()) {
            hook();
        }
    }

    /// Lets calls on this thread past the gate while held, so a row can
    /// reach the dispatch-time backstop with a withheld target (test plan B1).
    #[must_use = "the gate is skipped only while the guard is held"]
    pub(crate) struct SkipGate(());

    impl Drop for SkipGate {
        fn drop(&mut self) {
            SKIP_GATE.with(|skip| skip.set(false));
        }
    }

    /// Skip the gate on this thread until the returned guard drops.
    pub(crate) fn skip_gate_for_test() -> SkipGate {
        SKIP_GATE.with(|skip| skip.set(true));
        SkipGate(())
    }

    /// Whether the gate is skipped on this thread.
    pub(crate) fn gate_skipped() -> bool {
        SKIP_GATE.with(Cell::get)
    }
}

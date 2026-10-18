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
        static BEFORE_GATE: std::cell::RefCell<Option<Box<dyn FnOnce()>>> =
            const { std::cell::RefCell::new(None) };
        static BEFORE_RESUME: std::cell::RefCell<Option<Box<dyn FnOnce()>>> =
            const { std::cell::RefCell::new(None) };
        static BEFORE_STEP: std::cell::RefCell<Option<Box<dyn FnOnce()>>> =
            const { std::cell::RefCell::new(None) };
    }

    /// Run `hook` once, the next time the `/mcp` route stage on this thread
    /// has run the gate's judgement (test plan D1).
    #[cfg(feature = "firewall")]
    pub(crate) fn after_gate(hook: impl FnOnce() + 'static) {
        AFTER_GATE.with(|slot| *slot.borrow_mut() = Some(Box::new(hook)));
    }

    /// Run `hook` once, the next time the `/mcp` route stage on this thread
    /// is about to ask the whole-call gate, after the route checks (MIK-8387
    /// G0: a reload between S1 and S2).
    #[cfg(feature = "firewall")]
    pub(crate) fn before_gate(hook: impl FnOnce() + 'static) {
        BEFORE_GATE.with(|slot| *slot.borrow_mut() = Some(Box::new(hook)));
    }

    /// Called just before the route stage asks the whole-call gate.
    pub(crate) fn gate_start() {
        if let Some(hook) = BEFORE_GATE.with(|slot| slot.borrow_mut().take()) {
            hook();
        }
    }

    /// Run `hook` once, the next time a chain on this thread is about to
    /// judge its resume step (MIK-8387 R1g: a reload after S1).
    pub(crate) fn before_resume(hook: impl FnOnce() + 'static) {
        BEFORE_RESUME.with(|slot| *slot.borrow_mut() = Some(Box::new(hook)));
    }

    /// Called just before a chain judges its resume step.
    pub(crate) fn resume_start() {
        if let Some(hook) = BEFORE_RESUME.with(|slot| slot.borrow_mut().take()) {
            hook();
        }
    }

    /// Run `hook` once, the next time a playbook on this thread is about to
    /// invoke a step, after admission (MIK-8353 3d-2: a policy change between
    /// admission and the step).
    pub(crate) fn before_step(hook: impl FnOnce() + 'static) {
        BEFORE_STEP.with(|slot| *slot.borrow_mut() = Some(Box::new(hook)));
    }

    /// Called just before a playbook invokes a step.
    pub(crate) fn step_start() {
        if let Some(hook) = BEFORE_STEP.with(|slot| slot.borrow_mut().take()) {
            hook();
        }
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
    #[cfg(feature = "firewall")]
    pub(crate) struct SkipGate(());

    #[cfg(feature = "firewall")]
    impl Drop for SkipGate {
        fn drop(&mut self) {
            SKIP_GATE.with(|skip| skip.set(false));
        }
    }

    /// Skip the gate on this thread until the returned guard drops.
    #[cfg(feature = "firewall")]
    pub(crate) fn skip_gate_for_test() -> SkipGate {
        SKIP_GATE.with(|skip| skip.set(true));
        SkipGate(())
    }

    /// Whether the gate is skipped on this thread.
    pub(crate) fn gate_skipped() -> bool {
        SKIP_GATE.with(Cell::get)
    }
}

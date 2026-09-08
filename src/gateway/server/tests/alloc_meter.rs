// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A `cfg(test)`-only global allocator that counts real allocations on ONE
//! thread while a scope is open.
//!
//! Why a global allocator and not a proxy: the claim under test is "a refused
//! dispatch allocates under 16 KiB". Retained heap, bytes hashed, or a counter
//! wrapped around one suspected call site would all answer a different
//! question. Only `GlobalAlloc` sees what the dispatch actually asks the
//! allocator for, including the allocations nobody wrote down.
//!
//! Three properties this file is reviewed on:
//!
//! 1. **The inactive path is trivial.** This allocator is installed for the
//!    whole lib-test binary, so every other test in the crate runs through it.
//!    When no scope is open the cost is one relaxed thread-local `bool` read
//!    and a forward to `System`. No lock, no buffer, no allocation, no
//!    initialiser — the cells are `const`-initialised, so touching them cannot
//!    allocate and cannot register a destructor.
//! 2. **Deallocation is never counted and never touches the cells.** The
//!    checkpoint asks for allocated bytes, never net bytes, so `dealloc` has
//!    nothing to do but forward — which also removes the thread-teardown
//!    hazard entirely on that path.
//! 3. **Failure is silent, never a panic.** A panic raised inside the
//!    allocator is not recoverable in any useful way. `try_with` losing a
//!    record during teardown drops the record.
//!
//! Contamination is handled a second time by the caller: every measuring test
//! re-executes itself as a child process running exactly one test on a
//! current-thread runtime, so no unrelated test's allocations can land in a
//! total. See `signing_nonce_allocations_support::isolate`.

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;

thread_local! {
    /// Whether THIS thread is inside an open measurement scope.
    static ACTIVE: Cell<bool> = const { Cell::new(false) };
    static BYTES: Cell<u64> = const { Cell::new(0) };
    static CALLS: Cell<u64> = const { Cell::new(0) };
}

/// Installed for the test binary only — this module is `cfg(test)` through its
/// parent declaration in `server/mod.rs`.
#[global_allocator]
static METERED_SYSTEM: MeteredSystem = MeteredSystem;

pub(super) struct MeteredSystem;

/// Nothing below allocates, so recording cannot re-enter the allocator.
fn record(bytes: usize) {
    let _ = ACTIVE.try_with(|active| {
        if active.get() {
            let _ = BYTES.try_with(|total| total.set(total.get().saturating_add(bytes as u64)));
            let _ = CALLS.try_with(|calls| calls.set(calls.get().saturating_add(1)));
        }
    });
}

// SAFETY: every method forwards its exact arguments to the `System` allocator
// and returns its exact result, so the allocator contract is whatever `System`
// already guarantees. `record` runs before the forward, performs no allocation
// and no deallocation, and never unwinds. The crate keeps `deny(unsafe_code)`;
// this allowance is confined to this delegating impl in a test-only module.
#[allow(unsafe_code)]
unsafe impl GlobalAlloc for MeteredSystem {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        record(layout.size());
        unsafe { System.alloc(layout) }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        record(layout.size());
        unsafe { System.alloc_zeroed(layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        // The new block is what was asked for. The old one is not subtracted:
        // a growing `Vec` that reallocates four times really did ask the
        // allocator for four blocks, and hiding three of them is exactly the
        // blindness the positive control exists to detect.
        record(new_size);
        unsafe { System.realloc(ptr, layout, new_size) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) }
    }
}

/// What one scope observed. Bytes AND calls: a byte total alone cannot
/// distinguish "one big copy" from "many small ones", and the diagnostics in a
/// failing assertion are worth more than the assertion.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct Measured {
    pub(super) bytes: u64,
    pub(super) calls: u64,
}

impl std::fmt::Display for Measured {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} bytes allocated across {} allocator calls",
            self.bytes, self.calls
        )
    }
}

/// An open measurement scope. RAII so an unwind through the awaited dispatch
/// still closes it — a leaked-open scope would silently meter the rest of the
/// process.
pub(super) struct Meter;

impl Meter {
    fn start() -> Self {
        // Refused BEFORE anything is mutated. A nested `start` that zeroed the
        // counters and only then panicked would leave the outer scope open on
        // a total that lost its first half — a corrupted reading that still
        // looks like a reading.
        assert!(
            !ACTIVE.with(Cell::get),
            "allocation meters must not nest: an inner scope would zero the outer total"
        );
        BYTES.with(|total| total.set(0));
        CALLS.with(|calls| calls.set(0));
        ACTIVE.with(|active| active.set(true));
        Self
    }

    fn stop(self) -> Measured {
        ACTIVE.with(|active| active.set(false));
        Measured {
            bytes: BYTES.with(Cell::get),
            calls: CALLS.with(Cell::get),
        }
    }
}

impl Drop for Meter {
    fn drop(&mut self) {
        ACTIVE.with(|active| active.set(false));
    }
}

/// Measure a synchronous body. Used by the two controls.
pub(super) fn measure<T>(body: impl FnOnce() -> T) -> (T, Measured) {
    let meter = Meter::start();
    let value = body();
    (value, meter.stop())
}

/// Measure an awaited body, with the future CONSTRUCTED INSIDE the scope.
///
/// Taking a future would leave its construction — and any clone a caller
/// performed while assembling the arguments — outside the total. Taking the
/// closure means the only work outside the scope is what the test prepared
/// before calling.
pub(super) async fn measure_async<F, Fut>(make: F) -> (Fut::Output, Measured)
where
    F: FnOnce() -> Fut,
    Fut: std::future::Future,
{
    let meter = Meter::start();
    let value = make().await;
    (value, meter.stop())
}

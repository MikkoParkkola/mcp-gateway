// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A `cfg(test)`-only global allocator that counts real allocations on ONE
//! thread while a scope is open.
//!
//! Why a global allocator and not a proxy: the claim under test is "a refused
//! dispatch allocates within its caps" (MIK-8400: small allocations and
//! large ones apart). Retained heap, bytes hashed, or a counter
//! wrapped around one suspected call site would all answer a different
//! question. Only `GlobalAlloc` sees what the dispatch actually asks the
//! allocator for, including the allocations nobody wrote down.
//!
//! Three properties this file is reviewed on:
//!
//! 1. **The inactive path is trivial.** This allocator is installed for the
//!    whole lib-test binary, so every other test in the crate runs through it.
//!    When no scope is open the cost is one relaxed thread-local `bool` read,
//!    one relaxed atomic `bool` load (the process-wide mode, MIK-8412) and a
//!    forward to `System`; with no free scan armed, a free adds two atomic
//!    loads. No lock, no buffer, no allocation, no
//!    initialiser — the cells are `const`-initialised, so touching them cannot
//!    allocate and cannot register a destructor.
//! 2. **Deallocation is never counted and never touches the cells.** The
//!    checkpoint asks for allocated bytes, never net bytes, so `dealloc` only
//!    forwards — which also removes the thread-teardown hazard entirely on
//!    that path. The one exception is the free scan: one atomic
//!    load, and a search of the block only while a marker is armed.
//! 3. **Failure is silent, never a panic.** A panic raised inside the
//!    allocator is not recoverable in any useful way. `try_with` losing a
//!    record during teardown drops the record.
//!
//! Contamination is handled a second time by the caller: every measuring test
//! re-executes itself as a child process running exactly one test on a
//! current-thread runtime, so no unrelated test's allocations can land in a
//! total. See [`isolate`].

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::sync::atomic::{AtomicBool, AtomicPtr, AtomicU64, AtomicUsize, Ordering};

thread_local! {
    /// Whether THIS thread is inside an open measurement scope.
    static ACTIVE: Cell<bool> = const { Cell::new(false) };
    static BYTES: Cell<u64> = const { Cell::new(0) };
    static CALLS: Cell<u64> = const { Cell::new(0) };
    static LARGEST: Cell<u64> = const { Cell::new(0) };
    static LARGE: Cell<u64> = const { Cell::new(0) };
    static LARGE_TOTAL: Cell<u64> = const { Cell::new(0) };
}

/// Installed for the test binary only — this module is `cfg(test)` through its
/// parent declaration in `server/mod.rs`.
#[global_allocator]
static METERED_SYSTEM: MeteredSystem = MeteredSystem;

pub(super) struct MeteredSystem;

/// An allocation this size or larger is counted in [`Measured::large`]. On a
/// refused dispatch the only ones today are boxed dispatch futures; any
/// allocation this large counts, a long string included.
pub(crate) const LARGE_BYTES: usize = 2 * 1024;

/// Process-wide counters for [`measure_async_process_wide`]: every thread's
/// allocations while set, the blocking pool's included (MIK-8412: custody
/// work runs in `spawn_blocking`). Only an isolated child may set it, where
/// no other test runs. Atomics, so recording still never allocates.
static WIDE: AtomicBool = AtomicBool::new(false);
static WIDE_BYTES: AtomicU64 = AtomicU64::new(0);
static WIDE_CALLS: AtomicU64 = AtomicU64::new(0);
static WIDE_LARGEST: AtomicU64 = AtomicU64::new(0);
static WIDE_LARGE: AtomicU64 = AtomicU64::new(0);
static WIDE_LARGE_TOTAL: AtomicU64 = AtomicU64::new(0);

/// The free scan: while a marker is armed, every block freed, and
/// every block a reallocation moves, is searched for it before it goes back
/// to the allocator. A hit is a copy of the marker returned still holding it,
/// that is, never wiped. Process-wide, because a block is freed on whatever
/// thread drops it, so only an isolated child may arm it.
/// The armed marker. Pointer and length are published together as one
/// record, set once per arming and never freed, so a free racing a re-arm
/// never pairs one marker's address with another's length.
struct Needle {
    ptr: *const u8,
    len: usize,
}
static SCAN_NEEDLE: AtomicPtr<Needle> = AtomicPtr::new(std::ptr::null_mut());
/// Searches running now, on any thread: teardown waits for them before it
/// reads the counts.
static SCAN_INFLIGHT: AtomicUsize = AtomicUsize::new(0);
static SCAN_HITS: AtomicU64 = AtomicU64::new(0);
/// Blocks searched while armed (large enough to hold the marker), so a row
/// can tell "no block held it" from "no block was freed".
static SCAN_SEARCHED: AtomicU64 = AtomicU64::new(0);
/// One block a row expects to be freed (the returned credential's own
/// buffer), so "no block held the marker" is tied to that block, not to
/// whatever else happened to be freed.
static SCAN_WATCH: AtomicPtr<u8> = AtomicPtr::new(std::ptr::null_mut());
static SCAN_WATCH_FREED: AtomicBool = AtomicBool::new(false);

/// One byte at `at`, read through inline assembly. A block's bytes may be
/// uninitialized as far as Rust is concerned (spare capacity, a struct's
/// padding), and reading those as `u8` in Rust is undefined. An `asm!` output
/// is always an initialized value, so this read is defined whatever the byte
/// is. The free scan arms only on these two targets.
///
/// # Safety
///
/// `at` must be readable for one byte for the whole call: inside a live block
/// this allocator handed out and has not yet returned, or inside the
/// `'static` marker. The instruction loads one byte and writes nothing.
#[allow(unsafe_code)]
unsafe fn read_byte(at: *const u8) -> u8 {
    let word: u32;
    // SAFETY: the caller's contract above; see the Rust Reference's rules
    // for inline assembly: an output operand holds the value the
    // instruction produced, which is initialized.
    #[cfg(target_arch = "x86_64")]
    unsafe {
        std::arch::asm!(
            "movzx {w:e}, byte ptr [{p}]",
            w = out(reg) word,
            p = in(reg) at,
            options(nostack, preserves_flags, readonly)
        );
    }
    #[cfg(target_arch = "aarch64")]
    unsafe {
        std::arch::asm!(
            "ldrb {w:w}, [{p}]",
            w = out(reg) word,
            p = in(reg) at,
            options(nostack, preserves_flags, readonly)
        );
    }
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    {
        let _ = at;
        word = 0;
    }
    // The load zero-extends one byte, so the low byte is the whole value.
    word.to_le_bytes()[0]
}

/// Whether the free scan can read bytes on this target.
const SCAN_SUPPORTED: bool = cfg!(any(target_arch = "x86_64", target_arch = "aarch64"));

/// Register one allocator callback's scan work, if a scan is armed. Teardown
/// waits for every registered callback, so a hit or a watched free it records
/// is counted before the results are read. The armed state is checked again
/// after registering, so a callback that raced a teardown records nothing.
fn scan_enter() -> bool {
    let armed = || {
        !SCAN_NEEDLE.load(Ordering::SeqCst).is_null()
            || !SCAN_WATCH.load(Ordering::SeqCst).is_null()
    };
    if !armed() {
        return false;
    }
    SCAN_INFLIGHT.fetch_add(1, Ordering::SeqCst);
    if armed() {
        true
    } else {
        SCAN_INFLIGHT.fetch_sub(1, Ordering::SeqCst);
        false
    }
}

fn scan_leave() {
    SCAN_INFLIGHT.fetch_sub(1, Ordering::SeqCst);
}

/// Whether the block at `ptr` (all `size` bytes of its layout, spare capacity
/// included) holds the armed marker. Call between [`scan_enter`] and
/// [`scan_leave`]. Never allocates, never unwinds.
fn holds_marker(ptr: *const u8, size: usize) -> bool {
    let needle = SCAN_NEEDLE.load(Ordering::SeqCst);
    if needle.is_null() {
        return false;
    }
    // SAFETY: a published needle is leaked, never freed, and points at a
    // `'static` marker of `len` bytes.
    #[allow(unsafe_code)]
    let needle = unsafe { &*needle };
    if size < needle.len {
        return false;
    }
    SCAN_SEARCHED.fetch_add(1, Ordering::Relaxed);
    // SAFETY: `start + at` stays below `size` for the block and below `len`
    // for the needle, so every address is inside the live block or the
    // `'static` marker.
    #[allow(unsafe_code)]
    let byte = |base: *const u8, at: usize| unsafe { read_byte(base.add(at)) };
    (0..=size - needle.len)
        .any(|start| (0..needle.len).all(|at| byte(ptr, start + at) == byte(needle.ptr, at)))
}

/// Nothing below allocates, so recording cannot re-enter the allocator.
fn record(bytes: usize) {
    if WIDE.load(Ordering::Relaxed) {
        let bytes = bytes as u64;
        WIDE_BYTES.fetch_add(bytes, Ordering::Relaxed);
        WIDE_CALLS.fetch_add(1, Ordering::Relaxed);
        WIDE_LARGEST.fetch_max(bytes, Ordering::Relaxed);
        if bytes >= LARGE_BYTES as u64 {
            WIDE_LARGE.fetch_add(1, Ordering::Relaxed);
            WIDE_LARGE_TOTAL.fetch_add(bytes, Ordering::Relaxed);
        }
    }
    let _ = ACTIVE.try_with(|active| {
        if active.get() {
            let _ = BYTES.try_with(|total| total.set(total.get().saturating_add(bytes as u64)));
            let _ = CALLS.try_with(|calls| calls.set(calls.get().saturating_add(1)));
            let _ = LARGEST.try_with(|largest| largest.set(largest.get().max(bytes as u64)));
            if bytes >= LARGE_BYTES {
                let _ = LARGE.try_with(|large| large.set(large.get().saturating_add(1)));
                let _ = LARGE_TOTAL
                    .try_with(|total| total.set(total.get().saturating_add(bytes as u64)));
            }
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
        // Searched before the move, counted only if the block did move: a
        // block grown in place was not returned.
        let armed = scan_enter();
        let held = armed && holds_marker(ptr, layout.size());
        let moved = unsafe { System.realloc(ptr, layout, new_size) };
        if armed {
            if !moved.is_null() && moved != ptr {
                if held {
                    SCAN_HITS.fetch_add(1, Ordering::Relaxed);
                }
                if ptr == SCAN_WATCH.load(Ordering::SeqCst) {
                    SCAN_WATCH_FREED.store(true, Ordering::Relaxed);
                }
            }
            scan_leave();
        }
        moved
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        if scan_enter() {
            if !ptr.is_null() && ptr == SCAN_WATCH.load(Ordering::SeqCst) {
                SCAN_WATCH_FREED.store(true, Ordering::Relaxed);
            }
            if holds_marker(ptr, layout.size()) {
                SCAN_HITS.fetch_add(1, Ordering::Relaxed);
            }
            scan_leave();
        }
        unsafe { System.dealloc(ptr, layout) }
    }
}

/// What one scope observed. Bytes AND calls: a byte total alone cannot
/// distinguish "one big copy" from "many small ones", and the diagnostics in a
/// failing assertion are worth more than the assertion. The largest single
/// allocation and the count of large ones name a big copy outright
/// (MIK-8400).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Measured {
    pub(crate) bytes: u64,
    pub(crate) calls: u64,
    pub(crate) largest: u64,
    pub(crate) large: u64,
    /// The bytes of those large allocations, included in `bytes`.
    pub(crate) large_bytes: u64,
}

impl std::fmt::Display for Measured {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} bytes allocated across {} allocator calls (largest {}, {} of {}+ bytes)",
            self.bytes, self.calls, self.largest, self.large, LARGE_BYTES
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
        LARGEST.with(|largest| largest.set(0));
        LARGE.with(|large| large.set(0));
        LARGE_TOTAL.with(|total| total.set(0));
        ACTIVE.with(|active| active.set(true));
        Self
    }

    #[expect(
        clippy::unused_self,
        reason = "self is consumed by value on purpose: taking ownership ends the \
                  RAII scope explicitly here rather than at the end of the caller's \
                  block, even though Meter itself carries no fields to read"
    )]
    fn stop(self) -> Measured {
        ACTIVE.with(|active| active.set(false));
        Measured {
            bytes: BYTES.with(Cell::get),
            calls: CALLS.with(Cell::get),
            largest: LARGEST.with(Cell::get),
            large: LARGE.with(Cell::get),
            large_bytes: LARGE_TOTAL.with(Cell::get),
        }
    }
}

impl Drop for Meter {
    fn drop(&mut self) {
        ACTIVE.with(|active| active.set(false));
    }
}

/// Measure a synchronous body. Used by the two controls.
pub(crate) fn measure<T>(body: impl FnOnce() -> T) -> (T, Measured) {
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
pub(crate) async fn measure_async<F, Fut>(make: F) -> (Fut::Output, Measured)
where
    F: FnOnce() -> Fut,
    Fut: std::future::Future,
{
    let meter = Meter::start();
    let value = make().await;
    (value, meter.stop())
}

/// Set in a re-executed child. Its presence is what tells a test body it is
/// the one that must actually measure.
const CHILD_ENV: &str = "MCPGW_ALLOC_METER_CHILD";

/// Returns `true` in the PARENT, after running this one test in a child that
/// did the measuring. Returns `false` in the child, meaning "you are the
/// measurement, proceed".
///
/// Why a child at all: thread-local totals already keep other tests out of a
/// reading, but [`measure_async_process_wide`] counts every thread, so only a
/// process running exactly one test can use it.
///
/// `--exact` plus the assertion on `1 passed` is load-bearing. A child that
/// matched zero tests exits 0, and the parent would go green on a test that
/// never ran — a case that can never fail is not a test.
pub(crate) fn isolate(test_path: &str) -> bool {
    if std::env::var_os(CHILD_ENV).is_some() {
        return false;
    }
    let exe = std::env::current_exe().expect("the running test binary must be locatable");
    let output = std::process::Command::new(exe)
        .args([test_path, "--exact", "--nocapture", "--test-threads=1"])
        .env(CHILD_ENV, "1")
        .output()
        .expect("re-executing the test binary must succeed");
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    assert!(
        output.status.success(),
        "isolated child failed for {test_path}\n--- child stdout ---\n{stdout}\n--- child stderr ---\n{stderr}"
    );
    assert!(
        stdout.contains("1 passed"),
        "isolated child for {test_path} did not run exactly one test\n--- child stdout ---\n{stdout}"
    );
    true
}

/// Clears the process-wide flag on every exit, an unwind included.
struct WideScope;

impl Drop for WideScope {
    fn drop(&mut self) {
        WIDE.store(false, Ordering::SeqCst);
    }
}

/// [`measure_async`] counting EVERY thread's allocations, the blocking pool's
/// included, for a dispatch that offloads work (MIK-8412). Only inside an
/// [`isolate`]d child: elsewhere other tests' threads would land in it.
pub(crate) async fn measure_async_process_wide<F, Fut>(make: F) -> (Fut::Output, Measured)
where
    F: FnOnce() -> Fut,
    Fut: std::future::Future,
{
    assert!(
        std::env::var_os(CHILD_ENV).is_some(),
        "process-wide metering runs only in an isolated child"
    );
    assert!(
        !WIDE.load(Ordering::SeqCst),
        "process-wide meters must not nest"
    );
    // Zeroed before arming, so no allocation lands between the two.
    for counter in [
        &WIDE_BYTES,
        &WIDE_CALLS,
        &WIDE_LARGEST,
        &WIDE_LARGE,
        &WIDE_LARGE_TOTAL,
    ] {
        counter.store(0, Ordering::SeqCst);
    }
    WIDE.store(true, Ordering::SeqCst);
    let scope = WideScope;

    let value = make().await;
    drop(scope);
    let read = |counter: &AtomicU64| counter.load(Ordering::SeqCst);
    (
        value,
        Measured {
            bytes: read(&WIDE_BYTES),
            calls: read(&WIDE_CALLS),
            largest: read(&WIDE_LARGEST),
            large: read(&WIDE_LARGE),
            large_bytes: read(&WIDE_LARGE_TOTAL),
        },
    )
}

/// MIK-8412: the process-wide mode is off unless an isolated child arms it.
/// In this (parent) process nothing arms it, so an allocation lands in no
/// process-wide counter.
#[test]
fn the_process_wide_mode_is_off_by_default() {
    assert!(
        std::env::var_os(CHILD_ENV).is_none() && !WIDE.load(Ordering::SeqCst),
        "process-wide metering is armed outside an isolated child"
    );
    let before = WIDE_CALLS.load(Ordering::SeqCst);
    drop(std::hint::black_box(vec![0_u8; 4 * LARGE_BYTES]));
    assert_eq!(
        WIDE_CALLS.load(Ordering::SeqCst),
        before,
        "an allocation was counted process-wide while the mode was off"
    );
}

/// Outside an isolated child the process-wide meter refuses to start.
#[test]
#[should_panic(expected = "process-wide metering runs only in an isolated child")]
fn the_process_wide_meter_refuses_outside_a_child() {
    tokio::runtime::Builder::new_current_thread()
        .build()
        .expect("runtime")
        .block_on(measure_async_process_wide(|| async {}));
}

/// Disarms the free scan on drop, so an unwind through the scanned body
/// cannot leave every later free in the process being searched.
struct ScanScope;

impl Drop for ScanScope {
    fn drop(&mut self) {
        SCAN_NEEDLE.store(std::ptr::null_mut(), Ordering::SeqCst);
        SCAN_WATCH.store(std::ptr::null_mut(), Ordering::SeqCst);
        // Every callback registered before the withdrawal finishes its
        // search and its count updates before the counts are read.
        // Teardown runs as ordinary test code, so it may yield; the
        // callbacks it waits on hold no lock and finish on their own.
        while SCAN_INFLIGHT.load(Ordering::SeqCst) != 0 {
            std::thread::yield_now();
        }
    }
}

/// The shortest marker a free scan accepts: longer than any inline storage, so
/// a copy can only live in a heap block the scan sees.
pub(crate) const MIN_MARKER: usize = 64;

fn arm_scan(marker: &'static [u8]) -> ScanScope {
    assert!(
        std::env::var_os(CHILD_ENV).is_some(),
        "a free scan runs only in an isolated child: it sees every thread's frees"
    );
    if !SCAN_SUPPORTED {
        panic!("the free scan reads bytes through inline asm on x86_64 and aarch64 only");
    }
    assert!(
        marker.len() >= MIN_MARKER,
        "a free-scan marker must be at least {MIN_MARKER} bytes"
    );
    assert!(
        SCAN_NEEDLE.load(Ordering::SeqCst).is_null(),
        "free scans must not nest"
    );
    SCAN_HITS.store(0, Ordering::SeqCst);
    SCAN_SEARCHED.store(0, Ordering::SeqCst);
    SCAN_WATCH_FREED.store(false, Ordering::SeqCst);
    let needle = Box::leak(Box::new(Needle {
        ptr: marker.as_ptr(),
        len: marker.len(),
    }));
    SCAN_NEEDLE.store(needle, Ordering::SeqCst);
    ScanScope
}

/// What one free scan saw.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Scanned {
    /// Blocks returned to the allocator still holding the marker: unwiped.
    pub(crate) hits: u64,
    /// Blocks searched: every block freed or moved that was large enough to
    /// hold the marker.
    pub(crate) searched: u64,
    /// Whether the watched block (see [`scan_frees_watching`]) was freed.
    pub(crate) watched_freed: bool,
}

fn scanned() -> Scanned {
    Scanned {
        hits: SCAN_HITS.load(Ordering::SeqCst),
        searched: SCAN_SEARCHED.load(Ordering::SeqCst),
        watched_freed: SCAN_WATCH_FREED.load(Ordering::SeqCst),
    }
}

/// Run `body` with the free scan armed on `marker`; returns its value and
/// what the scan saw while it ran. `marker` is `'static` so the scan's own
/// needle is never freed.
pub(crate) fn scan_frees<T>(marker: &'static [u8], body: impl FnOnce() -> T) -> (T, Scanned) {
    let scope = arm_scan(marker);
    let value = body();
    drop(scope);
    (value, scanned())
}

/// [`scan_frees`], also watching the block at `watched` (for example the
/// heap buffer of the returned credential's value): [`Scanned::watched_freed`]
/// says whether that exact block was freed while the scan ran, so a zero-hit
/// result is tied to the credential's own buffer.
pub(crate) fn scan_frees_watching<T>(
    marker: &'static [u8],
    watched: *const u8,
    body: impl FnOnce() -> T,
) -> (T, Scanned) {
    let scope = arm_scan(marker);
    SCAN_WATCH.store(watched.cast_mut(), Ordering::SeqCst);
    let value = body();
    drop(scope);
    (value, scanned())
}

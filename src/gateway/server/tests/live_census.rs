// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A census of live heap blocks holding a marker, taken at a chosen moment.
//!
//! The free scan sees only copies freed unwiped: a copy wiped on drop is
//! zeroed before the allocator sees it. To count every copy of a credential
//! alive at once, wiped or not, the allocator records each block it hands out
//! while the census is armed, and a census reads every recorded live block.
//!
//! Reviewed on the same rules as the meter: nothing here allocates or
//! unwinds, and the disarmed path is one atomic load. The table is a fixed
//! static array (linear probing, tombstones never reused), so recording
//! cannot re-enter the allocator. A census reads blocks other threads may be
//! freeing, so while one runs, every free waits for it: a block is never
//! read after it was returned.

use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};

/// Table size. A dispatch over loopback HTTP makes on the order of 20 000
/// allocations; the table is sized well past that, and an overflow is
/// reported, never silently dropped.
const SLOTS: usize = 1 << 18;
/// A slot whose block was freed. Never a real address.
const GONE: usize = 1;

static PTRS: [AtomicUsize; SLOTS] = [const { AtomicUsize::new(0) }; SLOTS];
static SIZES: [AtomicUsize; SLOTS] = [const { AtomicUsize::new(0) }; SLOTS];
static ARMED: AtomicBool = AtomicBool::new(false);
static OVERFLOW: AtomicBool = AtomicBool::new(false);
/// Set while a census reads blocks; every free waits until it clears.
static READING: AtomicBool = AtomicBool::new(false);
/// What the census saw: how many censuses ran, and the most copies one found.
static TAKEN: AtomicU64 = AtomicU64::new(0);
static MOST: AtomicU64 = AtomicU64::new(0);

fn start_slot(ptr: usize) -> usize {
    // Allocations are aligned, so the low bits carry nothing.
    (ptr >> 4).wrapping_mul(0x9E37_79B9_7F4A_7C15) % SLOTS
}

/// Record a block handed out. Called by the allocator.
pub(super) fn on_alloc(ptr: *mut u8, size: usize) {
    if ptr.is_null() || !ARMED.load(Ordering::Acquire) {
        return;
    }
    let ptr = ptr as usize;
    let mut slot = start_slot(ptr);
    for _ in 0..SLOTS {
        if PTRS[slot]
            .compare_exchange(0, ptr, Ordering::AcqRel, Ordering::Relaxed)
            .is_ok()
        {
            SIZES[slot].store(size, Ordering::Release);
            return;
        }
        slot = (slot + 1) % SLOTS;
    }
    OVERFLOW.store(true, Ordering::Relaxed);
}

/// Forget a block before it is returned, after any census reading it ends.
/// Called by the allocator.
pub(super) fn on_free(ptr: *mut u8) {
    if ptr.is_null() || !ARMED.load(Ordering::Acquire) {
        return;
    }
    while READING.load(Ordering::Acquire) {
        std::hint::spin_loop();
    }
    let ptr = ptr as usize;
    let mut slot = start_slot(ptr);
    for _ in 0..SLOTS {
        match PTRS[slot].load(Ordering::Acquire) {
            0 => return,
            found if found == ptr => {
                SIZES[slot].store(0, Ordering::Release);
                PTRS[slot].store(GONE, Ordering::Release);
                return;
            }
            _ => slot = (slot + 1) % SLOTS,
        }
    }
}

/// Start recording. The table is cleared first; a census armed twice at once
/// is refused.
pub(super) fn arm() {
    assert!(!ARMED.load(Ordering::SeqCst), "censuses must not nest");
    for slot in 0..SLOTS {
        PTRS[slot].store(0, Ordering::Relaxed);
        SIZES[slot].store(0, Ordering::Relaxed);
    }
    OVERFLOW.store(false, Ordering::SeqCst);
    TAKEN.store(0, Ordering::SeqCst);
    MOST.store(0, Ordering::SeqCst);
    ARMED.store(true, Ordering::SeqCst);
}

pub(super) fn disarm() {
    ARMED.store(false, Ordering::SeqCst);
}

/// Count every live recorded block holding the marker, using `holds` to
/// search one block. Frees on other threads wait while it reads.
pub(super) fn take(holds: impl Fn(*const u8, usize) -> bool) {
    if !ARMED.load(Ordering::Acquire) {
        return;
    }
    while READING
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Relaxed)
        .is_err()
    {
        std::hint::spin_loop();
    }
    let mut copies = 0u64;
    for slot in 0..SLOTS {
        let ptr = PTRS[slot].load(Ordering::Acquire);
        let size = SIZES[slot].load(Ordering::Acquire);
        if ptr > GONE && size > 0 && holds(ptr as *const u8, size) {
            copies += 1;
        }
    }
    READING.store(false, Ordering::Release);
    TAKEN.fetch_add(1, Ordering::Relaxed);
    MOST.fetch_max(copies, Ordering::Relaxed);
}

/// Censuses taken, the most copies one found, and whether the table overflowed.
pub(super) fn result() -> (u64, u64, bool) {
    (
        TAKEN.load(Ordering::SeqCst),
        MOST.load(Ordering::SeqCst),
        OVERFLOW.load(Ordering::SeqCst),
    )
}

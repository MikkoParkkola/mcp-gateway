#!/usr/bin/env python3
"""Throwaway measurement (never merged): count heap allocations per call.

  alloc_count_patch.py ARM_DIR

Patches one checked-out arm so its binary counts every allocation it asks the
global allocator for, the same thing src/gateway/server/tests/alloc_meter.rs
counts (a GlobalAlloc forwarding to System), but process-wide and in the real
binary, so v3.5.1 (which has no meter) and 4.0 are counted the same way.
mimalloc's #[global_allocator] is removed where present: the count is the
code's, not the allocator's, so every arm forwards to the same System.
With ALLOC_COUNT_FILE set, a thread rewrites "allocs reallocs bytes" there
every 50 ms (write to a temp file, then rename, so a reader never sees half).
"""
import sys
from pathlib import Path

MODULE = r'''
#[allow(unsafe_code)]
mod alloc_count {
    use std::alloc::{GlobalAlloc, Layout, System};
    use std::sync::atomic::{AtomicU64, Ordering::Relaxed};

    static ALLOCS: AtomicU64 = AtomicU64::new(0);
    static REALLOCS: AtomicU64 = AtomicU64::new(0);
    static BYTES: AtomicU64 = AtomicU64::new(0);

    struct Counting;

    // SAFETY: every method forwards its exact arguments to System.
    unsafe impl GlobalAlloc for Counting {
        unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
            ALLOCS.fetch_add(1, Relaxed);
            BYTES.fetch_add(layout.size() as u64, Relaxed);
            unsafe { System.alloc(layout) }
        }
        unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
            ALLOCS.fetch_add(1, Relaxed);
            BYTES.fetch_add(layout.size() as u64, Relaxed);
            unsafe { System.alloc_zeroed(layout) }
        }
        unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
            REALLOCS.fetch_add(1, Relaxed);
            BYTES.fetch_add(new_size as u64, Relaxed);
            unsafe { System.realloc(ptr, layout, new_size) }
        }
        unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
            unsafe { System.dealloc(ptr, layout) }
        }
    }

    #[global_allocator]
    static GLOBAL: Counting = Counting;

    pub fn start() {
        let Some(path) = std::env::var_os("ALLOC_COUNT_FILE") else { return };
        let path = std::path::PathBuf::from(path);
        let tmp = path.with_extension("tmp");
        std::thread::spawn(move || loop {
            let line = format!(
                "{} {} {}\n",
                ALLOCS.load(Relaxed),
                REALLOCS.load(Relaxed),
                BYTES.load(Relaxed)
            );
            if std::fs::write(&tmp, line).is_ok() {
                let _ = std::fs::rename(&tmp, &path);
            }
            std::thread::sleep(std::time::Duration::from_millis(50));
        });
    }
}
'''

MIMALLOC = "#[global_allocator]\nstatic GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;\n"
MAIN = "fn main() -> ExitCode {\n"


def main(arm: str) -> None:
    root = Path(arm)
    allocator = root / "src/allocator.rs"
    if allocator.exists():
        text = allocator.read_text()
        assert text.count(MIMALLOC) == 1, "allocator.rs: expected one mimalloc global_allocator"
        allocator.write_text(text.replace(MIMALLOC, ""))
    main_rs = root / "src/main.rs"
    text = main_rs.read_text()
    assert text.count(MAIN) == 1, "main.rs: expected one `fn main() -> ExitCode {`"
    main_rs.write_text(text.replace(MAIN, MAIN + "    alloc_count::start();\n") + MODULE)


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    main(sys.argv[1])

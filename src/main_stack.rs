// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The thread the async main body runs on (split from `main.rs`).

/// Stack for the thread that runs the async main body.
///
/// Clap's derived parser needs about 900 KB of stack in an unoptimized build
/// (the generated `augment_subcommands` frames alone are ~650 KB), which is
/// over the 1 MiB Windows gives a process's main thread. 8 MiB is the Linux
/// default, so every platform gets the stack CI already exercises.
const MAIN_STACK_BYTES: usize = 8 * 1024 * 1024;

/// Run `body` on a thread with [`MAIN_STACK_BYTES`] of stack and return its
/// value. A panic in `body` is re-raised on the caller (the thread already
/// printed it), so the exit status stays a panic's.
pub(crate) fn on_main_stack<T: Send + 'static>(body: impl FnOnce() -> T + Send + 'static) -> T {
    std::thread::Builder::new()
        .name("main".into())
        .stack_size(MAIN_STACK_BYTES)
        .spawn(body)
        .expect("spawn the main runtime thread")
        .join()
        .unwrap_or_else(|payload| std::panic::resume_unwind(payload))
}

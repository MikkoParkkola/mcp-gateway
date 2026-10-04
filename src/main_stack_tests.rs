// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The async main body runs on its own thread with the main stack size.

use crate::on_main_stack;

/// The body runs with the full main stack: a 4 MiB frame fits, which is more
/// than std's 2 MiB default for a spawned thread and Windows' 1 MiB main.
#[test]
#[expect(
    clippy::large_stack_arrays,
    reason = "the oversized frame is the property under test"
)]
fn the_main_body_gets_the_full_stack() {
    let len = on_main_stack(|| {
        let frame = [1_u8; 4 * 1024 * 1024];
        std::hint::black_box(&frame).len()
    });
    assert_eq!(len, 4 * 1024 * 1024);
}

/// A panic in the body reaches the caller, so the process still exits as a
/// panic rather than with a normal status.
#[test]
fn a_panic_in_the_main_body_reaches_the_caller() {
    let caught = std::panic::catch_unwind(|| on_main_stack(|| panic!("body panicked")));
    let payload = caught.expect_err("the panic must propagate");
    assert_eq!(payload.downcast_ref::<&str>(), Some(&"body panicked"));
}

/// MIK-7683: only `serve --stdio` bounds the runtime's shutdown. HTTP serve
/// (with or without the subcommand) and every other command keep waiting for
/// blocking work, whose audit and store flushes are not proven finished.
#[test]
fn only_stdio_serve_bounds_the_runtime_shutdown() {
    use crate::{RuntimeShutdown, STDIO_RUNTIME_SHUTDOWN_TIMEOUT};
    use mcp_gateway::cli::Command;
    assert_eq!(
        RuntimeShutdown::of(Some(&Command::Serve { stdio: true })),
        RuntimeShutdown::Bounded(STDIO_RUNTIME_SHUTDOWN_TIMEOUT)
    );
    assert_eq!(
        RuntimeShutdown::of(Some(&Command::Serve { stdio: false })),
        RuntimeShutdown::WaitForBlockingWork
    );
    assert_eq!(
        RuntimeShutdown::of(None),
        RuntimeShutdown::WaitForBlockingWork
    );
}

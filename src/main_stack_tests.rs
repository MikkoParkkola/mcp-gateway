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

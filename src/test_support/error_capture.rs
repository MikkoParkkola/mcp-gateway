// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The ERROR lines `body` logs on this thread, as plain text (MIK-8254).
//!
//! Shared by `#[path]` between the binary's runtime tests and the
//! fresh-process row in `tests/log_capture_interest.rs`, so the row proves the
//! capture those tests actually use.

use std::io::Write;
use std::sync::{Arc, Mutex};

#[path = "interest.rs"]
mod interest;

#[derive(Clone, Default)]
struct Captured(Arc<Mutex<Vec<u8>>>);

impl Write for Captured {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0
            .lock()
            .expect("the log buffer")
            .extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Every ERROR line `body` logs on this thread.
pub fn errors_logged(body: impl FnOnce()) -> String {
    interest::keep_interest_open();
    let captured = Captured::default();
    let writer = captured.clone();
    let subscriber = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::ERROR)
        .with_ansi(false)
        .with_writer(move || writer.clone())
        .finish();
    tracing::subscriber::with_default(subscriber, body);
    let bytes = captured.0.lock().expect("the log buffer").clone();
    String::from_utf8(bytes).expect("utf-8 log lines")
}

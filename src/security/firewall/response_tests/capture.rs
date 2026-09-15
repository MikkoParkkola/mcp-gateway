// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! Scoped test log capture reused by engine and final-delivery tests.

use std::io::Write;
use std::sync::{Arc, Mutex};

struct CapturedWriter(Arc<Mutex<Vec<u8>>>);

impl Write for CapturedWriter {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

pub(crate) fn capture_warnings<T>(operation: impl FnOnce() -> T) -> (T, String) {
    // Keep shared callsite interest live when a sibling test reaches the same
    // warning without a scoped subscriber. The registry discards events; only
    // the thread-local subscriber below captures this operation's output.
    use tracing_subscriber::prelude::*;
    static INTEREST: std::sync::Once = std::sync::Once::new();
    INTEREST.call_once(|| {
        let _ = tracing::subscriber::set_global_default(
            tracing_subscriber::Registry::default()
                .with(tracing::level_filters::LevelFilter::TRACE),
        );
    });
    let buffer = Arc::new(Mutex::new(Vec::new()));
    let writer = Arc::clone(&buffer);
    let subscriber = tracing_subscriber::fmt()
        .without_time()
        .with_ansi(false)
        .with_max_level(tracing::Level::WARN)
        .with_writer(move || CapturedWriter(Arc::clone(&writer)))
        .finish();
    let result = tracing::subscriber::with_default(subscriber, operation);
    let output = String::from_utf8(buffer.lock().unwrap().clone()).unwrap();
    (result, output)
}

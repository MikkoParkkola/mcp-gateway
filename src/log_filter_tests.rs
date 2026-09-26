// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! F17-T19: tungstenite's client handshake dumps the whole upgrade request
//! (query string and every header) at TRACE. The production filter caps that
//! target at DEBUG even when the operator asks for TRACE by name.

use std::io::Write;
use std::sync::{Arc, Mutex};

use tracing_subscriber::EnvFilter;
use tracing_subscriber::layer::SubscriberExt;

use super::cap_handshake_logging;

const HANDSHAKE_TARGET: &str = "tungstenite::handshake::client";

#[derive(Clone, Default)]
struct Buffer(Arc<Mutex<Vec<u8>>>);

impl Write for Buffer {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Emit one TRACE and one DEBUG event at the handshake target through the
/// production filter built from `spec`, and return what was written.
fn emitted_under(spec: &str) -> String {
    let buffer = Buffer::default();
    let writer = buffer.clone();
    let subscriber = tracing_subscriber::registry()
        .with(cap_handshake_logging(EnvFilter::new(spec)))
        .with(
            tracing_subscriber::fmt::layer()
                .with_ansi(false)
                .with_writer(move || writer.clone()),
        );
    tracing::subscriber::with_default(subscriber, || {
        tracing::trace!(target: HANDSHAKE_TARGET, "Request: GET /mcp?token=SECRET");
        tracing::debug!(target: HANDSHAKE_TARGET, "Client handshake done.");
    });
    String::from_utf8(buffer.0.lock().unwrap().clone()).unwrap()
}

#[test]
fn handshake_request_dump_is_suppressed_even_when_trace_is_requested_by_name() {
    for spec in [
        "trace",
        "tungstenite=trace",
        "tungstenite::handshake=trace",
        "tungstenite::handshake::client=trace",
    ] {
        let out = emitted_under(spec);
        // Positive control: the target is live, so silence below is the cap.
        assert!(
            out.contains("Client handshake done."),
            "{spec}: the DEBUG line must still be emitted, got {out:?}"
        );
        assert!(
            !out.contains("SECRET"),
            "{spec}: the TRACE request dump must be capped, got {out:?}"
        );
    }
}

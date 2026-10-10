// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! #1943: building a gateway warns about remote backends that run without
//! signed provenance. Every constructor reaches `new_with_env`, which both the
//! HTTP and the stdio start use, so this covers both.

use std::io::Write;
use std::sync::{Arc, Mutex};

use super::Gateway;
use crate::config::Config;

#[derive(Clone, Default)]
struct Sink(Arc<Mutex<Vec<u8>>>);

impl Write for Sink {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().expect("sink lock").extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// WARN-level log text emitted while `Gateway::new(config)` runs.
fn warnings_while_building(config: Config) -> String {
    // A process-wide interested subscriber keeps callsite interest open, so the
    // scoped one below sees every record (see the note in the stdio tests).
    crate::test_log_capture::keep_interest_open();
    let sink = Sink::default();
    let writer = sink.clone();
    let subscriber = tracing_subscriber::fmt()
        .with_ansi(false)
        .with_max_level(tracing::Level::WARN)
        .with_writer(move || writer.clone())
        .finish();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("a current-thread runtime");
    tracing::subscriber::with_default(subscriber, || {
        runtime.block_on(async {
            Gateway::new(config).await.expect("gateway builds");
        });
    });
    let bytes = sink.0.lock().expect("sink lock").clone();
    String::from_utf8(bytes).expect("utf-8 logs")
}

fn config(yaml: &str) -> Config {
    serde_yaml::from_str(yaml).expect("test config parses")
}

#[test]
fn building_a_gateway_warns_about_an_unverified_remote_backend() {
    let config = config("backends:\n  api:\n    http_url: https://api.example.test/mcp\n");
    let expected = config
        .remote_provenance_warning()
        .expect("the backend is unverified");
    let logs = warnings_while_building(config);
    assert!(
        logs.lines()
            .any(|line| line.contains("WARN") && line.contains(&expected)),
        "no WARN with {expected:?} in:\n{logs}"
    );
}

#[test]
fn no_provenance_warning_without_a_remote_backend() {
    let config = config("backends:\n  local:\n    command: npx some-server\n");
    let logs = warnings_while_building(config);
    assert!(!logs.contains("signed provenance"), "{logs}");
}

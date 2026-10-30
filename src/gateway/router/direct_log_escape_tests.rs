// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! LOGINJ.3, direct route: a client's tool name that validation refuses is
//! logged by name, and the name cannot forge a line in the text log.

use std::sync::{Arc, Mutex};

use serde_json::json;
use tracing_subscriber::layer::SubscriberExt as _;

use super::direct_guards_fixture::{Answer, fixture, post_direct};

/// The planted name: a newline that starts a forged line, and an erase code.
const PROBE: &str = "read\n2026-10-28T12:00:00Z  WARN forged: admin granted\x1b[2K";

#[derive(Clone, Default)]
struct Buf(Arc<Mutex<Vec<u8>>>);

impl std::io::Write for Buf {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.lock().expect("buffer").extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for Buf {
    type Writer = Self;
    fn make_writer(&'a self) -> Self {
        self.clone()
    }
}

#[tokio::test]
async fn a_refused_tool_name_cannot_forge_a_log_line() {
    crate::test_log_capture::keep_interest_open();
    let fx = fixture(Answer::Ok, |_| {}).await;
    for ansi in [false, true] {
        let buf = Buf::default();
        let layer = crate::log_escape::escaping(
            tracing_subscriber::fmt::layer()
                .with_ansi(ansi)
                .with_writer(buf.clone()),
        );
        let guard = tracing::subscriber::set_default(tracing_subscriber::registry().with(layer));
        let (_, body) = post_direct(&fx, "alpha", "k-std", PROBE, json!({}), None, None).await;
        drop(guard);
        assert!(
            body.get("error").is_some(),
            "the name was not refused: {body}"
        );
        let out = String::from_utf8(buf.0.lock().expect("buffer").clone()).expect("utf-8");
        assert!(out.contains("Tool name rejected by validation"), "{out:?}");
        assert!(
            !out.lines()
                .any(|l| l.starts_with("2026-10-28T12:00:00Z  WARN forged")),
            "a forged line: {out:?}"
        );
        assert!(!out.contains("\x1b[2K") && !out.contains('\r'), "{out:?}");
    }
}

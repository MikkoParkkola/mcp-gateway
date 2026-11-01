// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Every scanner warning names a client's server and key escaped: a name
//! holding an ANSI escape or a bidi override cannot reach the terminal.

use std::path::Path;

use serde_json::{Value, json};

use super::parse;
use crate::discovery::DiscoverySource;
use crate::test_log_capture::capture_warnings;

/// A name and a key that would recolour or reverse a terminal line.
const NAME: &str = "srv\u{1b}[31m\u{202e}x";
const KEY: &str = "K\u{1b}[0m\u{2028}";

fn warnings(entry: &Value) -> String {
    let (_, logs) = capture_warnings(|| {
        parse(
            NAME,
            entry,
            &DiscoverySource::ClaudeDesktop,
            Path::new("/client/config.json"),
        )
    });
    logs
}

/// One row per warning site, each with the entry that triggers it and the
/// text that proves the site fired.
#[test]
fn every_scanner_warning_shows_the_name_and_key_escaped() {
    let rows: [(&str, Value, &str); 4] = [
        (
            "a non-string value",
            json!({"command": "npx", "env": {KEY: 5}}),
            "is not a string",
        ),
        (
            "a variable only the client resolves",
            json!({"command": "npx", "env": {KEY: "${input:token}"}}),
            "cannot resolve",
        ),
        (
            "an argument no command line can hold",
            json!({"command": "npx", "args": ["a\u{0}b"]}),
            "cannot be quoted",
        ),
        (
            "neither command nor url",
            json!({}),
            "Unsupported server config format",
        ),
    ];
    for (trigger, entry, fired) in rows {
        let logs = warnings(&entry);
        assert!(
            logs.contains(fired),
            "{trigger}: the site did not fire: {logs}"
        );
        for raw in ['\u{1b}', '\u{202e}', '\u{2028}'] {
            assert!(
                !logs.contains(raw),
                "{trigger}: {raw:?} reached the log: {logs:?}"
            );
        }
        assert!(
            logs.contains("\\u{1b}"),
            "{trigger}: the escape is not shown: {logs}"
        );
    }
}

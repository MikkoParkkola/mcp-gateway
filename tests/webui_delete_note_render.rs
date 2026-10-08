// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8051: the dashboard shows the note a backend DELETE returns.
//!
//! The API returning `{"note": ...}` is not enough; the user has to see it.
//! The dashboard's own `removeServer` function, extracted from `index.html`,
//! runs under node against a stubbed `fetch` and DOM, and the note element is
//! checked afterwards.

use std::process::Command;

const INDEX: &str = include_str!("../src/gateway/ui/index.html");

/// `async function removeServer(...) { ... }`, as the page defines it.
fn remove_server_source() -> &'static str {
    let start = INDEX
        .find("async function removeServer(")
        .expect("index.html defines removeServer");
    let end = INDEX[start..]
        .find("\n}\n")
        .expect("removeServer has a closing brace");
    &INDEX[start..start + end + 2]
}

/// Run `removeServer('a')` with `fetch` answering `status` and `body`, and
/// return the note element's `textContent` and `style.display` afterwards.
fn rendered(status: u16, body: &str) -> (String, String) {
    let script = format!(
        r"
const note = {{ textContent: '', style: {{ display: 'none' }} }};
globalThis.document = {{ getElementById: (id) => (id === 'add-server-note' ? note : null) }};
globalThis.confirm = () => true;
globalThis.alert = (m) => {{ throw new Error('alert: ' + m); }};
globalThis.authHeaders = () => ({{}});
globalThis.refreshDashboard = () => {{}};
globalThis.fetch = async () => ({{
  ok: true,
  status: {status},
  statusText: 'OK',
  json: async () => ({body}),
}});
{source}
await removeServer('a');
console.log(JSON.stringify([note.textContent, note.style.display]));
",
        source = remove_server_source()
    );
    let output = Command::new("node")
        .args(["--input-type=module", "-e", &script])
        .output()
        .expect("node is required: this test runs the dashboard's own JavaScript");
    assert!(
        output.status.success(),
        "node failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let shown: (String, String) =
        serde_json::from_slice(&output.stdout).expect("note state as JSON");
    shown
}

/// DEL-NOTE.1: a 200 with a note puts it on screen.
#[test]
fn the_dashboard_shows_a_delete_note() {
    let (text, display) = rendered(
        200,
        r"{ note: 'Comments inside the removed entry went with it: line 6' }",
    );
    assert!(text.contains("line 6"), "the note was not shown: {text:?}");
    assert_ne!(display, "none", "the note element stayed hidden");
}

/// DEL-NOTE.3: a 204 (nothing dropped) shows nothing.
#[test]
fn the_dashboard_shows_nothing_for_a_plain_delete() {
    let (text, display) = rendered(204, "{}");
    assert!(text.is_empty(), "{text:?}");
    assert_eq!(display, "none");
}

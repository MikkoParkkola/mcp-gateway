// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! ISO-T5: the two source rules per-subscriber isolation rests on.
//!
//! - **Keys.** Every backend notification a listener path emits takes its
//!   `lifecycle_key` from `key_of` or `backend_key`, the functions that put a
//!   per-user listener's observation key into it. A literal `None`, or a key
//!   from anywhere else, would let fan-out treat a per-user occurrence as the
//!   backend's shared one.
//! - **Credential.** In the listener transports, a request is sent only inside
//!   a `send` helper, and each such helper goes through `with_credential`, so
//!   no listener request leaves without the subscriber's credential seam.
//!
//! Both rules count what they find, so a scan that matches nothing fails, and
//! each is shown failing on a fixture that breaks it.

use std::path::Path;

/// Files whose backend notifications are emitted by a listener path, relative
/// to `src/events`.
const EMIT_FILES: &[&str] = &["upstream_session_notes.rs", "backend_source.rs"];
/// Backend-notification emits those files hold today.
const EMITS: usize = 3;
/// The listener transports, relative to `src/transport/http`.
const SEND_FILES: &[&str] = &["listen.rs", "sse_listen.rs", "streamable_listen.rs"];
/// `send` helpers those files hold today.
const SEND_HELPERS: usize = 2;

/// The text before the first inline test module: product code only.
fn product(text: &str) -> &str {
    text.find("#[cfg(test)]\nmod ")
        .map_or(text, |at| &text[..at])
}

/// The value of the `lifecycle_key` field in the struct literal that starts at
/// line `from`, or `None` when the literal has no such field.
fn key_field(lines: &[&str], from: usize) -> Option<String> {
    lines.iter().skip(from).take(20).find_map(|line| {
        let rest = line.trim_start().strip_prefix("lifecycle_key")?;
        let rest = rest.trim_end().trim_end_matches(',');
        Some(match rest.strip_prefix(':') {
            Some(value) => value.trim().to_owned(),
            None => "lifecycle_key".to_owned(),
        })
    })
}

/// Every backend-notification emit in `text` whose key is not bound from
/// `key_of` or `backend_key` in the lines above it, and how many emits there
/// were.
fn bad_emits(file: &str, text: &str) -> (Vec<String>, usize) {
    let lines: Vec<&str> = product(text).lines().collect();
    let mut bad = Vec::new();
    let mut emits = 0;
    for (at, line) in lines.iter().enumerate() {
        if !line.contains("kind: SourceKind::BackendNotification") {
            continue;
        }
        let opens_event = lines[at.saturating_sub(2)..at]
            .iter()
            .any(|above| above.contains("SourceEvent {"));
        if !opens_event {
            continue;
        }
        emits += 1;
        let place = format!("{file}:{}", at + 1);
        let Some(value) = key_field(&lines, at) else {
            bad.push(format!("{place}: no lifecycle_key"));
            continue;
        };
        let binding = format!("let {value} = ");
        let bound = lines[at.saturating_sub(30)..at].iter().any(|above| {
            above.contains(&binding)
                && (above.contains("key_of(") || above.contains("backend_key("))
        });
        if !bound {
            bad.push(format!(
                "{place}: lifecycle_key {value} is not from key_of or backend_key"
            ));
        }
    }
    (bad, emits)
}

/// The function a line opens, if it opens one.
fn opens_fn(line: &str) -> Option<&str> {
    let rest = line.trim_start();
    let at = rest.find("fn ")?;
    let head = &rest[..at];
    if !head
        .split_whitespace()
        .all(|w| w.starts_with("pub") || w == "async")
    {
        return None;
    }
    let name = &rest[at + 3..];
    let end = name.find(|c: char| !(c.is_alphanumeric() || c == '_'))?;
    Some(&name[..end])
}

/// Every raw `.send()` in `text` outside a `send` helper, every `send` helper
/// that never reaches `with_credential`, and how many helpers there were.
fn bad_sends(file: &str, text: &str) -> (Vec<String>, usize) {
    let mut bad = Vec::new();
    let mut helpers = 0;
    let mut current: Option<(&str, usize, bool)> = None;
    let close = |current: Option<(&str, usize, bool)>, bad: &mut Vec<String>| {
        if let Some(("send", line, false)) = current {
            bad.push(format!(
                "{file}:{line}: send helper never reaches with_credential"
            ));
        }
    };
    for (at, line) in product(text).lines().enumerate() {
        if let Some(name) = opens_fn(line) {
            close(current.take(), &mut bad);
            if name == "send" {
                helpers += 1;
            }
            current = Some((name, at + 1, false));
        }
        if line.contains("with_credential")
            && let Some(open) = current.as_mut()
        {
            open.2 = true;
        }
        let sends = line.trim_start().starts_with(".send()") || line.contains(").send()");
        if sends && current.map(|(name, ..)| name) != Some("send") {
            bad.push(format!(
                "{file}:{}: request sent outside a send helper",
                at + 1
            ));
        }
    }
    close(current, &mut bad);
    (bad, helpers)
}

fn read(dir: &str, file: &str) -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join(dir).join(file);
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
}

#[test]
fn iso_t5_every_listener_emit_carries_its_listeners_key() {
    let mut bad = Vec::new();
    let mut emits = 0;
    for file in EMIT_FILES {
        let (found, count) = bad_emits(file, &read("src/events", file));
        bad.extend(found);
        emits += count;
    }
    assert!(bad.is_empty(), "{bad:#?}");
    assert_eq!(
        emits, EMITS,
        "a listener emit was added or removed: update EMITS"
    );
}

#[test]
fn iso_t5_every_listener_request_goes_through_the_credential_seam() {
    let mut bad = Vec::new();
    let mut helpers = 0;
    for file in SEND_FILES {
        let (found, count) = bad_sends(file, &read("src/transport/http", file));
        bad.extend(found);
        helpers += count;
    }
    assert!(bad.is_empty(), "{bad:#?}");
    assert_eq!(
        helpers, SEND_HELPERS,
        "a send helper was added or removed: update SEND_HELPERS"
    );
}

/// The key rule fails on a `None` key, on a key bound from anything else, and
/// on an emit with no key at all; it passes the shapes the product uses.
#[test]
fn iso_t5_the_key_rule_fails_on_a_broken_emit() {
    let good = "let lifecycle_key = self.key_of(&name, &data);\nhub.emit(SourceEvent {\n    kind: SourceKind::BackendNotification,\n    lifecycle_key,\n});\nlet key = backend_key(None, &n, &json!({}));\nhub.emit(SourceEvent {\n    kind: SourceKind::BackendNotification,\n    lifecycle_key: key,\n});\n";
    assert_eq!(bad_emits("good.rs", good), (vec![], 2));
    let none = "hub.emit(SourceEvent {\n    kind: SourceKind::BackendNotification,\n    lifecycle_key: None,\n});\n";
    assert_eq!(bad_emits("none.rs", none).0.len(), 1);
    let elsewhere = "let lifecycle_key = Some(name.clone());\nhub.emit(SourceEvent {\n    kind: SourceKind::BackendNotification,\n    lifecycle_key,\n});\n";
    assert_eq!(bad_emits("elsewhere.rs", elsewhere).0.len(), 1);
    let missing = "hub.emit(SourceEvent {\n    kind: SourceKind::BackendNotification,\n});\n";
    assert_eq!(bad_emits("missing.rs", missing).0.len(), 1);
}

/// The credential rule fails on a request sent outside the helper and on a
/// helper that skips `with_credential`; it passes the product's shape.
#[test]
fn iso_t5_the_credential_rule_fails_on_a_broken_send() {
    let good = "async fn send(&self) {\n    source.with_credential(|h| build(h).send())\n}\nasync fn notify(&self) {\n    self.send(headers, |h| t.client.post(url).headers(h))\n}\n";
    assert_eq!(bad_sends("good.rs", good), (vec![], 1));
    let raw = "async fn notify(&self) {\n    t.client.post(url).headers(h).send().await\n}\n";
    assert_eq!(bad_sends("raw.rs", raw).0.len(), 1);
    let bypass = "async fn send(&self) {\n    build(headers).send().await\n}\n";
    assert_eq!(bad_sends("bypass.rs", bypass).0.len(), 1);
}

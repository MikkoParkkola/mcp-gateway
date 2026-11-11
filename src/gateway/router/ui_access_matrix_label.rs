// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A matrix cell's label for refusals and caller-scoped answers: the fields
//! that identify the answer's class and scope, blind to fields added beside
//! them, and the check that the label is as strong as the whole-body pin it
//! replaced. Kept beside `ui_access_matrix_tests.rs` for the file-size ceiling.

use super::*;

/// Seeded fixture values: a body that shows one shows that caller's or that
/// event's data, so each is a scope marker wherever it appears in a string.
const SCOPE_MARKERS: &[&str] = &[
    BEARER,
    ADMIN_KEY,
    STANDARD_KEY,
    ISSUER,
    DEV,
    OTHER_DEV,
    SEEDED_EVENTS[0].0,
    SEEDED_EVENTS[1].0,
    "tool_0",
    "tool_1",
    "tool_2",
];

/// Fields that say which kind of answer this is, or what the caller may do,
/// recorded with their path wherever they hold a scalar. Human texts
/// (`message`, `reason`) are not among them, so rewording moves no cell; a bare
/// `error` string is, because several refusals carry nothing else.
const CLASS_FIELDS: &[&str] = &[
    "reason_code",
    "code",
    "error",
    "kind",
    "role",
    "ok",
    "allowed",
    "admin",
    "mutation_disabled_reason",
];

/// Top-level objects whose every scalar is the caller's identity or permission
/// (status `auth`, the control-plane `actor` and `authorizations`).
const CLASS_OBJECTS: &[&str] = &["auth", "actor", "authorizations"];

/// Top-level lists of codes, each item recorded (the control-plane's limits).
const CLASS_LISTS: &[&str] = &["current_limits"];

/// Keys only the wider status view carries: their presence is the scope.
const STATUS_VIEW_KEYS: &[&str] = &["servers", "circuit_breakers", "tool_count", "counts_since"];

/// Labels longer than this are recorded by a hash of the label (still blind
/// to fields outside it); the control-plane's run to about 2.6 KB.
const LABEL_SHOWN_MAX: usize = 160;

/// The markers `body` shows, sorted and joined: what identifies this answer's
/// class and scope, blind to fields added beside them. `None` when it shows
/// none, so the caller keeps the whole-body hash.
pub(super) fn label(path: &str, mut body: Value) -> Option<String> {
    fn walk(value: &Value, at: &str, top: &str, out: &mut std::collections::BTreeSet<String>) {
        match value {
            Value::Object(map) => {
                for (key, child) in map {
                    let path = if at.is_empty() {
                        key.clone()
                    } else {
                        format!("{at}.{key}")
                    };
                    let top = if at.is_empty() { key.as_str() } else { top };
                    let scalar = !(child.is_object() || child.is_array());
                    if scalar
                        && (CLASS_FIELDS.contains(&key.as_str()) || CLASS_OBJECTS.contains(&top))
                    {
                        out.insert(format!("{path}={child}"));
                    } else if at.is_empty()
                        && CLASS_LISTS.contains(&key.as_str())
                        && child.is_array()
                    {
                        for item in child.as_array().into_iter().flatten() {
                            out.insert(format!("{path}[]={item}"));
                        }
                    } else {
                        walk(child, &path, top, out);
                    }
                }
            }
            Value::Array(items) => items
                .iter()
                .for_each(|item| walk(item, &format!("{at}[]"), top, out)),
            Value::String(text) => {
                for marker in SCOPE_MARKERS.iter().filter(|m| text.contains(**m)) {
                    out.insert((*marker).to_string());
                }
            }
            _ => {}
        }
    }
    let mut out = std::collections::BTreeSet::new();
    if let Some(answer) = body.as_object_mut().filter(|_| path == routes::UI_STATUS) {
        // The `access` report has its own test against the matrix.
        answer.remove("access");
        for key in STATUS_VIEW_KEYS.iter().filter(|k| answer.contains_key(**k)) {
            out.insert(format!("has:{key}"));
        }
    }
    walk(&body, "", "", &mut out);
    let label = out
        .into_iter()
        .collect::<Vec<_>>()
        .join(",")
        .replace(['\t', '\n'], " ");
    match label.len() {
        0 => None,
        n if n > LABEL_SHOWN_MAX => Some(format!("L{}", hash12(label.as_bytes()))),
        _ => Some(label),
    }
}

/// One cell's label pin beside its whole-body pin.
pub(super) struct Pins {
    pub(super) path: &'static str,
    pub(super) old: String,
    pub(super) new: String,
}

/// The strength check: within a route, two answers the whole-body pin tells
/// apart must stay apart under the label, so no caller can be handed another
/// caller's answer unnoticed. The reverse, a label telling apart answers the
/// hash had merged (it strips clock and host keys), only refines; those are
/// printed for review, with the number of cells converted and the routes that
/// keep a hash.
pub(super) fn no_two_distinct_answers_share_a_label(pins: &[Pins]) {
    type Groups<'a> = BTreeMap<(&'a str, &'a str), std::collections::BTreeSet<&'a str>>;
    let mut by_label = Groups::new();
    let mut by_old = Groups::new();
    for pin in pins {
        by_label
            .entry((pin.path, &pin.new))
            .or_default()
            .insert(&pin.old);
        by_old
            .entry((pin.path, &pin.old))
            .or_default()
            .insert(&pin.new);
    }
    for ((path, old), labels) in by_old.iter().filter(|(_, labels)| labels.len() > 1) {
        println!("refined: {path} {old} -> {labels:?}");
    }
    let converted = pins.iter().filter(|pin| pin.old != pin.new).count();
    let hashed: std::collections::BTreeSet<&str> = pins
        .iter()
        .filter(|pin| {
            pin.new.split_once(':').is_some_and(|(_, pin)| {
                pin.len() == 12 && pin.bytes().all(|b| b.is_ascii_hexdigit())
            })
        })
        .map(|pin| pin.path)
        .collect();
    println!("strength check: {converted} cells converted; routes keeping a hash: {hashed:?}");
    let merged: Vec<String> = by_label
        .iter()
        .filter(|(_, olds)| olds.len() > 1)
        .map(|((path, label), olds)| format!("{path} {label}: merges {olds:?}"))
        .collect();
    assert!(
        merged.is_empty(),
        "the label merges answers the whole-body pin told apart:\n{}",
        merged.join("\n")
    );
}

/// What a cell records for one answer. Refusals and caller-scoped answers
/// record their [`label`], so a field added beside it moves no cell; a body
/// that is not JSON, or shows no marker, keeps [`cell_hash`]'s whole-body hash.
pub(super) fn cell(path: &str, status: StatusCode, body: &[u8]) -> String {
    let code = status.as_u16();
    let refused = matches!(code, 401 | 403);
    let scoped = status.is_success()
        && attributes(path).scoped
        && path != routes::UI_ACTIVITY
        && path != routes::UI_ACTIVITY_EXPORT;
    if (refused || scoped)
        && !body.is_empty()
        && let Some(label) = serde_json::from_slice::<Value>(body)
            .ok()
            .and_then(|value| label(path, value))
    {
        return format!("{code}:{label}");
    }
    cell_hash(path, status, body)
}

/// The whole-body pin a cell recorded before [`label`]; still the fallback,
/// and the strength check's comparator.
pub(super) fn cell_hash(path: &str, status: StatusCode, body: &[u8]) -> String {
    let code = status.as_u16();
    let refused = matches!(code, 401 | 403);
    if refused && !body.is_empty() {
        return format!("{code}:{}", hash12(body));
    }
    if status.is_success() && path == routes::UI_ACTIVITY {
        // The list's scope is which seeded calls it shows. The audit layer
        // appends this run's own records too, with clocks and hashes of their
        // own, so only the seeded rows are pinned.
        let list: Value = serde_json::from_slice(body).unwrap_or(Value::Null);
        let mut seen: Vec<&str> = list["rows"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|row| row["tool"].as_str())
            .filter(|tool| tool.starts_with("tool_"))
            .collect();
        seen.sort_unstable();
        return format!("{code}:{}", seen.join(","));
    }
    if status.is_success() && path == routes::UI_ACTIVITY_EXPORT {
        // The export's scope is which seeded calls it carries; like the list,
        // only those are pinned.
        let text = String::from_utf8_lossy(body);
        let mut seen: Vec<&str> = text
            .split(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
            .filter(|token| token.starts_with("tool_"))
            .collect();
        seen.sort_unstable();
        seen.dedup();
        return format!("{code}:{}", seen.join(","));
    }
    if status.is_success() && attributes(path).scoped && !body.is_empty() {
        let canonical = if let Ok(mut v) = serde_json::from_slice::<Value>(body) {
            strip(&mut v);
            if path == routes::UI_STATUS
                && let Some(answer) = v.as_object_mut()
            {
                // The `access` report is new in this change and has its own
                // test against the matrix; every other member is pinned.
                answer.remove("access");
            }
            v.to_string()
        } else {
            let mut lines: Vec<&str> = std::str::from_utf8(body)
                .unwrap_or_default()
                .lines()
                .collect();
            lines.sort_unstable();
            lines.join("\n")
        };
        return format!("{code}:{}", hash12(canonical.as_bytes()));
    }
    code.to_string()
}

// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Rewrite a backend's `http_url` or `ws_url` as `url` in gateway.yaml text.
//!
//! The rewrite works on the text, line by line, so every comment and every
//! other line stays as it was. It renames a key only where it is a direct
//! field of an entry under `backends:` and that entry has no `url` already.
//! A backend written in flow style (`name: { ... }`) is reported, not edited.

use std::collections::BTreeSet;

/// The result of a rewrite: the new text, the 1-based numbers of the lines
/// it changed, the backends it could not edit, and the backends it left on
/// their alias because the address is not a literal of that key's scheme
/// (an address from the environment, `${VAR}`, cannot be `url`).
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct UrlRewrite {
    pub text: String,
    pub changed: Vec<usize>,
    pub skipped: Vec<String>,
    pub kept: Vec<String>,
}

/// The transport key a `url` stands for, by scheme. A private copy of the
/// library's table, which is not public; a test holds the two equal.
pub(crate) fn transport_key_for(url: &str) -> Option<&'static str> {
    let lower = url.to_ascii_lowercase();
    if lower.starts_with("http://") || lower.starts_with("https://") {
        Some("http_url")
    } else if lower.starts_with("ws://") || lower.starts_with("wss://") {
        Some("ws_url")
    } else {
        None
    }
}

/// Rewrite the aliases of every backend, or only of the backends in `only`.
pub(crate) fn rewrite_url_aliases(text: &str, only: Option<&BTreeSet<String>>) -> UrlRewrite {
    let mut lines: Vec<String> = text.split_inclusive('\n').map(str::to_string).collect();
    let mut changed = Vec::new();
    let mut skipped = Vec::new();
    let mut kept = Vec::new();
    let mut renamed: Vec<(String, &'static str)> = Vec::new();
    let doc: Option<serde_yaml::Value> = serde_yaml::from_str(text).ok();
    for entry in backend_entries(&lines) {
        if only.is_some_and(|names| !names.contains(&entry.name)) {
            continue;
        }
        if entry.flow || entry.aliases.len() > 1 {
            skipped.push(entry.name);
            continue;
        }
        if entry.has_url {
            // `url` beside an alias is the loader's to refuse, naming both.
            continue;
        }
        if let Some(&(at, alias)) = entry.aliases.first() {
            let value = doc
                .as_ref()
                .and_then(|d| d.get("backends")?.get(entry.name.as_str())?.get(alias))
                .and_then(serde_yaml::Value::as_str);
            if value.and_then(transport_key_for) != Some(alias) {
                // Renaming would not load (`${VAR}`) or would switch transport.
                kept.push(entry.name);
                continue;
            }
            lines[at] = lines[at].replacen(alias, "url", 1);
            changed.push(at + 1);
            renamed.push((entry.name, alias));
        }
    }
    let rewritten = lines.concat();
    if !changed.is_empty() && !only_renamed(text, &rewritten, &renamed) {
        // A line that looked like a key was text inside a value. Nothing is
        // saved; each backend involved is reported for a hand edit.
        skipped.extend(renamed.into_iter().map(|(name, _)| name));
        return UrlRewrite {
            text: text.to_string(),
            changed: Vec::new(),
            skipped,
            kept,
        };
    }
    UrlRewrite {
        text: rewritten,
        changed,
        skipped,
        kept,
    }
}

/// Whether `after` parses to exactly `before` with each `(backend, alias)`
/// key renamed `url` and every value, comment-free, unchanged.
fn only_renamed(before: &str, after: &str, renamed: &[(String, &'static str)]) -> bool {
    use serde_yaml::Value;
    let (Ok(mut expected), Ok(actual)) = (
        serde_yaml::from_str::<Value>(before),
        serde_yaml::from_str::<Value>(after),
    ) else {
        return false;
    };
    for (name, alias) in renamed {
        let Some(fields) = expected
            .get_mut("backends")
            .and_then(|b| b.get_mut(name.as_str()))
            .and_then(Value::as_mapping_mut)
        else {
            return false;
        };
        let Some(value) = fields.remove(*alias) else {
            return false;
        };
        fields.insert(Value::from("url"), value);
    }
    expected == actual
}

/// One entry under `backends:`: its name, whether it is written in flow
/// style, whether it has `url`, and the line index of each alias key.
struct Entry {
    name: String,
    flow: bool,
    has_url: bool,
    aliases: Vec<(usize, &'static str)>,
}

/// Indentation of a line, or `None` for a blank or comment-only line.
fn indent(line: &str) -> Option<usize> {
    let body = line.trim_start_matches(' ');
    (!body.trim().is_empty() && !body.starts_with('#')).then(|| line.len() - body.len())
}

/// The key a mapping line starts with, unquoted.
fn key_of(line: &str) -> Option<String> {
    let body = line.trim_start();
    let (key, _) = body.split_once(':')?;
    let key = key.trim().trim_matches(|c| c == '"' || c == '\'');
    // A backend name may hold spaces; a list item is not a key.
    (!key.is_empty() && !key.starts_with('-')).then(|| key.to_string())
}

/// The entries of the top-level `backends:` block.
fn backend_entries(lines: &[String]) -> Vec<Entry> {
    let Some(start) = lines
        .iter()
        .position(|l| indent(l) == Some(0) && key_of(l).as_deref() == Some("backends"))
    else {
        return Vec::new();
    };
    let mut entries: Vec<Entry> = Vec::new();
    let mut entry_indent = None;
    let mut field_indent = None;
    for (at, line) in lines.iter().enumerate().skip(start + 1) {
        let Some(depth) = indent(line) else { continue };
        if depth == 0 {
            break;
        }
        let entry_level = *entry_indent.get_or_insert(depth);
        if depth == entry_level {
            let Some(name) = key_of(line) else { continue };
            let rest = line
                .trim_start()
                .split_once(':')
                .map_or("", |(_, r)| r)
                .trim_start();
            entries.push(Entry {
                name,
                flow: rest.starts_with('{'),
                has_url: false,
                aliases: Vec::new(),
            });
            field_indent = None;
        } else if depth > entry_level
            && let Some(entry) = entries.last_mut()
            && depth == *field_indent.get_or_insert(depth)
        {
            match key_of(line).as_deref() {
                Some("url") => entry.has_url = true,
                Some("http_url") => entry.aliases.push((at, "http_url")),
                Some("ws_url") => entry.aliases.push((at, "ws_url")),
                _ => {}
            }
        }
    }
    entries
}

#[cfg(test)]
#[path = "backend_url_keys_tests.rs"]
mod tests;

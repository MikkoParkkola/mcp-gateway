// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Adding one backend to gateway.yaml as a text edit, so the file's comments
//! survive. A re-serialised `Config` drops every comment, including the
//! security warning `init` writes next to `bearer_token`.

use serde_yaml::{Mapping, Value};

use crate::config::Config;

/// The text at `original` with `config.backends[name]` appended to its
/// top-level `backends:` mapping, or `None` when the edit cannot be proven
/// right. Proven means: `config` is `before` plus exactly that backend, and
/// the edited text parses to the original document plus exactly that entry.
/// `None` sends the caller to the full re-serialisation.
pub(super) fn with_backend_added(
    original: &str,
    before: &Config,
    config: &Config,
    name: &str,
) -> Option<String> {
    let backend = config.backends.get(name)?;
    if before.backends.contains_key(name) || !only_adds(before, config, name) {
        return None;
    }
    let entry_value = serde_yaml::to_value(backend).ok()?;
    let mut entry = Mapping::new();
    entry.insert(name.into(), entry_value.clone());
    let block = serde_yaml::to_string(&entry).ok()?;
    let edited = splice(original, &block)?;

    let mut want: Value = serde_yaml::from_str(original).ok()?;
    let root = want.as_mapping_mut()?;
    let key = Value::from("backends");
    match root.get(&key) {
        None | Some(Value::Null) => {
            root.insert(key.clone(), Value::Mapping(Mapping::new()));
        }
        Some(Value::Mapping(_)) => {}
        Some(_) => return None,
    }
    root.get_mut(&key)?
        .as_mapping_mut()?
        .insert(name.into(), entry_value);
    let got: Value = serde_yaml::from_str(&edited).ok()?;
    (got == want).then_some(edited)
}

/// Whether `config` differs from `before` only by the backend `name`.
fn only_adds(before: &Config, config: &Config, name: &str) -> bool {
    let added = |c: &Config| -> Option<serde_json::Value> {
        let mut value = serde_json::to_value(c).ok()?;
        if let Some(backends) = value.get_mut("backends").and_then(|b| b.as_object_mut()) {
            backends.remove(name);
        }
        Some(value)
    };
    matches!((added(before), added(config)), (Some(a), Some(b)) if a == b)
}

/// Append `block` (a one-key YAML mapping) to the top-level `backends:`
/// mapping of `original`, indented as its existing entries are. A file with
/// no such key gets one at the end. Comments that lead the next top-level
/// key stay with that key.
fn splice(original: &str, block: &str) -> Option<String> {
    let lines: Vec<&str> = original.lines().collect();
    let indented = |line: &str| line.starts_with([' ', '\t']);
    let Some(header) = lines.iter().position(|l| l.starts_with("backends:")) else {
        let separator = if original.is_empty() || original.ends_with('\n') {
            ""
        } else {
            "\n"
        };
        let entry = block
            .lines()
            .map(|l| format!("  {l}"))
            .collect::<Vec<_>>()
            .join("\n");
        return Some(format!("{original}{separator}backends:\n{entry}\n"));
    };
    // Only an empty or block-style mapping is edited; flow style such as
    // `backends: {a: ...}` is left to the full rewrite.
    let after_key = lines[header]["backends:".len()..].trim_start();
    let comment = after_key.find('#').map_or("", |at| &after_key[at..]);
    let head = match after_key[..after_key.len() - comment.len()].trim() {
        "" | "{}" => format!(
            "backends:{}{comment}",
            if comment.is_empty() { "" } else { " " }
        ),
        _ => return None,
    };
    let end = lines[header + 1..]
        .iter()
        .position(|l| !l.is_empty() && !indented(l) && !l.starts_with('#'))
        .map_or(lines.len(), |i| header + 1 + i);
    let last = (header + 1..end)
        .rev()
        .find(|&i| indented(lines[i]))
        .unwrap_or(header);
    let child_indent = lines[header + 1..end]
        .iter()
        .find(|l| indented(l) && !l.trim_start().starts_with('#'))
        .map_or("  ", |l| &l[..l.len() - l.trim_start().len()]);

    let mut out: Vec<String> = lines[..header].iter().map(ToString::to_string).collect();
    out.push(head);
    out.extend(lines[header + 1..=last].iter().map(ToString::to_string));
    out.extend(block.lines().map(|l| format!("{child_indent}{l}")));
    out.extend(lines[last + 1..].iter().map(ToString::to_string));
    Some(out.join("\n") + "\n")
}

#[cfg(test)]
mod tests {
    use super::splice;

    const BLOCK: &str = "new:\n  command: echo\n";

    #[test]
    fn appends_inside_the_mapping_before_the_next_keys_comment() {
        let original = "# top\nbackends:\n    old:\n      command: x  # why\n\n# leads auth\nauth:\n  enabled: true\n";
        let edited = splice(original, BLOCK).expect("block style");
        assert_eq!(
            edited,
            "# top\nbackends:\n    old:\n      command: x  # why\n    new:\n      command: echo\n\n# leads auth\nauth:\n  enabled: true\n"
        );
    }

    #[test]
    fn adds_a_mapping_when_there_is_none() {
        let edited = splice("# only a comment\nserver:\n  port: 1", BLOCK).expect("appends");
        assert_eq!(
            edited,
            "# only a comment\nserver:\n  port: 1\nbackends:\n  new:\n    command: echo\n"
        );
        // A commented-out example is not the mapping.
        let edited = splice("# backends:\n#   x: {}\n", BLOCK).expect("appends");
        assert!(edited.ends_with("#   x: {}\nbackends:\n  new:\n    command: echo\n"));
    }

    #[test]
    fn fills_an_empty_mapping_and_leaves_flow_style_alone() {
        let edited = splice("backends: {}  # none yet\nauth: {}\n", BLOCK).expect("empty");
        assert_eq!(
            edited,
            "backends: # none yet\n  new:\n    command: echo\nauth: {}\n"
        );
        assert_eq!(splice("backends: {a: {command: x}}\n", BLOCK), None);
    }
}

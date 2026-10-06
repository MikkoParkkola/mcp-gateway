// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Adding or removing one backend in gateway.yaml as a text edit, so the file's comments
//! survive. A re-serialised `Config` drops every comment, including the
//! security warning `init` writes next to `bearer_token`.

use serde_yaml::{Mapping, Value};

use crate::config::Config;

/// The text at `original` with the one backend edit that turns `before` into
/// `config`: `name` added to the top-level `backends:` mapping, or removed
/// from it. `None` when the edit cannot be proven right, which sends the
/// caller to the full re-serialisation. Proven means: `config` differs from
/// `before` only by `name`, and the edited text parses to the original
/// document with exactly that entry added or removed.
pub(super) fn with_backend_edited(
    original: &str,
    before: &Config,
    config: &Config,
    name: &str,
) -> Option<String> {
    if !only_differs_by(before, config, name) {
        return None;
    }
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
    let backends = root.get_mut(&key)?.as_mapping_mut()?;
    let edited = match (before.backends.get(name), config.backends.get(name)) {
        (None, Some(backend)) => {
            let entry_value = serde_yaml::to_value(backend).ok()?;
            let mut entry = Mapping::new();
            entry.insert(name.into(), entry_value.clone());
            backends.insert(name.into(), entry_value);
            splice(original, &serde_yaml::to_string(&entry).ok()?)?
        }
        (Some(_), None) => {
            backends.remove(name)?;
            remove_entry(original, name)?
        }
        _ => return None,
    };
    let got: Value = serde_yaml::from_str(&edited).ok()?;
    // The text must also load as `config` itself: `original` is re-read at
    // write time, and a file another writer changed since `before` was
    // loaded would otherwise be written without `config`'s validation.
    let loaded = serde_json::to_value(serde_yaml::from_str::<Config>(&edited).ok()?).ok()?;
    (got == want && loaded == serde_json::to_value(config).ok()?).then_some(edited)
}

/// Whether `config` differs from `before` only by the backend `name`.
fn only_differs_by(before: &Config, config: &Config, name: &str) -> bool {
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

/// Remove the entry `name` from the top-level block-style `backends:`
/// mapping of `original`, with every line it spans. Blank lines and comments
/// that lead the next entry stay. An emptied mapping becomes `backends: {}`.
fn remove_entry(original: &str, name: &str) -> Option<String> {
    let lines: Vec<&str> = original.lines().collect();
    let indented = |line: &str| line.starts_with([' ', '\t']);
    let content = |line: &str| {
        let t = line.trim_start();
        !t.is_empty() && !t.starts_with('#')
    };
    let header = lines.iter().position(|l| l.starts_with("backends:"))?;
    let end = lines[header + 1..]
        .iter()
        .position(|l| !l.is_empty() && !indented(l) && !l.starts_with('#'))
        .map_or(lines.len(), |i| header + 1 + i);
    let child = lines[header + 1..end].iter().find(|l| content(l))?;
    let depth = child.len() - child.trim_start().len();
    let names_entry = |line: &str| {
        let Some(rest) = line.get(depth..) else {
            return false;
        };
        if rest.starts_with([' ', '\t']) {
            return false;
        }
        rest.split_once(':')
            .is_some_and(|(key, _)| key.trim().trim_matches(|c| c == '"' || c == '\'') == name)
    };
    let start = (header + 1..end).find(|&i| names_entry(lines[i]))?;
    // The entry runs to the next line at the child depth or shallower.
    let next = (start + 1..end)
        .find(|&i| content(lines[i]) && lines[i].len() - lines[i].trim_start().len() <= depth)
        .unwrap_or(end);
    // Give back the blank and comment lines that lead whatever follows.
    let mut stop = next;
    while stop > start + 1 && !content(lines[stop - 1]) {
        stop -= 1;
    }

    let mut out: Vec<String> = lines[..start].iter().map(ToString::to_string).collect();
    out.extend(lines[stop..].iter().map(ToString::to_string));
    let emptied = !lines[header + 1..end]
        .iter()
        .enumerate()
        .any(|(k, l)| !(start..stop).contains(&(header + 1 + k)) && content(l));
    if emptied {
        let after_key = lines[header]["backends:".len()..].trim_start();
        out[header] = if after_key.starts_with('#') {
            format!("backends: {{}} {after_key}")
        } else {
            "backends: {}".to_owned()
        };
    }
    Some(out.join("\n") + "\n")
}

#[cfg(test)]
mod tests {
    use super::{remove_entry, splice};

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

    #[test]
    fn a_file_changed_since_it_was_loaded_is_not_spliced() {
        use super::with_backend_edited;
        use crate::config::Config;
        let config_of = |yaml: &str| serde_yaml::from_str::<Config>(yaml).expect("config");
        let before = config_of("backends: {}\n");
        let config = config_of("backends:\n  new:\n    command: echo\n");
        assert!(
            with_backend_edited("backends: {}\n", &before, &config, "new").is_some(),
            "the unchanged file is spliced"
        );
        // Another writer added `other` after `before` was loaded: the edit
        // would write a config nobody validated.
        let changed = "backends:\n  other:\n    command: x\n";
        assert_eq!(with_backend_edited(changed, &before, &config, "new"), None);
    }

    #[test]
    fn removes_one_entry_and_keeps_the_rest() {
        let original = "backends:\n  # a's note\n  a:\n    command: x\n\n  # leads b\n  b:\n    command: y\n# leads auth\nauth: {}\n";
        assert_eq!(
            remove_entry(original, "a").expect("a"),
            "backends:\n  # a's note\n\n  # leads b\n  b:\n    command: y\n# leads auth\nauth: {}\n"
        );
        assert_eq!(
            remove_entry(original, "b").expect("b"),
            "backends:\n  # a's note\n  a:\n    command: x\n\n  # leads b\n# leads auth\nauth: {}\n"
        );
        assert_eq!(remove_entry(original, "missing"), None);
    }

    #[test]
    fn removing_the_last_entry_leaves_an_empty_mapping() {
        assert_eq!(
            remove_entry("backends:  # mine\n  a:\n    command: x\n", "a").expect("a"),
            "backends: {} # mine\n"
        );
        // Bare `backends:` would load as null, not the empty mapping.
        assert_eq!(
            remove_entry("backends:\n  a:\n    command: x\nauth: {}\n", "a").expect("a"),
            "backends: {}\nauth: {}\n"
        );
    }
}

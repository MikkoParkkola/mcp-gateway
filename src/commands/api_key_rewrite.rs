// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! `mcp-gateway upgrade` turns each plaintext `auth.api_keys[].key` into the
//! `key_sha256` digest `hash-key` prints (MIK-8044), in the same single
//! rewrite as the other keys. Neither the key nor its digest is ever printed.
//! A value that names a secret elsewhere (`env:`, `file:`, `${...}`) is never
//! read and never hashed: it stays for the operator, as does any entry the
//! rewrite cannot prove it changed alone.

use mcp_gateway::config::api_key_digest_spec;

/// Why an entry's plaintext key stayed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum KeyLeft {
    /// The value names a secret held elsewhere; hashing the name would give a
    /// digest no client can match.
    Reference,
    /// `key_sha256` is set too and is not this key's digest.
    Conflict,
    /// No single-line edit could be proven to change only this entry.
    Unprovable,
}

/// What the rewrite did with one entry that carries `key`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum KeyRewrite {
    /// The `key:` line at `line` (1-based) now holds `key_sha256`.
    Hashed { name: String, line: usize },
    /// `key_sha256` already held this key's digest; the `key:` line went.
    Dropped { name: String, line: usize },
    /// The key stayed, so the config will not load until it is fixed by hand.
    Left { name: String, why: KeyLeft },
}

/// How an entry's `key:` line changes.
#[derive(Clone, Copy)]
enum Edit<'a> {
    /// Replace it with `key_sha256: "<digest>"`.
    Hash(&'a str),
    /// Delete it: `key_sha256` already matches.
    Drop,
}

/// `text` with every plaintext key it can safely hash rewritten, and one
/// report row per entry that carries `key`.
pub(crate) fn hash_plaintext_api_keys(text: &str) -> (Option<String>, Vec<KeyRewrite>) {
    // Each entry keeps its place in `api_keys`: the edit finds it by index.
    let entries: Vec<(usize, String, String, Option<String>)> =
        super::retired_config_keys::loose(text)
            .as_ref()
            .and_then(|doc| doc.get("auth")?.get("api_keys")?.as_sequence().cloned())
            .unwrap_or_default()
            .iter()
            .enumerate()
            .filter_map(|(i, entry)| {
                let key = entry.get("key")?.as_str()?.to_owned();
                let name = entry
                    .get("name")
                    .and_then(crate::yaml::Value::as_str)
                    .map_or_else(|| format!("#{i}"), str::to_owned);
                let digest = entry
                    .get("key_sha256")
                    .map(|d| d.as_str().unwrap_or_default().to_owned());
                Some((i, name, key, digest))
            })
            .collect();
    let mut current = text.to_owned();
    let mut report = Vec::new();
    for (index, name, key, set_digest) in entries {
        if ["env:", "file:", "keychain:"]
            .iter()
            .any(|prefix| key.starts_with(prefix))
            || key.contains("${")
        {
            report.push(KeyRewrite::Left {
                name,
                why: KeyLeft::Reference,
            });
            continue;
        }
        let digest = api_key_digest_spec(key.as_bytes());
        let edit = match set_digest {
            None => Edit::Hash(&digest),
            Some(set) if set == digest => Edit::Drop,
            Some(_) => {
                report.push(KeyRewrite::Left {
                    name,
                    why: KeyLeft::Conflict,
                });
                continue;
            }
        };
        match edit_entry(&current, index, edit) {
            Some((after, line)) => {
                current = after;
                report.push(match edit {
                    Edit::Hash(_) => KeyRewrite::Hashed { name, line },
                    Edit::Drop => KeyRewrite::Dropped { name, line },
                });
            }
            None => report.push(KeyRewrite::Left {
                name,
                why: KeyLeft::Unprovable,
            }),
        }
    }
    ((current != text).then_some(current), report)
}

/// `text` with the `key:` line of entry `index` edited, proven by a strict
/// parse to change only that entry, and the edited line's number.
fn edit_entry(text: &str, index: usize, edit: Edit<'_>) -> Option<(String, usize)> {
    let mut expected: crate::yaml::Value = crate::yaml::from_str(text).ok()?;
    let entry = expected
        .get_mut("auth")?
        .get_mut("api_keys")?
        .get_mut(index)?
        .as_mapping_mut()?;
    entry.remove("key")?;
    if let Edit::Hash(digest) = edit {
        entry.insert("key_sha256".into(), digest.into());
    }
    let lines: Vec<&str> = text.split_inclusive('\n').collect();
    (0..lines.len()).find_map(|at| {
        let line = lines[at];
        let body = line.trim_start_matches([' ', '\t']);
        let (head, rest) = match body.strip_prefix("- ") {
            Some(rest) => (true, rest.trim_start()),
            None => (false, body),
        };
        if !rest.starts_with("key:") {
            return None;
        }
        let replacement = match edit {
            Edit::Hash(digest) => {
                let lead = &line[..line.len() - rest.len()];
                let ending = if line.ends_with("\r\n") {
                    "\r\n"
                } else if line.ends_with('\n') {
                    "\n"
                } else {
                    ""
                };
                // A trailing comment on the line is dropped: it may quote the key.
                format!("{lead}key_sha256: \"{digest}\"{ending}")
            }
            // Deleting a list item's first line would orphan its other keys.
            Edit::Drop if head => return None,
            Edit::Drop => String::new(),
        };
        let after: String = lines
            .iter()
            .enumerate()
            .map(|(i, l)| if i == at { replacement.as_str() } else { l })
            .collect();
        let actual: crate::yaml::Value = crate::yaml::from_str(&after).ok()?;
        (actual == expected).then_some((after, at + 1))
    })
}

#[cfg(test)]
mod tests {
    use super::{KeyLeft, KeyRewrite, hash_plaintext_api_keys};
    use mcp_gateway::config::api_key_digest_spec;

    fn entries(body: &str) -> String {
        format!("auth:\n  enabled: true\n  api_keys:\n{body}")
    }

    fn left(text: &str) -> Vec<KeyLeft> {
        let (after, report) = hash_plaintext_api_keys(text);
        assert_eq!(after, None, "{text}");
        report
            .into_iter()
            .map(|r| match r {
                KeyRewrite::Left { why, .. } => why,
                other => panic!("not left: {other:?}"),
            })
            .collect()
    }

    /// T2 (A4, C2): a reference is never hashed or resolved.
    #[test]
    fn a_reference_stays() {
        for value in ["env:K", "file:/k", "\"a-${K}\""] {
            let text = entries(&format!("    - name: c\n      key: {value}\n"));
            assert_eq!(left(&text), [KeyLeft::Reference], "{value}");
        }
    }

    /// T3: a matching digest drops the key line; a different one stays.
    #[test]
    fn a_set_digest_drops_the_key_or_conflicts() {
        let digest = api_key_digest_spec(b"pt");
        let text = entries(&format!(
            "    - name: c\n      key: pt\n      key_sha256: \"{digest}\"\n"
        ));
        let (after, _) = hash_plaintext_api_keys(&text);
        assert_eq!(
            after,
            Some(entries(&format!(
                "    - name: c\n      key_sha256: \"{digest}\"\n"
            )))
        );
        let text = entries("    - name: c\n      key: pt\n      key_sha256: \"sha256:00\"\n");
        assert_eq!(left(&text), [KeyLeft::Conflict]);
        // T3c (C3): an env digest is a conflict; the variable is never read.
        let text = entries("    - name: c\n      key: pt\n      key_sha256: env:SURF2_D\n");
        assert_eq!(left(&text), [KeyLeft::Conflict]);
    }

    /// T3b (B3): a list item's first line keeps its marker; dropping it is left.
    #[test]
    fn a_list_head_key_keeps_its_marker() {
        let digest = api_key_digest_spec(b"pt");
        let text = entries("    - key: pt  # old\n      name: c\n");
        let (after, _) = hash_plaintext_api_keys(&text);
        assert_eq!(
            after,
            Some(entries(&format!(
                "    - key_sha256: \"{digest}\"\n      name: c\n"
            )))
        );
        let text = entries(&format!("    - key: pt\n      key_sha256: \"{digest}\"\n"));
        assert_eq!(left(&text), [KeyLeft::Unprovable]);
    }

    /// T3 (P5): only the entry with a key changes; escapes are decoded first.
    #[test]
    fn only_the_plaintext_entry_changes_and_escapes_are_decoded() {
        let text = entries(
            "    - name: a\n      key_sha256: \"sha256:aa\"\n    - name: b\n      key: \"p\\tq\\u00e9\"\n    - name: c\n      key_sha256: \"sha256:cc\"\n",
        );
        let (after, report) = hash_plaintext_api_keys(&text);
        let digest = api_key_digest_spec("p\tq\u{e9}".as_bytes());
        assert_eq!(
            after,
            Some(text.replace(
                "key: \"p\\tq\\u00e9\"",
                &format!("key_sha256: \"{digest}\"")
            ))
        );
        assert_eq!(
            report,
            [KeyRewrite::Hashed {
                name: "b".into(),
                line: 7
            }]
        );
    }

    /// T3 (P5): a multi-line value or a repeated key cannot be proven.
    #[test]
    fn an_unprovable_entry_stays() {
        let text = entries("    - name: c\n      key: |\n        pt\n");
        assert_eq!(left(&text), [KeyLeft::Unprovable]);
        let text = entries("    - name: c\n      key: pt\n      key: pu\n");
        assert_eq!(left(&text), [KeyLeft::Unprovable]);
    }
}

// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! How a secret slot is shown (ADR-028, MIK-8908.KC.8): a reference as
//! written, a literal as `<set>`. Every surface that shows or exports config
//! reads the literal config and shows its secret slots through this, so a
//! resolved value is never shown.

use super::secret_ref::SecretRef;

/// What a secret slot holding `literal` (its text in gateway.yaml) shows:
/// an `env:`, `file:` or `keychain:` reference as written, an empty value as
/// `<empty>`, and any other value as `<set>`. Pure: it reads nothing, and no
/// part of a literal value is ever returned.
#[must_use]
pub fn secret_slot(literal: &str) -> String {
    if literal.is_empty() {
        return "<empty>".to_owned();
    }
    match SecretRef::parse(literal) {
        SecretRef::Literal(_) => "<set>".to_owned(),
        _ => literal.to_owned(),
    }
}

/// Every backend `env` and `headers` slot of `config` that holds a reference,
/// keyed by its field path (`backends.<name>.env.<KEY>`), in path order.
/// `config` must be the literal config: an evaluated one holds values.
pub(crate) fn backend_secret_references(
    config: &super::Config,
) -> std::collections::BTreeMap<String, String> {
    let mut references = std::collections::BTreeMap::new();
    for (name, backend) in &config.backends {
        let slots = backend
            .env
            .iter()
            .map(|(key, value)| (format!("backends.{name}.env.{key}"), value))
            .chain(
                backend
                    .headers
                    .iter()
                    .map(|(key, value)| (format!("backends.{name}.headers.{key}"), value)),
            );
        for (field, value) in slots {
            if super::secret_ref::is_reference(value) {
                references.insert(field, secret_slot(value));
            }
        }
    }
    references
}

#[cfg(test)]
mod tests {
    use super::{backend_secret_references, secret_slot};
    use crate::config::Config;

    const SENTINEL: &str = "kc-display-sentinel-7f3a";

    #[test]
    fn kc8_a_reference_shows_as_written_and_a_literal_as_set() {
        assert_eq!(secret_slot("keychain:gw.k"), "keychain:gw.k");
        assert_eq!(secret_slot("env:API_KEY"), "env:API_KEY");
        assert_eq!(secret_slot("file:/run/secret"), "file:/run/secret");
        assert_eq!(secret_slot(""), "<empty>");
    }

    #[test]
    fn kc8_no_part_of_a_literal_ever_shows() {
        let mid = format!("Bearer keychain:{SENTINEL}");
        for literal in [SENTINEL, mid.as_str(), "x", "keychainz", " keychain:x"] {
            let shown = secret_slot(literal);
            assert_eq!(shown, "<set>", "{literal:?}");
            // Every substring of length 3 or more of the literal is absent.
            let bytes = literal.as_bytes();
            for start in 0..bytes.len() {
                for end in (start + 3)..=bytes.len() {
                    let part = &literal[start..end];
                    assert!(
                        !shown.contains(part),
                        "{part:?} of {literal:?} shown as {shown:?}"
                    );
                }
            }
        }
    }

    #[test]
    fn kc8_backend_references_are_listed_by_field_and_literals_are_left_out() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("gateway.yaml");
        let body = format!(
            "server:\n  port: 0\nbackends:\n  tool:\n    command: \"/bin/true\"\n    env:\n      API_KEY: keychain:gw.k\n      LITERAL: {SENTINEL}\n    headers:\n      Authorization: env:TOKEN\n"
        );
        crate::gateway::test_helpers::write_owner_only(&path, body).expect("write");
        let literal = Config::load_literal(Some(&path)).expect("literal");
        let shown = backend_secret_references(&literal);
        assert_eq!(shown["backends.tool.env.API_KEY"], "keychain:gw.k");
        assert_eq!(shown["backends.tool.headers.Authorization"], "env:TOKEN");
        assert!(!shown.contains_key("backends.tool.env.LITERAL"));
        assert!(!format!("{shown:?}").contains(SENTINEL));
    }
}

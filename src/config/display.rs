// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! How a secret slot is shown (ADR-028): a reference as
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
/// Only the web UI's config read lists them, hence the feature gate.
#[cfg(feature = "webui")]
pub(crate) fn backend_secret_references(
    config: &super::Config,
) -> std::collections::BTreeMap<String, String> {
    // Two slots can join to one key (a server name and a field name may both
    // hold dots); the one walked last wins, as it always has.
    reference_slots(config)
        .map(|(server, kind, field, value)| {
            (
                format!("backends.{server}.{kind}.{field}"),
                secret_slot(value),
            )
        })
        .collect()
}

/// One backend secret slot that holds a reference, with its parts unjoined, so
/// a reader never has to split the flat key to learn whose slot it is.
#[cfg(feature = "webui")]
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub(crate) struct SecretReferenceRecord {
    /// The server's name as written in the config.
    pub(crate) server: String,
    /// `env` or `headers`.
    pub(crate) kind: &'static str,
    /// The environment or header name, whole.
    pub(crate) field: String,
    /// The reference as `secret_slot` shows it; never a value.
    pub(crate) reference: String,
}

/// Every backend slot of `config` that holds a reference, as records sorted by
/// server, then kind, then field, each compared by bytes. `config` must be the
/// literal config, as for [`backend_secret_references`].
#[cfg(feature = "webui")]
pub(crate) fn backend_secret_reference_records(
    config: &super::Config,
) -> Vec<SecretReferenceRecord> {
    let mut records: Vec<SecretReferenceRecord> = reference_slots(config)
        .map(|(server, kind, field, value)| SecretReferenceRecord {
            server: server.to_owned(),
            kind,
            field: field.to_owned(),
            reference: secret_slot(value),
        })
        .collect();
    records.sort_by(|a, b| (&a.server, a.kind, &a.field).cmp(&(&b.server, b.kind, &b.field)));
    records
}

/// Each backend `env` and `headers` slot that holds a reference, as (server,
/// kind, field, value), in the order the backends and their maps iterate.
#[cfg(feature = "webui")]
fn reference_slots(
    config: &super::Config,
) -> impl Iterator<Item = (&str, &'static str, &str, &str)> {
    config
        .backends
        .iter()
        .flat_map(|(name, backend)| {
            let env = backend
                .env
                .iter()
                .map(move |(key, value)| (name.as_str(), "env", key.as_str(), value.as_str()));
            let headers = backend
                .headers
                .iter()
                .map(move |(key, value)| (name.as_str(), "headers", key.as_str(), value.as_str()));
            env.chain(headers)
        })
        .filter(|(_, _, _, value)| super::secret_ref::is_reference(value))
}

#[cfg(tp3)]
#[cfg(test)]
mod tests {
    use super::secret_slot;

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
        for literal in [
            SENTINEL,
            mid.as_str(),
            "x",
            "keychainz",
            " keychain:x",
            "pässwörd-ключ",
        ] {
            let shown = secret_slot(literal);
            assert_eq!(shown, "<set>", "{literal:?}");
            // Every byte window of length 3 or more of the literal is absent.
            let bytes = literal.as_bytes();
            for len in 3..=bytes.len() {
                for part in bytes.windows(len) {
                    assert!(
                        !shown.as_bytes().windows(len).any(|w| w == part),
                        "{part:?} of {literal:?} shown as {shown:?}"
                    );
                }
            }
        }
    }

    #[cfg(feature = "webui")]
    #[test]
    fn kc8_backend_references_are_listed_by_field_and_literals_are_left_out() {
        use super::backend_secret_references;
        use crate::config::Config;

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

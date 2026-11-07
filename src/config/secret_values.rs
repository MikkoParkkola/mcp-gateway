// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The one rule for a secret-shaped value an operator or a client file gives
//! a backend, shared by every writer that puts a backend into gateway.yaml:
//! the web UI panel and discovery adopt, and the CLI `add`, `setup` and
//! `discover --write`. Built in every configuration, since the CLI writers
//! are.

/// How one `env` or `headers` value of a backend is written to gateway.yaml.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ValueClass {
    /// Written as given: empty, a whole-value secret reference (`env:`,
    /// `file:`, `keychain:`), or a template the load expands.
    Kept,
    /// A literal: when [`stores_env_value`] or [`stores_header_value`] says
    /// so it goes to the secret store and gateway.yaml holds the store's
    /// reference; otherwise it is written as typed.
    Stored,
}

/// The one rule for a value an operator gives a backend, shared by the web UI
/// add, update and preview and the CLI `add`. `Err` is the refusal's stable
/// code: `literal_default` for `${NAME:-text}` with a non-empty default, and
/// `literal_in_template` for literal text beside a template other than one
/// scheme word (`Bearer ${TOKEN}` is a template; `sk-${SUFFIX}` is not), the
/// same codes discovery adopt refuses with. Either would put text that may be
/// a secret into gateway.yaml as text.
pub(crate) fn classify(value: &str) -> Result<ValueClass, &'static str> {
    use crate::config::secret_ref::{has_literal_default, only_scheme_beside_templates};
    if value.is_empty() || crate::config::is_reference(value) {
        return Ok(ValueClass::Kept);
    }
    if !value.contains("${") {
        return Ok(ValueClass::Stored);
    }
    if has_literal_default(value) {
        Err("literal_default")
    } else if !only_scheme_beside_templates(value) {
        Err("literal_in_template")
    } else {
        Ok(ValueClass::Kept)
    }
}

/// Words an env key may end with, beyond the firewall's own credential names,
/// that mark its value as a credential (`GITHUB_PAT`, `SENTRY_DSN`,
/// `GOOGLE_CREDENTIALS`, `STRIPE_SECRET`, `APIKEY`). Only the last word
/// counts: a stored value becomes a whole-value reference, which the redactor
/// holds at any length, so a setting such as `TOKEN_LIMIT=1` stored would scrub
/// every `1` from tool results.
const ENV_CREDENTIAL_ENDINGS: [&str; 6] = [
    "pat",
    "dsn",
    "credential",
    "credentials",
    "secret",
    "apikey",
];

/// Words that, directly before a final `key`, mark an env credential beyond
/// the firewall's own pairs (`SESSION_KEY`, `AUTH_KEY`, `ENCRYPTION_KEY`).
const ENV_KEY_QUALIFIERS: [&str; 5] = ["session", "cookie", "auth", "access", "encryption"];

/// Whether env key `key` names a credential, judged by its last words only:
/// the firewall's credential-name rule
/// ([`crate::security::credential_names::family_of`], which already leaves
/// out pagination names such as `next_page_token`), or a final word in
/// [`ENV_CREDENTIAL_ENDINGS`], or a final `key` after an
/// [`ENV_KEY_QUALIFIERS`] word. Words are the firewall's own split (`_`, `-`,
/// camel case). Headers are not judged: every header value is stored. The
/// panel and discovery adopt both store by this rule.
pub(crate) fn names_a_credential(key: &str) -> bool {
    use crate::security::credential_names::{family_of, words};
    if family_of(key).is_some() {
        return true;
    }
    match words(key).as_slice() {
        // Rails' `SECRET_KEY_BASE`.
        [.., a, b, c] if a == "secret" && b == "key" && c == "base" => true,
        [.., last] if ENV_CREDENTIAL_ENDINGS.contains(&last.as_str()) => true,
        [.., before, last] => last == "key" && ENV_KEY_QUALIFIERS.contains(&before.as_str()),
        _ => false,
    }
}

/// Whether env value `value` under key `key` goes to the store: its key
/// [`names_a_credential`] and it is at least the redactor's short-value bound
/// long. A stored value is redacted wherever it appears, at any length, so a
/// shorter one (`1`, `true`, `none`, as in `HF_HUB_DISABLE_IMPLICIT_TOKEN=1`)
/// would blank ordinary text: it is written as typed, as in 3.x.
pub(crate) fn stores_env_value(key: &str, value: &str) -> bool {
    stores_header_value(value) && names_a_credential(key)
}

/// Whether a header value goes to the store: any header that is at least
/// the redactor's short-value bound long. A shorter one (`Authorization: none`)
/// is written as typed, for the reason [`stores_env_value`] gives.
pub(crate) fn stores_header_value(value: &str) -> bool {
    value.len() >= crate::security::needles::SHORT_VALUE_BYTES
}

/// Whether a value a client file gives a discovered server is stored (both
/// discovery adopts: the web UI's and `discover --write`): a template or an
/// empty value never is; a value the shared rule stores
/// ([`stores_header_value`], [`stores_env_value`]) is; and so is any value
/// that reads as a gateway secret reference (`file:/x`, `env:X`) under any
/// name and at any length, because written as text the gateway would read it
/// as a reference instead of the client's literal.
pub(crate) fn stores_discovered_value(header: bool, key: &str, value: &str) -> bool {
    if value.is_empty() || value.contains("${") {
        return false;
    }
    let by_rule = if header {
        stores_header_value(value)
    } else {
        stores_env_value(key, value)
    };
    by_rule || crate::config::is_reference(value)
}

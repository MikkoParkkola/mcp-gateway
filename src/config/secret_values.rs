// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The one rule for a secret-shaped value an operator or a client file gives
//! a backend, shared by every writer that puts a backend into gateway.yaml:
//! the web UI panel and discovery adopt, and the CLI `add`, `setup` and
//! `discover --write`. Built in every configuration, since the CLI writers
//! are. The capability editor uses the same rule with its own brace grammar.

#[cfg(feature = "webui")]
use std::collections::HashSet;

/// The template grammar of the file receiving a value. Reference forms from
/// another grammar must never turn literal text into an accepted template.
#[derive(Debug, Clone, Copy)]
pub(crate) enum Syntax {
    Dollar,
    /// Only the capability editor, which is part of the web UI, writes this grammar.
    #[cfg(feature = "webui")]
    Brace {
        parameters: HashSet<String>,
    },
}

/// Whether a value may remain in a definition under the selected grammar.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ValueClass {
    /// Written as given: empty, a supported template, or (Dollar only) a
    /// whole-value secret reference (`env:`, `file:`, `keychain:`).
    Kept,
    /// A literal: when [`stores_env_value`] or [`stores_header_value`] says
    /// so it goes to the secret store and gateway.yaml holds the store's
    /// reference; otherwise it is written as typed. The capability editor
    /// refuses this class under a credential-named header instead of storing it.
    Stored,
}

/// The one rule for a value an operator gives a backend, shared by the web UI
/// add, update and preview and the CLI `add`. `Err` is the refusal's stable
/// code: `literal_default` for `${NAME:-text}` with a non-empty default, and
/// `literal_in_template` for literal text beside a template other than one
/// scheme word (`Bearer ${TOKEN}` is a template; `sk-${SUFFIX}` is not), the
/// same codes discovery adopt refuses with. Either would put text that may be
/// a secret into gateway.yaml as text. Brace uses the capability's declared
/// inputs and system references, returning `Stored` for every literal form.
pub(crate) fn classify(value: &str, syntax: Syntax) -> Result<ValueClass, &'static str> {
    use crate::config::secret_ref::{has_literal_default, only_scheme_beside_templates};
    match syntax {
        Syntax::Dollar => {}
        #[cfg(feature = "webui")]
        Syntax::Brace { parameters } => return Ok(classify_brace(value, &parameters)),
    }
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

/// Use the resolver's scanner without resolving anything. Only names the
/// validator recognizes may disappear; expressions remain literal in a
/// credential header even though the validator permits them elsewhere.
#[cfg(feature = "webui")]
fn classify_brace(value: &str, parameters: &HashSet<String>) -> ValueClass {
    use crate::capability::validator::is_known_placeholder;
    use crate::config::secret_ref::SCHEME_PREFIXES;

    if value.is_empty() {
        return ValueClass::Kept;
    }
    if value.contains("{{") {
        return ValueClass::Stored;
    }
    let mut found = false;
    let outside = crate::secrets::fill_placeholders(value, |name| {
        let known = !name.contains('?') && is_known_placeholder(name, parameters);
        found |= known;
        Ok(known.then(String::new))
    });
    if let Ok(outside) = outside
        && found
        && (outside.is_empty()
            || (SCHEME_PREFIXES.contains(&outside.as_str()) && value.starts_with(&outside)))
    {
        ValueClass::Kept
    } else {
        ValueClass::Stored
    }
}

/// Whether `name` names a credential: the shared rule's credential words, or
/// an HTTP authentication header (`Authorization`, `Proxy-Authorization`,
/// `Cookie`). Dashes count as underscores, leading dashes are dropped.
#[cfg(feature = "webui")]
pub(crate) fn credential_name(name: &str) -> bool {
    let name = name.trim_start_matches('-').replace('-', "_");
    let lower = name.to_ascii_lowercase();
    ["authorization", "proxy_authorization", "cookie"].contains(&lower.as_str())
        || names_a_credential(&name)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "webui")]
    #[test]
    fn brace_values_keep_only_known_placeholders_and_one_leading_scheme() {
        // Declaring TOKEN must not make the other grammar's ${TOKEN} safe.
        let parameters = HashSet::from(["token".into(), "TOKEN".into(), "input".into()]);
        let cases = [
            ("", ValueClass::Kept),
            ("{env.API_KEY}", ValueClass::Kept),
            ("Bearer {env.API_KEY}", ValueClass::Kept),
            ("Basic {env.API_KEY}", ValueClass::Kept),
            ("Token {env.API_KEY}", ValueClass::Kept),
            ("Bot {env.API_KEY}", ValueClass::Kept),
            ("{keychain.svc}", ValueClass::Kept),
            ("{oauth.provider}", ValueClass::Kept),
            ("{access_token}", ValueClass::Kept),
            ("{refresh_token}", ValueClass::Kept),
            ("{api_key}", ValueClass::Kept),
            ("{bearer_token}", ValueClass::Kept),
            ("{auth_token}", ValueClass::Kept),
            ("{timestamp}", ValueClass::Kept),
            ("{service_auth_header}", ValueClass::Kept),
            ("{token}", ValueClass::Kept),
            ("{token[0]}", ValueClass::Kept),
            ("{token.value}", ValueClass::Kept),
            ("{token[0].value}", ValueClass::Kept),
            ("Bearer {env.KEY}{token}", ValueClass::Kept),
            ("literal", ValueClass::Stored),
            ("Bearer literal", ValueClass::Stored),
            ("{env.KEY}-suffix", ValueClass::Stored),
            ("prefix-{token}", ValueClass::Stored),
            ("{token}Bearer ", ValueClass::Stored),
            ("Bearer {token}Basic {env.KEY}", ValueClass::Stored),
            (" Bearer {token}", ValueClass::Stored),
            ("Bearer {token} ", ValueClass::Stored),
            ("Bearer ", ValueClass::Stored),
            ("{unknown}", ValueClass::Stored),
            ("{unknown.value}", ValueClass::Stored),
            ("{unknown[0]}", ValueClass::Stored),
            ("{}", ValueClass::Stored),
            (r#"{"api_key":"literal"}"#, ValueClass::Stored),
            (r#"{"api_key":"{env.KEY}"}"#, ValueClass::Stored),
            ("{{token}}", ValueClass::Stored),
            ("{{input.mode ? 'a' : 'b'}}", ValueClass::Stored),
            ("{input.mode ? 'a' : 'b'}", ValueClass::Stored),
            ("{env.KEY ? 'a' : 'b'}", ValueClass::Stored),
            ("{env.KEY", ValueClass::Stored),
            ("{env.KEY}}", ValueClass::Stored),
            ("${TOKEN}", ValueClass::Stored),
            ("Bearer ${TOKEN}", ValueClass::Stored),
            ("${env.KEY}", ValueClass::Stored),
            ("env:TOKEN", ValueClass::Stored),
            ("file:/secret", ValueClass::Stored),
            ("keychain:svc", ValueClass::Stored),
        ];
        for (value, expected) in cases {
            assert_eq!(
                classify(
                    value,
                    Syntax::Brace {
                        parameters: parameters.clone(),
                    },
                ),
                Ok(expected),
                "{value:?}"
            );
        }
    }

    #[test]
    fn dollar_values_retain_the_backend_grammar_and_refusal_codes() {
        let cases = [
            ("", Ok(ValueClass::Kept)),
            ("${TOKEN}", Ok(ValueClass::Kept)),
            ("Bearer ${TOKEN}", Ok(ValueClass::Kept)),
            ("${TOKEN:-}", Ok(ValueClass::Kept)),
            ("env:TOKEN", Ok(ValueClass::Kept)),
            ("file:/secret", Ok(ValueClass::Kept)),
            ("keychain:svc", Ok(ValueClass::Kept)),
            ("literal", Ok(ValueClass::Stored)),
            ("Bearer {env.TOKEN}", Ok(ValueClass::Stored)),
            ("${TOKEN:-literal}", Err("literal_default")),
            ("${TOKEN}-suffix", Err("literal_in_template")),
            ("prefix-${TOKEN}", Err("literal_in_template")),
        ];
        for (value, expected) in cases {
            assert_eq!(classify(value, Syntax::Dollar), expected, "{value:?}");
        }
    }

    #[cfg(feature = "webui")]
    #[test]
    fn credential_header_names_share_the_backend_name_gate() {
        for name in [
            "Authorization",
            "authorization",
            "AUTHORIZATION",
            "Proxy-Authorization",
            "Cookie",
            "x-api-key",
            "X-Auth-Token",
            "X-Credentials",
        ] {
            assert!(credential_name(name), "{name}");
        }
        for name in ["Accept", "User-Agent", "Content-Type", "X-Mode", "X-Custom"] {
            assert!(!credential_name(name), "{name}");
        }
    }
}

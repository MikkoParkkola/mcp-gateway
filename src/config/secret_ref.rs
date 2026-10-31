// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The one grammar for whole-value secret references, and the one `${VAR}`
//! expander (C4, SECRET.1).
//!
//! A reference that resolves to nothing is refused. Unset and empty are the
//! same case: an empty credential is never a deliberate one, and on the
//! comparison side an empty bearer matches an empty presented token.
//!
//! Most callers classify only `Literal(_)` versus "a reference". The few that
//! match an arm (reload recording, `server.metrics_token`, message signing) do
//! so because their failure contract differs from `resolve`'s.
//!
//! `file:/abs/path` (C9, SECRET.2) reads the secret from a file, the way
//! Kubernetes delivers one: the C2 mode rule on the handle it reads, at most
//! 64 KiB, UTF-8, one trailing newline stripped, and empty refused.

use std::path::Path;
use std::sync::LazyLock;

use regex::Regex;

use super::EnvOverlay;
use crate::{Error, Result};

/// A whole-value secret as written in operator config.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SecretRef<'a> {
    /// `env:NAME`: the value `NAME` holds in the overlay.
    Env(&'a str),
    /// `file:PATH`: the content of the file at `PATH`, which must be absolute.
    File(&'a Path),
    /// `keychain:NAME`: the OS keychain entry `NAME` (ADR-028).
    Keychain(&'a str),
    /// Anything else: the text itself is the secret.
    Literal(&'a str),
}

impl<'a> SecretRef<'a> {
    /// Classifies `text`. Never fails; a malformed reference is reported by
    /// [`SecretRef::resolve`].
    #[must_use]
    pub(crate) fn parse(text: &'a str) -> Self {
        if let Some(name) = text.strip_prefix("env:") {
            Self::Env(name)
        } else if let Some(path) = text.strip_prefix("file:") {
            Self::File(Path::new(path))
        } else if let Some(name) = text.strip_prefix("keychain:") {
            Self::Keychain(name)
        } else {
            Self::Literal(text)
        }
    }

    /// The secret `field` holds. Unset and empty are both refused, for a
    /// reference and a literal alike: this is the one place that rule lives.
    /// The error never contains a value.
    ///
    /// # Errors
    ///
    /// [`Error::ConfigValidation`] naming `field` when the literal is empty, or
    /// the reference is blank, unset, or resolves to an empty string.
    pub(crate) fn resolve(self, field: &str, overlay: &EnvOverlay) -> Result<String> {
        match self {
            Self::Literal("") => Err(Error::ConfigValidation(format!("{field} is empty."))),
            Self::Literal(text) => Ok(text.to_owned()),
            Self::Env("") => Err(Error::ConfigValidation(format!(
                "{field} uses an empty env: reference"
            ))),
            Self::Env(name) => match overlay.resolve(name) {
                None => Err(Error::ConfigValidation(format!(
                    "{field} references missing environment variable '{name}'{}",
                    overlay.absent_files_hint()
                ))),
                Some(value) if value.is_empty() => Err(Error::ConfigValidation(format!(
                    "{field} references environment variable '{name}', which is empty; \
                     empty secrets are refused.{}",
                    overlay.absent_files_hint()
                ))),
                Some(value) => Ok(value),
            },
            Self::File(path) => read_file_ref(field, path),
            Self::Keychain(name) => read_keychain_ref(field, name, overlay),
        }
    }
}

/// Whether `name` fits ADR-028's keychain grammar, `[A-Za-z0-9._-]{1,128}`.
/// Text only; reads nothing.
pub(crate) fn is_keychain_name(name: &str) -> bool {
    (1..=128).contains(&name.len())
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

/// The secret a `keychain:` reference names: the entry's exact bytes, never
/// trimmed (ADR-028 rule 5).
///
/// # Errors
///
/// [`Error::ConfigValidation`] naming `field` alone when the name is not a
/// valid keychain name (the text may be a mistyped secret, so it is never
/// echoed), and naming `field` and the entry when the entry is missing,
/// empty, not UTF-8, or cannot be read.
pub(crate) fn read_keychain_ref(field: &str, name: &str, overlay: &EnvOverlay) -> Result<String> {
    use super::keychain::KeychainError;
    // Checked before any lookup: a name outside the grammar is a typo, and
    // asking the store about it could only prompt or mislead.
    if !is_keychain_name(name) {
        // The rejected text is not echoed: a mistyped literal secret would
        // otherwise land in the startup log.
        return Err(Error::ConfigValidation(format!(
            "{field} uses a keychain: reference whose name is not a valid keychain name \
             (1-128 of A-Z, a-z, 0-9, '.', '_', '-')."
        )));
    }
    let refused = |why: &str| {
        Error::ConfigValidation(format!("{field} references keychain entry '{name}', {why}"))
    };
    let bytes = match overlay.keychain().read(name) {
        Ok(bytes) => bytes,
        Err(KeychainError::Missing) => return Err(refused("which does not exist.")),
        Err(other) => {
            return Err(refused(&format!(
                "which cannot be read: {}.",
                other.reason()
            )));
        }
    };
    if bytes.as_bytes().is_empty() {
        return Err(refused("which is empty; empty secrets are refused."));
    }
    // Exact bytes: unlike `file:`, no trailing newline is stripped (ADR-028
    // rule 5); the store holds what the operator saved.
    std::str::from_utf8(bytes.as_bytes())
        .map(str::to_owned)
        .map_err(|_| refused("which is not UTF-8."))
}

/// The secret a `file:` reference names. See the module docs for the rules.
///
/// # Errors
///
/// [`Error::ConfigValidation`] naming `field` and the path when the path is not
/// absolute, the file cannot be read, other users may read or change it, it is
/// over 64 KiB or not UTF-8, or it holds nothing but a newline.
pub(crate) fn read_file_ref(field: &str, path: &Path) -> Result<String> {
    let shown = path.display();
    // `~` and relative paths are refused, not resolved: a secret's location
    // must not depend on the working directory or on whose HOME is set.
    if !path.is_absolute() {
        return Err(Error::ConfigValidation(format!(
            "{field} references file:{shown}, which is not an absolute path."
        )));
    }
    let text =
        super::secret_file::read_secret_file(path, super::secret_file::SecretFile::Reference)
            .map_err(|e| {
                let why = match e {
                    Error::Config(m) | Error::ConfigValidation(m) => m,
                    other => other.to_string(),
                };
                Error::ConfigValidation(format!("{field} references file:{shown}: {why}"))
            })?;
    // Exactly one: `kubectl create secret --from-file` and `echo` add one, and
    // anything beyond it is part of the secret.
    let value = text
        .strip_suffix("\r\n")
        .or_else(|| text.strip_suffix('\n'))
        .unwrap_or(&text);
    if value.is_empty() {
        return Err(Error::ConfigValidation(format!(
            "{field} references file:{shown}, which is empty; empty secrets are refused."
        )));
    }
    Ok(value.to_owned())
}

/// `${VAR}` and `${VAR:-default}`. The only copy of this pattern.
static TEMPLATE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\$\{([A-Z_][A-Z0-9_]*)(?::-([^}]*))?\}").expect("constant template pattern")
});

/// Why a template did not expand.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Unresolved {
    /// `${NAME}` whose variable is unset or empty, with no default.
    Unset(String),
    /// A `${` that is not a `${NAME}` reference. It carries nothing from the
    /// text: a literal secret can look like `${s3cr3t}`.
    Malformed,
}

/// A `${` in text the pattern did not consume is a reference that cannot
/// resolve, such as a lowercase `${github_token}`; it is refused rather than
/// sent upstream verbatim.
fn refuse_stray(segment: &str) -> std::result::Result<(), Unresolved> {
    if segment.contains("${") {
        Err(Unresolved::Malformed)
    } else {
        Ok(())
    }
}

/// Whether every `${` in `text` starts a `${NAME}` or `${NAME:-default}`
/// reference: the syntax a load accepts, checked without resolving anything.
pub(crate) fn is_template_syntax(text: &str) -> bool {
    let mut end = 0;
    for whole in TEMPLATE.find_iter(text) {
        if refuse_stray(&text[end..whole.start()]).is_err() {
            return false;
        }
        end = whole.end();
    }
    refuse_stray(&text[end..]).is_ok()
}

/// The text of `text` outside its `${NAME}` references, in order.
pub(crate) fn literal_outside_templates(text: &str) -> String {
    TEMPLATE.replace_all(text, "").into_owned()
}

/// Whether a `${NAME:-default}` in `text` has a non-empty default: text that
/// a load writes in place of an unset variable. `${NAME:-}` has none.
pub(crate) fn has_literal_default(text: &str) -> bool {
    TEMPLATE
        .captures_iter(text)
        .any(|caps| caps.get(2).is_some_and(|default| !default.is_empty()))
}

/// The `${NAME}` names `text` references, in order.
pub(super) fn template_names(text: &str) -> impl Iterator<Item = &str> {
    TEMPLATE
        .captures_iter(text)
        .filter_map(|caps| caps.get(1))
        .map(|name| name.as_str())
}

/// Expands every `${VAR}` in `text`. As in POSIX `${VAR:-default}`, a variable
/// that is unset or empty takes the default; with no default it is refused.
/// `${VAR:-}` is the explicit way to allow empty.
///
/// # Errors
///
/// The first variable that is unset or empty with no default, or the first
/// `${` that is not a `${NAME}` reference.
pub(crate) fn expand_template(
    text: &str,
    overlay: &EnvOverlay,
) -> std::result::Result<String, Unresolved> {
    let mut out = String::with_capacity(text.len());
    let mut end = 0;
    for caps in TEMPLATE.captures_iter(text) {
        let whole = caps.get(0).expect("group 0 always matches");
        refuse_stray(&text[end..whole.start()])?;
        out.push_str(&text[end..whole.start()]);
        let value = overlay
            .resolve(&caps[1])
            .filter(|value| !value.is_empty())
            .or_else(|| caps.get(2).map(|d| d.as_str().to_owned()))
            .ok_or_else(|| Unresolved::Unset(caps[1].to_owned()))?;
        out.push_str(&value);
        end = whole.end();
    }
    refuse_stray(&text[end..])?;
    out.push_str(&text[end..]);
    Ok(out)
}

/// [`expand_template`] for a config field, with the operator-facing message.
/// The caller collects these so one load reports every unresolved reference,
/// and appends [`EnvOverlay::absent_files_hint`] once.
///
/// # Errors
///
/// The message naming `field` and the unset or empty variable.
pub(crate) fn expand_field(
    field: &str,
    text: &str,
    overlay: &EnvOverlay,
) -> std::result::Result<String, String> {
    expand_template(text, overlay).map_err(|why| match why {
        Unresolved::Unset(var) => {
            // Every unset variable in the field, not only the first: one load
            // reports every unresolved reference.
            let mut vars = vec![var];
            for caps in TEMPLATE.captures_iter(text) {
                let name = &caps[1];
                let unset = caps.get(2).is_none()
                    && overlay.resolve(name).is_none_or(|value| value.is_empty());
                if unset && !vars.iter().any(|seen| seen == name) {
                    vars.push(name.to_owned());
                }
            }
            if let [var] = vars.as_slice() {
                format!(
                    "{field} references ${{{var}}}, which is not set (or is empty) and has no default. \
                     Set it, or write ${{{var}:-}} to allow empty."
                )
            } else {
                let names = vars.iter().map(|v| format!("${{{v}}}")).collect::<Vec<_>>();
                format!(
                    "{field} references {}, which are not set (or are empty) and have no default. \
                     Set them, or write ${{NAME:-}} to allow empty.",
                    names.join(", ")
                )
            }
        }
        Unresolved::Malformed => format!(
            "{field} contains a '${{' that is not a ${{NAME}} variable reference: names are \
             uppercase letters, digits and '_', starting with a letter or '_'."
        ),
    })
}

/// One backend `env` or `headers` value as the backend receives it
/// (ADR-028). The written text is classified once: a whole-value `env:`,
/// `file:` or `keychain:` reference resolves once, and its bytes are used
/// verbatim, never read again as a reference; anything else is a template
/// and gets [`expand_field`]'s `${VAR}` expansion, whose result is never
/// classified. The load and the pre-write check both call this, so they
/// cannot disagree.
///
/// # Errors
///
/// The message naming `field` (and the entry for a reference), never a value.
pub(crate) fn evaluate_backend_value(
    field: &str,
    written: &str,
    overlay: &EnvOverlay,
) -> std::result::Result<String, String> {
    match SecretRef::parse(written) {
        SecretRef::Literal(_) => expand_field(field, written, overlay),
        reference => reference.resolve(field, overlay).map_err(|e| match e {
            Error::ConfigValidation(message) => message,
            other => other.to_string(),
        }),
    }
}

/// [`evaluate_backend_value`] over every enabled backend's `headers` and
/// `env`, in place, collecting each unresolved one's message: backend env
/// and headers are secret slots too (ADR-028).
pub(crate) fn evaluate_backends(
    backends: &mut std::collections::HashMap<String, super::BackendConfig>,
    overlay: &EnvOverlay,
    unresolved: &mut Vec<String>,
) {
    for (name, backend) in backends.iter_mut().filter(|(_, b)| b.enabled) {
        let headers = backend
            .headers
            .iter_mut()
            .map(|(key, value)| (format!("backends.{name}.headers.{key}"), value));
        let env = backend
            .env
            .iter_mut()
            .map(|(key, value)| (format!("backends.{name}.env.{key}"), value));
        for (field, value) in headers.chain(env) {
            match evaluate_backend_value(&field, value, overlay) {
                Ok(evaluated) => *value = evaluated,
                Err(message) => unresolved.push(message),
            }
        }
    }
}

/// Whether `written` is a whole-value `env:`, `file:` or `keychain:` reference.
pub(crate) fn is_reference(written: &str) -> bool {
    !matches!(SecretRef::parse(written), SecretRef::Literal(_))
}

impl super::Config {
    /// Every required secret that resolves to nothing (an unresolvable `env:`
    /// reference or an empty literal), one message each, so the operator fixes
    /// them in one pass. `SecretRef::resolve` holds the rule (C4).
    pub(super) fn required_reference_errors(&self, overlay: &EnvOverlay) -> Vec<String> {
        let mut slots: Vec<(String, &str)> = Vec::new();
        if self.auth.enabled {
            if let Some(token) = self.auth.bearer_token.as_deref() {
                slots.push(("auth.bearer_token".into(), token));
            }
            for key in &self.auth.api_keys {
                if let Some(spec) = key.key_sha256.as_deref() {
                    slots.push((format!("auth.api_keys['{}'].key_sha256", key.name), spec));
                }
                if let Some(spec) = key.previous_key_sha256.as_deref() {
                    let field = format!("auth.api_keys['{}'].previous_key_sha256", key.name);
                    slots.push((field, spec));
                }
            }
        }
        if self.agent_auth.enabled {
            for agent in &self.agent_auth.agents {
                if let Some(secret) = agent.hs256_secret.as_deref() {
                    let field = format!("agent_auth.agents['{}'].hs256_secret", agent.client_id);
                    slots.push((field, secret));
                }
            }
        }
        if self.key_server.enabled
            && let Some(token) = self.key_server.admin_token.as_deref()
        {
            slots.push(("key_server.admin_token".into(), token));
        }
        slots
            .iter()
            .filter_map(|(field, value)| SecretRef::parse(value).resolve(field, overlay).err())
            .map(|error| match error {
                Error::ConfigValidation(message) => message,
                other => other.to_string(),
            })
            .collect()
    }

    /// One error for many unresolved references, with the absent-env-files
    /// hint once rather than on every line.
    pub(super) fn unresolved_error(messages: &[String], overlay: &EnvOverlay) -> Error {
        let hint = overlay.absent_files_hint();
        let lines: Vec<&str> = messages
            .iter()
            .map(|m| m.strip_suffix(hint.as_str()).unwrap_or(m))
            .collect();
        Error::ConfigValidation(format!("{}{hint}", lines.join("\n")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn overlay(body: &str) -> (tempfile::TempDir, EnvOverlay) {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("s.env");
        // Owner-only, or the C2 file-mode rule skips the fixture before it is read.
        crate::gateway::test_helpers::write_owner_only(&path, body).expect("write");
        let overlay = EnvOverlay::from_paths(&[path]);
        (dir, overlay)
    }

    #[test]
    fn parse_classifies_env_and_literal() {
        assert_eq!(SecretRef::parse("env:A"), SecretRef::Env("A"));
        assert_eq!(SecretRef::parse("plain"), SecretRef::Literal("plain"));
    }

    #[test]
    fn resolve_refuses_unset_empty_and_blank_name() {
        let (_d, o) = overlay("SR_EMPTY=\nSR_SET=v\n");
        assert_eq!(
            SecretRef::parse("env:SR_SET").resolve("f", &o).unwrap(),
            "v"
        );
        let empty = SecretRef::parse("env:SR_EMPTY")
            .resolve("f", &o)
            .unwrap_err();
        assert!(empty.to_string().contains("empty"), "{empty}");
        assert!(
            SecretRef::parse("env:SR_UNSET_C4")
                .resolve("f", &o)
                .is_err()
        );
        assert!(SecretRef::parse("env:").resolve("f", &o).is_err());
    }

    #[test]
    fn expand_refuses_unset_without_default_only() {
        let (_d, o) = overlay("SR_SET=v\n");
        assert_eq!(expand_template("a${SR_SET}b", &o).unwrap(), "avb");
        assert_eq!(expand_template("${SR_UNSET_C4:-d}", &o).unwrap(), "d");
        assert_eq!(expand_template("${SR_UNSET_C4:-}", &o).unwrap(), "");
        assert_eq!(
            expand_template("x${SR_UNSET_C4}", &o).unwrap_err(),
            Unresolved::Unset("SR_UNSET_C4".into())
        );
        assert_eq!(
            expand_template("Bearer ${lower}", &o).unwrap_err(),
            Unresolved::Malformed
        );
        assert_eq!(
            expand_template("x${", &o).unwrap_err(),
            Unresolved::Malformed
        );
    }
}

// MIK-8365: the transparency-log HMAC key resolves like every other secret.
#[cfg(all(test, unix))]
#[path = "transparency_secret_tests.rs"]
mod transparency_secret_tests;

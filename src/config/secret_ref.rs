// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The one grammar for whole-value secret references, and the one `${VAR}`
//! expander (C4, SECRET.1).
//!
//! A reference that resolves to nothing is refused. Unset and empty are the
//! same case: an empty credential is never a deliberate one, and on the
//! comparison side an empty bearer matches an empty presented token.
//!
//! Callers classify only `Literal(_)` versus "a reference". They never match a
//! reference arm, so a new arm (C9 adds `File`) changes only this file.

use std::sync::LazyLock;

use regex::Regex;

use super::EnvOverlay;
use crate::{Error, Result};

/// A whole-value secret as written in operator config.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SecretRef<'a> {
    /// `env:NAME`: the value `NAME` holds in the overlay.
    Env(&'a str),
    /// Anything else: the text itself is the secret.
    Literal(&'a str),
}

impl<'a> SecretRef<'a> {
    /// Classifies `text`. Never fails; a malformed reference is reported by
    /// [`SecretRef::resolve`].
    #[must_use]
    pub(crate) fn parse(text: &'a str) -> Self {
        text.strip_prefix("env:")
            .map_or(Self::Literal(text), Self::Env)
    }

    /// The secret `field` holds. Unset and empty are both refused, and the
    /// error never contains a value.
    ///
    /// # Errors
    ///
    /// [`Error::ConfigValidation`] naming `field` when the reference is empty,
    /// unset, or resolves to an empty string.
    pub(crate) fn resolve(self, field: &str, overlay: &EnvOverlay) -> Result<String> {
        match self {
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
        }
    }
}

/// `${VAR}` and `${VAR:-default}`. The only copy of this pattern.
static TEMPLATE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\$\{([A-Z_][A-Z0-9_]*)(?::-([^}]*))?\}").expect("constant template pattern")
});

/// Expands every `${VAR}` in `text`. A variable that is unset and has no
/// default is refused; `${VAR:-}` is the explicit way to allow empty.
///
/// # Errors
///
/// The name of the first variable that is unset with no default.
pub(crate) fn expand_template(
    text: &str,
    overlay: &EnvOverlay,
) -> std::result::Result<String, String> {
    let mut out = String::with_capacity(text.len());
    let mut end = 0;
    for caps in TEMPLATE.captures_iter(text) {
        let whole = caps.get(0).expect("group 0 always matches");
        out.push_str(&text[end..whole.start()]);
        let value = overlay
            .resolve(&caps[1])
            .or_else(|| caps.get(2).map(|d| d.as_str().to_owned()))
            .unwrap_or_default();
        out.push_str(&value);
        end = whole.end();
    }
    out.push_str(&text[end..]);
    Ok(out)
}

/// [`expand_template`] for a config field, with the operator-facing error.
///
/// # Errors
///
/// [`Error::ConfigValidation`] naming `field` and the unset variable.
pub(crate) fn expand_field(field: &str, text: &str, overlay: &EnvOverlay) -> Result<String> {
    expand_template(text, overlay).map_err(|var| {
        Error::ConfigValidation(format!(
            "{field} references ${{{var}}}, which is not set and has no default. \
             Set it, or write ${{{var}:-}} to allow empty.{}",
            overlay.absent_files_hint()
        ))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn overlay(body: &str) -> (tempfile::TempDir, EnvOverlay) {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("s.env");
        std::fs::write(&path, body).expect("write");
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
            "SR_UNSET_C4"
        );
    }
}

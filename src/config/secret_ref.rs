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
        } else if let Some(path) = text.strip_prefix("file:\u{0}") {
            Self::File(Path::new(path))
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
        }
    }
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
    let text = read_bounded(path).map_err(|e| {
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

#[cfg(unix)]
fn read_bounded(path: &Path) -> Result<String> {
    super::secret_file::read_secret_file(path, super::secret_file::SecretFile::Reference)
}

/// No mode bits to judge off Unix (as C2); the size and UTF-8 rules still hold.
#[cfg(not(unix))]
fn read_bounded(path: &Path) -> Result<String> {
    use std::io::Read as _;
    const LIMIT: u64 = 64 * 1024;
    let cannot = |e: std::io::Error| {
        Error::Config(format!("Cannot read secret file {}: {e}", path.display()))
    };
    let mut bytes = Vec::new();
    std::fs::File::open(path)
        .map_err(cannot)?
        .take(LIMIT + 1)
        .read_to_end(&mut bytes)
        .map_err(cannot)?;
    if bytes.len() as u64 > LIMIT {
        return Err(Error::Config(format!(
            "Refusing to load secret file {}: it is larger than 64 KiB, the limit for one secret.",
            path.display()
        )));
    }
    String::from_utf8(bytes).map_err(|_| {
        Error::Config(format!(
            "Cannot read secret file {}: it is not UTF-8.",
            path.display()
        ))
    })
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
    /// A `${` that is not a `${NAME}` reference. Carries the name only when it
    /// is identifier-like, so a literal secret containing `${` is not echoed.
    Malformed(Option<String>),
}

/// A `${` in text the pattern did not consume is a reference that cannot
/// resolve, such as a lowercase `${github_token}`; it is refused rather than
/// sent upstream verbatim.
fn refuse_stray(segment: &str) -> std::result::Result<(), Unresolved> {
    let Some(at) = segment.find("${") else {
        return Ok(());
    };
    let rest = &segment[at + 2..];
    let name = rest.split('}').next().filter(|n| {
        rest.contains('}')
            && !n.is_empty()
            && n.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
    });
    Err(Unresolved::Malformed(name.map(str::to_owned)))
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
        Unresolved::Unset(var) => format!(
            "{field} references ${{{var}}}, which is not set (or is empty) and has no default. \
             Set it, or write ${{{var}:-}} to allow empty."
        ),
        Unresolved::Malformed(Some(name)) => format!(
            "{field} contains ${{{name}}}, which is not a variable reference: names are \
             uppercase letters, digits and '_', starting with a letter or '_'."
        ),
        Unresolved::Malformed(None) => {
            format!("{field} contains a '${{' that is not a ${{NAME}} variable reference.")
        }
    })
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
        std::fs::write(&path, body).expect("write");
        // 0600, or the C2 file-mode rule skips the fixture before it is read.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).expect("chmod");
        }
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
            Unresolved::Malformed(Some("lower".into()))
        );
        assert_eq!(
            expand_template("x${", &o).unwrap_err(),
            Unresolved::Malformed(None)
        );
    }
}

// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The one parser of credential references, shared by the resolver and
//! `cap import --auth-key`.

use super::CapabilityExecutor;

/// The form of a credential reference as `fetch_credential` reads it; each
/// payload borrows from the key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CredentialForm<'a> {
    /// `env:NAME`.
    Env(&'a str),
    /// `keychain:NAME`.
    Keychain(&'a str),
    /// `oauth:PROVIDER`.
    OAuth(&'a str),
    /// `file:PATH`.
    File(&'a str),
    /// `{env.NAME}`.
    EnvTemplate(&'a str),
    /// A bare `UPPER_SNAKE_CASE` variable name.
    BareEnv(&'a str),
}

/// Why a key is not a credential reference. It never carries the key, so a
/// refusal built from it cannot repeat a value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum NotAReference {
    /// Nothing was given.
    Empty,
    /// None of the forms matched.
    Unrecognised,
}

/// The one parser of credential references: `fetch_credential`
/// and `cap import --auth-key` both read a key through it, so the CLI accepts
/// exactly what the resolver reads. A payload is not checked here: an empty
/// `env:` parses, and fails at resolve time as it always has.
pub(crate) fn credential_form(key: &str) -> std::result::Result<CredentialForm<'_>, NotAReference> {
    if let Some(name) = key.strip_prefix("env:") {
        Ok(CredentialForm::Env(name))
    } else if let Some(name) = key.strip_prefix("keychain:") {
        Ok(CredentialForm::Keychain(name))
    } else if let Some(provider) = key.strip_prefix("oauth:") {
        Ok(CredentialForm::OAuth(provider))
    } else if let Some(spec) = key.strip_prefix("file:") {
        Ok(CredentialForm::File(spec))
    } else if key.starts_with("{env.") && key.ends_with('}') {
        Ok(CredentialForm::EnvTemplate(&key[5..key.len() - 1]))
    } else if key.is_empty() {
        Err(NotAReference::Empty)
    } else if CapabilityExecutor::looks_like_env_var_name(key) {
        Ok(CredentialForm::BareEnv(key))
    } else {
        Err(NotAReference::Unrecognised)
    }
}

#[cfg(tp4)]
#[cfg(test)]
#[path = "credential_form_tests.rs"]
mod credential_form_tests;

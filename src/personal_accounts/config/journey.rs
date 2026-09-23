// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-6745 slice 1: hosted consent-journey CONFIGURATION (design §10).
//!
//! Configuration only. Nothing here mounts a route, reads a cookie or calls
//! Open `WebUI`: a block that passes is not thereby a working journey. Every
//! rule is decidable from the text, so it runs for a disabled store as well,
//! and none of it reads the environment.
//!
//! OMISSION IS A NO-OP. Without `accounts.hosted` the only rules that can
//! refuse are the ones a new field brings with it: a `session` block (which
//! would be inert) and `authorize_extra` off a `personal_managed` descriptor
//! (also inert). The R2-5/R3-1 caps apply only under `hosted`, so an existing
//! configuration is never refused by this slice.

use serde::{Deserialize, Serialize};
use url::{Host, Url};

use super::{AccountsConfig, AccountsConfigError, DescriptorMode};

/// Where a hosted provider callback lands, relative to `public_origin`.
const CALLBACK_PATH: &str = "/accounts/v1/callback";
/// Journey field caps (design §10, reviews R2-5 and R3-1).
const RETURN_PATH_MAX: usize = 256;
const ACCOUNT_ID_MAX: usize = 64;
const ISSUER_MAX: usize = 256;
const KEY_ID_MAX: usize = 64;

/// `accounts.hosted`: the one origin the browser routes are served on.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct HostedConfig {
    /// An https origin exactly as `Url::origin` serialises it.
    pub(crate) public_origin: String,
    /// Allowed post-journey landing paths, compared byte-exactly at request
    /// time and never normalised.
    pub(crate) return_paths: Vec<String>,
}

/// `accounts.adapters[].session`: enables the browser bridge for one adapter.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SessionConfig {
    /// Open `WebUI`'s session-user endpoint: https, or http on a loopback
    /// IP literal, because the session token is sent to it as a bearer.
    pub(crate) user_endpoint: String,
    /// The Open `WebUI` session cookie; `token` in v0.9.6.
    #[serde(default = "default_cookie_name")]
    pub(crate) cookie_name: String,
}

fn default_cookie_name() -> String {
    "token".to_string()
}

/// A descriptor's extra authorize parameters: a closed map, never free text
/// (design §6.1). Google issues no refresh token without
/// `access_type=offline`, and none on re-consent without `prompt=consent`.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct AuthorizeExtra {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) access_type: Option<AccessType>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) prompt: Option<Prompt>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) include_granted_scopes: Option<bool>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum AccessType {
    Offline,
    Online,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Prompt {
    Consent,
    SelectAccount,
    /// The wire value `none`: no UI at all. Renamed so it never reads as `Option::None`.
    #[serde(rename = "none")]
    Silent,
}

/// Every journey rule over the whole block. Reads nothing.
pub(super) fn validate(accounts: &AccountsConfig) -> Result<(), AccountsConfigError> {
    let mut bridges = accounts
        .adapters
        .iter()
        .enumerate()
        .filter_map(|(index, adapter)| adapter.session.as_ref().map(|s| (index, s)));
    for (index, session) in bridges.clone() {
        validate_session(index, session)?;
    }
    forbid_inert_authorize_extra(accounts)?;
    let Some(hosted) = accounts.hosted.as_ref() else {
        return match bridges.next() {
            Some((index, _)) => Err(AccountsConfigError::Adapter {
                index,
                problem: "session requires accounts.hosted; without it no bridge is mounted",
            }),
            None => Ok(()),
        };
    };
    // Exactly one: a single hosted origin makes adapter selection for the
    // journey-less browser routes deterministic (review L3).
    if bridges.count() != 1 {
        return Err(hosted_error(
            "hosted requires exactly one adapter with a session block",
        ));
    }
    validate_origin(&hosted.public_origin)?;
    validate_return_paths(&hosted.return_paths)?;
    validate_key_ids(accounts)?;
    validate_managed_descriptors(accounts, &hosted.public_origin)
}

fn hosted_error(problem: &'static str) -> AccountsConfigError {
    AccountsConfigError::Hosted { problem }
}

/// The session token travels to `user_endpoint` as a bearer, so it may leave
/// the host only over TLS. `localhost` is a name, not a literal: it resolves
/// through whatever the resolver says. Userinfo is refused so no credential is
/// ever written inline in the URL.
fn validate_session(index: usize, session: &SessionConfig) -> Result<(), AccountsConfigError> {
    let fail = |problem: &'static str| AccountsConfigError::Adapter { index, problem };
    let acceptable = Url::parse(&session.user_endpoint).is_ok_and(|url| {
        let loopback = match url.host() {
            Some(Host::Ipv4(ip)) => ip.is_loopback(),
            Some(Host::Ipv6(ip)) => ip.is_loopback(),
            _ => false,
        };
        let transport = match url.scheme() {
            "https" => url.has_host(),
            "http" => loopback,
            _ => false,
        };
        transport && url.username().is_empty() && url.password().is_none()
    });
    if !acceptable {
        return Err(fail(
            "session.user_endpoint must be https, or http on a loopback IP literal, with no userinfo",
        ));
    }
    if session.cookie_name.is_empty() || !session.cookie_name.bytes().all(is_cookie_token_byte) {
        return Err(fail("session.cookie_name must be a nonempty cookie token"));
    }
    Ok(())
}

/// RFC 6265 `cookie-name` is an RFC 7230 `token`.
fn is_cookie_token_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&byte)
}

/// Origin form exactly as `Url::origin` serialises it, which alone refuses a
/// path, a trailing slash, a query, userinfo and an explicit default port.
/// Exactness matters: the callback is `public_origin + CALLBACK_PATH` as a
/// string, so `https://h/` would make it `https://h//accounts/...`.
fn validate_origin(origin: &str) -> Result<(), AccountsConfigError> {
    let exact = Url::parse(origin)
        .is_ok_and(|url| url.scheme() == "https" && url.origin().ascii_serialization() == origin);
    if exact {
        return Ok(());
    }
    Err(hosted_error(
        "public_origin must be an https origin with no path, query, userinfo or default port",
    ))
}

/// Review L1. The single-slash rule refuses `//host` (protocol-relative) and
/// with it any scheme or relative form; the backslash rule refuses `/\host`,
/// which browsers read as `//host`. Printable ASCII without `?`, `#` or `%`
/// leaves nothing an encoding could hide a control, space or separator in.
fn validate_return_paths(paths: &[String]) -> Result<(), AccountsConfigError> {
    if paths.is_empty() {
        return Err(hosted_error("return_paths must be nonempty"));
    }
    for path in paths {
        if !path.starts_with('/') || path.starts_with("//") {
            return Err(hosted_error(
                "return_paths entries must start with exactly one /",
            ));
        }
        if path.contains('\\') {
            return Err(hosted_error(
                "return_paths entries must not contain a backslash",
            ));
        }
        if !path
            .bytes()
            .all(|b| b.is_ascii_graphic() && !b"?#%".contains(&b))
        {
            return Err(hosted_error(
                "return_paths entries must be printable ASCII with no space, ?, # or %",
            ));
        }
        if path.len() > RETURN_PATH_MAX {
            return Err(hosted_error(
                "return_paths entries must be at most 256 bytes",
            ));
        }
    }
    Ok(())
}

/// Review R3-1: a key id becomes a journey record's `digest_key_id`, so every
/// id is capped. `current_key_id` is required to be one of them elsewhere.
fn validate_key_ids(accounts: &AccountsConfig) -> Result<(), AccountsConfigError> {
    let capped = |id: &String| {
        id.len() <= KEY_ID_MAX
            && id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
    };
    if accounts.keys.keys().all(capped) {
        return Ok(());
    }
    Err(hosted_error(
        "accounts.keys: key ids must be at most 64 bytes of [A-Za-z0-9._-] when hosted is set",
    ))
}

/// Review R2-5 caps, plus the callback rule: the descriptor's `redirect_uri`
/// is already the exact https callback, so it must be the hosted one.
fn validate_managed_descriptors(
    accounts: &AccountsConfig,
    public_origin: &str,
) -> Result<(), AccountsConfigError> {
    let callback = format!("{public_origin}{CALLBACK_PATH}");
    let managed = accounts
        .descriptors
        .iter()
        .flatten()
        .filter(|(_, descriptor)| descriptor.mode == DescriptorMode::PersonalManaged);
    for (account_id, descriptor) in managed {
        let fail = |problem: &'static str| AccountsConfigError::Descriptor {
            account_id: account_id.clone(),
            problem,
        };
        let id_ok = account_id.len() <= ACCOUNT_ID_MAX
            && account_id
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'_' | b'-'));
        if !id_ok {
            return Err(fail(
                "account id must be at most 64 bytes of [a-z0-9_-] when hosted is set",
            ));
        }
        if descriptor
            .issuer
            .as_ref()
            .is_some_and(|issuer| issuer.len() > ISSUER_MAX)
        {
            return Err(fail("issuer must be at most 256 bytes when hosted is set"));
        }
        if descriptor.redirect_uri.as_deref() != Some(callback.as_str()) {
            return Err(fail(
                "redirect_uri must equal hosted.public_origin + /accounts/v1/callback",
            ));
        }
    }
    Ok(())
}

/// Only `personal_managed` builds an authorize request. `authorize_extra`
/// anywhere else is a knob that does nothing, and an inert line is refused
/// rather than silently carried, as everywhere in this block.
fn forbid_inert_authorize_extra(accounts: &AccountsConfig) -> Result<(), AccountsConfigError> {
    let inert = accounts
        .descriptors
        .iter()
        .flatten()
        .find(|(_, descriptor)| {
            descriptor.authorize_extra.is_some()
                && descriptor.mode != DescriptorMode::PersonalManaged
        });
    match inert {
        Some((account_id, _)) => Err(AccountsConfigError::Descriptor {
            account_id: account_id.clone(),
            problem: "authorize_extra is valid only on mode personal_managed",
        }),
        None => Ok(()),
    }
}

#[cfg(test)]
#[path = "journey_tests.rs"]
mod journey_tests;

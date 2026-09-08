// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! `accounts.adapters` — the Open WebUI signed-header adapter CONFIGURATION.
//!
//! SCOPE, STATED PLAINLY. This module is configuration only. It declares the
//! approved field names, refuses a block that cannot be honoured, and resolves
//! the signing secret when — and only when — the store is enabled. It wires no
//! middleware, trusts no header, and starts nothing: a configuration that parses
//! here is NOT thereby an authenticated identity path. The hosted browser bridge
//! remains the unresolved increment-4 interface the approved document says it is.
//!
//! THE APPROVED ROW, VERBATIM:
//!
//! > Explicit list, default empty; each Open WebUI adapter has kind
//! > `openwebui_signed_header`, unique `installation_id`, fixed `header`,
//! > `issuer` literal `open-webui`, `hmac_secret_ref` using env:, nonempty
//! > `allowed_api_key_names`, `max_lifetime_seconds` default 300 and
//! > `clock_skew_seconds` default 30
//!
//! and, in prose: the configured header cannot be `Authorization` or a reserved
//! gateway identity header; at least 32 random secret bytes; no secret reuse
//! with gateway authentication or store keys.
//!
//! TWO VALIDATION STAGES, DELIBERATELY SEPARATE.
//!
//! * [`validate`] is STRUCTURAL and reads no environment at all. It runs for
//!   every configuration, including `accounts.enabled: false`, because a
//!   malformed adapter is a malformed adapter whether or not custody is open,
//!   and an operator must learn about a duplicated `installation_id` or a
//!   reserved header at load time rather than on the day they flip the store on.
//! * [`resolve_secrets`] is MATERIAL and runs only from the enabled-store
//!   resolution path, through the caller's existing overlay. It never touches
//!   `std::env` itself, so a disabled block causes no environment read and no
//!   test needs a variable to exist.
//!
//! GATEWAY AUTHENTICATION SEPARATION, the other half of the approved reuse
//! rule, is now enforced — but by a THIRD entry point rather than by widening
//! [`resolve_secrets`], because the caller that knows the account store keys and
//! the caller that knows `auth.bearer_token`/`auth.api_keys` are different
//! callers:
//!
//! * [`validate_no_gateway_reference_alias`] is STRUCTURAL. Two references
//!   naming ONE variable are one secret whatever that variable holds, so this is
//!   decidable from the text and runs for a disabled store as well — no
//!   environment read, so the secret-free parser path stays secret-free.
//! * [`validate_no_gateway_material_reuse`] is MATERIAL and runs only where the
//!   store is enabled and secrets are being resolved anyway. It compares
//!   RESOLVED BYTES, so two differently NAMED variables holding one value, and a
//!   literal credential written inline, are both caught — which the reference
//!   check alone cannot do.
//!
//! Neither one calls `AuthConfig::resolve_bearer_token` or
//! `ApiKeyConfig::resolve_key`: those read `std::env` directly, bypassing the
//! overlay this slice resolves against, and the `auto` bearer MINTS A FRESH
//! RANDOM TOKEN on every call, so "comparing" against it would compare against a
//! value no running gateway holds. An `auto` bearer is therefore skipped by
//! construction rather than by luck: an independently generated 32-byte random
//! token is not a configured secret and cannot be the reused one.
//!
//! WHAT IS STILL OWED, SO NOBODY READS MORE INTO THIS THAN IS HERE. This remains
//! a CONFIGURATION increment. Nothing here authenticates a request, and a
//! configuration that passes these checks is not thereby a trusted adapter: the
//! eventual runtime builder must itself run the material validation before any
//! assertion is trusted, because a DISABLED store resolves no material at all
//! and only the structural half will have run. The hosted browser bridge and the
//! runtime signed-header verification stay open.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use super::AccountsConfigError;

/// The one approved adapter kind. An enum rather than a validated `String` so
/// that an unrecognised spelling is refused BY NAME at parse time
/// ("unknown variant") instead of being silently treated as the only member.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum AdapterKind {
    /// `openwebui_signed_header`.
    OpenwebuiSignedHeader,
}

/// One configured Open WebUI adapter, exactly the approved field set.
///
/// `deny_unknown_fields` matches the surrounding `accounts` block's posture: a
/// typo'd knob must be a startup refusal, never a silently inert line. The two
/// bounded-time fields carry the approved defaults through serde defaults and
/// are always serialized, so a rewritten configuration states the window it is
/// actually running with instead of leaving it implicit.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct AdapterConfig {
    pub(crate) kind: AdapterKind,
    /// Unique across the list; the identity namespace of one installation.
    pub(crate) installation_id: String,
    /// The assertion header, carried byte for byte as the operator wrote it.
    pub(crate) header: String,
    /// The literal `open-webui`.
    pub(crate) issuer: String,
    /// `env:VARIABLE`. Stays a reference: no signing material in the file, and
    /// none in a rewrite of it.
    pub(crate) hmac_secret_ref: String,
    /// Which authenticated gateway API keys may assert an identity. Required and
    /// nonempty: an absent or empty list must never read as "any key".
    pub(crate) allowed_api_key_names: Vec<String>,
    #[serde(default = "default_max_lifetime_seconds")]
    pub(crate) max_lifetime_seconds: u64,
    #[serde(default = "default_clock_skew_seconds")]
    pub(crate) clock_skew_seconds: u64,
}

/// The approved default assertion lifetime bound, in seconds.
const DEFAULT_MAX_LIFETIME_SECONDS: u64 = 300;
/// The approved default clock-skew tolerance, in seconds.
const DEFAULT_CLOCK_SKEW_SECONDS: u64 = 30;

fn default_max_lifetime_seconds() -> u64 {
    DEFAULT_MAX_LIFETIME_SECONDS
}

fn default_clock_skew_seconds() -> u64 {
    DEFAULT_CLOCK_SKEW_SECONDS
}

/// The literal issuer an Open WebUI assertion is bound to.
const ISSUER: &str = "open-webui";

/// At least this many resolved secret bytes, per the approved prose.
const MIN_SECRET_BYTES: usize = 32;

/// Header names the gateway owns or that carry a caller's own credential.
///
/// Compared case-insensitively because HTTP field names are case-insensitive: a
/// deployment configuring `authorization` must be refused exactly as one
/// configuring `Authorization` is. Letting a credential header double as the
/// assertion header would let a caller-supplied value be read as an asserted
/// identity, which is the confusion the rule exists to prevent.
const RESERVED_HEADERS: &[&str] = &[
    "authorization",
    "proxy-authorization",
    "www-authenticate",
    "proxy-authenticate",
    "cookie",
    "set-cookie",
    "host",
    "x-api-key",
    "x-mcp-passthrough-authorization",
    "x-mcp-profile",
];

/// Structural validation of the whole list. Reads nothing, resolves nothing.
///
/// Every rule here is decidable from the configuration text alone, which is why
/// it can run for a disabled store as well as an enabled one.
pub(crate) fn validate(adapters: &[AdapterConfig]) -> Result<(), AccountsConfigError> {
    let mut seen: BTreeSet<&str> = BTreeSet::new();
    for (index, adapter) in adapters.iter().enumerate() {
        let fail = |problem: &'static str| AccountsConfigError::Adapter { index, problem };

        if adapter.installation_id.trim().is_empty() {
            return Err(fail("installation_id must be nonempty"));
        }
        if !seen.insert(adapter.installation_id.as_str()) {
            return Err(AccountsConfigError::AdapterDuplicateInstallation {
                installation_id: adapter.installation_id.clone(),
            });
        }

        // The literal, exactly: a case variant is a different issuer identity,
        // and an empty one is not "any issuer".
        if adapter.issuer != ISSUER {
            return Err(fail("issuer must be the literal open-webui"));
        }

        validate_header(index, &adapter.header)?;
        validate_secret_ref(index, &adapter.hmac_secret_ref)?;

        if adapter.allowed_api_key_names.is_empty() {
            return Err(fail(
                "allowed_api_key_names must be nonempty; an empty allowlist is not \"any api key\"",
            ));
        }
        if adapter
            .allowed_api_key_names
            .iter()
            .any(|name| name.trim().is_empty())
        {
            return Err(fail(
                "allowed_api_key_names entries must be nonempty api key names",
            ));
        }

        // `exp` must EXCEED `iat` within the maximum lifetime, so a maximum of
        // zero admits no assertion at all. No upper bound is invented: the
        // approved document states none.
        if adapter.max_lifetime_seconds == 0 {
            return Err(fail(
                "max_lifetime_seconds must be a positive number of seconds, never zero",
            ));
        }
    }
    Ok(())
}

/// The configured header must be a real HTTP field name and not a reserved one.
fn validate_header(index: usize, header: &str) -> Result<(), AccountsConfigError> {
    let fail = |problem: &'static str| AccountsConfigError::Adapter { index, problem };

    if header.is_empty() {
        return Err(fail(
            "header must be a nonempty http field name; an empty header name is not empty-matching",
        ));
    }
    // RFC 9110 token characters. A value with a space or a control character
    // could never be matched at runtime, so it is refused at load.
    let is_token = header
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&byte));
    if !is_token {
        return Err(fail("header is not a valid http field name"));
    }
    if RESERVED_HEADERS
        .iter()
        .any(|reserved| header.eq_ignore_ascii_case(reserved))
    {
        return Err(fail(
            "header must not be authorization, cookie or another reserved gateway identity \
             header (compared case-insensitively)",
        ));
    }
    Ok(())
}

/// The reference SHAPE only: `env:` plus a nonempty variable name. Whether that
/// variable exists is a question for [`resolve_secrets`], not for this stage.
fn validate_secret_ref(index: usize, reference: &str) -> Result<(), AccountsConfigError> {
    let fail = |problem: &'static str| AccountsConfigError::Adapter { index, problem };

    let Some(variable) = reference.strip_prefix("env:") else {
        return Err(fail(
            "hmac_secret_ref must be an env: reference, never a literal secret",
        ));
    };
    if variable.trim().is_empty() {
        return Err(fail(
            "hmac_secret_ref env: reference must name a nonempty variable",
        ));
    }
    Ok(())
}

/// Resolve every adapter secret through the caller's overlay and enforce the
/// two MATERIAL rules. Returns the variable names read, in list order.
///
/// Called only from the enabled-store path, AFTER structural validation, so a
/// malformed adapter never causes an environment read. `store_keys` is the
/// already-decoded account key material, which is the only "other secret" this
/// module can see (see the module docs on what remains owed).
pub(crate) fn resolve_secrets(
    adapters: &[AdapterConfig],
    overlay: &dyn super::SecretOverlay,
    store_keys: &std::collections::BTreeMap<String, Vec<u8>>,
) -> Result<Vec<String>, AccountsConfigError> {
    Ok(resolve_material(adapters, overlay, store_keys)?.0)
}

/// The same resolution, keeping the MATERIAL for a runtime that must verify
/// signatures with it.
///
/// A separate entry point rather than a widened [`resolve_secrets`]: the config
/// load wants only the variable NAMES it read, and handing it signing bytes it
/// has no use for would put adapter material on the startup path for nothing.
/// Every rule [`resolve_secrets`] enforces — minimum length, no reuse with a
/// store key or another adapter — is enforced here, because it is the same
/// function; a runtime cannot obtain material without passing them.
pub(crate) fn resolve_runtime_secrets(
    adapters: &[AdapterConfig],
    overlay: &dyn super::SecretOverlay,
    store_keys: &std::collections::BTreeMap<String, Vec<u8>>,
) -> Result<Vec<Vec<u8>>, AccountsConfigError> {
    Ok(resolve_material(adapters, overlay, store_keys)?.1)
}

/// Resolve every adapter secret once, returning both the names read and the
/// bytes read, in list order.
fn resolve_material(
    adapters: &[AdapterConfig],
    overlay: &dyn super::SecretOverlay,
    store_keys: &std::collections::BTreeMap<String, Vec<u8>>,
) -> Result<(Vec<String>, Vec<Vec<u8>>), AccountsConfigError> {
    let mut read = Vec::new();
    let mut adapter_secrets: Vec<Vec<u8>> = Vec::new();

    for (index, adapter) in adapters.iter().enumerate() {
        let variable =
            adapter
                .hmac_secret_ref
                .strip_prefix("env:")
                .ok_or(AccountsConfigError::Adapter {
                    index,
                    problem: "hmac_secret_ref must be an env: reference, never a literal secret",
                })?;
        read.push(variable.to_string());
        let secret = overlay.resolve(variable).ok_or_else(|| {
            AccountsConfigError::AdapterSecretUnresolved {
                index,
                variable: variable.to_string(),
            }
        })?;
        let material = secret.into_bytes();
        if material.len() < MIN_SECRET_BYTES {
            return Err(AccountsConfigError::AdapterSecretTooShort { index });
        }
        // Reuse makes two trust domains one: an assertion signed with the store
        // key, or with another installation's key, would verify where it must
        // not. Compared on resolved material, never on the reference string.
        // The base64 form is compared as well as the raw bytes: `accounts.keys`
        // holds base64 of 32 bytes, so an operator who pointed both at the same
        // variable would otherwise compare "the encoded text" against "the
        // decoded key" and look distinct while being one secret.
        let decoded = {
            use base64::Engine as _;
            base64::engine::general_purpose::STANDARD
                .decode(&material)
                .ok()
        };
        if store_keys
            .values()
            .any(|key| key.as_slice() == material || Some(key.clone()) == decoded)
            || adapter_secrets.iter().any(|other| other == &material)
        {
            return Err(AccountsConfigError::AdapterSecretReuse { index });
        }
        adapter_secrets.push(material);
    }
    Ok((read, adapter_secrets))
}

/// One gateway authentication credential AS CONFIGURED — the literal text of
/// `auth.bearer_token` or of an `auth.api_keys[].key`, never a resolved value
/// and never the whole `AuthConfig`.
///
/// A borrowed view rather than an owned copy so that constructing the list
/// cannot itself duplicate secret material into a longer-lived allocation.
///
/// NO `Debug`, DELIBERATELY. `spec` is the credential AS CONFIGURED, which for
/// a literal `auth.bearer_token` or api key IS the secret; a derived formatter
/// would print it into any log line, panic message or `{:?}` of a containing
/// structure that ever reached one. Nothing formats this type today, so the
/// derive is removed rather than replaced: a hand-written redacting formatter
/// would be an unused surface, and the only honest way to keep material out of
/// a log is for there to be no way to print it at all. Errors already carry
/// [`GatewayCredential::label`], which is configuration coordinates only.
#[derive(Clone, Copy)]
pub(crate) enum GatewayCredential<'a> {
    /// `auth.bearer_token`, including the sentinel `auto`.
    BearerToken(&'a str),
    /// `auth.api_keys[index]`, with the operator's own label.
    ApiKey {
        index: usize,
        name: &'a str,
        spec: &'a str,
    },
}

impl<'a> GatewayCredential<'a> {
    /// The configured text: `auto`, `env:VARIABLE`, or a literal credential.
    fn spec(self) -> &'a str {
        match self {
            Self::BearerToken(spec) | Self::ApiKey { spec, .. } => spec,
        }
    }

    /// How the credential is NAMED in an error. Field path plus, for a key, the
    /// operator's label — both are configuration coordinates, never material.
    fn label(self) -> String {
        match self {
            Self::BearerToken(_) => "auth.bearer_token".to_string(),
            Self::ApiKey { index, name, .. } if name.trim().is_empty() => {
                format!("auth.api_keys[{index}]")
            }
            Self::ApiKey { index, name, .. } => format!("auth.api_keys[{index}] (name {name})"),
        }
    }

    /// The variable an `env:` credential refers to, if it is one.
    ///
    /// The `auto` bearer is not a reference and not a literal to compare: it is
    /// minted fresh per resolution, so it has no configured material at all.
    fn env_variable(self) -> Option<&'a str> {
        if self.is_auto_bearer() {
            return None;
        }
        self.spec().strip_prefix("env:")
    }

    fn is_auto_bearer(self) -> bool {
        matches!(self, Self::BearerToken(spec) if spec == "auto")
    }
}

/// Structural half of gateway separation: no adapter may name the SAME
/// environment variable as a gateway credential.
///
/// CALL IT BEFORE ANY CREDENTIAL IS INLINED. This compares REFERENCE TEXT on
/// both sides, so a caller that has already substituted `auth.bearer_token` or
/// an api key with the value its variable held is handing over plaintext, and
/// plaintext equals no `env:` name: the check then passes vacuously. With a
/// disabled store the material half does not run either, so that ordering
/// mistake is silent acceptance rather than a weaker diagnostic. The gateway's
/// own load path resolves secrets partway through, which is why it runs this
/// against the as-parsed configuration rather than leaving it to validation.
///
/// Decidable from the text, so it runs for every configuration including a
/// disabled store, and it reads nothing — a config with `accounts.enabled:
/// false` still causes no environment lookup. Useful on its own precisely
/// because it needs no variable to exist: an operator who wired one variable
/// into both places learns at load time rather than on the day they enable the
/// store.
pub(crate) fn validate_no_gateway_reference_alias(
    adapters: &[AdapterConfig],
    credentials: &[GatewayCredential<'_>],
) -> Result<(), AccountsConfigError> {
    for (index, adapter) in adapters.iter().enumerate() {
        let Some(variable) = adapter.hmac_secret_ref.strip_prefix("env:") else {
            // Shape is `validate`'s refusal to report, not this one's.
            continue;
        };
        // Case-sensitive: environment variable names are, so `SECRET` and
        // `secret` are two variables and treating them as one would refuse a
        // configuration that is in fact separated.
        if let Some(credential) = credentials
            .iter()
            .find(|credential| credential.env_variable() == Some(variable))
        {
            return Err(AccountsConfigError::AdapterSecretReusesGatewayAuth {
                index,
                credential: credential.label(),
            });
        }
    }
    Ok(())
}

/// Material half of gateway separation: no adapter secret may RESOLVE to the
/// bytes a gateway credential resolves to.
///
/// Run only where the store is enabled and adapter material is being resolved
/// anyway. Everything goes through `overlay`, never `std::env`, so this is the
/// same environment the rest of the load was evaluated against and a test needs
/// no process-wide variable.
///
/// A gateway credential that cannot be resolved is SKIPPED rather than refused:
/// a missing `auth.bearer_token` variable is `auth`'s own diagnostic, and
/// reporting it here would name someone else's field in an adapter error.
pub(crate) fn validate_no_gateway_material_reuse(
    adapters: &[AdapterConfig],
    overlay: &dyn super::SecretOverlay,
    credentials: &[GatewayCredential<'_>],
) -> Result<(), AccountsConfigError> {
    // Resolved once, before any adapter is looked at, so the comparison set is
    // the same for every index.
    let mut gateway: Vec<(String, Vec<u8>)> = Vec::new();
    for credential in credentials {
        if credential.is_auto_bearer() {
            // Independently generated randomness: no configured material to
            // reuse, so there is nothing here to compare and a positive result
            // is the correct one.
            continue;
        }
        let material = match credential.env_variable() {
            Some(variable) => overlay.resolve(variable),
            // A literal credential in the file is still the credential the
            // gateway authenticates with, so it is compared as material.
            None => Some(credential.spec().to_string()),
        };
        match material {
            Some(value) if !value.is_empty() => {
                gateway.push((credential.label(), value.into_bytes()))
            }
            _ => {}
        }
    }

    for (index, adapter) in adapters.iter().enumerate() {
        let Some(variable) = adapter.hmac_secret_ref.strip_prefix("env:") else {
            continue;
        };
        let Some(secret) = overlay.resolve(variable) else {
            // Unresolvable is `resolve_secrets`' refusal, reported there with
            // the variable named; nothing to compare here.
            continue;
        };
        let material = secret.into_bytes();
        // Compared on RESOLVED BYTES, never on the reference string: two
        // differently named variables holding one value are one secret, and
        // that is exactly the case a name-only check cannot see.
        if let Some((credential, _)) = gateway.iter().find(|(_, value)| value == &material) {
            return Err(AccountsConfigError::AdapterSecretReusesGatewayAuth {
                index,
                credential: credential.clone(),
            });
        }
    }
    Ok(())
}

#[cfg(test)]
#[path = "adapter_secret_tests.rs"]
mod secret_tests;

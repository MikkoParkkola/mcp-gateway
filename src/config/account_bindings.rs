// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Consumer side of `accounts.descriptors`: `backends[*].account` refusals and
//! the EFFECTIVE backend configuration a bound consumer actually runs with.
//!
//! ONE COMPILATION, TWO CALLERS. [`compile`] is the only place a reference is
//! resolved. `Config::validate_with_env` calls it through [`validate`] and
//! throws the result away — a refusal at load is the whole point — and gateway
//! startup calls it again to obtain the effective `BackendConfig` it registers
//! and the descriptors it installs strategies for. A second, startup-only rule
//! set would be a second policy nobody validated.
//!
//! WHAT A REFERENCE IS. The descriptor MAP KEY, which is the logical
//! `backend_id` of the account key (approved table row 422). Not the backend
//! registry name, not `provider`, not an email, not a display name. Two
//! descriptors may share one provider and stay distinct accounts, so resolving
//! by provider would silently merge two people's credentials.
//!
//! WHAT THE COMPILATION PRODUCES. A `personal_managed` descriptor compiles to
//! the EXISTING [`PropagationStrategyKind::Vault`] on the EXISTING
//! `identity_propagation` config — no new auth enum, no parallel pipeline — so
//! both dispatch consumers reach the one resolver. An `external` descriptor
//! contributes its own `external_strategy` verbatim. A `shared` descriptor
//! compiles to nothing: existing static behaviour is preserved exactly.
//!
//! The effective config also DROPS the backend's own OAuth block for a managed
//! consumer, so the legacy `OAuthClient` is never instantiated for a backend
//! whose credential is held in custody. That is a removal of a gateway-held
//! token, never a fallback to one.

use std::collections::BTreeMap;

use super::{BackendConfig, Config, TransportConfig};
use crate::identity_propagation::{
    IdentityPropagationConfig, PropagationStrategyKind, SessionMode,
};
use crate::personal_accounts::config::{AccountDescriptor, AccountsConfig, DescriptorMode};
use crate::personal_accounts::identity::AccountDescriptor as AccountKeyDescriptor;
use crate::secret_injection::InjectTarget;
use crate::{Error, Result};

/// One backend bound to one configured descriptor.
#[derive(Clone, Debug)]
pub(crate) struct BoundAccountBackend {
    /// Backend registry name (the `backends` map key).
    pub(crate) backend: String,
    /// The `accounts.descriptors` map key this backend named.
    pub(crate) descriptor_id: String,
    /// The descriptor's declared mode, as written.
    pub(crate) mode: DescriptorMode,
    /// The propagation configuration this binding compiles to, if any.
    /// `None` for `shared`: static behaviour is unchanged.
    pub(crate) propagation: Option<IdentityPropagationConfig>,
    /// The five-field account-key descriptor, for `personal_managed` only.
    pub(crate) account: Option<AccountKeyDescriptor>,
}

impl BoundAccountBackend {
    /// The configuration this backend actually runs with.
    ///
    /// Applied BEFORE the backend is constructed, so a managed consumer never
    /// reaches a constructor with a gateway-held OAuth client to build.
    pub(crate) fn effective(&self, config: &BackendConfig) -> BackendConfig {
        let mut effective = config.clone();
        if let Some(propagation) = self.propagation.clone() {
            effective.identity_propagation = Some(propagation);
        }
        // Shared mode deliberately has no custody requirement. Keep the
        // descriptor reference in the original Config for round trips, while
        // its effective runtime config follows the existing shared path.
        if self.mode == DescriptorMode::Shared {
            effective.account = None;
        }
        if self.mode == DescriptorMode::PersonalManaged {
            // Refused at load, so this can only be `None` already; cleared
            // rather than asserted because the constructor downstream reads
            // this field to decide whether to build an `OAuthClient` at all.
            effective.oauth = None;
        }
        effective
    }
}

/// Refuse a configuration whose account references do not resolve, or whose
/// managed consumers carry a credential that is not the account's.
///
/// # Errors
///
/// [`Error::ConfigValidation`] naming the backend and the reference.
pub(crate) fn validate(config: &Config) -> Result<()> {
    compile(config).map(|_| ())
}

/// Resolve every `backends[*].account` reference, or refuse.
///
/// Keyed by backend registry name. Backends with no reference are absent from
/// the map: an unbound backend keeps its configuration byte-for-byte.
///
/// # Errors
///
/// [`Error::ConfigValidation`] for an unresolved reference, a reference beside
/// `identity_propagation`, or a managed consumer that also carries a shared or
/// static credential.
pub(crate) fn compile(config: &Config) -> Result<BTreeMap<String, BoundAccountBackend>> {
    let mut bound = BTreeMap::new();
    for (name, backend) in &config.backends {
        let Some(reference) = backend.account.as_deref() else {
            if backend
                .identity_propagation
                .as_ref()
                .is_some_and(|propagation| propagation.strategy == PropagationStrategyKind::Vault)
            {
                return Err(Error::ConfigValidation(format!(
                    "backend '{name}' uses raw Vault identity propagation without an account descriptor; configure account instead"
                )));
            }
            continue;
        };
        bound.insert(
            name.clone(),
            compile_one(name, reference, backend, config.accounts.as_ref())?,
        );
    }
    Ok(bound)
}

/// Resolve one reference against the declared descriptors.
fn compile_one(
    name: &str,
    reference: &str,
    backend: &BackendConfig,
    accounts: Option<&AccountsConfig>,
) -> Result<BoundAccountBackend> {
    // Two answers to "how is this backend authenticated" is a conflict, not a
    // precedence rule: whichever a resolver happened to read first would win
    // silently, and the operator would never learn which one is live.
    if backend.identity_propagation.is_some() {
        return Err(Error::ConfigValidation(format!(
            "backend '{name}' declares both account '{reference}' and identity_propagation; \
             these are two different answers to how this backend is authenticated. Delete \
             one: keep account to bind the backend to accounts.descriptors, or keep \
             identity_propagation to mint per-user credentials directly."
        )));
    }

    let descriptor = accounts
        .and_then(|accounts| accounts.descriptors.as_ref())
        .and_then(|descriptors| descriptors.get(reference))
        .ok_or_else(|| {
            Error::ConfigValidation(format!(
                "backend '{name}' references account descriptor '{reference}', which is not a \
                 key in accounts.descriptors. The reference is the descriptor map key (the \
                 account's logical id) — never the backend name, the provider id, an email \
                 or a display name."
            ))
        })?;

    let (propagation, account) = match descriptor.mode {
        DescriptorMode::PersonalManaged => {
            validate_managed_consumer(name, reference, backend)?;
            let account = account_key_descriptor(name, reference, descriptor)?;
            let propagation = IdentityPropagationConfig {
                // The EXISTING kind, not a new one: managed custody dispatches
                // through the same `IdentityPropagation` trait every other
                // strategy does.
                strategy: PropagationStrategyKind::Vault,
                // The descriptor's own RFC 8707 resource is the audience the
                // credential is scoped to; it is also half of the account key,
                // so cache isolation and custody addressing cannot drift.
                audience: account.resource.clone(),
                // A managed account is one person's credential. There is no
                // best-effort mode: without the account there is nothing to
                // downgrade to that would still be that person.
                required: true,
                // A backend that answered as one user must not reuse that
                // session for the next one (IDP.7).
                session_mode: SessionMode::PerUser,
                token_exchange_endpoint: None,
                token_exchange_scope: None,
            };
            (Some(propagation), Some(account))
        }
        DescriptorMode::External => {
            let strategy = descriptor.external_strategy.clone().ok_or_else(|| {
                Error::ConfigValidation(format!(
                    "backend '{name}' references external account descriptor '{reference}', \
                     which declares no external_strategy"
                ))
            })?;
            (Some(strategy), None)
        }
        // Existing shared behaviour, preserved verbatim: a shared descriptor
        // names an account the deployment already serves statically, and
        // binding one must not tighten a configuration that never opted into
        // per-user credentials.
        DescriptorMode::Shared => (None, None),
    };

    Ok(BoundAccountBackend {
        backend: name.to_string(),
        descriptor_id: reference.to_string(),
        mode: descriptor.mode,
        propagation,
        account,
    })
}

/// The five-field key material a managed descriptor must carry.
///
/// `validate_descriptors` has already refused a managed descriptor missing
/// either field; this re-checks rather than unwrapping, because a compile that
/// panicked on an unvalidated `Config` would turn an operator error into a
/// crash.
fn account_key_descriptor(
    name: &str,
    reference: &str,
    descriptor: &AccountDescriptor,
) -> Result<AccountKeyDescriptor> {
    let (Some(resource), Some(issuer)) =
        (descriptor.resource.as_deref(), descriptor.issuer.as_deref())
    else {
        return Err(Error::ConfigValidation(format!(
            "backend '{name}' references personal_managed account descriptor '{reference}', \
             which is missing the resource/issuer the account key is built from"
        )));
    };
    Ok(AccountKeyDescriptor {
        descriptor_id: reference.to_string(),
        provider: descriptor.provider.clone(),
        resource: resource.to_string(),
        issuer: issuer.to_string(),
    })
}

/// What a `personal_managed` consumer may NOT also carry.
///
/// Each refusal is a credential that would reach the backend instead of, or
/// alongside, the account holder's own: a blessed-shared OAuth login, a static
/// `Authorization` header the transport sends anyway, an injected credential
/// aimed at the same header, or a transport that silently drops the per-request
/// credential and would run the call unauthenticated.
fn validate_managed_consumer(name: &str, reference: &str, backend: &BackendConfig) -> Result<()> {
    if let Some(oauth) = backend.oauth.as_ref()
        && (oauth.enabled || oauth.shared_account)
    {
        return Err(Error::ConfigValidation(format!(
            "backend '{name}' is bound to personal_managed account '{reference}' but also \
             declares its own gateway-held oauth client (oauth.enabled / \
             oauth.shared_account). A managed account is one person's credential under \
             custody, so a shared_account login beside it would serve some caller a \
             credential that is not theirs. Remove the oauth block from this backend."
        )));
    }

    // Value never echoed: the refusal is printed at startup and pasted into
    // support threads (CWE-532). The header NAME is the operator's answer.
    if let Some(header) = backend
        .headers
        .keys()
        .find(|header| header.eq_ignore_ascii_case("authorization"))
    {
        return Err(Error::ConfigValidation(format!(
            "backend '{name}' is bound to personal_managed account '{reference}' but also \
             sets a static '{header}' header. The transport would send it on every call, \
             overriding — or racing — the account holder's own credential. Remove the \
             header; the account supplies Authorization."
        )));
    }

    if let Some(rule) = backend.secrets.iter().find(|rule| {
        matches!(rule.inject_as, InjectTarget::Header)
            && rule.inject_key.eq_ignore_ascii_case("authorization")
    }) {
        return Err(Error::ConfigValidation(format!(
            "backend '{name}' is bound to personal_managed account '{reference}' but its \
             secret-injection rule '{}' injects the Authorization header. A managed \
             account's credential is the only Authorization this backend may carry.",
            rule.name
        )));
    }

    if !matches!(backend.transport, TransportConfig::Http { .. }) {
        return Err(Error::ConfigValidation(format!(
            "backend '{name}' is bound to personal_managed account '{reference}' but its \
             transport cannot carry a per-request credential header (only http transports \
             forward them; stdio and websocket silently drop them), so the call would run \
             unauthenticated instead of as the account holder."
        )));
    }
    Ok(())
}

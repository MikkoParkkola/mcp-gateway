// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Deployment `accounts` block -> `StoreConfig`. Refusing scaffold.
//!
//! Field names and rules are the approved configuration table (design doc rows
//! 414-432). Nothing here is invented, and no knob is added that the table does
//! not name.
//!
//! SECRETS FOLLOW THE EXISTING PATTERN, not an assumed one. `accounts.keys` maps
//! a key id to an `env:VARIABLE` reference, exactly like `auth.bearer_token` and
//! `agent_auth.agents[].hs256_secret`, and is resolved through the same
//! `EnvOverlay` that `Config::resolve_secret_refs` uses -- which also returns the
//! set of names it looked up, so a caller can assert WHICH variables were read.
//! An unresolvable name is left verbatim and reported as a missing reference, not
//! silently emptied. The scoped scan found no `SecretString`/`Zeroize` type in
//! this codebase, so none is assumed here.
//!
//! An inline literal key is a configuration error, not a convenience: it would
//! put 32 bytes of key material in a file that gets copied, diffed and pasted.
//!
//! Omitted `accounts` preserves existing behaviour and enables no managed
//! custody -- `resolve` answers `Ok(None)`, never a default store.

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

use super::StoreConfig;
use crate::identity_propagation::{IdentityPropagationConfig, PropagationStrategyKind};
use serde::{Deserialize, Serialize};

mod adapters;
mod descriptor_debug;

// Nameable from the rest of the crate without exposing the module: the type is
// part of `AccountsConfig`'s shape, the module layout is not.
pub(crate) use adapters::AdapterConfig;
// The gateway-credential view the separation checks below take. Nameable from
// `config::Config`, which is the only place that can see `auth`.
pub(crate) use adapters::GatewayCredential;

/// Structural gateway separation for the whole block: no adapter names the same
/// environment variable as a gateway credential.
///
/// Runs for EVERY configuration, enabled or not, and reads nothing — a disabled
/// store still causes no environment lookup, which is what keeps the
/// secret-free parser tests secret-free.
pub(crate) fn validate_adapter_gateway_reference_separation(
    accounts: Option<&AccountsConfig>,
    credentials: &[GatewayCredential<'_>],
) -> Result<(), AccountsConfigError> {
    let Some(accounts) = accounts else {
        return Ok(());
    };
    adapters::validate_no_gateway_reference_alias(&accounts.adapters, credentials)
}

/// Material gateway separation: no adapter secret resolves to a gateway
/// credential's bytes.
///
/// Deliberately gated on `enabled`, mirroring [`resolve`]: material is compared
/// only where material is being resolved anyway. A disabled store is left with
/// the structural check alone, so nothing downstream may read a passing
/// DISABLED configuration as a validated adapter trust boundary.
pub(crate) fn validate_adapter_gateway_material_separation(
    accounts: Option<&AccountsConfig>,
    overlay: &dyn SecretOverlay,
    credentials: &[GatewayCredential<'_>],
) -> Result<(), AccountsConfigError> {
    let Some(accounts) = accounts else {
        return Ok(());
    };
    if !accounts.enabled {
        return Ok(());
    }
    adapters::validate_no_gateway_material_reuse(&accounts.adapters, overlay, credentials)
}

/// One adapter as a RUNTIME may trust it: the approved fields plus the resolved
/// signing material, produced only by [`resolve_adapter_runtime`].
///
/// No `Debug`, deliberately: `secret` is HMAC signing material and a derived
/// `Debug` would put it in any trace that formats the struct.
#[derive(Clone)]
pub(crate) struct AdapterRuntime {
    pub(crate) installation_id: String,
    pub(crate) header: String,
    pub(crate) issuer: String,
    pub(crate) allowed_api_key_names: Vec<String>,
    pub(crate) max_lifetime_seconds: u64,
    pub(crate) clock_skew_seconds: u64,
    /// Resolved HMAC secret, already length- and separation-checked.
    pub(crate) secret: Vec<u8>,
}

/// Everything a runtime must establish BEFORE an adapter assertion may be
/// trusted, in one call that either yields material or refuses.
///
/// WHY THIS EXISTS RATHER THAN A READ OF [`resolve`]. `resolve` returns
/// [`AccountsConfigError::NotEnabled`] before it resolves anything, and
/// [`validate_adapter_gateway_material_separation`] returns `Ok(())` for a
/// disabled store on purpose. So for `accounts.enabled: false` the load has run
/// the STRUCTURAL half only: no adapter secret was read, no length was checked,
/// and no reuse with a store key or a gateway credential was compared. A runtime
/// that treated "configuration validated" as "adapter trusted" would verify
/// signatures with material nothing ever checked. The adapter list is a gateway
/// IDENTITY path and is not gated on custody being open, so the material half
/// runs here, for enabled and disabled blocks alike, and a failure is a refusal
/// rather than a downgrade.
///
/// Store keys are decoded here for the same reason, `enabled` or not: they are
/// the comparison set for the no-reuse rule, and a key that cannot be resolved
/// leaves that rule undecidable — which is a refusal, never a pass.
///
/// Reads nothing when no adapter is configured, so the common deployment causes
/// no environment lookup.
pub(crate) fn resolve_adapter_runtime(
    accounts: Option<&AccountsConfig>,
    overlay: &dyn SecretOverlay,
    credentials: &[GatewayCredential<'_>],
) -> Result<Vec<AdapterRuntime>, AccountsConfigError> {
    let Some(accounts) = accounts else {
        return Ok(Vec::new());
    };
    if accounts.adapters.is_empty() {
        return Ok(Vec::new());
    }
    if accounts.schema_version != SCHEMA_VERSION {
        return Err(AccountsConfigError::SchemaVersion);
    }
    if accounts.deployment != DEPLOYMENT {
        return Err(AccountsConfigError::Deployment);
    }

    // Structure before material, and both halves of gateway separation before
    // any adapter secret is handed out.
    adapters::validate(&accounts.adapters)?;
    adapters::validate_no_gateway_reference_alias(&accounts.adapters, credentials)?;
    adapters::validate_no_gateway_material_reuse(&accounts.adapters, overlay, credentials)?;

    let mut keys = BTreeMap::new();
    for (key_id, reference) in &accounts.keys {
        let variable = reference.strip_prefix("env:").ok_or_else(|| {
            AccountsConfigError::KeyNotAReference {
                key_id: key_id.clone(),
            }
        })?;
        let encoded = overlay.resolve(variable).ok_or_else(|| {
            AccountsConfigError::KeyReferenceUnresolved {
                key_id: key_id.clone(),
                variable: variable.to_string(),
            }
        })?;
        keys.insert(key_id.clone(), decode_key(key_id, &encoded)?);
    }

    let secrets = adapters::resolve_runtime_secrets(&accounts.adapters, overlay, &keys)?;
    Ok(accounts
        .adapters
        .iter()
        .zip(secrets)
        .map(|(adapter, secret)| AdapterRuntime {
            installation_id: adapter.installation_id.clone(),
            header: adapter.header.clone(),
            issuer: adapter.issuer.clone(),
            allowed_api_key_names: adapter.allowed_api_key_names.clone(),
            max_lifetime_seconds: adapter.max_lifetime_seconds,
            clock_skew_seconds: adapter.clock_skew_seconds,
            secret,
        })
        .collect())
}

/// The configured assertion headers, as TEXT, with no material resolved.
///
/// What a refusing runtime needs: when material cannot be trusted the adapter
/// must not verify anything, but it must still recognise — and refuse — the
/// headers the operator configured, instead of letting them fall through
/// unexamined to a handler.
pub(crate) fn adapter_header_names(accounts: Option<&AccountsConfig>) -> Vec<String> {
    accounts.map_or_else(Vec::new, |accounts| {
        accounts
            .adapters
            .iter()
            .map(|adapter| adapter.header.clone())
            .collect()
    })
}

/// The `accounts` block as configured. Unknown fields reject startup.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccountsConfig {
    /// Required literal `accounts.v1`.
    pub(crate) schema_version: String,
    /// Default false; required true for any `personal_managed` descriptor.
    #[serde(default)]
    pub(crate) enabled: bool,
    /// Literal `single_process` for managed custody, explicitly set.
    pub(crate) deployment: String,
    pub(crate) instance_id: String,
    pub(crate) store_dir: PathBuf,
    pub(crate) authority_dir: PathBuf,
    /// Nonempty key id, required present in `keys`.
    pub(crate) current_key_id: String,
    /// key id -> `env:VARIABLE` reference resolving to base64 of exactly 32 bytes.
    pub(crate) keys: BTreeMap<String, String>,
    /// Configured account id -> descriptor. The map key is the logical
    /// `backend_id` of the account key (approved table, row 422).
    ///
    /// Absent stays absent through a rewrite: an explicitly disabled store-only
    /// block must not grow a `descriptors: null` line it never carried.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) descriptors: Option<BTreeMap<String, AccountDescriptor>>,
    #[serde(default)]
    pub(crate) limits: AccountsLimits,
    /// Explicit adapter list, default empty (approved table, `accounts.adapters`).
    ///
    /// Always serialized, unlike `descriptors`: an operator who wrote
    /// `adapters: []` and one who omitted the line are running the SAME
    /// configuration — no adapter — and a rewrite may state that plainly. What a
    /// rewrite must never do is drop a configured entry, which is why this is a
    /// carried `Vec` rather than a parsed-and-forgotten field.
    #[serde(default)]
    pub(crate) adapters: Vec<AdapterConfig>,
}

/// Exactly the three declared spellings (approved table, row 423). A mode is
/// never inferred from exposure, user count or which other fields are present.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum DescriptorMode {
    Shared,
    External,
    PersonalManaged,
}

/// One configured account descriptor, as written.
///
/// STRINGS STAY STRINGS. Endpoint, issuer and resource values are carried
/// byte-for-byte: parsing them into a URL type would normalise
/// `https://accounts.google.com` into `https://accounts.google.com/`, and the
/// later authenticated-metadata check compares the CONFIGURED string with the
/// metadata field exactly (approved table, rows 425-426). A value silently
/// rewritten here cannot be compared honestly there.
///
/// Only `mode` and `provider` are structurally required. Everything else is
/// optional at the schema and required by MODE, because the fields a
/// `personal_managed` descriptor must carry are not the fields a `shared` or
/// `external` one must. `send_resource_parameter` is `Option<bool>` for the
/// same reason a plain `bool` would be wrong: `false` is a real answer for
/// Google REST, and a defaulted `false` would make "declared false" and "not
/// declared" indistinguishable.
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct AccountDescriptor {
    pub(crate) mode: DescriptorMode,
    /// Logical OAuth provider id. Does not itself select a token: two
    /// descriptors may share `google` and remain distinct accounts.
    pub(crate) provider: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) resource: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) issuer: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) authorization_endpoint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) token_endpoint: Option<String>,
    /// Optional only when unused, never caller-supplied.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) revocation_endpoint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) client_id: Option<String>,
    /// `env:VARIABLE` only, resolved nowhere near `Config`: the reference stays
    /// a reference so no client secret is materialised into a serialized or
    /// `Debug`-rendered configuration.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) client_secret_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) redirect_uri: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) scopes: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) send_resource_parameter: Option<bool>,
    /// How an `external` descriptor mints its credential: the EXISTING
    /// [`IdentityPropagationConfig`], carried verbatim so the endpoint,
    /// audience and session rules that type already enforces are the same ones
    /// here. Required on `external`, forbidden on every other mode — `vault` is
    /// what `personal_managed` COMPILES to, never something a descriptor asks
    /// for, and `passthrough` mints nothing at all.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) external_strategy: Option<IdentityPropagationConfig>,
}

/// Only the two bounds this slice maps onto `StoreConfig`. The other limit
/// fields in the approved table belong to journeys and catalogues and are not
/// invented here.
///
/// BOTH ARE "reject zero/overflow" (approved configuration table, design doc
/// row 432). The overflow half is not an invented ceiling: `storage.rs`'s
/// `validate_config` refuses a store whose
/// `max_authority_bytes.checked_add(16).and_then(|size| size.checked_mul(4))`
/// overflows, so the largest accepted `authority_bytes` is `(usize::MAX/4)-16`.
/// The numbers named on each field below are the approved DEFAULTS, not bounds.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct AccountsLimits {
    /// Default 10000 -> `StoreConfig::max_entries`. Zero and overflow reject.
    pub(crate) store_entries: usize,
    /// Default 16777216 -> `StoreConfig::max_authority_bytes`. Zero rejects, and
    /// so does any value the storage sealing arithmetic above cannot carry.
    pub(crate) authority_bytes: usize,
}

impl Default for AccountsLimits {
    fn default() -> Self {
        Self {
            store_entries: 10000,
            authority_bytes: 16_777_216,
        }
    }
}

/// Why a configuration is refused. Carries no secret material: a variant that
/// echoed a resolved key would put it in every log line that renders the error.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub(crate) enum AccountsConfigError {
    #[error("accounts configuration resolution is not implemented")]
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "per-user OAuth scaffolding, deferred to post-4.0.0 backlog MIK-6744/6745/6746"
        )
    )]
    RuntimeNotImplemented,
    #[error("accounts.schema_version must be the literal accounts.v1")]
    SchemaVersion,
    #[error("accounts.deployment must be the literal single_process for managed custody")]
    Deployment,
    #[error("accounts.enabled must be true for a personal_managed descriptor")]
    NotEnabled,
    #[error("accounts.instance_id must be nonempty")]
    InstanceId,
    #[error("accounts.{field} must be an absolute path with no symlink alias")]
    Directory { field: &'static str },
    #[error("accounts.store_dir and accounts.authority_dir must resolve to disjoint paths")]
    DirectoriesNotDisjoint,
    #[error("accounts.current_key_id is absent from accounts.keys")]
    CurrentKeyMissing,
    /// Named by key id only. The value is never part of the message.
    #[error("accounts.keys[{key_id}] must be an env: reference")]
    KeyNotAReference { key_id: String },
    #[error("accounts.keys[{key_id}] reference {variable} is unresolved")]
    KeyReferenceUnresolved { key_id: String, variable: String },
    #[error("accounts.keys[{key_id}] must decode to exactly 32 bytes")]
    KeyMaterial { key_id: String },
    #[error("accounts.limits.{field} must be a positive integer within bounds")]
    Limit { field: &'static str },
    #[error("accounts contains unknown field {field}")]
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "per-user OAuth scaffolding, deferred to post-4.0.0 backlog MIK-6744/6745/6746"
        )
    )]
    UnknownField { field: String },
    /// Named by account id and by what is wrong with it. `problem` is a fixed
    /// phrase, never a configured value: an echoed `client_secret_ref` would
    /// put a secret reference — and one day a mistyped literal secret — into
    /// the log line reporting the refusal.
    #[error("accounts.descriptors[{account_id}]: {problem}")]
    Descriptor {
        account_id: String,
        problem: &'static str,
    },
    /// The existing `IdentityPropagationConfig::validate` refusal for an
    /// `external_strategy` block, quoted rather than re-worded: that validator
    /// owns the audience/endpoint/session rules and its wording is what
    /// operators already see for a backend-level `identity_propagation`.
    /// Its messages name configuration shapes, never configured values.
    #[error("accounts.descriptors[{account_id}]: external_strategy is invalid: {problem}")]
    DescriptorStrategy { account_id: String, problem: String },
    /// One adapter entry, named by list position and by a FIXED phrase. The
    /// phrase is `&'static str` for the same reason `Descriptor::problem` is: a
    /// message that echoed the configured value would one day print an
    /// `hmac_secret_ref` that an operator mistyped as a literal secret.
    #[error("accounts.adapters[{index}]: {problem}")]
    Adapter { index: usize, problem: &'static str },
    /// The installation id IS echoed here, and only here: it is an operator
    /// label rather than credential material, and a duplicate is unactionable
    /// without knowing which one collided.
    #[error(
        "accounts.adapters: duplicate installation_id {installation_id}; each adapter \
         installation_id must be unique"
    )]
    AdapterDuplicateInstallation { installation_id: String },
    /// Names the variable, never its value — the same shape as
    /// `KeyReferenceUnresolved`.
    #[error("accounts.adapters[{index}] hmac_secret_ref reference {variable} is unresolved")]
    AdapterSecretUnresolved { index: usize, variable: String },
    #[error("accounts.adapters[{index}]: hmac_secret_ref must resolve to at least 32 secret bytes")]
    AdapterSecretTooShort { index: usize },
    #[error(
        "accounts.adapters[{index}]: hmac_secret_ref must not reuse another adapter's secret or \
         an accounts.keys store key"
    )]
    AdapterSecretReuse { index: usize },
    /// The other half of the approved reuse rule. `credential` is built from a
    /// FIXED field path plus, at most, the operator's own `name` label for an
    /// api key: a configuration coordinate, so that a refusal is actionable
    /// without a value ever being rendered. No resolved byte, no variable value
    /// and no literal credential reaches this message.
    #[error(
        "accounts.adapters[{index}]: hmac_secret_ref must not reuse gateway authentication \
         material ({credential}); adapter signing and gateway authentication are separate trust \
         domains"
    )]
    AdapterSecretReusesGatewayAuth { index: usize, credential: String },
}

/// `StoreConfig` itself carries raw key bytes and deliberately has no `Debug`,
/// so this wrapper cannot derive one either: it renders key IDs and never
/// values. Anything that reaches a log line goes through here.
#[derive(Clone)]
pub(crate) struct ResolvedAccounts {
    pub(crate) store: StoreConfig,
    /// Environment variable names looked up, in sorted order. Names only.
    pub(crate) secret_refs_read: Vec<String>,
}

impl std::fmt::Debug for ResolvedAccounts {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ResolvedAccounts")
            .field("instance_id", &self.store.instance_id)
            .field("current_key_id", &self.store.current_key_id)
            .field("key_ids", &self.store.keys.keys().collect::<Vec<_>>())
            .field("secret_refs_read", &self.secret_refs_read)
            .finish_non_exhaustive()
    }
}

/// Resolve the block into a `StoreConfig`, or `Ok(None)` when `accounts` is
/// omitted.
///
/// Structure is validated BEFORE any secret is read, so a malformed block never
/// causes an environment lookup. Key material is read last, once per declared
/// reference, in key-id order.
pub(crate) fn resolve(
    accounts: Option<&AccountsConfig>,
    overlay: &dyn SecretOverlay,
) -> Result<Option<ResolvedAccounts>, AccountsConfigError> {
    // Omitted `accounts` preserves existing behaviour and enables no managed
    // custody. Nothing is read, because nothing is configured.
    let Some(accounts) = accounts else {
        return Ok(None);
    };

    if accounts.schema_version != SCHEMA_VERSION {
        return Err(AccountsConfigError::SchemaVersion);
    }
    if accounts.deployment != DEPLOYMENT {
        return Err(AccountsConfigError::Deployment);
    }
    if !accounts.enabled {
        return Err(AccountsConfigError::NotEnabled);
    }
    if accounts.instance_id.is_empty() {
        return Err(AccountsConfigError::InstanceId);
    }

    validate_directory("store_dir", &accounts.store_dir)?;
    validate_directory("authority_dir", &accounts.authority_dir)?;
    // Same volume is allowed; the resolved paths must be neither equal nor
    // nested either way, so a token snapshot replacement cannot reach the
    // manifest and lock directory.
    if accounts.store_dir.starts_with(&accounts.authority_dir)
        || accounts.authority_dir.starts_with(&accounts.store_dir)
    {
        return Err(AccountsConfigError::DirectoriesNotDisjoint);
    }

    validate_limit("store_entries", accounts.limits.store_entries)?;
    validate_limit("authority_bytes", accounts.limits.authority_bytes)?;
    // The approved storage bound: `storage::validate_config` refuses a store
    // whose sealed-manifest arithmetic overflows, so a value that cannot carry
    // it is rejected here rather than at open time.
    if accounts
        .limits
        .authority_bytes
        .checked_add(16)
        .and_then(|size| size.checked_mul(4))
        .is_none()
    {
        return Err(AccountsConfigError::Limit {
            field: "authority_bytes",
        });
    }

    // Structure before material, here too: `resolve` is also reached directly
    // from custody bootstrap, which does not go through `validate_adapters`.
    // Re-checking is cheap and reads nothing.
    adapters::validate(&accounts.adapters)?;

    if !accounts.keys.contains_key(&accounts.current_key_id) {
        return Err(AccountsConfigError::CurrentKeyMissing);
    }

    // Reject malformed references anywhere in the block before resolving any
    // secret. A later invalid key must not cause an earlier environment read.
    for (key_id, reference) in &accounts.keys {
        if !reference.starts_with("env:") {
            return Err(AccountsConfigError::KeyNotAReference {
                key_id: key_id.clone(),
            });
        }
    }

    let mut keys = BTreeMap::new();
    let mut secret_refs_read = Vec::new();
    for (key_id, reference) in &accounts.keys {
        let variable = reference.strip_prefix("env:").ok_or_else(|| {
            AccountsConfigError::KeyNotAReference {
                key_id: key_id.clone(),
            }
        })?;
        secret_refs_read.push(variable.to_string());
        let encoded = overlay.resolve(variable).ok_or_else(|| {
            AccountsConfigError::KeyReferenceUnresolved {
                key_id: key_id.clone(),
                variable: variable.to_string(),
            }
        })?;
        let material = decode_key(key_id, &encoded)?;
        keys.insert(key_id.clone(), material);
    }
    secret_refs_read.extend(adapters::resolve_secrets(
        &accounts.adapters,
        overlay,
        &keys,
    )?);
    secret_refs_read.sort();
    secret_refs_read.dedup();

    Ok(Some(ResolvedAccounts {
        store: StoreConfig {
            instance_id: accounts.instance_id.clone(),
            store_dir: accounts.store_dir.clone(),
            authority_dir: accounts.authority_dir.clone(),
            current_key_id: accounts.current_key_id.clone(),
            keys,
            max_entries: accounts.limits.store_entries,
            max_authority_bytes: accounts.limits.authority_bytes,
        },
        secret_refs_read,
    }))
}

/// Validate the STATIC shape of `accounts.descriptors`, reading nothing.
///
/// Separate from [`resolve`] on purpose, and called before it. Two reasons,
/// both load-bearing:
///
/// - A `personal_managed` descriptor under `enabled: false` must REFUSE. The
///   caller deliberately swallows [`AccountsConfigError::NotEnabled`] from
///   `resolve`, because an explicitly disabled store-only block is an ordinary
///   configuration; routing the descriptor check through the same call would
///   let the refusal be swallowed with it.
/// - Structure is checked before any account secret is read, so a malformed
///   descriptor never causes an environment lookup.
///
/// Schema version and deployment keep their existing authority: they are
/// checked first here too, so a block that is wrong about both its schema and
/// its descriptors still reports the schema first.
///
/// NO NETWORK, NO CUSTODY. Endpoint strings are checked for shape only.
/// Authenticated issuer-metadata retrieval and the exact endpoint-equality
/// comparison against that metadata are a later increment; an endpoint that
/// merely SPELLS `https://` is not thereby a trusted endpoint.
pub(crate) fn validate_descriptors(
    accounts: Option<&AccountsConfig>,
) -> Result<(), AccountsConfigError> {
    let Some(accounts) = accounts else {
        return Ok(());
    };
    if accounts.schema_version != SCHEMA_VERSION {
        return Err(AccountsConfigError::SchemaVersion);
    }
    if accounts.deployment != DEPLOYMENT {
        return Err(AccountsConfigError::Deployment);
    }
    adapters::validate(&accounts.adapters)?;
    let Some(descriptors) = accounts.descriptors.as_ref() else {
        return Ok(());
    };

    for (account_id, descriptor) in descriptors {
        if account_id.is_empty() {
            return Err(AccountsConfigError::Descriptor {
                account_id: account_id.clone(),
                problem: "account id must be nonempty",
            });
        }
        if descriptor.provider.is_empty() {
            return Err(AccountsConfigError::Descriptor {
                account_id: account_id.clone(),
                problem: "provider must be nonempty",
            });
        }
        match descriptor.mode {
            DescriptorMode::PersonalManaged => {
                if !accounts.enabled {
                    return Err(AccountsConfigError::NotEnabled);
                }
                validate_managed(account_id, descriptor)?;
                forbid_external_strategy(account_id, descriptor)?;
            }
            DescriptorMode::External => validate_external(account_id, descriptor)?,
            DescriptorMode::Shared => forbid_external_strategy(account_id, descriptor)?,
        }
    }
    Ok(())
}

/// `external` mode carries the EXISTING `IdentityPropagationConfig`, and only
/// the two strategies that actually MINT an external credential are accepted
/// there.
///
/// `vault` is refused by name rather than by omission: it is the compilation
/// target of `personal_managed`, so a descriptor asking for it is asking the
/// external path to serve a managed account's custody, which it cannot. And
/// `passthrough` mints nothing — the caller supplies its own credential — so it
/// is not an external minting strategy either. Everything else about the block
/// (audience, token-exchange endpoint, session mode) is validated by the
/// existing `IdentityPropagationConfig::validate`, not re-implemented here.
fn validate_external(
    account_id: &str,
    descriptor: &AccountDescriptor,
) -> Result<(), AccountsConfigError> {
    let strategy =
        descriptor
            .external_strategy
            .as_ref()
            .ok_or_else(|| AccountsConfigError::Descriptor {
                account_id: account_id.to_string(),
                problem: "mode external requires an external_strategy block",
            })?;
    if !matches!(
        strategy.strategy,
        PropagationStrategyKind::SignedAssertion | PropagationStrategyKind::TokenExchange
    ) {
        return Err(AccountsConfigError::Descriptor {
            account_id: account_id.to_string(),
            problem: "external_strategy accepts only signed_assertion or token_exchange",
        });
    }
    if !strategy.required {
        return Err(AccountsConfigError::Descriptor {
            account_id: account_id.to_string(),
            problem: "external_strategy must set required: true for an account-bound external descriptor",
        });
    }
    strategy
        .validate()
        .map_err(|error| AccountsConfigError::DescriptorStrategy {
            account_id: account_id.to_string(),
            problem: error.to_string(),
        })
}

/// `external_strategy` on a non-external descriptor is a mode the operator did
/// not declare. A `shared` account mints nothing, and a `personal_managed` one
/// compiles to vault custody; honouring a strategy block on either would run a
/// backend under a trust model its `mode` line does not name.
fn forbid_external_strategy(
    account_id: &str,
    descriptor: &AccountDescriptor,
) -> Result<(), AccountsConfigError> {
    if descriptor.external_strategy.is_some() {
        return Err(AccountsConfigError::Descriptor {
            account_id: account_id.to_string(),
            problem: "external_strategy is valid only on mode external",
        });
    }
    Ok(())
}

/// The fields a `personal_managed` descriptor must carry (approved table, rows
/// 424-428). Every check is on the configured value as written.
fn validate_managed(
    account_id: &str,
    descriptor: &AccountDescriptor,
) -> Result<(), AccountsConfigError> {
    let fail = |problem: &'static str| AccountsConfigError::Descriptor {
        account_id: account_id.to_string(),
        problem,
    };

    // Parsed, never rewritten: the configured String is what gets sent. A
    // prefix test accepts "https://", which has no host to reach.
    let https_host = |value: &Option<String>| {
        value.as_ref().is_some_and(|value| {
            Url::parse(value).is_ok_and(|url| url.scheme() == "https" && url.has_host())
        })
    };

    // RFC 8707 resource is an absolute URI, not necessarily https: a urn: is
    // a legitimate resource identifier.
    if descriptor
        .resource
        .as_ref()
        .is_none_or(|value| Url::parse(value).is_err())
    {
        return Err(fail("resource must be present and nonempty"));
    }
    if !https_host(&descriptor.issuer) {
        return Err(fail("issuer must be present and nonempty"));
    }
    if descriptor
        .client_id
        .as_ref()
        .is_none_or(std::string::String::is_empty)
    {
        return Err(fail("client_id must be present and nonempty"));
    }

    for (value, problem) in [
        (
            &descriptor.authorization_endpoint,
            "authorization_endpoint must be present and https",
        ),
        (
            &descriptor.token_endpoint,
            "token_endpoint must be present and https",
        ),
        (
            &descriptor.redirect_uri,
            "redirect_uri must be present and an https callback",
        ),
    ] {
        if !https_host(value) {
            return Err(fail(problem));
        }
    }

    // Optional, per the table — but a configured one is still an endpoint.
    if descriptor.revocation_endpoint.is_some() && !https_host(&descriptor.revocation_endpoint) {
        return Err(fail("revocation_endpoint must be https when configured"));
    }
    // Optional, and a reference or nothing. A literal here is a client secret
    // in a file that gets copied, diffed and pasted.
    if descriptor
        .client_secret_ref
        .as_ref()
        .is_some_and(|value| !value.starts_with("env:"))
    {
        return Err(fail("client_secret_ref must be an env: reference"));
    }
    // Absence is the failure; `false` is a valid declaration (Google REST takes
    // no RFC 8707 resource parameter) and must not be reachable by omission.
    if descriptor.send_resource_parameter.is_none() {
        return Err(fail("send_resource_parameter must be declared explicitly"));
    }

    let scopes = descriptor
        .scopes
        .as_ref()
        .ok_or_else(|| fail("scopes must be present"))?;
    if scopes.is_empty() || scopes.iter().any(String::is_empty) {
        return Err(fail("scopes must be a nonempty list of nonempty scopes"));
    }
    // Refused, not silently deduplicated: a repeated scope is a configuration
    // the operator did not mean, and quietly fixing it hides the typo.
    if scopes.iter().collect::<BTreeSet<_>>().len() != scopes.len() {
        return Err(fail("scopes must not repeat"));
    }
    Ok(())
}

const SCHEMA_VERSION: &str = "accounts.v1";
const DEPLOYMENT: &str = "single_process";
use url::Url;
const KEY_BYTES: usize = 32;

fn validate_directory(
    field: &'static str,
    path: &std::path::Path,
) -> Result<(), AccountsConfigError> {
    if !path.is_absolute() {
        return Err(AccountsConfigError::Directory { field });
    }
    // A `..` component can alias out of the configured tree even when the
    // string is absolute, so it is refused with the same category.
    if path
        .components()
        .any(|part| matches!(part, std::path::Component::ParentDir))
    {
        return Err(AccountsConfigError::Directory { field });
    }
    Ok(())
}

fn validate_limit(field: &'static str, value: usize) -> Result<(), AccountsConfigError> {
    if value == 0 {
        return Err(AccountsConfigError::Limit { field });
    }
    Ok(())
}

/// Decode one reference's material. The value never appears in the error: a
/// message that echoed it would put a live key in the log line reporting the
/// failure.
fn decode_key(key_id: &str, encoded: &str) -> Result<Vec<u8>, AccountsConfigError> {
    use base64::Engine as _;

    let material = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .map_err(|_| AccountsConfigError::KeyMaterial {
            key_id: key_id.to_string(),
        })?;
    if material.len() != KEY_BYTES {
        return Err(AccountsConfigError::KeyMaterial {
            key_id: key_id.to_string(),
        });
    }
    Ok(material)
}

/// The existing overlay contract, narrowed to what this slice needs: a name in,
/// an optional value out. Implemented by `config::EnvOverlay` in production and
/// by a counting fake in tests.
pub(crate) trait SecretOverlay {
    fn resolve(&self, name: &str) -> Option<String>;
}

#[cfg(test)]
#[path = "config_tests.rs"]
mod config_tests;

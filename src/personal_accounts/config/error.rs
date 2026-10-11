// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Why an accounts configuration is refused.

/// Why a configuration is refused. Carries no secret material: a variant that
/// echoed a resolved key would put it in every log line that renders the error.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub(crate) enum AccountsConfigError {
    #[error("accounts configuration resolution is not implemented")]
    #[expect(
        dead_code,
        reason = "per-user OAuth scaffolding, deferred to post-4.0.0 backlog MIK-6744/6745/6746"
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
    #[error("accounts.keys[{key_id}] must be an env: or file: reference")]
    KeyNotAReference { key_id: String },
    #[error("accounts.keys[{key_id}] reference {variable} is unresolved")]
    KeyReferenceUnresolved { key_id: String, variable: String },
    /// A `file:` secret that could not be read or was refused (C9). The
    /// message names the field and path, never the content.
    #[error("{0}")]
    SecretFile(String),
    #[error("accounts.keys[{key_id}] must decode to exactly 32 bytes")]
    KeyMaterial { key_id: String },
    #[error("accounts.limits.{field} must be a positive integer within bounds")]
    Limit { field: &'static str },
    #[error("accounts contains unknown field {field}")]
    #[expect(
        dead_code,
        reason = "per-user OAuth scaffolding, deferred to post-4.0.0 backlog MIK-6744/6745/6746"
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
    /// A fixed phrase, like `Adapter::problem`: never a configured value.
    #[error("accounts.hosted: {problem}")]
    Hosted { problem: &'static str },
}

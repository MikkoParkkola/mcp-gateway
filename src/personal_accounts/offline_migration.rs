// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-6744.STORE.1 — the offline entry point for `accounts migrate-credentials`.
//!
//! The sibling of `initialize_store_offline` and deliberately the same shape:
//! it selects a configuration, resolves it through the existing loader so
//! `env_files` are honoured exactly as at startup, and performs one offline
//! operation. Nothing here launches a gateway, starts the custody worker,
//! builds an HTTP client or reaches the network.
//!
//! THE TWO OFFLINE COMMANDS DO NOT OVERLAP. `init-store` may CREATE a store and
//! refuses if either root holds anything. This one may never create one: it
//! opens an existing store, because migrating into a store nobody asked for
//! would be custody state with no opener, which is the concern
//! `OfflineInitError::NotConfigured` already names.

use super::{PersonalAccountStore, config, identity, storage};

/// What one backend's migration did, for an operator-facing report.
///
/// Names and paths only. No credential material, no account identity and no
/// key bytes reach this type, the way `InitializedStore` carries none.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MigratedCredential {
    /// The `accounts.descriptors` map key that was migrated.
    pub descriptor_id: String,
    /// The 3.x file the grant came from, as its basename.
    pub source: String,
    /// False when the account already held a grant, so the guarded commit
    /// fenced without writing. A re-run reports this rather than failing.
    pub written: bool,
}

/// Why an offline migration was refused.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum OfflineMigrationError {
    /// The configuration declares no `accounts` block, so there is no store.
    #[error("configuration declares no accounts block; there is no store to migrate into")]
    NotConfigured,
    /// The `accounts` block is invalid, or a key reference did not resolve.
    #[error("accounts configuration refused: {0}")]
    Configuration(String),
    /// No `personal_managed` descriptor carries the requested map key.
    #[error("no personal_managed account descriptor is declared with id `{0}`")]
    NoSuchDescriptor(String),
    /// The store could not be opened. It must already exist: this command
    /// never creates one, which stays `init-store`'s alone.
    #[error("accounts store could not be opened: {0}")]
    StoreUnavailable(String),
    /// The backend was refused, with the reason a user can act on.
    #[error("{0}")]
    Refused(String),
}

/// Migrate one 3.x credential into an ALREADY-INITIALIZED store.
///
/// OFFLINE AND EXPLICIT, the same category as `initialize_store_offline`, and
/// never reached by daemon startup. Nothing here launches a gateway, starts the
/// custody worker, builds an HTTP client or reaches the network: it opens the
/// configured store, reads one 3.x file and performs one guarded write.
///
/// THE 3.X SOURCE IS NEVER WRITTEN, and this command never creates a store.
/// A refusal leaves the deployment exactly where it started.
pub fn migrate_legacy_credential_offline(
    gateway_config: &crate::config::Config,
    overlay: &crate::config::EnvOverlay,
    descriptor_id: &str,
    legacy_issuer: &str,
    legacy_backend_name: Option<&str>,
) -> Result<MigratedCredential, OfflineMigrationError> {
    let declared = gateway_config
        .accounts
        .as_ref()
        .ok_or(OfflineMigrationError::NotConfigured)?;
    let descriptor = declared
        .descriptors
        .as_ref()
        .and_then(|declared| declared.get(descriptor_id))
        .filter(|descriptor| matches!(descriptor.mode, config::DescriptorMode::PersonalManaged))
        .ok_or_else(|| OfflineMigrationError::NoSuchDescriptor(descriptor_id.to_owned()))?
        .clone();
    // `resource` and `issuer` are mandatory for `personal_managed` and are
    // validated at load, so their absence here is a configuration fault rather
    // than a migration one.
    let (Some(resource), Some(issuer)) = (descriptor.resource.clone(), descriptor.issuer.clone())
    else {
        return Err(OfflineMigrationError::Configuration(format!(
            "descriptor `{descriptor_id}` declares no resource or issuer"
        )));
    };
    let key_descriptor = identity::AccountDescriptor {
        descriptor_id: descriptor_id.to_owned(),
        provider: descriptor.provider.clone(),
        resource,
        issuer,
    };

    let resolved = config::resolve(gateway_config.accounts.as_ref(), overlay)
        .map_err(|error| OfflineMigrationError::Configuration(error.to_string()))?
        .ok_or(OfflineMigrationError::NotConfigured)?;
    // `open`, never `initialize`: creating a store is `init-store`'s alone, and
    // a migration into a store nobody asked for would be custody state with no
    // opener.
    let store = PersonalAccountStore::open(resolved.store)
        .map_err(|error| OfflineMigrationError::StoreUnavailable(error.to_string()))?;

    let legacy = crate::oauth::TokenStorage::default_location()
        .map_err(|error| OfflineMigrationError::StoreUnavailable(error.to_string()))?;
    let registered = legacy.load_client_id(descriptor_id, &key_descriptor.resource);
    let request = storage::migration_entry::MigrationRequest {
        key_descriptor: &key_descriptor,
        descriptor: &descriptor,
        // The registry name the 3.x file was hashed over. Derived rather than
        // declared: the descriptor id is what a caller names, and a backend
        // renamed since 3.x is the only case needing the override.
        bound_backend: descriptor_id,
        legacy_backend_name,
        legacy_issuer,
        registered_client_id: registered.as_deref(),
    };
    let source = legacy
        .token_path(
            legacy_backend_name.unwrap_or(descriptor_id),
            &key_descriptor.resource,
        )
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or_default()
        .to_owned();

    match storage::migration_entry::migrate_backend(&store, &legacy, &request) {
        Ok(outcome) => Ok(MigratedCredential {
            descriptor_id: descriptor_id.to_owned(),
            source,
            written: outcome == storage::migration_entry::MigrationOutcome::Migrated,
        }),
        Err(refusal) => Err(OfflineMigrationError::Refused(refusal.to_string())),
    }
}

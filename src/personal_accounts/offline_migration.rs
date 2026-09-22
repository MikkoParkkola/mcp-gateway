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
    /// No backend in the registry names this descriptor.
    ///
    /// Without a bound backend there is no registry name, and so no way to say
    /// which 3.x file belongs to this descriptor.
    #[error(
        "no backend is configured against descriptor `{0}`, so no 3.x credential \
         file can be resolved for it; bind a backend to the descriptor, or pass \
         `--legacy-backend-name NAME`"
    )]
    NoBoundBackend(String),
    /// Several backends name this descriptor, each with its own 3.x file.
    #[error(
        "descriptor `{descriptor_id}` is named by {count} backends, and each has \
         its own 3.x credential file; pass `--legacy-backend-name NAME` to say \
         which one to migrate"
    )]
    AmbiguousBackend {
        /// The descriptor more than one backend names.
        descriptor_id: String,
        /// How many backends name it. The names are not carried: the count is
        /// what makes the refusal actionable, and the caller reads its own
        /// configuration to choose between them.
        count: usize,
    },
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
    // The one line a test cannot exercise without moving `HOME`, which is
    // process-global and unsafe in a parallel suite. Everything past it takes
    // the 3.x store as an argument and IS tested.
    let legacy = crate::oauth::TokenStorage::default_location()
        .map_err(|error| OfflineMigrationError::StoreUnavailable(error.to_string()))?;
    migrate_from(
        gateway_config,
        overlay,
        &legacy,
        descriptor_id,
        legacy_issuer,
        legacy_backend_name,
    )
}

/// Which BACKEND REGISTRY NAME the 3.x credential file was hashed over.
///
/// THE REGISTRY NAME AND THE DESCRIPTOR ID ARE DIFFERENT NAMESPACES, and
/// confusing them is not a lookup miss, it is a wrong-credential migration.
/// `backends` is the registry map; a backend's `account` field names an
/// `accounts.descriptors` MAP KEY. A backend registered as `gdrive` may name
/// descriptor `workspace-personal`, and nothing stops some OTHER backend being
/// registered under the name `workspace-personal`. Resolving the file by
/// descriptor id therefore finds that other backend's credential and migrates
/// it under a plausible success message -- silent, wrong, and with no thread
/// for the user to pull. That is the worst outcome this row can produce.
///
/// Derived rather than declared, because asking a caller to restate a fact the
/// compiled binding already holds creates a second source of truth whose
/// disagreement with reality is silent. The override exists for the one case
/// nothing records: a backend renamed since 3.x.
fn resolve_legacy_backend_name(
    gateway_config: &crate::config::Config,
    descriptor_id: &str,
    override_name: Option<&str>,
) -> Result<String, OfflineMigrationError> {
    if let Some(name) = override_name {
        return Ok(name.to_owned());
    }
    let bound = crate::config::account_bindings::compile(gateway_config)
        .map_err(|error| OfflineMigrationError::Configuration(error.to_string()))?;
    let mut named: Vec<String> = bound
        .into_iter()
        .filter(|(_, binding)| binding.descriptor_id == descriptor_id)
        .map(|(name, _)| name)
        .collect();
    match named.len() {
        1 => Ok(named.remove(0)),
        0 => Err(OfflineMigrationError::NoBoundBackend(
            descriptor_id.to_owned(),
        )),
        // Two backends sharing one descriptor is legal, and they have
        // different 3.x files. Guessing between them is the wrong-credential
        // outcome above, so the caller says which.
        count => Err(OfflineMigrationError::AmbiguousBackend {
            descriptor_id: descriptor_id.to_owned(),
            count,
        }),
    }
}

fn migrate_from(
    gateway_config: &crate::config::Config,
    overlay: &crate::config::EnvOverlay,
    legacy: &crate::oauth::TokenStorage,
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

    let backend_name =
        resolve_legacy_backend_name(gateway_config, descriptor_id, legacy_backend_name)?;
    let registered = legacy.load_client_id(&backend_name, &key_descriptor.resource);
    let request = storage::migration_entry::MigrationRequest {
        key_descriptor: &key_descriptor,
        descriptor: &descriptor,
        // The already-resolved registry name, override included, so the inner
        // entry point cannot derive a second and different one.
        bound_backend: &backend_name,
        legacy_backend_name: None,
        legacy_issuer,
        registered_client_id: registered.as_deref(),
    };
    let source = legacy
        .token_path(&backend_name, &key_descriptor.resource)
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or_default()
        .to_owned();

    match storage::migration_entry::migrate_backend(&store, legacy, &request) {
        Ok(outcome) => Ok(MigratedCredential {
            descriptor_id: descriptor_id.to_owned(),
            source,
            written: outcome == storage::migration_entry::MigrationOutcome::Migrated,
        }),
        Err(refusal) => Err(OfflineMigrationError::Refused(refusal.to_string())),
    }
}

#[cfg(test)]
#[path = "offline_migration_tests.rs"]
mod offline_migration_tests;

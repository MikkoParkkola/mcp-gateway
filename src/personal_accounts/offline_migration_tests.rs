// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-6744.STORE.1 — the offline entry point, through a real configuration.
//!
//! WHY THESE EXIST SEPARATELY FROM THE `migrate_backend` FIXTURES. Those hand
//! the entry point a `MigrationRequest` already built, so they cannot see a
//! defect in how that request is ASSEMBLED from configuration. The assembly is
//! where the two namespaces meet: `backends` is a registry map, and a backend's
//! `account` field names an `accounts.descriptors` MAP KEY. They are different
//! names for different things, and a backend may legally be registered under a
//! name that is also some descriptor's key.
//!
//! Every fixture below therefore uses a descriptor id and a backend registry
//! name that DIFFER. A suite where they coincide cannot distinguish the two,
//! and would certify a migration that resolves the wrong file.

use std::path::Path;

use super::{OfflineMigrationError, migrate_from};
use std::sync::Arc;

use crate::config::{Config, EnvOverlay};
use crate::oauth::TokenStorage;

const RESOURCE: &str = "https://mcp.example.test/v1/mcp";
const ISSUER: &str = "https://auth.example.test";
/// 2100-01-01, so a seeded grant is unexpired whenever this runs.
const FAR_FUTURE: u64 = 4_102_444_800;

/// A config whose backend registry name and descriptor id are deliberately
/// different, plus any extra backends the case needs.
fn config_yaml(root: &Path, extra_backends: &str) -> String {
    // Canonical, because the store refuses a path with non-normal components
    // and a macOS temp directory reaches it through a symlink.
    let root = root.canonicalize().expect("fixture root exists");
    let root = root.display();
    format!(
        "env_files:\n  - {root}/accounts.env\n\
backends:\n\
\x20 gdrive:\n\
\x20   http_url: https://mcp.example.test/v1/mcp\n\
\x20   account: workspace-personal\n\
{extra_backends}\
accounts:\n\
\x20 schema_version: accounts.v1\n\
\x20 enabled: true\n\
\x20 deployment: single_process\n\
\x20 instance_id: test-instance\n\
\x20 store_dir: {root}/records\n\
\x20 authority_dir: {root}/authority\n\
\x20 current_key_id: current\n\
\x20 keys:\n\
\x20   current: env:ACCOUNTS_KEY\n\
\x20 descriptors:\n\
\x20   workspace-personal:\n\
\x20     mode: personal_managed\n\
\x20     provider: workspace\n\
\x20     resource: {RESOURCE}\n\
\x20     issuer: {ISSUER}\n\
\x20     authorization_endpoint: {ISSUER}/authorize\n\
\x20     token_endpoint: {ISSUER}/token\n\
\x20     redirect_uri: https://app.example.test/callback\n\
\x20     client_id: client-abc\n\
\x20     scopes: [read, write]\n\
\x20     send_resource_parameter: true\n\
\x20 limits:\n\
\x20   store_entries: 1000\n\
\x20   authority_bytes: 16777216\n"
    )
}

/// Literal 3.x token JSON, tagged so a test can tell WHICH backend's credential
/// it is looking at. That tag is the whole point of these cases.
fn legacy_json(tag: &str) -> String {
    format!(
        r#"{{
  "access_token": "{tag}-access-token",
  "token_type": "Bearer",
  "refresh_token": "{tag}-refresh-token",
  "expires_at": {FAR_FUTURE},
  "scope": "read write"
}}"#
    )
}

struct Harness {
    _root: tempfile::TempDir,
    config: Config,
    overlay: Arc<EnvOverlay>,
    legacy: TokenStorage,
}

impl Harness {
    fn new(extra_backends: &str) -> Self {
        use base64::Engine as _;
        let root = tempfile::tempdir().expect("temp dir");
        let key = base64::engine::general_purpose::STANDARD.encode([0x51_u8; 32]);
        std::fs::write(
            root.path().join("accounts.env"),
            format!("ACCOUNTS_KEY={key}\n"),
        )
        .expect("env file");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(
                root.path().join("accounts.env"),
                std::fs::Permissions::from_mode(0o600),
            )
            .expect("chmod env");
        }
        let path = root.path().join("gateway.yaml");
        std::fs::write(&path, config_yaml(root.path(), extra_backends)).expect("config");
        let evaluated = Config::load_evaluated(Some(&path)).expect("the fixture config must load");

        let oauth = root.path().join("oauth");
        std::fs::create_dir_all(&oauth).expect("oauth dir");
        let legacy = TokenStorage::new(oauth).expect("3.x store");

        crate::personal_accounts::PersonalAccountStore::initialize(
            crate::personal_accounts::config::resolve(
                evaluated.config.accounts.as_ref(),
                evaluated.overlay.as_ref(),
            )
            .expect("resolve")
            .expect("accounts configured")
            .store,
        )
        .expect("offline initialization");

        Self {
            _root: root,
            config: evaluated.config,
            overlay: evaluated.overlay,
            legacy,
        }
    }

    /// Seed a 3.x credential under a BACKEND REGISTRY NAME.
    fn seed(&self, backend_name: &str, tag: &str) {
        let path = self.legacy.token_path(backend_name, RESOURCE);
        std::fs::write(&path, legacy_json(tag)).expect("seed");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).expect("chmod");
        }
    }

    fn migrate(
        &self,
        override_name: Option<&str>,
    ) -> Result<super::MigratedCredential, OfflineMigrationError> {
        migrate_from(
            &self.config,
            self.overlay.as_ref(),
            &self.legacy,
            "workspace-personal",
            ISSUER,
            override_name,
        )
    }

    fn stored_access_token(&self) -> Option<String> {
        let key = crate::personal_accounts::identity::AccountDescriptor {
            descriptor_id: "workspace-personal".to_owned(),
            provider: "workspace".to_owned(),
            resource: RESOURCE.to_owned(),
            issuer: ISSUER.to_owned(),
        };
        let account = crate::personal_accounts::identity::account_key(
            Some(crate::personal_accounts::identity::Principal::SoleOperator),
            &key,
        )
        .expect("sole-operator key");
        let settings = crate::personal_accounts::config::resolve(
            self.config.accounts.as_ref(),
            self.overlay.as_ref(),
        )
        .expect("resolve")
        .expect("configured")
        .store;
        let store = crate::personal_accounts::PersonalAccountStore::open(settings)
            .expect("the authority reopens");
        match store.lookup(&account).expect("lookup") {
            crate::personal_accounts::AccountLookup::Connected(record) => Some(record.access_token),
            _ => None,
        }
    }
}

/// THE POSITIVE CONTROL, and it is the case the direct fixtures cannot express:
/// the descriptor id and the backend registry name DIFFER.
///
/// The 3.x file is hashed over `gdrive`, the registry name. A resolver that
/// used the descriptor id would find nothing here.
#[test]
fn the_3_x_file_is_resolved_by_the_bound_backend_registry_name() {
    let harness = Harness::new("");
    harness.seed("gdrive", "gdrive");

    let report = harness
        .migrate(None)
        .expect("the bound backend's credential must migrate");
    assert!(report.written);
    assert_eq!(
        harness.stored_access_token().as_deref(),
        Some("gdrive-access-token"),
        "the grant must carry the BOUND backend's credential"
    );
}

/// THE CRITICAL CASE. A different backend is registered under a name that
/// happens to equal the descriptor id, and it has its own 3.x credential.
///
/// Resolving by descriptor id finds THAT backend's file and migrates someone
/// else's credential under a plausible success message — silent, wrong, and
/// with no thread for the user to pull. The bound backend has no file here, so
/// the only correct outcomes are a refusal or a miss; migrating the decoy is
/// never one of them.
#[test]
fn a_backend_named_like_the_descriptor_never_supplies_the_credential() {
    let extra = "  workspace-personal:\n    command: /bin/true\n";
    let harness = Harness::new(extra);
    // Only the DECOY has a 3.x file. The bound backend `gdrive` has none.
    harness.seed("workspace-personal", "decoy");

    let outcome = harness.migrate(None);

    assert_ne!(
        harness.stored_access_token().as_deref(),
        Some("decoy-access-token"),
        "MIGRATED THE WRONG BACKEND'S CREDENTIAL: resolving the 3.x file by \
         descriptor id instead of by the bound backend registry name attributes \
         one backend's token to another, and reports success while doing it"
    );
    assert!(
        outcome.is_err(),
        "the bound backend has no 3.x file, so this must refuse rather than \
         find someone else's: {outcome:?}"
    );
}

/// The override still works, and it is how a renamed backend is migrated.
#[test]
fn the_override_names_the_file_when_the_backend_was_renamed_since_3_x() {
    let harness = Harness::new("");
    harness.seed("gdrive-in-3x", "renamed");

    let report = harness
        .migrate(Some("gdrive-in-3x"))
        .expect("the override must resolve the former name");
    assert!(report.written);
    assert_eq!(
        harness.stored_access_token().as_deref(),
        Some("renamed-access-token")
    );
}

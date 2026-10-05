// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! `oauth migrate-legacy` rows (design 2026-10-05 §§13-15). Each runs against a
//! private temp token directory and a config loaded the way the CLI loads it.

use std::path::Path;

use super::{LegacyOAuthMigrateError, LegacyOAuthMigration, migrate_in};
use crate::config::Config;
use crate::oauth::TokenStorage;
use crate::oauth::client::storage_key;

const URL: &str = "https://notes.example.test/mcp";
const ISSUER: &str = "https://auth.example.test";
const FAR_FUTURE: u64 = 4_102_444_800;

struct Fixture {
    _root: tempfile::TempDir,
    config: Config,
    storage: TokenStorage,
}

fn private(path: &Path, content: &str) {
    crate::gateway::test_helpers::write_owner_only(path, content).expect("write");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).expect("chmod");
    }
    #[cfg(windows)]
    crate::private_fs::test_support::plant_owner_only("fixture", path);
}

fn fixture(backends: &str) -> Fixture {
    let root = tempfile::tempdir().expect("temp dir");
    let path = root.path().join("gateway.yaml");
    private(&path, &format!("backends:\n{backends}"));
    let config = Config::load_evaluated(Some(&path))
        .expect("fixture config loads")
        .config;
    let oauth = root.path().join("oauth");
    std::fs::create_dir_all(&oauth).expect("oauth dir");
    let storage = TokenStorage::new(oauth).expect("token dir");
    Fixture {
        _root: root,
        config,
        storage,
    }
}

const NOTES: &str =
    "  notes:\n    http_url: https://notes.example.test/mcp\n    oauth:\n      enabled: true\n";

impl Fixture {
    fn seed_token(&self, tag: &str) {
        private(
            &self.storage.token_path("notes", URL),
            &format!(
                r#"{{"access_token":"{tag}-access","token_type":"Bearer","refresh_token":"{tag}-refresh","expires_at":{FAR_FUTURE}}}"#
            ),
        );
    }
    fn seed_client(&self, id: &str) {
        private(
            &self.storage.client_path("notes", URL),
            &format!("\"{id}\""),
        );
    }
    fn key(&self) -> String {
        storage_key("notes", ISSUER)
    }
    fn run(&self, dry_run: bool) -> Result<super::LegacyOAuthMigrated, LegacyOAuthMigrateError> {
        migrate_in(&self.storage, &self.config, &request(dry_run))
    }
}

fn request(dry_run: bool) -> LegacyOAuthMigration<'static> {
    LegacyOAuthMigration {
        backend: "notes",
        issuer: ISSUER,
        legacy_backend_name: None,
        legacy_resource_url: None,
        dry_run,
    }
}

/// The 3.x token and client id land under the asserted issuer's key, where
/// the runtime reads them once discovery returns that issuer.
#[test]
fn carries_the_token_and_client_under_the_asserted_issuer() {
    let f = fixture(NOTES);
    f.seed_token("v3");
    f.seed_client("client-v3");
    let done = f.run(false).expect("migrates");
    assert!(done.wrote_token && done.wrote_client, "{done:?}");
    let token = f
        .storage
        .load(&f.key(), URL)
        .expect("readable under the 4.0 key");
    assert_eq!(token.access_token, "v3-access");
    assert_eq!(
        f.storage.load_client_id(&f.key(), URL).as_deref(),
        Some("client-v3")
    );
}

/// The 3.x files are read and never written: same bytes, mode and mtime.
#[test]
fn leaves_the_3x_files_exactly_as_they_were() {
    let f = fixture(NOTES);
    f.seed_token("v3");
    f.seed_client("client-v3");
    let snapshot = |p: &Path| {
        let meta = std::fs::metadata(p).expect("meta");
        (
            std::fs::read(p).expect("read"),
            meta.permissions(),
            meta.modified().expect("mtime"),
        )
    };
    let (token, client) = (
        f.storage.token_path("notes", URL),
        f.storage.client_path("notes", URL),
    );
    let before = (snapshot(&token), snapshot(&client));
    f.run(false).expect("migrates");
    assert_eq!(before, (snapshot(&token), snapshot(&client)));
}

/// An entry already under the 4.0 key wins; nothing is written.
#[test]
fn an_existing_4_0_entry_is_kept() {
    let f = fixture(NOTES);
    f.seed_token("v3");
    let mut current = f.storage.load("notes", URL).expect("seeded");
    current.access_token = "v4-access".to_owned();
    f.storage.save(&f.key(), URL, &current).expect("4.0 entry");
    let done = f.run(false).expect("not an error");
    assert!(done.already_present && !done.wrote_token, "{done:?}");
    assert_eq!(
        f.storage.load(&f.key(), URL).expect("kept").access_token,
        "v4-access"
    );
}

/// A 4.0 registration with another client id refuses before any write.
#[test]
fn a_different_4_0_client_refuses_and_writes_nothing() {
    let f = fixture(NOTES);
    f.seed_token("v3");
    f.seed_client("client-v3");
    f.storage
        .save_client_id(&f.key(), URL, "client-v4")
        .expect("4.0 client");
    assert!(matches!(
        f.run(false),
        Err(LegacyOAuthMigrateError::ClientMismatch(_))
    ));
    assert!(
        f.storage.load(&f.key(), URL).is_none(),
        "no token was published"
    );
}

/// A configured static client id that differs from the 3.x one refuses.
#[test]
fn a_different_static_client_id_refuses() {
    let f = fixture(&format!("{NOTES}      client_id: configured-client\n"));
    f.seed_token("v3");
    f.seed_client("client-v3");
    assert!(matches!(
        f.run(false),
        Err(LegacyOAuthMigrateError::ClientMismatch(_))
    ));
    assert!(f.storage.load(&f.key(), URL).is_none());
}

/// A dry run reports the plan and writes nothing.
#[test]
fn a_dry_run_writes_nothing() {
    let f = fixture(NOTES);
    f.seed_token("v3");
    let done = f.run(true).expect("plans");
    assert!(done.dry_run && !done.wrote_token, "{done:?}");
    assert!(f.storage.load(&f.key(), URL).is_none());
}

/// No 3.x client and no static client id: migrated, with a warning.
#[test]
fn a_missing_3x_client_warns() {
    let f = fixture(NOTES);
    f.seed_token("v3");
    let done = f.run(false).expect("migrates");
    assert!(done.wrote_token && !done.wrote_client, "{done:?}");
    assert!(
        done.warnings.iter().any(|w| w.contains("client")),
        "{done:?}"
    );
}

/// Refusals that write nothing: unknown backend, no oauth block, no source.
#[test]
fn refuses_what_it_cannot_migrate() {
    let f = fixture(&format!(
        "{NOTES}  plain:\n    http_url: https://plain.example.test/mcp\n"
    ));
    let mut other = request(false);
    other.backend = "missing";
    assert!(matches!(
        migrate_in(&f.storage, &f.config, &other),
        Err(LegacyOAuthMigrateError::NoSuchBackend(_))
    ));
    other.backend = "plain";
    assert!(matches!(
        migrate_in(&f.storage, &f.config, &other),
        Err(LegacyOAuthMigrateError::NotOAuth(_))
    ));
    assert!(matches!(
        f.run(false),
        Err(LegacyOAuthMigrateError::Source(_))
    ));
}

/// A running gateway holds the token directory's instance lock shared; the
/// command needs it exclusive and refuses rather than racing the gateway.
#[test]
fn a_running_gateway_refuses_the_migration() {
    let f = fixture(NOTES);
    f.seed_token("v3");
    let held = super::hold_instance_lock(&f.storage).expect("a gateway holds the lock");
    assert!(matches!(
        f.run(false),
        Err(LegacyOAuthMigrateError::GatewayRunning)
    ));
    drop(held);
    assert!(
        f.run(false)
            .expect("runs once the gateway stops")
            .wrote_token
    );
}

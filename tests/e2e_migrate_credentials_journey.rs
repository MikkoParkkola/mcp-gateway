// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Upgrade journey for a 3.5.x user with an OAuth credential, driven through
//! the built binary: `accounts init-store`, then `accounts
//! migrate-credentials` from the 3.x token file in `~/.mcp-gateway/oauth/`.
//!
//! Asserted on what the user sees: exit codes, the printed report and hints,
//! the 3.x file left byte-identical, and exactly one store record that does
//! not hold the token in plain text. A wrong issuer is refused first and
//! changes nothing; a re-run reports there is nothing to do.
//!
//! The backend registry name (`gdrive`) and the descriptor id differ on
//! purpose: the 3.x file is named after the backend, and a migration that
//! looked it up by descriptor id would find nothing.

// Unix-only: writes owner-only fixtures with POSIX mode bits.
#![cfg(unix)]

#[path = "common/gateway_bin.rs"]
mod gateway_bin;

use std::fs;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::process::Output;

use sha2::{Digest as _, Sha256};

const BACKEND: &str = "gdrive";
const BACKEND_URL: &str = "https://mcp.example.test/v1/mcp";
const DESCRIPTOR: &str = "workspace-personal";
const ISSUER: &str = "https://auth.example.test";
const ACCESS_TOKEN: &str = "legacy-access-token-e2e";
const REFRESH_TOKEN: &str = "legacy-refresh-token-e2e";
/// 32 raw bytes (all 0x51) in standard base64: a well-formed store key.
const KEY_B64: &str = "UVFRUVFRUVFRUVFRUVFRUVFRUVFRUVFRUVFRUVFRUVE=";

/// A token file as 3.5.x wrote it.
fn legacy_json() -> String {
    format!(
        "{{\n  \"access_token\": \"{ACCESS_TOKEN}\",\n  \"token_type\": \"Bearer\",\n  \
         \"refresh_token\": \"{REFRESH_TOKEN}\",\n  \"expires_at\": 4102444800,\n  \
         \"scope\": \"read write\"\n}}"
    )
}

/// 3.x names the file after the first 8 bytes of sha256("<backend>:<url>").
fn legacy_file_name() -> String {
    let digest = Sha256::digest(format!("{BACKEND}:{BACKEND_URL}").as_bytes());
    format!("{}_tokens.json", hex::encode(&digest[..8]))
}

fn owner_only(path: &Path, body: &str) {
    fs::write(path, body).expect("write fixture");
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).expect("chmod 600");
}

struct Install {
    _tmp: tempfile::TempDir,
    root: PathBuf,
    legacy: PathBuf,
}

impl Install {
    /// A 3.5.x home with one OAuth token file, and a 4.0 config that binds
    /// the same backend to a personal-account descriptor.
    fn new() -> Self {
        let tmp = tempfile::tempdir().expect("temp root");
        // Canonical: the store refuses a root reached through a symlink, and
        // the macOS temp dir is one.
        let root = tmp.path().canonicalize().expect("canonical temp root");

        let oauth = root.join("home/.mcp-gateway/oauth");
        fs::create_dir_all(&oauth).expect("3.x oauth dir");
        for dir in [oauth.as_path(), oauth.parent().expect("parent")] {
            fs::set_permissions(dir, fs::Permissions::from_mode(0o700)).expect("chmod 700");
        }
        let legacy = oauth.join(legacy_file_name());
        owner_only(&legacy, &legacy_json());

        owner_only(&root.join("keys.env"), &format!("ACCOUNTS_KEY={KEY_B64}\n"));
        let config = format!(
            "env_files:\n  - {root}/keys.env\n\
             backends:\n  {BACKEND}:\n    http_url: {BACKEND_URL}\n    account: {DESCRIPTOR}\n\
             accounts:\n  schema_version: accounts.v1\n  enabled: true\n  \
             deployment: single_process\n  instance_id: e2e-migrate\n  \
             store_dir: {root}/store\n  authority_dir: {root}/authority\n  \
             current_key_id: current\n  keys:\n    current: env:ACCOUNTS_KEY\n  \
             descriptors:\n    {DESCRIPTOR}:\n      mode: personal_managed\n      \
             provider: workspace\n      resource: {BACKEND_URL}\n      issuer: {ISSUER}\n      \
             authorization_endpoint: {ISSUER}/authorize\n      token_endpoint: {ISSUER}/token\n      \
             redirect_uri: https://app.example.test/callback\n      client_id: client-abc\n      \
             scopes: [read, write]\n      send_resource_parameter: true\n  \
             limits:\n    store_entries: 1000\n    authority_bytes: 16777216\n",
            root = root.display()
        );
        owner_only(&root.join("gateway.yaml"), &config);
        Self {
            _tmp: tmp,
            root,
            legacy,
        }
    }

    fn run(&self, args: &[&str]) -> Output {
        let mut command =
            gateway_bin::command(&self.root.join("home"), gateway_bin::Inherit::Environment);
        command
            .current_dir(&self.root)
            .arg("--config")
            .arg(self.root.join("gateway.yaml"))
            .args(args)
            .output()
            .expect("the binary runs")
    }

    fn migrate(&self, issuer: &str) -> Output {
        self.run(&[
            "accounts",
            "migrate-credentials",
            "--descriptor-id",
            DESCRIPTOR,
            "--legacy-issuer",
            issuer,
        ])
    }

    fn store_records(&self) -> Vec<PathBuf> {
        fs::read_dir(self.root.join("store"))
            .expect("store dir")
            .map(|e| e.expect("entry").path())
            .filter(|p| p.extension().is_some_and(|x| x == "json"))
            .collect()
    }
}

fn show(out: &Output) -> String {
    format!(
        "exit: {}\n--- stdout ---\n{}\n--- stderr ---\n{}",
        out.status,
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

fn assert_report(out: &Output, headline: &str) {
    assert!(out.status.success(), "{}", show(out));
    let stdout = String::from_utf8_lossy(&out.stdout);
    let lines: [&str; 4] = [
        headline,
        &format!("  descriptor_id: {DESCRIPTOR}"),
        &format!("  source file:   {}", legacy_file_name()),
        "Your 3.x credential file was not modified, renamed or deleted.",
    ];
    for line in lines {
        assert!(stdout.contains(line), "missing {line:?}\n{}", show(out));
    }
    for secret in [ACCESS_TOKEN, REFRESH_TOKEN] {
        assert!(
            !stdout.contains(secret) && !String::from_utf8_lossy(&out.stderr).contains(secret),
            "a token was printed\n{}",
            show(out)
        );
    }
}

#[test]
fn migrate_credentials_moves_a_3x_token_into_the_store_and_leaves_the_source() {
    let install = Install::new();
    let original = fs::read(&install.legacy).expect("3.x file");

    let init = install.run(&["accounts", "init-store"]);
    assert!(init.status.success(), "{}", show(&init));
    assert!(
        String::from_utf8_lossy(&init.stdout)
            .contains("Initialized an empty personal-account store."),
        "{}",
        show(&init)
    );
    assert!(
        install.store_records().is_empty(),
        "a fresh store holds no records"
    );

    // A credential from another authorization server is refused, with a hint.
    let refused = install.migrate("https://other-issuer.example.test");
    assert!(!refused.status.success(), "{}", show(&refused));
    let stderr = String::from_utf8_lossy(&refused.stderr);
    assert!(
        stderr.contains("is not this descriptor's issuer"),
        "{}",
        show(&refused)
    );
    assert!(
        stderr.contains("Your 3.x credential file is untouched"),
        "{}",
        show(&refused)
    );
    assert!(
        install.store_records().is_empty(),
        "a refusal writes no record"
    );

    let migrated = install.migrate(ISSUER);
    assert_report(
        &migrated,
        "Migrated one 3.x credential into the account store.",
    );
    let records = install.store_records();
    assert_eq!(records.len(), 1, "one grant migrated: {records:?}");
    let record = fs::read_to_string(&records[0]).expect("record");
    for secret in [ACCESS_TOKEN, REFRESH_TOKEN] {
        assert!(
            !record.contains(secret),
            "the store holds a token in plain text"
        );
    }

    let rerun = install.migrate(ISSUER);
    assert_report(&rerun, "Nothing to do: this account already holds a grant.");
    assert_eq!(install.store_records().len(), 1, "a re-run adds nothing");

    assert_eq!(
        fs::read(&install.legacy).expect("3.x file after"),
        original,
        "the 3.x file must be byte-identical after migration"
    );
}

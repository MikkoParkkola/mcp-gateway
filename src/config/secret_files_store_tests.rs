// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A secret saved to the `files` store reads back through the production
//! `file:` reader, which checks owner-only (mode, or the DACL on Windows).

use std::path::PathBuf;

use crate::secret_store::{
    FilesStore, NewSecret, SecretStore as _, StoreError, Vault, save_secrets,
};

#[test]
fn b2_b27_a_files_secret_is_owner_only_new_and_reads_back_byte_exact() {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = Vault::with_lock(dir.path(), dir.path().join("vault.lock"));
    let store = FilesStore::new(dir.path());
    let secrets = [NewSecret {
        field: "auth.bearer_token",
        value: b" a\n",
    }];
    let refs =
        save_secrets(&vault, &store, &secrets, |refs| Ok::<_, ()>(refs.to_vec())).expect("saved");
    let path = PathBuf::from(refs[0].strip_prefix("file:").expect("a file: reference"));
    assert!(path.is_absolute(), "{}", path.display());
    assert_eq!(path.parent(), Some(dir.path().join("secrets").as_path()));
    // The production reader checks owner-only (mode, or the DACL on
    // Windows) and drops one trailing newline.
    let read = super::secret_ref::read_file_ref("auth.bearer_token", &path).expect("read");
    assert_eq!(read.as_bytes(), b" a\n");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }
    // Create-new: an existing name is refused and its bytes stay.
    let name = path.file_name().unwrap().to_str().unwrap();
    assert_eq!(store.create(name, b"other"), Err(StoreError::Exists));
    assert_eq!(std::fs::read(&path).unwrap(), b" a\n\n");
}

#[test]
fn b1_secrets_store_is_a_known_key_and_a_typo_under_it_is_refused() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("gateway.yaml");
    // Owner-only, as the loader requires of a file that can hold secrets.
    let write = |text: &str| {
        let _ = std::fs::remove_file(&path);
        let mut file = crate::config_persistence::create_new_private(&path).unwrap();
        std::io::Write::write_all(&mut file, text.as_bytes()).unwrap();
    };
    write("secrets:\n  store: files\n");
    let config = super::Config::load(Some(&path)).expect("secrets.store loads");
    assert_eq!(config.secrets.store, super::SecretStoreChoice::Files);
    write("secrets:\n  stor: files\n");
    let refused = super::Config::load(Some(&path)).expect_err("a typo is refused");
    assert!(refused.to_string().contains("secrets.stor"), "{refused}");
}

#[test]
fn b2_values_ending_in_cr_or_crlf_round_trip_through_file_ref() {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = Vault::with_lock(dir.path(), dir.path().join("vault.lock"));
    let store = FilesStore::new(dir.path());
    for value in [&b"pasted\r"[..], b"\r", b"a\r\n", b"a\r\nb", b"x\n"] {
        let refs = save_secrets(
            &vault,
            &store,
            &[NewSecret {
                field: "auth.bearer_token",
                value,
            }],
            |refs| Ok::<_, ()>(refs.to_vec()),
        )
        .expect("saved");
        let path = PathBuf::from(refs[0].strip_prefix("file:").unwrap());
        let read = super::secret_ref::read_file_ref("auth.bearer_token", &path).expect("read");
        assert_eq!(read.as_bytes(), value, "{value:?}");
    }
}

// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Deleting one unused entry: re-checked under the vault lock, one store at a time, no line before the delete.

#[cfg(unix)]
use super::Deleted;
use super::tests::{index_bytes, list, quiet, rig, saved, secret_path, soon, sources};
#[cfg(unix)]
use super::tests::{save_field, scoped_removal};
use super::{DeleteRefused, NamingSources, delete_unused};
use crate::gateway::test_helpers::write_owner_only;
#[cfg(unix)]
use crate::secret_store::fresh_name;
use crate::secret_store::index::Index;
use crate::secret_store::{
    FilesStore, NewSecret, SecretStore, StoreError, StoreKind, Vault, save_secrets,
};
use std::collections::BTreeMap;
#[cfg(unix)]
use std::path::PathBuf;
use std::sync::Mutex;
#[cfg(unix)]
use std::sync::mpsc;
#[cfg(unix)]
use std::time::{Duration, Instant};

/// In-memory keychain store. `exists` and `delete` can be faulted after a save.
pub(super) struct Fault {
    entries: Mutex<BTreeMap<String, Vec<u8>>>,
    calls: Mutex<Vec<String>>,
    exists_error: Mutex<Option<StoreError>>,
    delete_error: Mutex<Option<StoreError>>,
}

impl Fault {
    pub(super) fn new() -> Self {
        Self {
            entries: Mutex::default(),
            calls: Mutex::default(),
            exists_error: Mutex::default(),
            delete_error: Mutex::default(),
        }
    }

    #[cfg(unix)]
    fn land(&self, name: &str) {
        self.entries
            .lock()
            .expect("entries")
            .insert(name.to_owned(), b"v".to_vec());
    }

    pub(super) fn set_exists(&self, error: StoreError) {
        *self.exists_error.lock().expect("exists fault") = Some(error);
    }

    fn clear_exists(&self) {
        *self.exists_error.lock().expect("exists fault") = None;
    }

    pub(super) fn set_delete(&self, error: StoreError) {
        *self.delete_error.lock().expect("delete fault") = Some(error);
    }

    fn clear(&self) {
        self.calls.lock().expect("calls").clear();
    }

    fn calls(&self) -> Vec<String> {
        self.calls.lock().expect("calls").clone()
    }

    fn saw(&self, prefix: &str) -> bool {
        self.calls().iter().any(|call| call.starts_with(prefix))
    }

    fn note(&self, what: &str, name: &str) {
        self.calls
            .lock()
            .expect("calls")
            .push(format!("{what} {name}"));
    }
}

impl SecretStore for Fault {
    fn kind(&self) -> StoreKind {
        StoreKind::Keychain
    }

    fn limit(&self) -> usize {
        4096
    }

    fn probe(&self) -> Result<(), StoreError> {
        Ok(())
    }

    fn exists(&self, name: &str) -> Result<bool, StoreError> {
        self.note("exists", name);
        if let Some(error) = self.exists_error.lock().expect("exists fault").clone() {
            return Err(error);
        }
        Ok(self.entries.lock().expect("entries").contains_key(name))
    }

    fn create(&self, name: &str, value: &[u8]) -> Result<String, StoreError> {
        self.note("create", name);
        let mut entries = self.entries.lock().expect("entries");
        if entries.contains_key(name) {
            return Err(StoreError::Exists);
        }
        entries.insert(name.to_owned(), value.to_vec());
        Ok(format!("keychain:{name}"))
    }

    fn delete(&self, name: &str) -> Result<(), StoreError> {
        self.note("delete", name);
        if let Some(error) = self.delete_error.lock().expect("delete fault").clone() {
            return Err(error);
        }
        self.entries.lock().expect("entries").remove(name);
        Ok(())
    }
}

pub(super) fn fault_entry() -> (
    tempfile::TempDir,
    Vault,
    Fault,
    String,
    Vec<u8>,
    NamingSources,
) {
    let (dir, vault) = rig();
    let store = Fault::new();
    save_secrets(
        &vault,
        &store,
        &[NewSecret {
            field: "f",
            value: b"v",
        }],
        |_| Ok::<_, &str>(()),
    )
    .expect("save");
    let name = Index::at(dir.path())
        .live()
        .expect("index")
        .into_iter()
        .next()
        .expect("one indexed name")
        .name;
    store.clear();
    let index = index_bytes(dir.path());
    let sources = quiet(dir.path());
    (dir, vault, store, name, index, sources)
}

/// The vault lock, held on another thread. A same-thread flock does not
/// exclude the caller that is about to delete.
#[cfg(unix)]
pub(super) struct LockHold {
    release: Option<mpsc::Sender<()>>,
    handle: Option<std::thread::JoinHandle<()>>,
}

#[cfg(unix)]
pub(super) fn hold_vault(lock: PathBuf) -> LockHold {
    let (held_tx, held_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel::<()>();
    let handle = std::thread::spawn(move || {
        let held = crate::config_persistence::lock::lock_file_blocking(
            &lock,
            "the secret vault",
            Instant::now() + Duration::from_secs(5),
        )
        .expect("hold the vault lock");
        held_tx.send(()).expect("held");
        let _ = release_rx.recv();
        drop(held);
    });
    held_rx
        .recv_timeout(Duration::from_secs(5))
        .expect("the vault lock is held");
    LockHold {
        release: Some(release_tx),
        handle: Some(handle),
    }
}

#[cfg(unix)]
impl LockHold {
    pub(super) fn release(mut self) {
        self.join();
    }

    fn join(&mut self) {
        if let Some(tx) = self.release.take() {
            let _ = tx.send(());
        }
        if let Some(handle) = self.handle.take() {
            handle.join().expect("vault lock holder");
        }
    }
}

#[cfg(unix)]
impl Drop for LockHold {
    fn drop(&mut self) {
        if let Some(tx) = self.release.take() {
            let _ = tx.send(());
        }
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

#[cfg(unix)]
#[test]
fn delete_removes_one_entry() {
    const ROW: &str = "delete_removes_one_entry";
    let (dir, vault) = rig();
    let store = FilesStore::new(dir.path());
    let first = save_field(&vault, dir.path(), "auth.bearer_token", b"one");
    let second = save_field(&vault, dir.path(), "key_server.admin_token", b"two");
    let sources = quiet(dir.path());
    let got = delete_unused(&vault, &store, &first, &sources, soon());
    assert_eq!(got, Ok(Deleted::Removed), "{ROW}: {got:?}");
    assert!(
        !secret_path(dir.path(), &first).exists(),
        "{ROW}: file remains"
    );
    let listed = list(&vault, &[&store]);
    assert!(
        listed.iter().all(|entry| entry.name != first),
        "{ROW}: still listed: {listed:?}"
    );
    assert!(
        listed.iter().any(|entry| entry.name == second),
        "{ROW}: other entry dropped: {listed:?}"
    );
    let text = std::fs::read_to_string(dir.path().join("secrets-index.jsonl")).expect("index");
    assert!(
        scoped_removal(&text, &first),
        "{ROW}: removal line is not store-scoped:\n{text}"
    );
}

#[cfg(unix)]
#[test]
fn delete_keeps_same_name_in_other_store() {
    const ROW: &str = "delete_keeps_same_name_in_other_store";
    let (dir, vault) = rig();
    let files = FilesStore::new(dir.path());
    let name = save_field(&vault, dir.path(), "f", b"v");
    let fault = Fault::new();
    fault.land(&name);
    Index::at(dir.path())
        .append_created(&name, StoreKind::Keychain)
        .expect("index");
    let sources = quiet(dir.path());
    let got = delete_unused(&vault, &files, &name, &sources, soon());
    assert_eq!(got, Ok(Deleted::Removed), "{ROW}: {got:?}");
    assert!(
        !secret_path(dir.path(), &name).exists(),
        "{ROW}: files entry remains"
    );
    let listed = list(&vault, &[&files, &fault]);
    assert_eq!(listed.len(), 1, "{ROW}: {listed:?}");
    assert_eq!(listed[0].name, name, "{ROW}: {listed:?}");
    assert_eq!(listed[0].store, StoreKind::Keychain, "{ROW}: {listed:?}");
    let again = delete_unused(&vault, &fault, &name, &sources, soon());
    assert_eq!(
        again,
        Ok(Deleted::Removed),
        "{ROW}: keychain delete {again:?}"
    );
}

#[cfg(unix)]
#[test]
fn delete_refuses_unlisted_and_mismatch() {
    const ROW: &str = "delete_refuses_unlisted_and_mismatch";
    let (dir, vault) = rig();
    let files = FilesStore::new(dir.path());
    let sources = quiet(dir.path());
    let ghost = fresh_name("missing", 1, 1);
    let before = index_bytes(dir.path());
    let got = delete_unused(&vault, &files, &ghost, &sources, soon());
    assert_eq!(
        got,
        Err(DeleteRefused::NotListed),
        "{ROW}: unlisted {got:?}"
    );
    assert_eq!(index_bytes(dir.path()), before, "{ROW}: index changed");
    let only = fresh_name("other", 2, 2);
    Index::at(dir.path())
        .append_created(&only, StoreKind::Keychain)
        .expect("index");
    let before = index_bytes(dir.path());
    let got = delete_unused(&vault, &files, &only, &sources, soon());
    assert_eq!(
        got,
        Err(DeleteRefused::StoreMismatch),
        "{ROW}: mismatch {got:?}"
    );
    assert_eq!(index_bytes(dir.path()), before, "{ROW}: index changed");
}

#[test]
fn delete_refuses_bad_names() {
    const ROW: &str = "delete_refuses_bad_names";
    let (dir, vault) = rig();
    let gateway = dir.path().join("gateway.yaml");
    let before = b"k: clean\n".to_vec();
    write_owner_only(&gateway, &before).expect("yaml");
    std::fs::create_dir_all(dir.path().join("secrets")).expect("secrets");
    let store = FilesStore::new(dir.path());
    let sources = sources(dir.path());
    for bad in ["../gateway.yaml", "a/b"] {
        let got = delete_unused(&vault, &store, bad, &sources, soon());
        assert_eq!(got, Err(DeleteRefused::BadName), "{ROW} {bad}: {got:?}");
    }
    assert_eq!(
        std::fs::read(&gateway).expect("yaml"),
        before,
        "{ROW}: gateway.yaml changed"
    );
    let del = store.delete("../gateway.yaml");
    let after = std::fs::read(&gateway).ok();
    assert!(
        del.is_err(),
        "{ROW}: files delete accepted '../gateway.yaml': {del:?}"
    );
    assert_eq!(
        after.as_deref(),
        Some(before.as_slice()),
        "{ROW}: gateway.yaml changed"
    );
}

#[cfg(unix)]
#[test]
fn delete_refuses_named() {
    const ROW: &str = "delete_refuses_named";
    let (dir, vault, name) = saved();
    let suffix = name.rsplit('.').next().expect("suffix");
    write_owner_only(dir.path().join("gateway.yaml"), format!("k: {suffix}\n")).expect("yaml");
    let path = secret_path(dir.path(), &name);
    let file = std::fs::read(&path).expect("entry");
    let index = index_bytes(dir.path());
    let got = delete_unused(
        &vault,
        &FilesStore::new(dir.path()),
        &name,
        &sources(dir.path()),
        soon(),
    );
    assert_eq!(got, Err(DeleteRefused::Named), "{ROW}: {got:?}");
    assert_eq!(
        std::fs::read(&path).expect("entry"),
        file,
        "{ROW}: entry changed"
    );
    assert_eq!(index_bytes(dir.path()), index, "{ROW}: index changed");
}

#[test]
fn delete_failure_writes_no_line() {
    const ROW: &str = "delete_failure_writes_no_line";
    let (dir, vault, store, name, index, sources) = fault_entry();
    store.set_delete(StoreError::Failed("injected delete failure".to_owned()));
    let got = delete_unused(&vault, &store, &name, &sources, soon());
    assert!(
        store.saw("delete "),
        "{ROW}: delete was not asked: {:?}",
        store.calls()
    );
    assert!(
        matches!(got, Err(DeleteRefused::Failed(_))),
        "{ROW}: {got:?}"
    );
    assert_eq!(index_bytes(dir.path()), index, "{ROW}: index changed");
    let listed = list(&vault, &[&store]);
    assert_eq!(listed.len(), 1, "{ROW}: {listed:?}");
    assert_eq!(listed[0].name, name, "{ROW}: dropped");
}

#[test]
fn exists_error_writes_no_line() {
    const ROW: &str = "exists_error_writes_no_line";
    let (dir, vault, store, name, index, sources) = fault_entry();
    store.set_exists(StoreError::TimedOut);
    let got = delete_unused(&vault, &store, &name, &sources, soon());
    assert!(
        store.saw("exists "),
        "{ROW}: exists was not asked: {:?}",
        store.calls()
    );
    assert!(
        matches!(
            got,
            Err(DeleteRefused::TimedOut) | Err(DeleteRefused::Failed(_))
        ),
        "{ROW}: {got:?}"
    );
    assert_eq!(index_bytes(dir.path()), index, "{ROW}: index changed");
    store.clear_exists();
    let listed = list(&vault, &[&store]);
    assert_eq!(listed.len(), 1, "{ROW}: {listed:?}");
    assert_eq!(
        listed[0].name, name,
        "{ROW}: dropped once the fault cleared"
    );
}

#[test]
fn delete_timed_out_keeps_listing() {
    const ROW: &str = "delete_timed_out_keeps_listing";
    let (dir, vault, store, name, index, sources) = fault_entry();
    store.set_delete(StoreError::TimedOut);
    let got = delete_unused(&vault, &store, &name, &sources, soon());
    assert_eq!(got, Err(DeleteRefused::TimedOut), "{ROW}: {got:?}");
    assert_eq!(index_bytes(dir.path()), index, "{ROW}: index changed");
    let listed = list(&vault, &[&store]);
    assert_eq!(listed.len(), 1, "{ROW}: {listed:?}");
    assert_eq!(listed[0].name, name, "{ROW}: dropped");
}

#[cfg(unix)]
#[test]
fn already_gone_writes_the_line() {
    const ROW: &str = "already_gone_writes_the_line";
    let (dir, vault, name) = saved();
    std::fs::remove_file(secret_path(dir.path(), &name)).expect("remove by hand");
    let sources = quiet(dir.path());
    let store = FilesStore::new(dir.path());
    let got = delete_unused(&vault, &store, &name, &sources, soon());
    assert_eq!(got, Ok(Deleted::AlreadyGone), "{ROW}: {got:?}");
    let text = std::fs::read_to_string(dir.path().join("secrets-index.jsonl")).expect("index");
    assert!(
        scoped_removal(&text, &name),
        "{ROW}: no store-scoped removal line:\n{text}"
    );
    let again = delete_unused(&vault, &store, &name, &sources, soon());
    assert_eq!(
        again,
        Ok(Deleted::AlreadyGone),
        "{ROW}: second call {again:?}"
    );
}

#[cfg(unix)]
#[test]
fn delete_waits_for_the_vault_alone() {
    const ROW: &str = "delete_waits_for_the_vault_alone";
    let (dir, vault, name) = saved();
    let path = secret_path(dir.path(), &name);
    let file = std::fs::read(&path).expect("entry");
    let index = index_bytes(dir.path());
    let sources = quiet(dir.path());
    let hold = hold_vault(vault.lock_path().to_path_buf());
    let started = Instant::now();
    let got = delete_unused(
        &vault,
        &FilesStore::new(dir.path()),
        &name,
        &sources,
        started + Duration::from_millis(200),
    );
    let waited = started.elapsed();
    hold.release();
    assert_eq!(got, Err(DeleteRefused::Busy), "{ROW}: {got:?}");
    // Far below the store's 30 s lock wait: the delete gave up at its own deadline.
    assert!(waited < Duration::from_secs(10), "{ROW}: waited {waited:?}");
    assert_eq!(
        std::fs::read(&path).expect("entry"),
        file,
        "{ROW}: entry changed"
    );
    assert_eq!(index_bytes(dir.path()), index, "{ROW}: index changed");
}

/// Off Unix every files-store delete is refused before the lock. The entry and the index stay.
#[cfg(not(unix))]
#[test]
fn files_delete_refused_off_unix() {
    const ROW: &str = "files_delete_refused_off_unix";
    let (dir, vault, name) = saved();
    let path = secret_path(dir.path(), &name);
    let file = std::fs::read(&path).unwrap_or_else(|error| panic!("{ROW}: entry: {error}"));
    let index = index_bytes(dir.path());
    let got = delete_unused(
        &vault,
        &FilesStore::new(dir.path()),
        &name,
        &quiet(dir.path()),
        soon(),
    );
    let text = match &got {
        Err(DeleteRefused::Failed(text)) => text.as_str(),
        other => panic!("{ROW}: {other:?}"),
    };
    assert!(text.contains("links"), "{ROW}: {text}");
    let again = std::fs::read(&path).unwrap_or_else(|error| panic!("{ROW}: entry: {error}"));
    assert_eq!(again, file, "{ROW}: entry changed");
    assert_eq!(index_bytes(dir.path()), index, "{ROW}: index changed");
}

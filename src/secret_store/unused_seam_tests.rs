// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Seam rows: a source edited before the re-check, a stop between the store delete and its
//! line, a listing that survives one failing store, and the vault lock freed after each refusal.

use super::delete_tests::Fault;
#[cfg(unix)]
use super::delete_tests::{fault_entry, hold_vault};
use super::listing;
use super::seam::{BEFORE_RECHECK, STOP_AFTER_STORE_DELETE};
#[cfg(unix)]
use super::tests::{index_bytes, saved, scoped_removal, secret_path, soon, sources};
use super::tests::{quiet, rig, save_field};
#[cfg(unix)]
use super::{DeleteRefused, Deleted, delete_unused};
#[cfg(unix)]
use crate::gateway::test_helpers::write_owner_only;
#[cfg(unix)]
use crate::secret_store::index::Index;
use crate::secret_store::{
    FilesStore, NewSecret, SecretStore, StoreError, StoreKind, save_secrets,
};
#[cfg(unix)]
use std::io::Write as _;
#[cfg(unix)]
use std::time::Instant;

/// Clears both seams on drop, so a failing assertion cannot leak one into the next row.
#[must_use]
struct SeamGuard;

impl SeamGuard {
    fn reset() {
        BEFORE_RECHECK.with(|slot| *slot.borrow_mut() = None);
        STOP_AFTER_STORE_DELETE.with(|cell| cell.set(false));
    }
}

impl Drop for SeamGuard {
    fn drop(&mut self) {
        Self::reset();
    }
}

fn seams() -> SeamGuard {
    SeamGuard::reset();
    SeamGuard
}

/// Appends `line(name)` to the config at the seam before the re-check, then deletes: the
/// delete refuses as Named and leaves the entry and the index byte for byte.
#[cfg(unix)]
fn refused_after_config_edit(row: &str, line: fn(&str) -> String) {
    let _guard = seams();
    let (dir, vault, name) = saved();
    let sources = quiet(dir.path());
    let config = sources.config.clone();
    let text = line(&name);
    BEFORE_RECHECK.with(|slot| {
        *slot.borrow_mut() = Some(Box::new(move || {
            let mut file = std::fs::OpenOptions::new()
                .append(true)
                .open(&config)
                .expect("config");
            writeln!(file, "{text}").expect("edit the config");
        }));
    });
    let path = secret_path(dir.path(), &name);
    let file = std::fs::read(&path).expect("entry");
    let index = index_bytes(dir.path());
    let got = delete_unused(
        &vault,
        &FilesStore::new(dir.path()),
        &name,
        &sources,
        soon(),
    );
    assert_eq!(got, Err(DeleteRefused::Named), "{row}: {got:?}");
    assert_eq!(
        std::fs::read(&path).expect("entry"),
        file,
        "{row}: entry changed"
    );
    assert_eq!(index_bytes(dir.path()), index, "{row}: index changed");
}

/// The edit plants the entry's name, so the re-check's own naming refuses.
#[cfg(unix)]
#[test]
fn delete_refuses_on_digest_change() {
    refused_after_config_edit("delete_refuses_on_digest_change", |name| {
        format!("# {name}")
    });
}

/// The edit names nothing, so only the changed digest refuses: a source that moved
/// between the two reads is not trusted to be the one the first read cleared.
#[cfg(unix)]
#[test]
fn delete_refuses_on_unnaming_edit() {
    refused_after_config_edit("delete_refuses_on_unnaming_edit", |_| "# edited".to_owned());
}

#[cfg(unix)]
#[test]
fn delete_crash_between_delete_and_line() {
    const ROW: &str = "delete_crash_between_delete_and_line";
    let _guard = seams();
    let (dir, vault, name) = saved();
    let store = FilesStore::new(dir.path());
    let sources = quiet(dir.path());
    let index = index_bytes(dir.path());
    STOP_AFTER_STORE_DELETE.with(|cell| cell.set(true));
    let got = delete_unused(&vault, &store, &name, &sources, soon());
    assert!(
        matches!(got, Err(DeleteRefused::Failed(_))),
        "{ROW}: {got:?}"
    );
    assert_eq!(
        store.exists(&name),
        Ok(false),
        "{ROW}: store still holds the entry"
    );
    let live = Index::at(dir.path()).live();
    assert!(
        live.as_ref()
            .ok()
            .is_some_and(|rows| rows.iter().any(|entry| entry.name == name)),
        "{ROW}: name is not live: {live:?}"
    );
    assert_eq!(
        index_bytes(dir.path()),
        index,
        "{ROW}: a line was written before the stop"
    );
    STOP_AFTER_STORE_DELETE.with(|cell| cell.set(false));
    let again = delete_unused(&vault, &store, &name, &sources, soon());
    assert_eq!(again, Ok(Deleted::AlreadyGone), "{ROW}: repeat {again:?}");
    let text = std::fs::read_to_string(dir.path().join("secrets-index.jsonl")).expect("index");
    assert!(
        scoped_removal(&text, &name),
        "{ROW}: no store-scoped removal line:\n{text}"
    );
    let live = Index::at(dir.path()).live();
    assert!(
        live.as_ref()
            .ok()
            .is_some_and(|rows| rows.iter().all(|entry| entry.name != name)),
        "{ROW}: name still live: {live:?}"
    );
}

#[test]
fn listing_partial_on_store_error() {
    const ROW: &str = "listing_partial_on_store_error";
    const SECRET: &str = "UNUSED-SECRET-VALUE";
    const CANARY: &str = "EXISTS-CANARY";
    let _guard = seams();
    let (dir, vault) = rig();
    let files = FilesStore::new(dir.path());
    let name = save_field(&vault, dir.path(), "f", SECRET.as_bytes());
    let fault = Fault::new();
    save_secrets(
        &vault,
        &fault,
        &[NewSecret {
            field: "k",
            value: SECRET.as_bytes(),
        }],
        |_| Ok::<_, &str>(()),
    )
    .expect("save");
    fault.set_exists(StoreError::Failed(CANARY.to_owned()));
    let got = listing(&vault, &[&files, &fault], &quiet(dir.path()));
    assert_eq!(got.entries.len(), 1, "{ROW}: entries {got:?}");
    assert_eq!(got.entries[0].name, name, "{ROW}: {got:?}");
    assert_eq!(got.entries[0].store, StoreKind::Files, "{ROW}: {got:?}");
    assert_eq!(got.errors.len(), 1, "{ROW}: errors {got:?}");
    assert_eq!(got.errors[0].0, fault.kind(), "{ROW}: {got:?}");
    assert!(
        !got.errors[0].1.contains(SECRET),
        "{ROW}: error text carries the secret: {}",
        got.errors[0].1
    );
    let entry = &got.entries[0];
    let shown = format!("{entry:?}");
    assert!(
        !shown.contains(SECRET),
        "{ROW}: entry carries the secret: {shown}"
    );
    assert!(
        !shown.contains(CANARY),
        "{ROW}: entry carries the error text: {shown}"
    );
}

#[cfg(unix)]
#[test]
fn vault_lock_released_after_refusals() {
    const ROW: &str = "vault_lock_released_after_refusals";
    let _guard = seams();

    {
        let (dir, vault, name) = saved();
        let sources = sources(dir.path());
        write_owner_only(&sources.config, format!("k: {name}\n")).expect("yaml");
        let got = delete_unused(
            &vault,
            &FilesStore::new(dir.path()),
            &name,
            &sources,
            soon(),
        );
        assert_eq!(got, Err(DeleteRefused::Named), "{ROW}: named {got:?}");
        hold_vault(vault.lock_path().to_path_buf()).release();
    }
    {
        let (dir, vault, name) = saved();
        let sources = quiet(dir.path());
        let hold = hold_vault(vault.lock_path().to_path_buf());
        let got = delete_unused(
            &vault,
            &FilesStore::new(dir.path()),
            &name,
            &sources,
            Instant::now(),
        );
        hold.release();
        assert_eq!(got, Err(DeleteRefused::Busy), "{ROW}: busy {got:?}");
        hold_vault(vault.lock_path().to_path_buf()).release();
    }
    {
        let (_dir, vault, store, name, _index, sources) = fault_entry();
        store.set_exists(StoreError::TimedOut);
        let got = delete_unused(&vault, &store, &name, &sources, soon());
        assert_eq!(
            got,
            Err(DeleteRefused::TimedOut),
            "{ROW}: timed out {got:?}"
        );
        hold_vault(vault.lock_path().to_path_buf()).release();
    }
    {
        let (_dir, vault, store, name, _index, sources) = fault_entry();
        store.set_delete(StoreError::Failed("injected delete failure".to_owned()));
        let got = delete_unused(&vault, &store, &name, &sources, soon());
        assert!(
            matches!(got, Err(DeleteRefused::Failed(_))),
            "{ROW}: failed {got:?}"
        );
        hold_vault(vault.lock_path().to_path_buf()).release();
    }
}
